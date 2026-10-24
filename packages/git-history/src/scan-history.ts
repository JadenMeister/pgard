import {
  createFindingFingerprint,
  type AnalyzerOutput,
  type Confidence,
  type Coverage,
  type Finding,
  type FindingStatus,
  type Severity,
} from "@pgard/findings";
import { HISTORY_RULES, type HistoryRuleId } from "./history-rules.js";
import { runGit as defaultRunGit, type GitRunner } from "./run-git.js";
import {
  SECRET_KIND_LABEL,
  detectSecrets,
  isEnvironmentFile,
  type DetectedSecret,
  type DetectedSecretKind,
} from "./secret-patterns.js";

export interface HistoryScanOptions {
  runner?: GitRunner;
  signal?: AbortSignal;
  /** Most recent commits (HEAD ancestry) whose changes are scanned. Default 1000. */
  maxCommits?: number;
  /** Blobs larger than this are skipped. Default 1 MiB. */
  maxBlobBytes?: number;
  /** Total bytes of blob content read from history. Default 64 MiB. */
  maxTotalBytes?: number;
}

const SHA = /^[0-9a-f]{40}$/;
const BATCH_BYTES = 8 * 1024 * 1024;
const STRONG_KINDS: ReadonlySet<DetectedSecretKind> = new Set([
  "private_key",
  "aws_access_key_id",
  "aws_secret_access_key",
  "github_token",
  "slack_token",
  "stripe_key",
  "google_api_key",
]);

interface TreeEntry {
  sha: string;
  path: string;
}

interface HistoryEntry extends TreeEntry {
  commit: string;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new Error("aborted");
}

/** `ls-tree -r -z HEAD`: "<mode> blob <sha>\t<path>\0" */
async function listHeadBlobs(cwd: string, runner: GitRunner): Promise<TreeEntry[]> {
  const output = await runner(
    { subcommand: "ls-tree", flags: ["-r", "-z", "--full-tree"], operands: ["HEAD"] },
    { cwd },
  );
  const entries: TreeEntry[] = [];
  for (const record of output.split("\0")) {
    const match = /^\d{6} blob ([0-9a-f]{40})\t([\s\S]+)$/.exec(record);
    if (match?.[1] && match[2]) entries.push({ sha: match[1], path: match[2] });
  }
  return entries;
}

/**
 * Blobs added or modified by each commit (newest first), via
 * `diff-tree -r -z --root --no-commit-id --stdin` fed with commit ids (plumbing only).
 */
async function listHistoryBlobs(
  cwd: string,
  runner: GitRunner,
  commits: string[],
): Promise<HistoryEntry[]> {
  const entries: HistoryEntry[] = [];
  for (const commit of commits) {
    const output = await runner(
      {
        subcommand: "diff-tree",
        flags: ["-r", "-z", "--root", "--no-commit-id", "--no-renames", "-m", "--first-parent"],
        operands: [commit],
      },
      { cwd },
    );
    const parts = output.split("\0");
    for (let index = 0; index + 1 < parts.length; index += 2) {
      const header = parts[index] ?? "";
      const filePath = parts[index + 1] ?? "";
      const match = /^:\d{6} \d{6} [0-9a-f]{40} ([0-9a-f]{40}) ([AM])/.exec(header);
      if (match?.[1] && filePath) entries.push({ commit, sha: match[1], path: filePath });
    }
  }
  return entries;
}

/** Reads blob contents with `cat-file --batch-check` / `--batch`, bounded by size. */
async function readBlobs(
  cwd: string,
  runner: GitRunner,
  shas: string[],
  maxBlobBytes: number,
  budget: { remaining: number },
): Promise<{ contents: Map<string, string>; skippedLarge: number; skippedBudget: number }> {
  const contents = new Map<string, string>();
  let skippedLarge = 0;
  let skippedBudget = 0;
  if (shas.length === 0) return { contents, skippedLarge, skippedBudget };
  const check = await runner(
    { subcommand: "cat-file", flags: ["--batch-check"] },
    { cwd, input: `${shas.join("\n")}\n`, maxBuffer: shas.length * 80 + 1024 },
  );
  const sizes: { sha: string; size: number }[] = [];
  for (const line of check.split("\n")) {
    const match = /^([0-9a-f]{40}) blob (\d+)$/.exec(line);
    if (!match?.[1] || !match[2]) continue;
    const size = Number(match[2]);
    if (size > maxBlobBytes) {
      skippedLarge += 1;
      continue;
    }
    if (size > budget.remaining) {
      skippedBudget += 1;
      continue;
    }
    budget.remaining -= size;
    sizes.push({ sha: match[1], size });
  }
  for (let start = 0; start < sizes.length;) {
    let bytes = 0;
    let end = start;
    while (
      end < sizes.length &&
      (end === start || bytes + (sizes[end]?.size ?? 0) <= BATCH_BYTES)
    ) {
      bytes += sizes[end]?.size ?? 0;
      end += 1;
    }
    const batch = sizes.slice(start, end);
    const raw = await runner(
      { subcommand: "cat-file", flags: ["--batch"] },
      {
        cwd,
        input: `${batch.map((entry) => entry.sha).join("\n")}\n`,
        encoding: "latin1",
        maxBuffer: bytes + batch.length * 80 + 1024,
      },
    );
    let offset = 0;
    while (offset < raw.length) {
      const headerEnd = raw.indexOf("\n", offset);
      if (headerEnd === -1) break;
      const header = /^([0-9a-f]{40}) blob (\d+)$/.exec(raw.slice(offset, headerEnd));
      if (!header?.[1] || !header[2]) break;
      const size = Number(header[2]);
      const body = raw.slice(headerEnd + 1, headerEnd + 1 + size);
      offset = headerEnd + 1 + size + 1;
      if (body.includes("\0")) continue; // binary
      contents.set(header[1], Buffer.from(body, "latin1").toString("utf8"));
    }
    start = end;
  }
  return { contents, skippedLarge, skippedBudget };
}

function createFinding(fields: {
  ruleId: HistoryRuleId;
  path: string;
  line: number | null;
  commit: string | null;
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  evidence: string;
  cause: string;
}): Finding {
  const rule = HISTORY_RULES.find((entry) => entry.id === fields.ruleId) ?? HISTORY_RULES[0];
  const location = {
    kind: fields.commit ? ("commit" as const) : ("file" as const),
    path: fields.path,
    line: fields.line,
    url: null,
    commit: fields.commit,
  };
  return {
    id: createFindingFingerprint({ ruleId: fields.ruleId, location, cause: fields.cause }),
    ruleId: fields.ruleId,
    title: rule.title,
    category: rule.category,
    severity: fields.severity,
    status: fields.status,
    confidence: fields.confidence,
    location,
    evidence: fields.evidence,
    impact: rule.impact,
    recommendation: rule.recommendation,
    references: { cwe: [...rule.cwe], owasp: [...rule.owasp], cve: [] },
    sources: ["history"],
  };
}

function assessment(kind: DetectedSecretKind): {
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
} {
  return STRONG_KINDS.has(kind)
    ? {
        severity: kind === "private_key" ? "critical" : "high",
        status: "confirmed",
        confidence: "high",
      }
    : { severity: "high", status: "suspected", confidence: "medium" };
}

/**
 * Scans what Git stores — never the working tree — for committed environment files and
 * secrets: tracked files at HEAD and blobs added or modified in recent commits. Untracked or
 * ignored local files (such as a local `.env`) are never read. Secret values are kept in memory
 * only to tell current secrets from removed ones; findings name the kind, never the value.
 */
export async function scanGitHistory(
  projectRoot: string,
  options: HistoryScanOptions = {},
): Promise<AnalyzerOutput> {
  const runner = options.runner ?? defaultRunGit;
  const maxCommits = Math.max(1, Math.min(options.maxCommits ?? 1000, 100_000));
  const maxBlobBytes = options.maxBlobBytes ?? 1024 * 1024;
  const budget = { remaining: options.maxTotalBytes ?? 64 * 1024 * 1024 };
  const findings: Finding[] = [];
  const coverage: Coverage[] = [];

  // 1. Tracked files at HEAD.
  throwIfAborted(options.signal);
  const headBlobs = await listHeadBlobs(projectRoot, runner);
  const headRead = await readBlobs(
    projectRoot,
    runner,
    [...new Set(headBlobs.map((entry) => entry.sha))],
    maxBlobBytes,
    budget,
  );
  const currentValues = new Set<string>();
  const report = (entry: TreeEntry, secret: DetectedSecret, commit: string | null) => {
    const label = SECRET_KIND_LABEL[secret.kind];
    findings.push(
      createFinding({
        ruleId: commit ? "PG-SECRET-003" : "PG-SECRET-002",
        path: entry.path,
        line: secret.line,
        commit,
        ...assessment(secret.kind),
        evidence: commit
          ? `${label} added in commit ${commit.slice(0, 12)} and no longer present in current files (value redacted)`
          : `${label} in a tracked file (value redacted)`,
        cause: `${secret.kind}:${secret.line}`,
      }),
    );
  };
  for (const entry of headBlobs) {
    if (isEnvironmentFile(entry.path)) {
      findings.push(
        createFinding({
          ruleId: "PG-SECRET-001",
          path: entry.path,
          line: null,
          commit: null,
          severity: "high",
          status: "confirmed",
          confidence: "high",
          evidence: "environment file is tracked at HEAD (values not shown)",
          cause: "env-file-head",
        }),
      );
    }
    const content = headRead.contents.get(entry.sha);
    if (content === undefined) continue;
    for (const secret of detectSecrets(content)) {
      currentValues.add(secret.value);
      report(entry, secret, null);
    }
  }
  const headProblems = [
    ...(headRead.skippedLarge > 0
      ? [`${headRead.skippedLarge} file(s) over ${Math.round(maxBlobBytes / 1024)} KiB skipped`]
      : []),
    ...(headRead.skippedBudget > 0
      ? [`${headRead.skippedBudget} file(s) skipped after the read budget was used`]
      : []),
  ];
  coverage.push({
    area: "history:tracked-files",
    scope: "history",
    status: headProblems.length > 0 ? "partial" : "completed",
    ruleIds: ["PG-SECRET-001", "PG-SECRET-002"],
    note: `${headBlobs.length} tracked file(s) at HEAD; Git objects only (untracked/ignored files are not read).${headProblems.length > 0 ? ` ${headProblems.join("; ")}.` : ""}`,
  });

  // 2. Recent history (HEAD ancestry).
  throwIfAborted(options.signal);
  const revList = await runner(
    { subcommand: "rev-list", flags: [`--max-count=${maxCommits + 1}`], operands: ["HEAD"] },
    { cwd: projectRoot },
  );
  const allCommits = revList.split("\n").filter((line) => SHA.test(line));
  const isTruncated = allCommits.length > maxCommits;
  const commits = allCommits.slice(0, maxCommits);
  const historyEntries = await listHistoryBlobs(projectRoot, runner, commits);
  throwIfAborted(options.signal);
  const headShas = new Set(headBlobs.map((entry) => entry.sha));
  // Oldest commit that introduced each blob, so a finding points where the value appeared.
  const introducedBy = new Map<string, HistoryEntry>();
  for (const entry of historyEntries) introducedBy.set(`${entry.sha}\0${entry.path}`, entry);
  const reported = new Set<string>();
  for (const entry of [...introducedBy.values()].reverse()) {
    if (
      isEnvironmentFile(entry.path) &&
      !headBlobs.some((head) => head.path === entry.path) &&
      !reported.has(`env:${entry.path}`)
    ) {
      reported.add(`env:${entry.path}`);
      findings.push(
        createFinding({
          ruleId: "PG-SECRET-001",
          path: entry.path,
          line: null,
          commit: entry.commit,
          severity: "high",
          status: "confirmed",
          confidence: "high",
          evidence: `environment file was committed in ${entry.commit.slice(0, 12)} and later removed; its values remain in history (values not shown)`,
          cause: "env-file-history",
        }),
      );
    }
  }
  const historyShas = [...new Set([...introducedBy.values()].map((entry) => entry.sha))].filter(
    (sha) => !headShas.has(sha),
  );
  const historyRead = await readBlobs(projectRoot, runner, historyShas, maxBlobBytes, budget);
  for (const entry of [...introducedBy.values()].reverse()) {
    const content = historyRead.contents.get(entry.sha);
    if (content === undefined) continue;
    for (const secret of detectSecrets(content)) {
      if (currentValues.has(secret.value)) continue; // already reported at HEAD
      const key = `${secret.kind}\0${secret.value}`;
      if (reported.has(key)) continue; // report each removed value once (where it first appeared)
      reported.add(key);
      report(entry, secret, entry.commit);
    }
  }
  const historyProblems = [
    ...(isTruncated ? [`only the most recent ${maxCommits} commits were scanned`] : []),
    ...(historyRead.skippedLarge > 0
      ? [`${historyRead.skippedLarge} blob(s) over ${Math.round(maxBlobBytes / 1024)} KiB skipped`]
      : []),
    ...(historyRead.skippedBudget > 0
      ? [`${historyRead.skippedBudget} blob(s) skipped after the read budget was used`]
      : []),
  ];
  coverage.push({
    area: "history:commits",
    scope: "history",
    status: historyProblems.length > 0 ? "partial" : "completed",
    ruleIds: ["PG-SECRET-001", "PG-SECRET-003"],
    note: `${commits.length} commit(s) in HEAD's history (first-parent changes); other branches are not scanned.${historyProblems.length > 0 ? ` ${historyProblems.join("; ")}.` : ""}`,
  });

  return { findings, coverage };
}
