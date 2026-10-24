import { readFile } from "node:fs/promises";
import path from "node:path";
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
import { GitCommandError, runGit as defaultRunGit, type GitRunner } from "./run-git.js";
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
  /**
   * The commit to scan — normally the revision the authorization gate verified, so the scan
   * cannot drift to a different HEAD. Defaults to `HEAD`.
   */
  revision?: string | null;
  /** Most recent commits in the revision's history whose changes are scanned. Default 1000. */
  maxCommits?: number;
  /** Blobs larger than this are skipped. Default 1 MiB. */
  maxBlobBytes?: number;
  /** Total bytes of blob content read. Default 64 MiB. */
  maxTotalBytes?: number;
  /** Wall-clock budget for the history part; when exceeded, coverage is partial. Default 60 s. */
  timeBudgetMs?: number;
  /** Injectable clock (ms) for tests. */
  now?: () => number;
}

const SHA = /^[0-9a-f]{40}$/;
const BATCH_BYTES = 8 * 1024 * 1024;
const LIST_MAX_BUFFER = 64 * 1024 * 1024;
const COMMITS_PER_DIFF_BATCH = 200;
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

const UTF8 = new TextDecoder("utf-8", { fatal: true });

/**
 * Decodes a path read as latin1 (one char per byte). Valid UTF-8 is decoded; otherwise
 * non-ASCII bytes are shown as `\xNN` so the reported path stays exact and unambiguous.
 */
export function decodeGitPath(latin1: string): string {
  const bytes = Buffer.from(latin1, "latin1");
  try {
    return UTF8.decode(bytes);
  } catch {
    return [...bytes]
      .map((byte) =>
        byte >= 0x20 && byte < 0x7f
          ? String.fromCharCode(byte)
          : `\\x${byte.toString(16).padStart(2, "0")}`,
      )
      .join("");
  }
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new Error("aborted");
}

function isOutputLimit(error: unknown): boolean {
  return error instanceof GitCommandError && error.kind === "output_limit";
}

/** `ls-tree -r -z <rev>`: "<mode> blob <sha>\t<path>\0" (paths decoded from raw bytes). */
async function listTreeBlobs(
  cwd: string,
  runner: GitRunner,
  revision: string,
  signal?: AbortSignal,
): Promise<TreeEntry[]> {
  const output = await runner(
    { subcommand: "ls-tree", flags: ["-r", "-z", "--full-tree"], operands: [revision] },
    { cwd, encoding: "latin1", maxBuffer: LIST_MAX_BUFFER, ...(signal ? { signal } : {}) },
  );
  const entries: TreeEntry[] = [];
  for (const record of output.split("\0")) {
    const match = /^\d{6} blob ([0-9a-f]{40})\t([\s\S]+)$/.exec(record);
    if (match?.[1] && match[2]) entries.push({ sha: match[1], path: decodeGitPath(match[2]) });
  }
  return entries;
}

/**
 * Blobs added or modified by each commit, from one `diff-tree --stdin` process per batch of
 * commits. Every commit reachable from the revision is listed (side branches included); merge
 * commits show their changes against the first parent. Root and shallow-boundary commits list
 * every file. A batch whose output is too large is split in half and retried, down to single
 * commits, so one huge commit cannot hide its neighbours.
 */
async function listHistoryBlobs(
  cwd: string,
  runner: GitRunner,
  commits: string[],
  signal: AbortSignal | undefined,
  isOverBudget: () => boolean,
): Promise<{ entries: HistoryEntry[]; processedCommits: number; problems: string[] }> {
  const entries: HistoryEntry[] = [];
  let processedCommits = 0;
  let skippedCommits = 0;
  let isOutOfTime = false;
  const queue: string[][] = [];
  for (let start = 0; start < commits.length; start += COMMITS_PER_DIFF_BATCH) {
    queue.push(commits.slice(start, start + COMMITS_PER_DIFF_BATCH));
  }
  while (queue.length > 0) {
    throwIfAborted(signal);
    if (isOverBudget()) {
      isOutOfTime = true;
      break;
    }
    const batch = queue.shift() as string[];
    let output: string;
    try {
      output = await runner(
        {
          subcommand: "diff-tree",
          flags: ["--stdin", "-r", "-z", "--root", "--no-renames", "-m", "--first-parent"],
        },
        {
          cwd,
          input: `${batch.join("\n")}\n`,
          encoding: "latin1",
          maxBuffer: LIST_MAX_BUFFER,
          ...(signal ? { signal } : {}),
        },
      );
    } catch (error) {
      if (!isOutputLimit(error)) throw error;
      if (batch.length > 1) {
        const middle = Math.ceil(batch.length / 2);
        queue.unshift(batch.slice(0, middle), batch.slice(middle));
      } else {
        skippedCommits += 1;
        processedCommits += 1;
      }
      continue;
    }
    let commit: string | null = null;
    const parts = output.split("\0");
    for (let index = 0; index < parts.length; index += 1) {
      const part = parts[index] ?? "";
      if (SHA.test(part)) {
        commit = part;
        continue;
      }
      const match = /^:\d{6} \d{6} [0-9a-f]{40} ([0-9a-f]{40}) ([AM])$/.exec(part);
      const filePath = parts[index + 1];
      if (part.startsWith(":")) index += 1; // the path record follows every header
      if (match?.[1] && commit && filePath) {
        entries.push({ commit, sha: match[1], path: decodeGitPath(filePath) });
      }
    }
    processedCommits += batch.length;
  }
  const problems = [
    ...(skippedCommits > 0
      ? [`changes of ${skippedCommits} commit(s) were too large to list and were skipped`]
      : []),
    ...(isOutOfTime
      ? [`time budget reached after ${processedCommits} of ${commits.length} commits`]
      : []),
  ];
  return { entries, processedCommits, problems };
}

/** Reads blob contents with `cat-file --batch-check` / `--batch`, bounded by size. */
async function readBlobs(
  cwd: string,
  runner: GitRunner,
  shas: string[],
  maxBlobBytes: number,
  budget: { remaining: number },
  signal: AbortSignal | undefined,
): Promise<{
  contents: Map<string, string>;
  skippedLarge: number;
  skippedBudget: number;
  skippedBinary: number;
}> {
  const contents = new Map<string, string>();
  let skippedLarge = 0;
  let skippedBudget = 0;
  let skippedBinary = 0;
  if (shas.length === 0) return { contents, skippedLarge, skippedBudget, skippedBinary };
  const withSignal = signal ? { signal } : {};
  const check = await runner(
    { subcommand: "cat-file", flags: ["--batch-check"] },
    { cwd, input: `${shas.join("\n")}\n`, maxBuffer: shas.length * 80 + 1024, ...withSignal },
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
    throwIfAborted(signal);
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
        ...withSignal,
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
      if (body.includes("\0")) {
        skippedBinary += 1;
        continue;
      }
      contents.set(header[1], Buffer.from(body, "latin1").toString("utf8"));
    }
    start = end;
  }
  return { contents, skippedLarge, skippedBudget, skippedBinary };
}

/**
 * Resolves `<revision>:<path>` for each path with `cat-file --batch-check` and reads the current
 * contents of those that exist. `shas` maps path -> blob id, `null` when the path is absent, or
 * no entry when it could not be checked (paths with escaped bytes or newlines).
 */
async function readCurrentBlobs(
  cwd: string,
  runner: GitRunner,
  revision: string,
  paths: string[],
  maxBlobBytes: number,
  budget: { remaining: number },
  signal: AbortSignal | undefined,
): Promise<{ shas: Map<string, string | null>; contents: Map<string, string> }> {
  const shas = new Map<string, string | null>();
  const contents = new Map<string, string>();
  const queryable = [...new Set(paths)].filter((item) => !/[\n\r]|\\x[0-9a-f]{2}/.test(item));
  if (queryable.length === 0) return { shas, contents };
  const output = await runner(
    { subcommand: "cat-file", flags: ["--batch-check"] },
    {
      cwd,
      input: `${queryable.map((item) => `${revision}:${item}`).join("\n")}\n`,
      maxBuffer: queryable.length * 200 + 1024,
      ...(signal ? { signal } : {}),
    },
  );
  const lines = output.split("\n");
  queryable.forEach((item, index) => {
    const match = /^([0-9a-f]{40}) blob \d+$/.exec(lines[index] ?? "");
    if (match?.[1]) shas.set(item, match[1]);
    else if ((lines[index] ?? "").endsWith(" missing")) shas.set(item, null);
  });
  const present = [...shas.entries()].filter(
    (entry): entry is [string, string] => entry[1] !== null,
  );
  const read = await readBlobs(
    cwd,
    runner,
    [...new Set(present.map(([, sha]) => sha))],
    maxBlobBytes,
    budget,
    signal,
  );
  for (const [item, sha] of present) {
    const content = read.contents.get(sha);
    if (content !== undefined) contents.set(item, content);
  }
  return { shas, contents };
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
  // A header with no key body may be a sample or a key split across string pieces: review it.
  if (kind === "private_key_header") {
    return { severity: "high", status: "suspected", confidence: "low" };
  }
  return STRONG_KINDS.has(kind)
    ? {
        severity: kind === "private_key" ? "critical" : "high",
        status: "confirmed",
        confidence: "high",
      }
    : { severity: "high", status: "suspected", confidence: "medium" };
}

function skipNotes(
  read: { skippedLarge: number; skippedBudget: number; skippedBinary: number },
  maxBlobBytes: number,
  noun: string,
): { problems: string[]; info: string[] } {
  return {
    problems: [
      ...(read.skippedLarge > 0
        ? [`${read.skippedLarge} ${noun}(s) over ${Math.round(maxBlobBytes / 1024)} KiB skipped`]
        : []),
      ...(read.skippedBudget > 0
        ? [`${read.skippedBudget} ${noun}(s) skipped after the read budget was used`]
        : []),
    ],
    info: read.skippedBinary > 0 ? [`${read.skippedBinary} binary ${noun}(s) not scanned`] : [],
  };
}

function formatNote(base: string, problems: string[], info: string[]): string {
  const extra = [...problems, ...info];
  return extra.length > 0 ? `${base} ${extra.join("; ")}.` : base;
}

/** Commit ids at the edge of a shallow clone (their parents are missing). */
async function readShallowBoundary(cwd: string, runner: GitRunner): Promise<Set<string> | null> {
  const isShallow = (
    await runner({ subcommand: "rev-parse", flags: ["--is-shallow-repository"] }, { cwd }).catch(
      () => "false",
    )
  ).trim();
  if (isShallow !== "true") return null;
  try {
    const commonDir = (
      await runner({ subcommand: "rev-parse", flags: ["--git-common-dir"] }, { cwd })
    ).trim();
    const text = await readFile(path.resolve(cwd, commonDir, "shallow"), "utf8");
    return new Set(text.split("\n").filter((line) => SHA.test(line)));
  } catch {
    return new Set();
  }
}

/**
 * Scans what Git stores — never the working tree — for committed environment files and
 * secrets: tracked files at the scanned revision and blobs added or modified in recent commits
 * reachable from it. Untracked or ignored local files (such as a local `.env`) are
 * never read. Secret values are kept in memory only to tell current secrets from removed ones;
 * findings name the kind, never the value. Limits (commits, blob size, total bytes, time,
 * output size, shallow clones) degrade coverage to `partial` with a note.
 */
export async function scanGitHistory(
  projectRoot: string,
  options: HistoryScanOptions = {},
): Promise<AnalyzerOutput> {
  const runner = options.runner ?? defaultRunGit;
  const signal = options.signal;
  const now = options.now ?? Date.now;
  const startedAt = now();
  const timeBudgetMs = options.timeBudgetMs ?? 60_000;
  const isOverBudget = () => now() - startedAt > timeBudgetMs;
  const maxCommits = Math.max(1, Math.min(options.maxCommits ?? 1000, 100_000));
  const maxBlobBytes = options.maxBlobBytes ?? 1024 * 1024;
  const budget = { remaining: options.maxTotalBytes ?? 64 * 1024 * 1024 };
  const findings: Finding[] = [];
  const coverage: Coverage[] = [];

  throwIfAborted(signal);
  const requested = options.revision ?? "HEAD";
  const revision = (
    await runner(
      {
        subcommand: "rev-parse",
        flags: ["--verify", "--quiet"],
        operands: [`${requested}^{commit}`],
      },
      { cwd: projectRoot },
    ).catch(() => "")
  ).trim();
  if (!SHA.test(revision)) {
    const note =
      options.revision && options.revision !== "HEAD"
        ? `The revision to scan (${options.revision.slice(0, 12)}) was not found in the repository.`
        : "The repository has no commit to scan.";
    return {
      findings: [],
      coverage: [
        {
          area: "history:tracked-files",
          scope: "history",
          status: "not_tested",
          ruleIds: [],
          note,
        },
        { area: "history:commits", scope: "history", status: "not_tested", ruleIds: [], note },
      ],
    };
  }

  // 1. Tracked files at the scanned revision.
  let headBlobs: TreeEntry[] = [];
  const headProblems: string[] = [];
  let isHeadListComplete = true;
  try {
    headBlobs = await listTreeBlobs(projectRoot, runner, revision, signal);
  } catch (error) {
    if (!isOutputLimit(error)) throw error;
    isHeadListComplete = false;
    headProblems.push("the tracked file list was too large to read");
  }
  const headRead = await readBlobs(
    projectRoot,
    runner,
    [...new Set(headBlobs.map((entry) => entry.sha))],
    maxBlobBytes,
    budget,
    signal,
  );
  const currentValues = new Set<string>();
  const report = (
    entry: TreeEntry,
    secret: DetectedSecret,
    commit: string | null,
    isBoundary: boolean,
    isCurrentStateUnknown = false,
  ) => {
    const label = SECRET_KIND_LABEL[secret.kind];
    const where = `${isBoundary ? "present in" : "added in"} commit ${commit?.slice(0, 12) ?? ""}${isBoundary ? " (shallow clone boundary; it may have been added earlier)" : ""}`;
    findings.push(
      createFinding({
        ruleId: commit ? "PG-SECRET-003" : "PG-SECRET-002",
        path: entry.path,
        line: secret.line,
        commit,
        ...assessment(secret.kind),
        evidence: commit
          ? isCurrentStateUnknown
            ? `${label} ${where}; whether it is still in the current files could not be checked (value redacted)`
            : `${label} ${where} and no longer present in current files (value redacted)`
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
          evidence: "environment file is tracked in the current commit (values not shown)",
          cause: "env-file-head",
        }),
      );
    }
    const content = headRead.contents.get(entry.sha);
    if (content === undefined) continue;
    for (const secret of detectSecrets(content, { path: entry.path })) {
      currentValues.add(secret.value);
      report(entry, secret, null, false);
    }
  }
  const headSkips = skipNotes(headRead, maxBlobBytes, "file");
  headProblems.push(...headSkips.problems);
  coverage.push({
    area: "history:tracked-files",
    scope: "history",
    status: headProblems.length > 0 ? "partial" : "completed",
    ruleIds: ["PG-SECRET-001", "PG-SECRET-002"],
    note: formatNote(
      `${headBlobs.length} tracked file(s) in commit ${revision.slice(0, 12)}; Git objects only (untracked/ignored files are not read).`,
      headProblems,
      headSkips.info,
    ),
  });

  // 2. Recent history (all commits reachable from the scanned revision).
  throwIfAborted(signal);
  const shallowBoundary = await readShallowBoundary(projectRoot, runner);
  const revList = await runner(
    {
      subcommand: "rev-list",
      // All reachable commits, not only first-parent: a secret added and removed on a merged
      // side branch must still be found.
      flags: [`--max-count=${maxCommits + 1}`],
      operands: [revision],
    },
    { cwd: projectRoot, ...(signal ? { signal } : {}) },
  );
  const allCommits = revList.split("\n").filter((line) => SHA.test(line));
  const isTruncated = allCommits.length > maxCommits;
  const commits = allCommits.slice(0, maxCommits);
  const listed = await listHistoryBlobs(projectRoot, runner, commits, signal, isOverBudget);
  const headShas = new Set(headBlobs.map((entry) => entry.sha));
  const headPaths = new Set(headBlobs.map((entry) => entry.path));
  // Oldest commit that introduced each blob/path pair, so a finding points where it appeared.
  const introducedBy = new Map<string, HistoryEntry>();
  for (const entry of listed.entries) introducedBy.set(`${entry.sha}\0${entry.path}`, entry);
  const oldestFirst = [...introducedBy.values()].reverse();
  const isBoundary = (commit: string) => shallowBoundary?.has(commit) ?? false;
  const reported = new Set<string>();
  let unknownCurrentState = 0;
  let unknownEnvState = 0;
  const historyShas = [...new Set(oldestFirst.map((entry) => entry.sha))].filter(
    (sha) => !headShas.has(sha),
  );
  const historyRead = await readBlobs(
    projectRoot,
    runner,
    historyShas,
    maxBlobBytes,
    budget,
    signal,
  );
  // When the current file list could not be read, ask Git directly whether the paths that
  // matter (environment files and paths whose history holds a secret not seen in current
  // files) still exist at the revision, so current secrets are not reported as "removed".
  // Lookup failures or an exhausted time budget leave the state unknown (neutral wording,
  // partial coverage) instead of failing the whole history area.
  let currentByPath: { shas: Map<string, string | null>; contents: Map<string, string> } | null =
    null;
  const candidatePaths = new Set<string>();
  if (!isHeadListComplete) {
    for (const entry of oldestFirst) {
      if (isEnvironmentFile(entry.path)) {
        candidatePaths.add(entry.path);
        continue;
      }
      const content = historyRead.contents.get(entry.sha);
      if (
        content !== undefined &&
        detectSecrets(content, { path: entry.path }).some(
          (secret) => !currentValues.has(secret.value),
        )
      ) {
        candidatePaths.add(entry.path);
      }
    }
    currentByPath = { shas: new Map(), contents: new Map() };
    if (!isOverBudget() && candidatePaths.size > 0) {
      try {
        currentByPath = await readCurrentBlobs(
          projectRoot,
          runner,
          revision,
          [...candidatePaths],
          maxBlobBytes,
          budget,
          signal,
        );
      } catch (error) {
        if (!(error instanceof GitCommandError) || error.kind === "cancelled") throw error;
      }
    }
  }
  for (const entry of oldestFirst) {
    const currentSha = currentByPath?.shas.get(entry.path);
    if (isEnvironmentFile(entry.path) && currentSha && !reported.has(`env:${entry.path}`)) {
      reported.add(`env:${entry.path}`);
      findings.push(
        createFinding({
          ruleId: "PG-SECRET-001",
          path: entry.path,
          line: null,
          commit: null,
          severity: "high",
          status: "confirmed",
          confidence: "high",
          evidence: "environment file is tracked in the current commit (values not shown)",
          cause: "env-file-head",
        }),
      );
      continue;
    }
    if (
      isEnvironmentFile(entry.path) &&
      // Present files were handled above; otherwise use the full current list when we have it.
      (currentByPath !== null || !headPaths.has(entry.path)) &&
      !reported.has(`env:${entry.path}`)
    ) {
      reported.add(`env:${entry.path}`);
      const boundary = isBoundary(entry.commit);
      // On the overflow path only a lookup that answered "missing" proves the file was removed;
      // a skipped, failed or unanswerable lookup leaves its current state unknown.
      const isStateUnknown = currentByPath !== null && currentSha === undefined;
      if (isStateUnknown) unknownEnvState += 1;
      findings.push(
        createFinding({
          ruleId: "PG-SECRET-001",
          path: entry.path,
          line: null,
          commit: entry.commit,
          severity: "high",
          status: "confirmed",
          confidence: "high",
          evidence: `environment file was ${boundary ? "present in" : "committed in"} ${entry.commit.slice(0, 12)}${boundary ? " (shallow clone boundary)" : ""}${isStateUnknown ? "; whether it is still tracked in the current commit could not be checked" : " and later removed"}; its values remain in history (values not shown)`,
          cause: "env-file-history",
        }),
      );
    }
  }
  // On the overflow path, compare each history value with every current blob that was looked
  // up (not only the same path), so a secret moved to another file is reported as current, not
  // as removed. Every path whose history holds the value is looked up. If a looked-up file
  // exists but its contents could not be read, "removed" cannot be claimed for any value.
  const currentLocations = new Map<string, { path: string; line: number }>();
  for (const [currentPath, current] of currentByPath?.contents ?? []) {
    for (const found of detectSecrets(current, { path: currentPath })) {
      if (!currentLocations.has(found.value)) {
        currentLocations.set(found.value, { path: currentPath, line: found.line });
      }
    }
  }
  // A candidate path Git gave no answer for (unqueryable name, failed or skipped lookup) or whose
  // contents could not be read may hold the value, so it counts as unread too.
  const hasUnreadCurrent = [...candidatePaths].some((candidate) => {
    const sha = currentByPath?.shas.get(candidate);
    return sha === undefined || (sha !== null && !currentByPath?.contents.has(candidate));
  });
  const historySkips = skipNotes(historyRead, maxBlobBytes, "blob");
  // On the overflow path a value's current location is only known if it appears in the scanned
  // history. If commits were cut off (commit window, time budget) or history blobs were skipped,
  // the value may still live in a file not seen here, so "removed" cannot be claimed.
  const isHistoryIncomplete =
    isTruncated || listed.problems.length > 0 || historySkips.problems.length > 0;
  // A tracked file at the revision that was skipped for size or the read budget may hold the
  // value, so "removed" cannot be claimed for a value not found in the files that were read.
  const hasUnreadHead = headRead.skippedLarge > 0 || headRead.skippedBudget > 0;
  for (const entry of oldestFirst) {
    throwIfAborted(signal);
    const content = historyRead.contents.get(entry.sha);
    if (content === undefined) continue;
    for (const secret of detectSecrets(content, { path: entry.path })) {
      if (currentValues.has(secret.value)) continue; // already reported in current files
      const key = `${secret.kind}\0${secret.value}`;
      if (reported.has(key)) continue; // report each removed value once (where it first appeared)
      reported.add(key);
      if (currentByPath) {
        const current = currentByPath.contents.get(entry.path);
        const location = currentLocations.get(secret.value);
        if (location) {
          report(
            { sha: entry.sha, path: location.path },
            { ...secret, line: location.line },
            null,
            false,
          );
          continue;
        }
        const isKnownAbsent =
          (currentByPath.shas.get(entry.path) === null || current !== undefined) &&
          !hasUnreadCurrent &&
          !hasUnreadHead &&
          !isHistoryIncomplete;
        report(entry, secret, entry.commit, isBoundary(entry.commit), !isKnownAbsent);
        if (!isKnownAbsent) unknownCurrentState += 1;
        continue;
      }
      report(entry, secret, entry.commit, isBoundary(entry.commit), hasUnreadHead);
      if (hasUnreadHead) unknownCurrentState += 1;
    }
  }
  const historyProblems = [
    ...(unknownCurrentState > 0
      ? [
          `for ${unknownCurrentState} finding(s) it could not be checked whether the value is still in the current files`,
        ]
      : []),
    ...(unknownEnvState > 0
      ? [
          `for ${unknownEnvState} environment file(s) it could not be checked whether they are still tracked in the current commit`,
        ]
      : []),
    ...(shallowBoundary
      ? [
          "shallow clone: history before the clone boundary is not available, so older secrets cannot be checked",
        ]
      : []),
    ...(isTruncated ? [`only the most recent ${maxCommits} commits were scanned`] : []),
    ...listed.problems,
    ...historySkips.problems,
  ];
  coverage.push({
    area: "history:commits",
    scope: "history",
    status: historyProblems.length > 0 ? "partial" : "completed",
    ruleIds: ["PG-SECRET-001", "PG-SECRET-003"],
    note: formatNote(
      `${listed.processedCommits} commit(s) reachable from ${revision.slice(0, 12)}; branches not merged into it are not scanned.`,
      historyProblems,
      historySkips.info,
    ),
  });

  return { findings, coverage };
}
