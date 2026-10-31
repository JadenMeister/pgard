import path from "node:path";
import {
  createFindingFingerprint,
  type AnalyzerOutput,
  type Confidence,
  coverageNote,
  type Coverage,
  type RuleStat,
  type Finding,
  type FindingStatus,
  type Severity,
} from "@pgard/findings";
import {
  describeCommittedDependencyDirectories,
  findCommittedDependencyDirectories,
} from "./dependency-directories.js";
import { readSmallRegularFile } from "./safe-read.js";
import { HISTORY_RULES, type HistoryRuleId } from "./history-rules.js";
import { GitCommandError, GREP_FLAGS, runGit as defaultRunGit, type GitRunner } from "./run-git.js";
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
  /**
   * Scan only the commits since an earlier scan and carry its commit findings over. This is used
   * only when the result is provably the same as a full scan; otherwise the whole history is
   * scanned and the output says so (`incremental.mode === "full"`).
   */
  incremental?: HistoryIncrementalBase;
}

/** What an earlier history scan left behind. */
export interface HistoryIncrementalBase {
  /** The commit the earlier scan covered; must be an ancestor of the scanned revision. */
  baseRevision: string;
  /** The earlier scan's findings that name a commit (PG-SECRET-001 and PG-SECRET-003 in history). */
  carried: readonly Finding[];
  /** Paths of the earlier scan's findings about files in the tracked tree (no commit). */
  trackedFindingPaths: readonly string[];
}

/** How the history area was scanned. */
export interface HistoryScanMode {
  mode: "incremental" | "full";
  /** Commits whose changes were read in this scan. */
  commitsScanned: number;
  /** Commits of the earlier scan whose findings were carried over. */
  commitsReused: number;
}

export type HistoryScanOutput = AnalyzerOutput & { history: HistoryScanMode };

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
  /** Decode binary UTF-16 blobs (only needed for the files at the scanned revision). */
  decodeUtf16Blobs = false,
): Promise<{
  contents: Map<string, string>;
  skippedLarge: number;
  skippedBudget: number;
  skippedBinary: number;
  /** Blobs not read because of size or the read budget. */
  unreadShas: string[];
  /** Binary blobs that are UTF-16 text (byte order mark), decoded. */
  utf16: Map<string, string>;
}> {
  const contents = new Map<string, string>();
  const unreadShas: string[] = [];
  const utf16 = new Map<string, string>();
  let skippedLarge = 0;
  let skippedBudget = 0;
  let skippedBinary = 0;
  if (shas.length === 0) {
    return { contents, skippedLarge, skippedBudget, skippedBinary, unreadShas, utf16 };
  }
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
      unreadShas.push(match[1]);
      continue;
    }
    if (size > budget.remaining) {
      skippedBudget += 1;
      unreadShas.push(match[1]);
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
        const text = decodeUtf16Blobs ? decodeUtf16(body) : null;
        if (text !== null) utf16.set(header[1], text);
        continue;
      }
      contents.set(header[1], Buffer.from(body, "latin1").toString("utf8"));
    }
    start = end;
  }
  return { contents, skippedLarge, skippedBudget, skippedBinary, unreadShas, utf16 };
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

/** Shortest search string that still identifies a value (shorter values are not checked). */
export const MIN_SEARCH_LENGTH = 8;

/**
 * The fixed string to search for a value: the value itself, or the longest line of a multi-line
 * value (such as a key body line), since `git grep` matches line by line. `null` when it cannot
 * be searched reliably: no line is long enough, or the text holds U+FFFD (bytes that were not
 * valid UTF-8 were replaced while decoding, so the original bytes are not known).
 */
export function searchStringFor(value: string): string | null {
  const longest = value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .reduce((best, line) => (line.length > best.length ? line : best), "");
  if (longest.length < MIN_SEARCH_LENGTH) return null;
  if (longest.includes("\0") || longest.includes("\uFFFD")) return null;
  return longest;
}

/**
 * Asks Git whether any file at the revision contains any of `values`, with one fixed-string
 * `git grep -q` over the whole tree (binary files included). The values go to git on stdin,
 * never in argv. Resolves `true` only when Git confirms that none is present; a match, a value
 * that cannot be searched, a failed search or running out of `timeoutMs` resolves `false`.
 */
async function isAbsentFromRevision(
  cwd: string,
  runner: GitRunner,
  revision: string,
  values: readonly string[],
  signal: AbortSignal | undefined,
  timeoutMs: number,
): Promise<boolean> {
  const patterns = new Set<string>();
  for (const value of values) {
    const pattern = searchStringFor(value);
    if (pattern === null) return false;
    patterns.add(pattern);
  }
  if (patterns.size === 0) return true;
  if (timeoutMs <= 0) return false;
  const deadline = AbortSignal.timeout(timeoutMs);
  try {
    await runner(
      { subcommand: "grep", flags: [...GREP_FLAGS], operands: [revision] },
      {
        cwd,
        input: `${[...patterns].join("\n")}\n`,
        maxBuffer: 64 * 1024,
        signal: signal ? AbortSignal.any([signal, deadline]) : deadline,
      },
    );
    return false; // exit code 0: at least one file matches
  } catch (error) {
    if (signal?.aborted) throw error;
    // Out of time budget, git grep's "no match" (exit code 1), or a failure: only exit code 1
    // proves absence.
    return error instanceof GitCommandError && error.kind === "failed" && error.exitCode === 1;
  }
}

const UTF16_BOMS = ["\xff\xfe", "\xfe\xff"];

const UTF16LE = new TextDecoder("utf-16le");
const UTF16BE = new TextDecoder("utf-16be");

/**
 * UTF-16 text (by its byte order mark) decoded from a latin1 body, or `null`. Never throws: an
 * odd trailing byte or an invalid sequence decodes to U+FFFD.
 */
function decodeUtf16(latin1: string): string | null {
  const bom = latin1.slice(0, 2);
  if (!UTF16_BOMS.includes(bom)) return null;
  const bytes = Buffer.from(latin1.slice(2), "latin1");
  return (bom === "\xfe\xff" ? UTF16BE : UTF16LE).decode(bytes);
}

/** Most size- or budget-skipped files whose first bytes are checked for a UTF-16 mark. */
const MAX_PREFIX_CHECKS = 100;

/**
 * Whether any of these blobs (not read because of size or the read budget) starts with a UTF-16
 * byte order mark. `git grep` cannot search UTF-16 text, so such a file leaves "removed"
 * unknown. Reads only the first bytes of each blob. Resolves `true` (unknown) when there are too
 * many blobs to check, the time budget runs out, or a read fails.
 */
async function hasUtf16Blob(
  cwd: string,
  runner: GitRunner,
  shas: readonly string[],
  signal: AbortSignal | undefined,
  isOverBudget: () => boolean,
): Promise<boolean> {
  if (shas.length > MAX_PREFIX_CHECKS) return true;
  for (const sha of shas) {
    throwIfAborted(signal);
    if (isOverBudget()) return true;
    try {
      const raw = await runner(
        { subcommand: "cat-file", flags: ["--batch"] },
        {
          cwd,
          input: `${sha}\n`,
          encoding: "latin1",
          maxBuffer: 128,
          truncate: true,
          ...(signal ? { signal } : {}),
        },
      );
      const headerEnd = raw.indexOf("\n");
      if (headerEnd === -1) return true;
      if (UTF16_BOMS.includes(raw.slice(headerEnd + 1, headerEnd + 3))) return true;
    } catch (error) {
      if (signal?.aborted) throw error;
      return true;
    }
  }
  return false;
}

export function createFinding(fields: {
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
  const rule = HISTORY_RULES.find((entry) => entry.id === fields.ruleId);
  if (rule === undefined) throw new Error(`Unknown history rule ${fields.ruleId}`);
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

export function assessment({ kind, weak, codeText }: DetectedSecret): {
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
} {
  // A header with no key body may be a sample or a key split across string pieces, and a short
  // or simple password may be a local default, and a value that looks like code text inside a
  // string literal may be a code sample: review them.
  if (kind === "private_key_header" || weak === true || codeText === true) {
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

/** `200 bytes`, `1.5 KiB`, `1024 KiB`: never rounds a small limit down to "0 KiB". */
export function formatByteLimit(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`;
  return `${Number((bytes / 1024).toFixed(1))} KiB`;
}

function skipNotes(
  read: { skippedLarge: number; skippedBudget: number; skippedBinary: number },
  maxBlobBytes: number,
  noun: string,
): { problems: string[]; info: string[] } {
  return {
    problems: [
      ...(read.skippedLarge > 0
        ? [`${read.skippedLarge} ${noun}(s) over ${formatByteLimit(maxBlobBytes)} skipped`]
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

const MAX_SHALLOW_FILE_BYTES = 8 * 1024 * 1024;

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
    // An unsafe file (symlink, FIFO, oversized, unreadable) yields no boundary ids; the scan is
    // still reported as shallow and runs in full.
    const result = await readSmallRegularFile(
      path.resolve(cwd, commonDir, "shallow"),
      MAX_SHALLOW_FILE_BYTES,
    );
    if (result.state !== "ok") return new Set();
    return new Set(result.text.split("\n").filter((line) => SHA.test(line)));
  } catch {
    return new Set();
  }
}

/**
 * Scans what Git stores — never the working tree — for committed environment files and
 * secrets: tracked files at the scanned revision and blobs added or modified in recent commits
 * reachable from it. Tracked dependency directories (`node_modules/`, ...) at the revision yield
 * one PG-HYGIENE-001 suggestion. Untracked or ignored local files (such as a local `.env`) are
 * never read. Secret values are kept in memory only to tell current secrets from removed ones;
 * findings name the kind, never the value. Limits (commits, blob size, total bytes, time,
 * output size, shallow clones) degrade coverage to `partial` with a note.
 */
export async function scanGitHistory(
  projectRoot: string,
  options: HistoryScanOptions = {},
): Promise<HistoryScanOutput> {
  if (options.incremental !== undefined) {
    const attempt = await runHistoryScan(projectRoot, options, options.incremental);
    if (attempt !== null) return attempt;
  }
  const full = await runHistoryScan(projectRoot, options, null);
  if (full === null) throw new Error("A full history scan always returns a result.");
  return full;
}

/** `git diff-tree` of two commits: the paths whose content differs. */
async function listChangedPathsWith(
  cwd: string,
  runner: GitRunner,
  from: string,
  to: string,
  signal?: AbortSignal,
): Promise<Set<string>> {
  const output = await runner(
    {
      subcommand: "diff-tree",
      flags: ["-r", "-z", "--no-renames", "--name-only"],
      operands: [from, to],
    },
    { cwd, encoding: "latin1", maxBuffer: LIST_MAX_BUFFER, ...(signal ? { signal } : {}) },
  );
  return new Set(
    output
      .split("\0")
      .filter((entry) => entry.length > 0)
      .map(decodeGitPath),
  );
}

/**
 * True when `ancestor` is reachable from `descendant` (false when it is not, or is unknown to
 * the repository: a rebase, a force-push or another clone).
 */
export async function isAncestorCommit(
  cwd: string,
  ancestor: string,
  descendant: string,
  runner: GitRunner = defaultRunGit,
): Promise<boolean> {
  if (!SHA.test(ancestor) || !SHA.test(descendant)) return false;
  try {
    // Commits of `ancestor` that `descendant` cannot reach: none when it is an ancestor.
    const output = await runner(
      {
        subcommand: "rev-list",
        flags: ["--max-count=1"],
        operands: [`${descendant}..${ancestor}`],
      },
      { cwd },
    );
    if (output.trim() !== "") return false;
    // The range is empty for an unknown commit too on some versions; make sure it exists.
    await runner(
      {
        subcommand: "rev-parse",
        flags: ["--verify", "--quiet"],
        operands: [`${ancestor}^{commit}`],
      },
      { cwd },
    );
    return true;
  } catch {
    return false;
  }
}

/** Lists commits (newest first) of `range`, at most `max`. */
async function listRange(
  cwd: string,
  runner: GitRunner,
  range: string,
  max: number,
  signal?: AbortSignal,
): Promise<string[]> {
  const output = await runner(
    { subcommand: "rev-list", flags: [`--max-count=${max}`], operands: [range] },
    { cwd, ...(signal ? { signal } : {}) },
  );
  return output.split("\n").filter((line) => SHA.test(line));
}

/**
 * The history scan. With a `plan` it reads only the commits since `plan.baseRevision` and returns
 * `null` whenever it cannot show that the result equals a full scan's (the caller then scans in
 * full). Why a plan is sound: the tracked-file findings are always recomputed from the revision;
 * earlier commit findings stay true while (a) no tracked file that had a finding changed (so a
 * secret that was current has not become "removed"), (b) the new commits add no secret or
 * environment file (so nothing new can duplicate, or be duplicated by, an earlier finding), and
 * (c) no file was left unread, which would make "removed" depend on files the earlier scan did not
 * see. Anything unusual (shallow clone, truncated history, problems of any kind) means a full scan.
 */
async function runHistoryScan(
  projectRoot: string,
  options: HistoryScanOptions,
  plan: HistoryIncrementalBase | null,
): Promise<HistoryScanOutput | null> {
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
  if (!SHA.test(revision) && plan !== null) return null;
  if (!SHA.test(revision)) {
    const requested12 = (options.revision ?? "").slice(0, 12);
    const note =
      options.revision && options.revision !== "HEAD"
        ? /^[A-Za-z0-9][A-Za-z0-9 ._+#()/:-]{0,59}$/.test(requested12)
          ? coverageNote("history_revision_not_found", { revision: requested12 })
          : {
              note: `The revision to scan (${requested12}) was not found in the repository.`,
            }
        : coverageNote("history_no_commit");
    return {
      findings: [],
      coverage: [
        {
          area: "history:tracked-files",
          scope: "history",
          status: "not_tested",
          ruleIds: [],
          ...note,
        },
        { area: "history:commits", scope: "history", status: "not_tested", ruleIds: [], ...note },
      ],
      ruleStats: [],
      history: { mode: "full", commitsScanned: 0, commitsReused: 0 },
    };
  }

  // The earlier scan must be an ancestor, and none of the files it reported on may have changed.
  let newCommits: string[] | null = null;
  if (plan !== null) {
    if (!(await isAncestorCommit(projectRoot, plan.baseRevision, revision, runner))) return null;
    try {
      const changed = await listChangedPathsWith(
        projectRoot,
        runner,
        plan.baseRevision,
        revision,
        signal,
      );
      if (plan.trackedFindingPaths.some((trackedPath) => changed.has(trackedPath))) return null;
      newCommits = await listRange(
        projectRoot,
        runner,
        `${plan.baseRevision}..${revision}`,
        maxCommits + 1,
        signal,
      );
    } catch (error) {
      if (signal?.aborted) throw error;
      return null;
    }
    if (newCommits.length > maxCommits) return null;
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
    true,
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
        ...assessment(secret),
        evidence:
          (commit
            ? isCurrentStateUnknown
              ? `${label} ${where}; whether it is still in the current files could not be checked (value redacted)`
              : `${label} ${where} and no longer present in current files (value redacted)`
            : `${label} in a tracked file (value redacted)`) +
          (secret.codeText === true
            ? "; the value looks like code text inside a string literal (inferred)"
            : ""),
        cause: `${secret.kind}:${secret.line}`,
      }),
    );
  };
  for (const entry of headBlobs) {
    const isEnvFile = isEnvironmentFile(entry.path);
    const content = headRead.contents.get(entry.sha);
    const secrets = content === undefined ? [] : detectSecrets(content, { path: entry.path });
    if (isEnvFile) {
      // The generic credential lines of an environment file are folded into this one finding.
      // The count is part of the evidence (so of the finding's identity): a suppression or
      // baseline entry made for the file as it was does not hide a credential added later.
      const folded = secrets.filter((secret) => secret.kind === "generic_credential").length;
      findings.push(
        createFinding({
          ruleId: "PG-SECRET-001",
          path: entry.path,
          line: null,
          commit: null,
          severity: "high",
          status: "confirmed",
          confidence: "high",
          evidence: `environment file is tracked in the current commit (${folded > 0 ? `${folded} credential value${folded === 1 ? "" : "s"} inside, not shown` : "values not shown"})`,
          cause: "env-file-head",
        }),
      );
    }
    for (const secret of secrets) {
      // Still a current value, so the same value in history is not called "removed".
      currentValues.add(secret.value);
      if (isEnvFile && secret.kind === "generic_credential") continue;
      report(entry, secret, null, false);
    }
  }
  // One project-level suggestion when dependency directories are tracked (paths only).
  const dependencyDirectories = findCommittedDependencyDirectories(
    headBlobs.map((entry) => entry.path),
  );
  const firstDirectory = dependencyDirectories[0];
  if (firstDirectory !== undefined) {
    const text = describeCommittedDependencyDirectories(dependencyDirectories, revision);
    findings.push({
      ...createFinding({
        ruleId: "PG-HYGIENE-001",
        path: `${firstDirectory.root}/`,
        line: null,
        commit: null,
        severity: "info",
        status: "informational",
        confidence: "low",
        evidence: text.evidence,
        cause: "dependency-directory-tracked",
      }),
      recommendation: text.recommendation,
      context: "vendored",
    });
  }
  const headSkips = skipNotes(headRead, maxBlobBytes, "file");
  headProblems.push(...headSkips.problems);
  coverage.push({
    area: "history:tracked-files",
    scope: "history",
    status: headProblems.length > 0 ? "partial" : "completed",
    ruleIds: ["PG-SECRET-001", "PG-SECRET-002", "PG-HYGIENE-001"],
    note: formatNote(
      `${headBlobs.length} tracked file(s) in commit ${revision.slice(0, 12)}; Git objects only (untracked/ignored files are not read).`,
      headProblems,
      headSkips.info,
    ),
    // Only the plain case has a code; a note that lists problems stays English.
    ...(headProblems.length + headSkips.info.length === 0
      ? coverageNote("history_tracked_files", {
          count: headBlobs.length,
          revision: revision.slice(0, 12),
        })
      : {}),
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
  if (plan !== null && (isTruncated || shallowBoundary !== null)) return null;
  const commits = newCommits ?? allCommits.slice(0, maxCommits);
  const reusedCommits = newCommits === null ? 0 : allCommits.length - newCommits.length;
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
  // Detection depends on the path (source code vs config files), so results are kept per pair.
  const historySecrets = new Map<string, DetectedSecret[]>();
  const secretsOf = (entry: TreeEntry, content: string): DetectedSecret[] => {
    const key = `${entry.sha}\0${entry.path}`;
    let found = historySecrets.get(key);
    if (found === undefined) {
      found = detectSecrets(content, { path: entry.path });
      historySecrets.set(key, found);
    }
    return found;
  };
  // Before any value is called "removed", make sure no current file holds it:
  // - Normal path: tracked files that were not read as text (over the size limit, after the read
  //   budget, or binary) may hold it. Only needed when such files exist.
  // - Overflow path: the tracked file list is missing, so files never looked up may hold it.
  // One fixed-string `git grep` of the revision (values on stdin, bounded by the remaining time
  // budget) settles it, plus the UTF-16 files git grep cannot search: decoded binary files are
  // searched in memory, and skipped files with a UTF-16 mark leave the state unknown. "Removed"
  // is claimed only when all of this confirms absence; otherwise the current state is unknown.
  // (On the overflow path UTF-16 files outside the looked-up paths cannot be checked.)
  const removedValues = new Set<string>();
  for (const entry of oldestFirst) {
    const content = historyRead.contents.get(entry.sha);
    if (content === undefined) continue;
    for (const secret of secretsOf(entry, content)) {
      if (!currentValues.has(secret.value) && !currentLocations.has(secret.value)) {
        removedValues.add(secret.value);
      }
    }
  }
  const unreadHeadFiles = headRead.skippedLarge + headRead.skippedBudget + headRead.skippedBinary;
  let isRemovalConfirmed = true;
  if (removedValues.size > 0 && (currentByPath !== null || unreadHeadFiles > 0)) {
    const values = [...removedValues];
    const utf16Texts = [...headRead.utf16.values()];
    isRemovalConfirmed =
      !isOverBudget() &&
      values.every((value) => {
        // Same search string as git grep (longest line); one that cannot be searched is unknown.
        const search = searchStringFor(value);
        return search !== null && !utf16Texts.some((text) => text.includes(search));
      }) &&
      (await isAbsentFromRevision(
        projectRoot,
        runner,
        revision,
        values,
        signal,
        timeBudgetMs - (now() - startedAt),
      )) &&
      !(await hasUtf16Blob(projectRoot, runner, headRead.unreadShas, signal, isOverBudget));
  }
  const hasUnreadHead = !isRemovalConfirmed;
  for (const entry of oldestFirst) {
    throwIfAborted(signal);
    const content = historyRead.contents.get(entry.sha);
    if (content === undefined) continue;
    for (const secret of secretsOf(entry, content)) {
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
  if (plan !== null) {
    const hasNewSecrets = oldestFirst.some((entry) => {
      if (isEnvironmentFile(entry.path)) return true;
      const content = historyRead.contents.get(entry.sha) ?? headRead.contents.get(entry.sha);
      return content !== undefined && secretsOf(entry, content).length > 0;
    });
    const unreadNew =
      historyRead.skippedLarge + historyRead.skippedBudget + historyRead.skippedBinary;
    if (
      historyProblems.length > 0 ||
      headProblems.length > 0 ||
      !isHeadListComplete ||
      listed.problems.length > 0 ||
      (plan.carried.length > 0 && (hasNewSecrets || unreadNew > 0 || unreadHeadFiles > 0))
    ) {
      return null;
    }
    // Earlier commit findings carry over unchanged (their review state is applied again later).
    for (const carried of plan.carried) {
      const {
        suppression: _suppression,
        inBaseline: _inBaseline,
        context: _context,
        ...rest
      } = carried;
      findings.push(rest);
    }
  }
  const processedCommits = listed.processedCommits + reusedCommits;
  coverage.push({
    area: "history:commits",
    scope: "history",
    status: historyProblems.length > 0 ? "partial" : "completed",
    ruleIds: ["PG-SECRET-001", "PG-SECRET-003"],
    note: formatNote(
      `${processedCommits} commit(s) reachable from ${revision.slice(0, 12)}; branches not merged into it are not scanned.`,
      historyProblems,
      historySkips.info,
    ),
    ...(historyProblems.length + historySkips.info.length === 0
      ? coverageNote("history_commits", {
          count: processedCommits,
          revision: revision.slice(0, 12),
        })
      : {}),
  });

  // Rule stats. A finding with a commit belongs to the commits area, one without to the tracked
  // files area. Targets are counted from what was read: tracked files listed and read as text,
  // commits processed and history blobs read as text. A shallow or truncated history shows in
  // the area's status and note, not in these counts.
  const countFindings = (ruleId: string, inCommits: boolean) =>
    findings.filter(
      (finding) => finding.ruleId === ruleId && (finding.location.commit !== null) === inCommits,
    ).length;
  const readTrackedFiles = headBlobs.filter((entry) => headRead.contents.has(entry.sha)).length;
  const stat = (
    area: string,
    status: Coverage["status"],
    ruleId: string,
    targets: RuleStat["targets"],
    inCommits: boolean,
  ): RuleStat => ({
    ruleId,
    area,
    scope: "history",
    status,
    targets,
    findings: countFindings(ruleId, inCommits),
  });
  const trackedStatus = headProblems.length > 0 ? "partial" : "completed";
  const commitsStatus = historyProblems.length > 0 ? "partial" : "completed";
  const files = (examined: number) => [{ unit: "files", examined, reason: null }];
  const commitCount = { unit: "commits", examined: processedCommits, reason: null };
  // Which old blobs count depends on the current tree (a blob that left it now counts), so an
  // incremental scan cannot recount them without reading the old commits: it says so.
  const blobCount: RuleStat["targets"][number] =
    plan === null
      ? { unit: "blobs", examined: historyRead.contents.size, reason: null }
      : {
          unit: "blobs",
          examined: null,
          reason: "Blobs of earlier commits were not read again, so they were not recounted.",
        };
  const ruleStats: RuleStat[] = [
    stat("history:tracked-files", trackedStatus, "PG-SECRET-001", files(headBlobs.length), false),
    stat("history:tracked-files", trackedStatus, "PG-SECRET-002", files(readTrackedFiles), false),
    stat("history:tracked-files", trackedStatus, "PG-HYGIENE-001", files(headBlobs.length), false),
    stat("history:commits", commitsStatus, "PG-SECRET-001", [commitCount], true),
    stat("history:commits", commitsStatus, "PG-SECRET-003", [commitCount, blobCount], true),
  ];

  return {
    findings,
    coverage,
    ruleStats,
    history: {
      mode: plan === null ? "full" : "incremental",
      commitsScanned: listed.processedCommits,
      commitsReused: reusedCommits,
    },
  };
}

/**
 * Paths whose content differs between two commits (`git diff-tree --no-renames`: a rename is a
 * deletion plus an addition). Rejects when Git cannot compare them.
 */
export function listChangedPaths(
  cwd: string,
  from: string,
  to: string,
  signal?: AbortSignal,
): Promise<Set<string>> {
  return listChangedPathsWith(cwd, defaultRunGit, from, to, signal);
}
