import { runGit as defaultRunGit, GitCommandError, type GitRunner } from "./run-git.js";
import { decodeGitPath } from "./scan-history.js";

/**
 * Reads what is staged for the next commit: the index compared with HEAD, using only plumbing
 * that is already on the Git allowlist (`ls-files -s`, `ls-tree -r`, `cat-file`). Contents come
 * from Git objects, never from the working tree, so an unstaged edit can neither hide a staged
 * secret nor raise a false alarm. Nothing here can modify the repository.
 */

/** Why a staged file was not read. The first group is by design; the second means "not scanned". */
export type StagedSkipReason =
  /** Contains NUL bytes (and is not UTF-16 text). Binary files are not scanned for text secrets. */
  | "binary"
  /** A symbolic link: the blob holds the link target, not file content. */
  | "symlink"
  /** A submodule pointer (no file content). */
  | "submodule"
  /** Larger than the per-file limit. */
  | "too_large"
  /** More changed files than the file limit. */
  | "file_limit"
  /** The total byte budget was used up. */
  | "byte_budget"
  /** The time budget ran out before the file was read. */
  | "time_budget"
  /** A merge conflict entry (stage 1 to 3): the commit cannot happen until it is resolved. */
  | "unmerged"
  /** The object could not be read. */
  | "unreadable";

/** Reasons that leave a file unexamined by surprise rather than by design. */
export const INCOMPLETE_SKIP_REASONS: ReadonlySet<StagedSkipReason> = new Set([
  "too_large",
  "file_limit",
  "byte_budget",
  "time_budget",
  "unmerged",
  "unreadable",
]);

export interface StagedFile {
  /** Repository-relative path with forward slashes (also on Windows). */
  path: string;
  /** `renamed`: the same content as a path HEAD has and the index no longer has. */
  kind: "added" | "modified" | "renamed";
  /** The staged text. */
  content: string;
  /** The text HEAD has at this path (modified) or at the old path (renamed); `null` for added. */
  previous: string | null;
}

export interface StagedSkip {
  path: string;
  reason: StagedSkipReason;
}

export interface StagedChanges {
  files: StagedFile[];
  skipped: StagedSkip[];
  /** Paths in HEAD that the index no longer has (nothing to scan). */
  deleted: number;
  /** Staged paths that are the same as HEAD's, not examined. */
  unchanged: number;
  /** Bytes of Git objects read. */
  bytesRead: number;
}

export interface StagedReadOptions {
  runner?: GitRunner;
  signal?: AbortSignal;
  /** Absolute path of the index to read (`GIT_INDEX_FILE` of the hook); default: the repository's own. */
  indexFile?: string;
  /** Most changed files read; the rest are `file_limit`. Default 500. */
  maxFiles?: number;
  /** Largest blob read. Default 1 MiB (the same as the source scan). */
  maxFileBytes?: number;
  /** Most bytes of blobs read (staged and HEAD versions together). Default 16 MiB. */
  maxTotalBytes?: number;
  /** Absolute time (ms, from `now`) after which no more blobs are read. */
  deadline?: number;
  now?: () => number;
}

export const STAGED_MAX_FILES = 500;
export const STAGED_MAX_FILE_BYTES = 1024 * 1024;
export const STAGED_MAX_TOTAL_BYTES = 16 * 1024 * 1024;
const LIST_MAX_BUFFER = 64 * 1024 * 1024;
const BATCH_BYTES = 8 * 1024 * 1024;
const SHA = /^[0-9a-f]{40}$/;
const UTF16_LE = new TextDecoder("utf-16le");
const UTF16_BE = new TextDecoder("utf-16be");

interface IndexEntry {
  mode: string;
  sha: string;
  stage: number;
  path: string;
}

interface HeadEntry {
  mode: string;
  sha: string;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new Error("aborted");
}

/** `ls-files -s -z`: "<mode> <sha> <stage>\t<path>\0". */
async function listIndex(
  cwd: string,
  runner: GitRunner,
  options: StagedReadOptions,
  timeoutMs: number | undefined,
): Promise<IndexEntry[]> {
  const output = await runner(
    { subcommand: "ls-files", flags: ["-s", "-z", "--full-name"] },
    {
      cwd,
      encoding: "latin1",
      maxBuffer: LIST_MAX_BUFFER,
      ...(options.signal ? { signal: options.signal } : {}),
      ...(options.indexFile ? { indexFile: options.indexFile } : {}),
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
    },
  );
  const entries: IndexEntry[] = [];
  for (const record of output.split("\0")) {
    const match = /^(\d{6}) ([0-9a-f]{40}) ([0-3])\t([\s\S]+)$/.exec(record);
    if (match?.[1] && match[2] && match[3] && match[4]) {
      entries.push({
        mode: match[1],
        sha: match[2],
        stage: Number(match[3]),
        path: decodeGitPath(match[4]),
      });
    }
  }
  return entries;
}

/** HEAD's tree, or an empty one when there is no commit yet (the first commit). */
async function listHead(
  cwd: string,
  runner: GitRunner,
  options: StagedReadOptions,
  timeoutMs: number | undefined,
): Promise<Map<string, HeadEntry>> {
  const common = {
    cwd,
    ...(options.signal ? { signal: options.signal } : {}),
    ...(timeoutMs === undefined ? {} : { timeoutMs }),
  };
  let head: string;
  try {
    head = (
      await runner(
        { subcommand: "rev-parse", flags: ["--verify", "--quiet"], operands: ["HEAD^{commit}"] },
        common,
      )
    ).trim();
  } catch (error) {
    // `--verify --quiet` exits 1 when HEAD does not exist: the repository has no commit yet.
    if (error instanceof GitCommandError && error.kind === "failed" && error.exitCode === 1) {
      return new Map();
    }
    throw error;
  }
  if (!SHA.test(head)) return new Map();
  const output = await runner(
    { subcommand: "ls-tree", flags: ["-r", "-z", "--full-tree"], operands: [head] },
    { ...common, encoding: "latin1", maxBuffer: LIST_MAX_BUFFER },
  );
  const entries = new Map<string, HeadEntry>();
  for (const record of output.split("\0")) {
    const match = /^(\d{6}) (?:blob|commit) ([0-9a-f]{40})\t([\s\S]+)$/.exec(record);
    if (match?.[1] && match[2] && match[3]) {
      entries.set(decodeGitPath(match[3]), { mode: match[1], sha: match[2] });
    }
  }
  return entries;
}

/** Text of a blob body (read as latin1): UTF-8, or UTF-16 with a byte order mark; `null` if binary. */
export function decodeStagedBlob(latin1: string): string | null {
  const bom = latin1.slice(0, 2);
  if (bom === "\xff\xfe" || bom === "\xfe\xff") {
    const bytes = Buffer.from(latin1.slice(2), "latin1");
    return (bom === "\xfe\xff" ? UTF16_BE : UTF16_LE).decode(bytes);
  }
  if (latin1.includes("\0")) return null;
  return Buffer.from(latin1, "latin1").toString("utf8");
}

/** Milliseconds until `deadline` (at least 1), or `undefined` when there is no deadline. */
function timeoutUntil(deadline: number, now: () => number): number | undefined {
  if (!Number.isFinite(deadline)) return undefined;
  return Math.max(1, Math.min(deadline - now(), 2 ** 31 - 1));
}

function withTimeout(timeoutMs: number | undefined): { timeoutMs?: number } {
  return timeoutMs === undefined ? {} : { timeoutMs };
}

interface BlobRead {
  /** `null` text: binary. */
  text: Map<string, string | null>;
  /** Blobs not read: reason by sha. */
  unread: Map<string, StagedSkipReason>;
  bytes: number;
}

/** `cat-file --batch-check` for sizes, then `--batch` in batches, within the byte and time budgets. */
async function readBlobs(
  cwd: string,
  runner: GitRunner,
  shas: readonly string[],
  limits: {
    maxFileBytes: number;
    budget: { remaining: number };
    deadline: number;
    now: () => number;
  },
  options: StagedReadOptions,
): Promise<BlobRead> {
  const text = new Map<string, string | null>();
  const unread = new Map<string, StagedSkipReason>();
  let bytes = 0;
  if (shas.length === 0) return { text, unread, bytes };
  const withSignal = options.signal ? { signal: options.signal } : {};
  const remainingMs = () => timeoutUntil(limits.deadline, limits.now);
  const check = await runner(
    { subcommand: "cat-file", flags: ["--batch-check"] },
    {
      cwd,
      input: `${shas.join("\n")}\n`,
      maxBuffer: shas.length * 100 + 1024,
      ...withTimeout(remainingMs()),
      ...withSignal,
    },
  );
  const sizes = new Map<string, number>();
  for (const line of check.split("\n")) {
    const match = /^([0-9a-f]{40}) blob (\d+)$/.exec(line);
    if (match?.[1] && match[2]) sizes.set(match[1], Number(match[2]));
  }
  const readable: { sha: string; size: number }[] = [];
  for (const sha of shas) {
    const size = sizes.get(sha);
    if (size === undefined) unread.set(sha, "unreadable");
    else if (size > limits.maxFileBytes) unread.set(sha, "too_large");
    else if (size > limits.budget.remaining) unread.set(sha, "byte_budget");
    else {
      limits.budget.remaining -= size;
      readable.push({ sha, size });
    }
  }
  for (let start = 0; start < readable.length;) {
    throwIfAborted(options.signal);
    if (limits.now() >= limits.deadline) {
      for (const item of readable.slice(start)) unread.set(item.sha, "time_budget");
      break;
    }
    let batchBytes = 0;
    let end = start;
    while (
      end < readable.length &&
      (end === start || batchBytes + (readable[end]?.size ?? 0) <= BATCH_BYTES)
    ) {
      batchBytes += readable[end]?.size ?? 0;
      end += 1;
    }
    const batch = readable.slice(start, end);
    const raw = await runner(
      { subcommand: "cat-file", flags: ["--batch"] },
      {
        cwd,
        input: `${batch.map((item) => item.sha).join("\n")}\n`,
        encoding: "latin1",
        maxBuffer: batchBytes + batch.length * 100 + 1024,
        ...withTimeout(remainingMs()),
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
      bytes += size;
      text.set(header[1], decodeStagedBlob(body));
    }
    for (const item of batch) {
      if (!text.has(item.sha)) unread.set(item.sha, "unreadable");
    }
    start = end;
  }
  return { text, unread, bytes };
}

/**
 * The staged changes: every index entry whose content or mode differs from HEAD. A renamed file
 * is a new path with content HEAD already had elsewhere (`kind: "renamed"`); a deleted path has
 * nothing to scan. Files that cannot be read are listed in `skipped` with the reason, so a
 * caller can tell "nothing found" from "not looked at".
 */
export async function readStagedChanges(
  projectRoot: string,
  options: StagedReadOptions = {},
): Promise<StagedChanges> {
  const runner = options.runner ?? defaultRunGit;
  const now = options.now ?? Date.now;
  const deadline = options.deadline ?? Number.POSITIVE_INFINITY;
  const timeoutMs = timeoutUntil(deadline, now);
  const [index, head] = await Promise.all([
    listIndex(projectRoot, runner, options, timeoutMs),
    listHead(projectRoot, runner, options, timeoutMs),
  ]);
  const skipped: StagedSkip[] = [];
  const candidates: { entry: IndexEntry; before: HeadEntry | undefined }[] = [];
  const indexPaths = new Set<string>();
  let unchanged = 0;
  for (const entry of index) {
    indexPaths.add(entry.path);
    if (entry.stage !== 0) {
      skipped.push({ path: entry.path, reason: "unmerged" });
      continue;
    }
    const before = head.get(entry.path);
    if (before !== undefined && before.sha === entry.sha && before.mode === entry.mode) {
      unchanged += 1;
      continue;
    }
    if (entry.mode === "160000") {
      skipped.push({ path: entry.path, reason: "submodule" });
      continue;
    }
    if (entry.mode === "120000") {
      skipped.push({ path: entry.path, reason: "symlink" });
      continue;
    }
    candidates.push({ entry, before });
  }
  // A path HEAD has and the index no longer has: its content may reappear under a new name.
  const deletedBySha = new Map<string, string>();
  let deleted = 0;
  for (const [headPath, entry] of head) {
    if (indexPaths.has(headPath)) continue;
    deleted += 1;
    if (entry.mode !== "160000" && !deletedBySha.has(entry.sha))
      deletedBySha.set(entry.sha, headPath);
  }
  candidates.sort((a, b) =>
    a.entry.path < b.entry.path ? -1 : a.entry.path > b.entry.path ? 1 : 0,
  );
  const maxFiles = options.maxFiles ?? STAGED_MAX_FILES;
  for (const extra of candidates.splice(maxFiles)) {
    skipped.push({ path: extra.entry.path, reason: "file_limit" });
  }
  const renamedFrom = new Map<string, string>();
  for (const { entry, before } of candidates) {
    const old = before === undefined ? deletedBySha.get(entry.sha) : undefined;
    if (old !== undefined) renamedFrom.set(entry.path, old);
  }
  // The staged versions come first so the byte budget goes to what is about to be committed.
  const stagedShas = [...new Set(candidates.map(({ entry }) => entry.sha))];
  const budget = { remaining: options.maxTotalBytes ?? STAGED_MAX_TOTAL_BYTES };
  const limits = {
    maxFileBytes: options.maxFileBytes ?? STAGED_MAX_FILE_BYTES,
    budget,
    deadline,
    now,
  };
  const stagedSet = new Set(stagedShas);
  const previousShas = [
    ...new Set(
      candidates.flatMap(({ before }) =>
        before !== undefined && before.mode !== "160000" ? [before.sha] : [],
      ),
    ),
  ].filter((sha) => !stagedSet.has(sha));
  // One batch for both, so Git starts as few times as possible.
  const stagedRead = await readBlobs(
    projectRoot,
    runner,
    [...stagedShas, ...previousShas],
    limits,
    options,
  );
  const previousText = (sha: string): string | null | undefined => stagedRead.text.get(sha);
  const files: StagedFile[] = [];
  for (const { entry, before } of candidates) {
    const reason = stagedRead.unread.get(entry.sha);
    if (reason !== undefined) {
      skipped.push({ path: entry.path, reason });
      continue;
    }
    const content = stagedRead.text.get(entry.sha);
    if (content === undefined) {
      skipped.push({ path: entry.path, reason: "unreadable" });
      continue;
    }
    if (content === null) {
      skipped.push({ path: entry.path, reason: "binary" });
      continue;
    }
    const isRenamed = renamedFrom.has(entry.path);
    // Without the older text every line counts as new, which can only add alerts.
    const previous =
      before !== undefined && before.mode !== "160000"
        ? (previousText(before.sha) ?? null)
        : isRenamed
          ? content
          : null;
    files.push({
      path: entry.path,
      kind: before !== undefined ? "modified" : isRenamed ? "renamed" : "added",
      content,
      previous,
    });
  }
  return {
    files,
    skipped,
    deleted,
    unchanged,
    bytesRead: stagedRead.bytes,
  };
}
