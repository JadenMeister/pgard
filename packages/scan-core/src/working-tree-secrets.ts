import path from "node:path";
import { FINDING_TEXT_VARIANTS, type Coverage, type Finding } from "@pgard/findings";
import {
  decodeStagedBlobBoth,
  isGitDirectoryName,
  openDirectoryNoFollow,
  readSmallRegularFileBytes,
  scanStagedPaths,
  scanStagedSecrets,
  type StagedSkipReason,
} from "@pgard/git-history";
import type { AnalyzerContext } from "./types.js";

/**
 * Secrets in the current files of a folder, for the code-only scan (#414). The secret rules
 * (PG-SECRET-001/002) otherwise run only in the history scope, which reads Git objects; a
 * code-only scan reads no Git object, so it needs its own pass over the files on disk. It uses
 * the same detection and decoding as the pre-commit check: `scanStagedSecrets` with every line
 * counted as new, UTF-8 and UTF-16 (with or without a byte order mark, plus the UTF-8 reading of
 * UTF-16 bytes), NUL bytes in text read as spaces, and a `.env` file reported by its name even
 * when its content is not read. It never puts a secret value in a finding.
 *
 * A hostile tree cannot make it do unbounded work: directories are read entry by entry
 * (`opendir`), and the walk stops at `entries` directory entries, `files` files, `totalBytes`
 * bytes read, `depth` folders deep or `timeMs`, whichever comes first, checking for cancellation
 * on every entry. The time limit is hard: every file-system call is raced against the deadline
 * and against Cancel, so a hung network or FUSE mount ends the walk on time (the area is
 * `partial`, the stuck call is abandoned in its thread and its result dropped) instead of
 * blocking it. Files over `fileBytes` are not read. Every file is opened with `O_NOFOLLOW` and
 * `O_NONBLOCK` and checked again on the open handle (`readSmallRegularFileBytes`), and every
 * folder is `lstat`-checked, opened with `O_DIRECTORY | O_NOFOLLOW` where the system has them and
 * compared (`dev`, `ino`) with what `lstat` saw (`openDirectoryNoFollow`), so a folder or file
 * swapped for a symbolic link or a FIFO is neither followed nor able to block the read; links and
 * special files are never read. A folder on another device than the root (a mount point) is not
 * entered, and is named in the note. The folder's own `pgard.config.json` `exclude` is untrusted
 * and is not applied. Anything left out (a limit, a large or unreadable file, a mount) makes the
 * area `partial`, and the note names the files. A file with a known binary format
 * (PNG, ZIP, ...) is skipped by design, as in the pre-commit check, and named in the note; it
 * does not make the area partial. A file that only looks binary by its content (no known
 * signature: it may be text, such as a log with colour codes) is not read and makes the area
 * `partial`.
 */
export const WORKING_TREE_SECRETS_AREA = "secrets:working-tree";

export const WORKING_TREE_LIMITS = {
  entries: 300_000,
  files: 20_000,
  fileBytes: 1024 * 1024,
  totalBytes: 64 * 1024 * 1024,
  depth: 24,
  timeMs: 20_000,
} as const;
export type WorkingTreeLimits = { -readonly [K in keyof typeof WORKING_TREE_LIMITS]: number };

const SKIPPED_DIRECTORIES = new Set(["node_modules", "bower_components", ".hg", ".svn"]);
/** Paths named per kind in the coverage note. */
const MAX_NAMED = 5;

export interface WorkingTreeSecretsOutput {
  findings: Finding[];
  coverage: Coverage[];
}

type Skip = "too_large" | "unreadable" | "binary" | "binary_suspected";

class Named {
  readonly paths: string[] = [];
  count = 0;
  add(entry: string): void {
    this.count += 1;
    if (this.paths.length < MAX_NAMED) this.paths.push(entry);
  }
  describe(what: string): string | null {
    if (this.count === 0) return null;
    const more =
      this.count > this.paths.length ? ` and ${this.count - this.paths.length} more` : "";
    return `${this.count} ${what}: ${this.paths.join(", ")}${more}.`;
  }
}

/** The file-system calls of the walk; injected in tests (a call that never returns). */
export interface WorkingTreeFs {
  openDirectory: typeof openDirectoryNoFollow;
  readFile: typeof readSmallRegularFileBytes;
}

const DEFAULT_FS: WorkingTreeFs = {
  openDirectory: openDirectoryNoFollow,
  readFile: readSmallRegularFileBytes,
};

/**
 * `work`, `{ kind: "time" }` when `remainingMs` runs out first, or a rejection `aborted` when
 * `signal` aborts. The file system can hang in a call that never returns (a dead network or
 * FUSE mount); the walk must still end on time and on Cancel, so it stops waiting for the call
 * instead of for the file system. The abandoned call stays in a libuv thread until it returns
 * (`onLate` gets what it returns, so a handle is not leaked), but nothing waits for it.
 */
function bounded<T>(
  work: Promise<T>,
  remainingMs: number,
  signal: AbortSignal | undefined,
  onLate?: (value: T) => void,
): Promise<{ kind: "done"; value: T } | { kind: "time" }> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (action: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      action();
    };
    const onAbort = (): void => finish(() => reject(new Error("aborted")));
    const timer = setTimeout(
      () => finish(() => resolve({ kind: "time" })),
      Math.max(0, remainingMs),
    );
    if (signal?.aborted === true) {
      onAbort();
    } else {
      signal?.addEventListener("abort", onAbort, { once: true });
    }
    work.then(
      (value) => {
        if (settled) onLate?.(value);
        finish(() => resolve({ kind: "done", value }));
      },
      (error: unknown) => finish(() => reject(error)),
    );
  });
}

export async function scanWorkingTreeSecrets(
  context: Pick<AnalyzerContext, "projectRoot" | "projectConfig" | "signal">,
  options: { limits?: Partial<WorkingTreeLimits>; now?: () => number; fs?: WorkingTreeFs } = {},
): Promise<WorkingTreeSecretsOutput> {
  const limits: WorkingTreeLimits = { ...WORKING_TREE_LIMITS, ...options.limits };
  const now = options.now ?? Date.now;
  const fs = options.fs ?? DEFAULT_FS;
  const deadline = now() + limits.timeMs;
  // The folder's own `pgard.config.json` is untrusted here: its `exclude` could hide a file from
  // this check. It is not applied; the note says how many patterns were ignored.
  const ignoredExcludes = context.projectConfig?.exclude.length ?? 0;
  const throwIfAborted = (): void => {
    if (context.signal?.aborted === true) throw new Error("aborted");
  };
  let entriesSeen = 0;
  let filesRead = 0;
  let bytesRead = 0;
  let stoppedBy: "entries" | "files" | "bytes" | "time" | null = null;
  let hitDepth = false;
  const large = new Named();
  const unreadable = new Named();
  const binary = new Named();
  const suspected = new Named();
  const unreadFolders = new Named();
  const mounts = new Named();
  const notRead: Array<{ path: string; reason: StagedSkipReason }> = [];
  const findings: Finding[] = [];
  const skip = (entry: string, why: Skip): void => {
    const named = { too_large: large, binary, binary_suspected: suspected, unreadable }[why];
    named.add(entry);
    notRead.push({ path: entry, reason: why });
  };
  /** Waits for `work` no longer than the deadline; `null` when the time is up. */
  const waitFor = async <T>(
    work: Promise<T>,
    onLate?: (value: T) => void,
  ): Promise<{ value: T } | null> => {
    const result = await bounded(work, deadline - now(), context.signal, onLate);
    return result.kind === "done" ? { value: result.value } : null;
  };

  let rootDev: bigint | undefined;
  const stack: Array<{ relative: string; depth: number }> = [{ relative: "", depth: 0 }];
  walk: while (stack.length > 0) {
    throwIfAborted();
    const { relative, depth } = stack.pop() as { relative: string; depth: number };
    const shown = relative === "" ? "." : relative;
    // Each folder is opened without following a link swapped in since the parent was listed, and
    // on the root's device only: a mount point (a network share, a FUSE mount, another disk) is
    // counted and named, never entered.
    const attempt = await waitFor(
      fs.openDirectory(path.join(context.projectRoot, relative), {
        allowSymlink: relative === "",
        ...(rootDev === undefined ? {} : { expectedDev: rootDev }),
        bufferSize: 64,
      }),
      (late) => {
        if (late.state === "ok") void late.dir.close().catch(() => undefined);
      },
    );
    if (attempt === null) {
      stoppedBy = "time";
      break walk;
    }
    const opened = attempt.value;
    if (opened.state !== "ok") {
      if (opened.state === "unsafe" && opened.found === "mount") mounts.add(shown);
      // A link swapped in since the parent was listed is not a folder to read.
      else if (opened.state === "unsafe" && opened.found === "symlink") continue;
      else if (opened.state !== "absent" || relative === "") unreadFolders.add(shown);
      continue;
    }
    if (rootDev === undefined) rootDev = opened.dev;
    const directory = opened.dir;
    let isAbandoned = false;
    try {
      for (;;) {
        throwIfAborted();
        const next = await waitFor(directory.read());
        if (next === null) {
          stoppedBy = "time";
          isAbandoned = true;
          break walk;
        }
        const entry = next.value;
        if (entry === null) break;
        entriesSeen += 1;
        if (entriesSeen > limits.entries) stoppedBy = "entries";
        else if (now() > deadline) stoppedBy = "time";
        if (stoppedBy !== null) break walk;
        const child = relative === "" ? entry.name : `${relative}/${entry.name}`;
        if (entry.isDirectory()) {
          if (isGitDirectoryName(entry.name) || SKIPPED_DIRECTORIES.has(entry.name)) continue;
          if (depth + 1 > limits.depth) {
            hitDepth = true;
            continue;
          }
          stack.push({ relative: child, depth: depth + 1 });
          continue;
        }
        if (!entry.isFile()) continue; // symbolic links and special files are never read
        if (filesRead >= limits.files) {
          stoppedBy = "files";
          break walk;
        }
        const attemptRead = await waitFor(
          fs.readFile(path.join(context.projectRoot, child), limits.fileBytes),
        );
        if (attemptRead === null) {
          stoppedBy = "time";
          break walk;
        }
        const read = attemptRead.value;
        if (read.state === "absent") continue; // removed since the directory was read
        if (read.state === "unsafe") {
          // A link or special file swapped in since the directory was read is not a file.
          if (read.found === "symlink" || read.found === "special") continue;
          skip(child, read.found === "too-large" ? "too_large" : "unreadable");
          continue;
        }
        if (bytesRead + read.bytes.length > limits.totalBytes) {
          stoppedBy = "bytes";
          notRead.push({ path: child, reason: "too_large" });
          break walk;
        }
        bytesRead += read.bytes.length;
        filesRead += 1;
        const decoded = decodeStagedBlobBoth(read.bytes.toString("latin1"));
        if (decoded.text === null) {
          skip(child, decoded.binary === "content" ? "binary_suspected" : "binary");
          continue;
        }
        const scan = scanStagedSecrets([
          {
            path: child,
            kind: "added",
            content: decoded.text,
            previous: null,
            ...(decoded.alternate === null ? {} : { alternate: decoded.alternate }),
          },
        ]);
        findings.push(...scan.findings.map(relabel));
      }
    } catch (error) {
      throwIfAborted();
      if (error instanceof Error && error.message === "aborted") throw error;
      unreadFolders.add(shown);
    } finally {
      // After a timeout the close may hang as well: not waited for.
      const closing = directory.close().catch(() => undefined);
      if (!isAbandoned) await closing;
    }
  }
  // A `.env` file is reported by its name even when its content was not read.
  findings.push(
    ...scanStagedPaths(notRead.map((item) => ({ kind: "added" as const, ...item }))).map(relabel),
  );

  const isPartial =
    stoppedBy !== null ||
    hitDepth ||
    large.count > 0 ||
    suspected.count > 0 ||
    unreadable.count > 0 ||
    unreadFolders.count > 0 ||
    mounts.count > 0;
  const parts = [`${filesRead} file(s) on disk checked for secrets.`];
  for (const line of [
    large.describe(`file(s) over ${size(limits.fileBytes)} were not read`),
    suspected.describe("file(s) looked binary without a known file format and were not read"),
    unreadable.describe("file(s) could not be read"),
    unreadFolders.describe("folder(s) could not be read"),
    mounts.describe("folder(s) are on another device (a mount point) and were not entered"),
    binary.describe("binary file(s) were skipped by design"),
  ]) {
    if (line !== null) parts.push(line);
  }
  if (ignoredExcludes > 0) {
    parts.push(
      `The folder's own pgard.config.json exclude (${ignoredExcludes} pattern${ignoredExcludes === 1 ? "" : "s"}) is not applied to this check.`,
    );
  }
  if (hitDepth) parts.push(`Folders deeper than ${limits.depth} levels were not checked.`);
  if (stoppedBy !== null) {
    const why = {
      entries: `${limits.entries} folder entries`,
      files: `${limits.files} files`,
      bytes: `${size(limits.totalBytes)} read`,
      time: seconds(limits.timeMs),
    }[stoppedBy];
    parts.push(`The walk stopped at its limit (${why}); not every file was checked.`);
  }
  return {
    findings,
    coverage: [
      {
        area: WORKING_TREE_SECRETS_AREA,
        scope: "code",
        status: isPartial ? "partial" : "completed",
        ruleIds: ["PG-SECRET-001", "PG-SECRET-002"],
        note: parts.join(" "),
      },
    ],
  };
}

/** `1 MiB`, `512 KiB`, or `<1 KiB`: never a misleading `0`. */
function size(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${Math.round(bytes / (1024 * 1024))} MiB`;
  return bytes >= 1024 ? `${Math.round(bytes / 1024)} KiB` : "<1 KiB";
}

function seconds(milliseconds: number): string {
  return milliseconds >= 1000 ? `${Math.round(milliseconds / 1000)} s` : "<1 s";
}

/** The pre-commit wording says "staged"; these findings come from the files on disk. */
function relabel(finding: Finding): Finding {
  // Never "tracked file" or "committed to Git": the file may never have been committed.
  const text = FINDING_TEXT_VARIANTS[finding.ruleId]?.working_tree;
  return {
    ...finding,
    ...(text === undefined
      ? {}
      : {
          title: text.title.en,
          impact: text.impact.en,
          recommendation: text.recommendation.en,
        }),
    evidence:
      finding.ruleId === "PG-SECRET-001"
        ? "environment file in the project folder (values not shown)"
        : finding.evidence.replace(" in a staged file ", " in a file on disk "),
  };
}
