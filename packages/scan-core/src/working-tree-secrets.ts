import { opendir } from "node:fs/promises";
import path from "node:path";
import {
  compilePathMatcher,
  FINDING_TEXT_VARIANTS,
  type Coverage,
  type Finding,
} from "@pgard/findings";
import {
  decodeStagedBlobBoth,
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
 * on every entry. Files over `fileBytes` are not read. Every file is opened with `O_NOFOLLOW` and
 * `O_NONBLOCK` and checked again on the open handle (`readSmallRegularFileBytes`), so a file
 * swapped for a symbolic link or a FIFO is neither followed nor able to block the read; links
 * and special files are never read. Anything left out (a limit, a large or unreadable file)
 * makes the area `partial`, and the note names the files. Clearly binary files (a known file
 * signature, or binary content) are skipped by design, as in the pre-commit check, and named in
 * the note; they do not make the area partial.
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

const SKIPPED_DIRECTORIES = new Set([".git", "node_modules", "bower_components", ".hg", ".svn"]);
/** Paths named per kind in the coverage note. */
const MAX_NAMED = 5;

export interface WorkingTreeSecretsOutput {
  findings: Finding[];
  coverage: Coverage[];
}

type Skip = "too_large" | "unreadable" | "binary";

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

export async function scanWorkingTreeSecrets(
  context: Pick<AnalyzerContext, "projectRoot" | "projectConfig" | "signal">,
  options: { limits?: Partial<WorkingTreeLimits>; now?: () => number } = {},
): Promise<WorkingTreeSecretsOutput> {
  const limits: WorkingTreeLimits = { ...WORKING_TREE_LIMITS, ...options.limits };
  const now = options.now ?? Date.now;
  const deadline = now() + limits.timeMs;
  const excluded =
    context.projectConfig !== null && context.projectConfig.exclude.length > 0
      ? compilePathMatcher(context.projectConfig.exclude)
      : null;
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
  const unreadFolders = new Named();
  const notRead: Array<{ path: string; reason: StagedSkipReason }> = [];
  const findings: Finding[] = [];
  const skip = (entry: string, why: Skip): void => {
    (why === "too_large" ? large : why === "binary" ? binary : unreadable).add(entry);
    notRead.push({ path: entry, reason: why });
  };

  const stack: Array<{ relative: string; depth: number }> = [{ relative: "", depth: 0 }];
  walk: while (stack.length > 0) {
    throwIfAborted();
    const { relative, depth } = stack.pop() as { relative: string; depth: number };
    let directory;
    try {
      directory = await opendir(path.join(context.projectRoot, relative), { bufferSize: 64 });
    } catch {
      unreadFolders.add(relative === "" ? "." : relative);
      continue;
    }
    try {
      for await (const entry of directory) {
        throwIfAborted();
        entriesSeen += 1;
        if (entriesSeen > limits.entries) stoppedBy = "entries";
        else if (now() > deadline) stoppedBy = "time";
        if (stoppedBy !== null) break walk;
        const child = relative === "" ? entry.name : `${relative}/${entry.name}`;
        if (excluded?.matches(child) === true) continue;
        if (entry.isDirectory()) {
          if (SKIPPED_DIRECTORIES.has(entry.name)) continue;
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
        const read = await readSmallRegularFileBytes(
          path.join(context.projectRoot, child),
          limits.fileBytes,
        );
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
          skip(child, "binary");
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
      unreadFolders.add(relative === "" ? "." : relative);
    } finally {
      await directory.close().catch(() => undefined);
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
    unreadable.count > 0 ||
    unreadFolders.count > 0;
  const parts = [`${filesRead} file(s) on disk checked for secrets.`];
  for (const line of [
    large.describe(`file(s) over ${Math.round(limits.fileBytes / 1024)} KiB were not read`),
    unreadable.describe("file(s) could not be read"),
    unreadFolders.describe("folder(s) could not be read"),
    binary.describe("binary file(s) were skipped by design"),
  ]) {
    if (line !== null) parts.push(line);
  }
  if (hitDepth) parts.push(`Folders deeper than ${limits.depth} levels were not checked.`);
  if (stoppedBy !== null) {
    const why = {
      entries: `${limits.entries} folder entries`,
      files: `${limits.files} files`,
      bytes: `${Math.round(limits.totalBytes / (1024 * 1024))} MiB read`,
      time: `${Math.round(limits.timeMs / 1000)} s`,
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
