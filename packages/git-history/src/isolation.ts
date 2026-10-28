import { lstat } from "node:fs/promises";
import path from "node:path";
import { runGit as defaultRunGit, type GitRunner } from "./run-git.js";
import { readSmallRegularFile } from "./safe-read.js";

export type RepositoryIsolation = { isIsolated: true } | { isIsolated: false; reason: string };

/** Alternates and grafts hold a few short lines; anything bigger is not a normal repository. */
const MAX_METADATA_BYTES = 64 * 1024;

const MAX_SHALLOW_BYTES = 8 * 1024 * 1024;

type Probe = "empty" | "content" | "unsafe";

async function probeFile(filePath: string): Promise<Probe> {
  const result = await readSmallRegularFile(filePath, MAX_METADATA_BYTES);
  if (result.state === "absent") return "empty";
  if (result.state === "unsafe") return "unsafe";
  return result.text.trim().length > 0 ? "content" : "empty";
}

const METADATA_FILES = [
  [path.join("objects", "info", "alternates"), "object alternates"],
  [path.join("objects", "info", "http-alternates"), "object alternates"],
  [path.join("info", "grafts"), "grafts"],
] as const;

/** Returns a blocking result when an alternates or grafts file is present or unsafe to read. */
async function checkMetadataFiles(gitDir: string): Promise<RepositoryIsolation | null> {
  for (const [relative, label] of METADATA_FILES) {
    const probe = await probeFile(path.join(gitDir, relative));
    if (probe === "unsafe") {
      return {
        isIsolated: false,
        reason: `The repository's ${relative.split(path.sep).join("/")} could not be read safely (it is a symbolic link, not a regular file, too large or unreadable), so its ${label} can't be ruled out. Remove it or replace it with a regular file, or use a normal clone, and check again.`,
      };
    }
    if (probe === "content") {
      return {
        isIsolated: false,
        reason: `The repository uses ${label}, so its objects or history may come from elsewhere; this is not supported.`,
      };
    }
  }
  // A regular `shallow` file is allowed (shallow clones are supported); an unsafe one is not.
  const shallow = await readSmallRegularFile(path.join(gitDir, "shallow"), MAX_SHALLOW_BYTES);
  if (shallow.state === "unsafe") {
    return {
      isIsolated: false,
      reason:
        "The repository's shallow file could not be read safely (it is a symbolic link, not a regular file, too large or unreadable), so its history boundary can't be trusted. Remove it or replace it with a regular file, or use a normal clone, and check again.",
    };
  }
  return null;
}

const MAX_GITFILE_BYTES = 4096;

/**
 * Checks the metadata files before any Git process starts: Git itself may open an alternates
 * file, which blocks on a FIFO. Handles a plain `.git` directory and a gitfile (`gitdir: <path>`,
 * plus the `commondir` of a linked worktree). Returns a blocking result, or `null` when nothing
 * unsafe was found (the full check, after `rev-parse`, still runs). An unreadable gitfile is left
 * to Git and the later check.
 */
export async function preflightIsolation(projectRoot: string): Promise<RepositoryIsolation | null> {
  const dotGit = path.join(projectRoot, ".git");
  const stats = await lstat(dotGit).catch(() => null);
  if (stats === null) return null;
  if (stats.isDirectory()) return checkMetadataFiles(dotGit);
  if (!stats.isFile()) return null;
  const gitfile = await readSmallRegularFile(dotGit, MAX_GITFILE_BYTES);
  if (gitfile.state !== "ok") return null;
  const match = /^gitdir:\s*(.+?)\s*$/m.exec(gitfile.text);
  if (!match?.[1]) return null;
  const gitDir = path.resolve(projectRoot, match[1]);
  const dirs = [gitDir];
  const commonFile = await readSmallRegularFile(path.join(gitDir, "commondir"), MAX_GITFILE_BYTES);
  if (commonFile.state === "ok" && commonFile.text.trim().length > 0) {
    dirs.push(path.resolve(gitDir, commonFile.text.trim()));
  }
  for (const dir of dirs) {
    const blocked = await checkMetadataFiles(dir);
    if (blocked !== null) return blocked;
  }
  return null;
}

/**
 * Verifies the repository only uses its own objects and real history. Alternates
 * (`objects/info/alternates`, `http-alternates`) would let git read objects from other
 * repositories on disk; grafts and replace refs rewrite history. Any of them makes the checkout
 * an unreliable basis for authorization and analysis, so it is rejected. A metadata file that
 * cannot be read safely (symlink, FIFO, directory, oversized, unreadable) also rejects: the check
 * never fails open.
 */
export async function readRepositoryIsolation(
  projectRoot: string,
  runner: GitRunner = defaultRunGit,
): Promise<RepositoryIsolation> {
  const early = await preflightIsolation(projectRoot);
  if (early !== null) return early;
  let commonDir: string;
  try {
    const output = (
      await runner({ subcommand: "rev-parse", flags: ["--git-common-dir"] }, { cwd: projectRoot })
    ).trim();
    if (output.length === 0) {
      return { isIsolated: false, reason: "Could not locate the Git directory." };
    }
    commonDir = path.resolve(projectRoot, output);
  } catch {
    return { isIsolated: false, reason: "Could not locate the Git directory." };
  }
  const blocked = await checkMetadataFiles(commonDir);
  if (blocked !== null) return blocked;
  try {
    const replaceRefs = (
      await runner(
        {
          subcommand: "for-each-ref",
          flags: ["--count=1", "--format=%(refname)"],
          operands: ["refs/replace/"],
        },
        { cwd: projectRoot },
      )
    ).trim();
    if (replaceRefs.length > 0) {
      return {
        isIsolated: false,
        reason: "The repository has replace refs that rewrite history; this is not supported.",
      };
    }
  } catch {
    return { isIsolated: false, reason: "Could not inspect repository refs." };
  }
  return { isIsolated: true };
}
