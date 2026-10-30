import { realpath } from "node:fs";
import { lstat } from "node:fs/promises";
import path from "node:path";
import { runGit as defaultRunGit, type GitRunner } from "./run-git.js";

/**
 * Resolves the Git working-tree root containing `cwd`. Returns `null` when `cwd` is not inside
 * a Git work tree. Launchers use this to choose `ScanRequest.projectRoot`.
 */
export async function findGitRoot(
  cwd: string,
  runner: GitRunner = defaultRunGit,
): Promise<string | null> {
  try {
    const output = (
      await runner({ subcommand: "rev-parse", flags: ["--show-toplevel"] }, { cwd })
    ).trim();
    // Git prints forward slashes on Windows (`C:/Users/x`); callers expect native separators.
    return output.length > 0 ? path.normalize(output) : null;
  } catch {
    return null;
  }
}

/** The folder that holds the nearest `.git` entry at or above `cwd`, found without running Git. */
async function folderWithGitEntry(cwd: string): Promise<string | null> {
  let current = path.resolve(cwd);
  for (;;) {
    try {
      const entry = await lstat(path.join(current, ".git"));
      if (entry.isDirectory() || entry.isFile()) return current;
    } catch {
      // No `.git` entry here: keep walking up.
    }
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

async function realOf(value: string): Promise<string> {
  try {
    return await new Promise<string>((resolve, reject) =>
      realpath.native(value, (error, resolved) => (error ? reject(error) : resolve(resolved))),
    );
  } catch {
    return path.resolve(value);
  }
}

export type GitRootInspection =
  | { kind: "none" }
  | { kind: "root"; root: string }
  /**
   * Git put the work tree somewhere other than the folder that holds the `.git` entry (the
   * `core.worktree` setting of the scanned folder's own config). The files that would be read
   * are not the repository that was checked, so the folder is refused.
   */
  | { kind: "redirected"; root: string; repository: string | null };

/**
 * `findGitRoot`, plus a check that Git did not redirect the work tree (`core.worktree` in the
 * folder's own `.git/config`, #427). The root Git reports must be the folder that holds the
 * nearest `.git` entry; otherwise the authorization gate would verify one repository while the
 * code scope reads another folder.
 */
export async function inspectGitRoot(
  cwd: string,
  runner: GitRunner = defaultRunGit,
): Promise<GitRootInspection> {
  const root = await findGitRoot(cwd, runner);
  if (root === null) return { kind: "none" };
  const repository = await folderWithGitEntry(cwd);
  const fold = (value: string): string =>
    process.platform === "darwin" || process.platform === "win32" ? value.toLowerCase() : value;
  if (repository !== null && fold(await realOf(repository)) === fold(await realOf(root))) {
    return { kind: "root", root };
  }
  return { kind: "redirected", root, repository };
}
