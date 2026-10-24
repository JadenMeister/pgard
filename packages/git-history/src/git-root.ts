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
    return output.length > 0 ? output : null;
  } catch {
    return null;
  }
}
