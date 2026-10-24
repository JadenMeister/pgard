import { readFile } from "node:fs/promises";
import path from "node:path";
import { runGit as defaultRunGit, type GitRunner } from "./run-git.js";

export type RepositoryIsolation = { isIsolated: true } | { isIsolated: false; reason: string };

async function hasContent(filePath: string): Promise<boolean> {
  try {
    return (await readFile(filePath, "utf8")).trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * Verifies the repository only uses its own objects and real history. Alternates
 * (`objects/info/alternates`, `http-alternates`) would let git read objects from other
 * repositories on disk; grafts and replace refs rewrite history. Any of them makes the checkout
 * an unreliable basis for authorization and analysis, so it is rejected.
 */
export async function readRepositoryIsolation(
  projectRoot: string,
  runner: GitRunner = defaultRunGit,
): Promise<RepositoryIsolation> {
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
  for (const [relative, label] of [
    [path.join("objects", "info", "alternates"), "object alternates"],
    [path.join("objects", "info", "http-alternates"), "object alternates"],
    [path.join("info", "grafts"), "grafts"],
  ] as const) {
    if (await hasContent(path.join(commonDir, relative))) {
      return {
        isIsolated: false,
        reason: `The repository uses ${label}, so its objects or history may come from elsewhere; this is not supported.`,
      };
    }
  }
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
