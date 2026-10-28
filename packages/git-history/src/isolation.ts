import path from "node:path";
import { runGit as defaultRunGit, type GitRunner } from "./run-git.js";
import { readSmallRegularFile } from "./safe-read.js";

export type RepositoryIsolation = { isIsolated: true } | { isIsolated: false; reason: string };

/** Alternates and grafts hold a few short lines; anything bigger is not a normal repository. */
const MAX_METADATA_BYTES = 64 * 1024;

type Probe = "empty" | "content" | "unsafe";

async function probeFile(filePath: string): Promise<Probe> {
  const result = await readSmallRegularFile(filePath, MAX_METADATA_BYTES);
  if (result.state === "absent") return "empty";
  if (result.state === "unsafe") return "unsafe";
  return result.text.trim().length > 0 ? "content" : "empty";
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
    const probe = await probeFile(path.join(commonDir, relative));
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
