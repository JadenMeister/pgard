import { lstat, realpath } from "node:fs/promises";
import path from "node:path";
import { readRepositoryIsolation } from "./isolation.js";
import { runGit as defaultRunGit, type GitRunner } from "./run-git.js";

/**
 * Where a repository's hooks live and which index a running hook is committing. Everything is
 * read through the hardened Git runner (metadata-only plumbing); nothing here writes.
 */

/** The path modules, so Windows rules can be tested on any system. */
export type PathModule = Pick<typeof path, "relative" | "isAbsolute" | "resolve" | "sep">;

/**
 * True when `child` is `parent` or lies below it. Textual only (no symbolic links are resolved,
 * callers resolve those first). Uses the platform's own rules: on Windows the drive letter and
 * letter case do not matter and a path on another drive or a UNC share is outside.
 */
export function isPathInside(
  parent: string,
  child: string,
  pathModule: PathModule = path,
): boolean {
  const relative = pathModule.relative(pathModule.resolve(parent), pathModule.resolve(child));
  if (relative === "") return true;
  if (pathModule.isAbsolute(relative)) return false; // another drive or share
  return relative !== ".." && !relative.startsWith(`..${pathModule.sep}`);
}

export type HooksLocation =
  | {
      kind: "ready";
      /** This worktree's Git directory. */
      gitDir: string;
      /** The directory Git runs hooks from: `<common dir>/hooks`. */
      hooksDir: string;
      /** The repository's shared Git directory (`.git` of the main worktree). */
      commonDir: string;
    }
  | {
      /** `core.hooksPath` is set in the repository's own configuration. */
      kind: "custom";
      hooksPath: string;
      /** Absolute form (relative values are taken from the work tree root, as Git does). */
      resolved: string;
      isInsideRepository: boolean;
    }
  | { kind: "unsafe"; reason: string };

/** Git's null device, which the hardened runner sets as `core.hooksPath` on every call. */
const NULL_DEVICES: ReadonlySet<string> = new Set(["/dev/null", "NUL"]);

async function singleLine(
  runner: GitRunner,
  projectRoot: string,
  flag: "--absolute-git-dir" | "--git-common-dir",
): Promise<string | null> {
  const output = (
    await runner({ subcommand: "rev-parse", flags: [flag] }, { cwd: projectRoot })
  ).trim();
  return output.length > 0 && !output.includes("\0") ? output : null;
}

/**
 * The repository's own `core.hooksPath` values (local and included config only: the hardened
 * runner ignores global and system config). The runner itself adds one `core.hooksPath` entry
 * (the null device) at the end, which is removed here.
 */
async function readLocalHooksPath(runner: GitRunner, projectRoot: string): Promise<string | null> {
  const output = await runner(
    {
      subcommand: "config",
      flags: ["--null", "--get-regexp"],
      operands: ["^core\\.hookspath$"],
    },
    { cwd: projectRoot },
  );
  const values = output
    .split("\0")
    .filter((record) => record.length > 0)
    .map((record) => record.slice(record.indexOf("\n") + 1));
  const last = values[values.length - 1];
  if (last !== undefined && NULL_DEVICES.has(last)) values.pop();
  return values.length === 0 ? null : (values[values.length - 1] ?? "");
}

/**
 * Locates the hooks directory of the repository at `projectRoot` and checks it is safe to write
 * into: the repository layout passes the same isolation check as a scan (#370), no
 * `core.hooksPath` redirects hooks elsewhere, and the hooks directory, if it exists, is a real
 * directory whose real path is inside the repository's Git directory (a symbolic link out of it
 * is refused).
 */
export async function resolveHooksLocation(
  projectRoot: string,
  runner: GitRunner = defaultRunGit,
): Promise<HooksLocation> {
  const isolation = await readRepositoryIsolation(projectRoot, runner);
  if (!isolation.isIsolated) return { kind: "unsafe", reason: isolation.reason };
  let gitDirText: string | null;
  let commonDirText: string | null;
  let hooksPath: string | null;
  try {
    gitDirText = await singleLine(runner, projectRoot, "--absolute-git-dir");
    commonDirText = await singleLine(runner, projectRoot, "--git-common-dir");
    hooksPath = await readLocalHooksPath(runner, projectRoot);
  } catch {
    return { kind: "unsafe", reason: "The Git directory of this repository could not be read." };
  }
  if (gitDirText === null || commonDirText === null) {
    return { kind: "unsafe", reason: "The Git directory of this repository could not be read." };
  }
  if (hooksPath !== null) {
    const resolved = path.resolve(projectRoot, hooksPath);
    let real = resolved;
    try {
      real = await realpath(resolved);
    } catch {
      // A path that does not exist yet is judged by its text.
    }
    const root = await realpath(projectRoot).catch(() => projectRoot);
    return {
      kind: "custom",
      hooksPath,
      resolved,
      isInsideRepository: isPathInside(root, real),
    };
  }
  const gitDir = path.resolve(projectRoot, gitDirText);
  const commonDir = path.resolve(projectRoot, commonDirText);
  const hooksDir = path.join(commonDir, "hooks");
  const entry = await lstat(hooksDir).catch((error: NodeJS.ErrnoException) =>
    error.code === "ENOENT" ? null : error,
  );
  if (entry instanceof Error) {
    return { kind: "unsafe", reason: "The hooks directory could not be inspected." };
  }
  if (entry !== null) {
    const realCommon = await realpath(commonDir).catch(() => null);
    const realHooks = await realpath(hooksDir).catch(() => null);
    if (realCommon === null || realHooks === null) {
      return { kind: "unsafe", reason: "The hooks directory could not be resolved." };
    }
    if (!isPathInside(realCommon, realHooks)) {
      return {
        kind: "unsafe",
        reason: "The hooks directory is a symbolic link that leads outside this repository's .git.",
      };
    }
    const resolvedStats = await lstat(realHooks).catch(() => null);
    if (resolvedStats === null || !resolvedStats.isDirectory()) {
      return { kind: "unsafe", reason: "The hooks path is not a directory." };
    }
  }
  return { kind: "ready", gitDir, hooksDir, commonDir };
}

export type HookIndexFile =
  | { state: "default" }
  | { state: "custom"; indexFile: string }
  | { state: "unsafe"; reason: string };

/**
 * The index a running hook must read. Git sets `GIT_INDEX_FILE` for `git commit -a` and
 * `git commit <path>` to a temporary index that holds exactly what will be committed. The value
 * is accepted only when it names a regular file (not a link) whose real path is inside this
 * worktree's Git directory; anything else is refused, because reading the wrong index would
 * scan the wrong content.
 */
export async function resolveHookIndexFile(
  projectRoot: string,
  cwd: string,
  value: string | undefined,
  runner: GitRunner = defaultRunGit,
): Promise<HookIndexFile> {
  if (value === undefined || value === "") return { state: "default" };
  if (value.includes("\0"))
    return { state: "unsafe", reason: "GIT_INDEX_FILE is not a valid path." };
  let gitDirText: string | null;
  try {
    gitDirText = await singleLine(runner, projectRoot, "--absolute-git-dir");
  } catch {
    return { state: "unsafe", reason: "The Git directory of this repository could not be read." };
  }
  if (gitDirText === null) {
    return { state: "unsafe", reason: "The Git directory of this repository could not be read." };
  }
  const resolved = path.resolve(cwd, value);
  const stats = await lstat(resolved).catch(() => null);
  if (stats === null || !stats.isFile()) {
    return {
      state: "unsafe",
      reason: "GIT_INDEX_FILE does not name a regular file (a missing file or a link is refused).",
    };
  }
  const [realFile, realGitDir] = await Promise.all([
    realpath(resolved).catch(() => null),
    realpath(path.resolve(projectRoot, gitDirText)).catch(() => null),
  ]);
  if (realFile === null || realGitDir === null || !isPathInside(realGitDir, realFile)) {
    return { state: "unsafe", reason: "GIT_INDEX_FILE points outside this repository's .git." };
  }
  // The default index needs no override.
  if (realFile === path.join(realGitDir, "index")) return { state: "default" };
  return { state: "custom", indexFile: realFile };
}
