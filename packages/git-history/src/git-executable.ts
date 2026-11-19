import { existsSync, realpathSync, statSync } from "node:fs";
import path from "node:path";

export interface GitExecutableOptions {
  /** Directory git will run in (the scanned repository). Never searched for `git.exe`. */
  cwd?: string;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  /** The process's own current directory; never searched either. Test hook. */
  processCwd?: string;
  /** Test hook; defaults to a real `stat`. */
  isFile?: (filePath: string) => boolean;
  /** Test hook; defaults to `realpathSync.native`. Throws when the path does not exist. */
  realPath?: (value: string) => string;
  /** Test hook; whether a `.git` entry exists at the path. Defaults to a real check. */
  hasGitEntry?: (value: string) => boolean;
}

const win = path.win32;

function defaultIsFile(filePath: string): boolean {
  try {
    return statSync(filePath).isFile();
  } catch {
    return false;
  }
}

function defaultRealPath(value: string): string {
  return realpathSync.native(value);
}

function defaultHasGitEntry(value: string): boolean {
  return existsSync(win.join(value, ".git"));
}

/**
 * Windows ignores trailing dots and spaces in a path segment (`C:\repo.\bin` is `C:\repo\bin`),
 * so both spellings must compare the same.
 */
function stripTrailingDotsAndSpaces(value: string): string {
  return win
    .normalize(value)
    .split(/[\\/]/)
    .map((segment) =>
      segment === "." || segment === ".." ? segment : segment.replace(/[. ]+$/, ""),
    )
    .join("\\");
}

const comparable = (value: string): string => win.resolve(stripTrailingDotsAndSpaces(value));

/** `value` as it is spelled and as the file system resolves it (junctions, links, 8.3 names). */
function spellings(value: string, realPath: (value: string) => string): string[] {
  const result = [comparable(value)];
  try {
    result.push(comparable(realPath(value)));
  } catch {
    // Not on disk (or not readable): only the written form can be compared.
  }
  return result;
}

function isSameOrInside(candidate: string, base: string): boolean {
  const relative = win.relative(base, candidate);
  return relative === "" || (!relative.startsWith("..") && !win.isAbsolute(relative));
}

/** The nearest folder at or above `start` that holds a `.git` entry, found without running git. */
function repositoryRootAbove(
  start: string,
  hasGitEntry: (value: string) => boolean,
): string | null {
  let current = win.resolve(start);
  for (;;) {
    if (hasGitEntry(current)) return current;
    const parent = win.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

/**
 * The absolute PATH entries a Windows executable search may use: quotes are stripped, empty
 * entries and relative entries (which mean "the current directory") are dropped, and so are
 * entries with characters Windows forbids in paths.
 */
export function trustedPathEntries(pathValue: string): string[] {
  const entries: string[] = [];
  for (const raw of pathValue.split(";")) {
    let entry = raw.trim();
    if (entry.length >= 2 && entry.startsWith('"') && entry.endsWith('"')) {
      entry = entry.slice(1, -1).trim();
    }
    // Drive-absolute only: `C:\x`. Rooted-without-drive (`\x`), `C:x` and UNC paths are refused.
    if (!/^[A-Za-z]:[\\/]/.test(entry) || /["<>|*?\0]/.test(entry)) continue;
    entries.push(win.normalize(entry));
  }
  return entries;
}

/**
 * Resolves the git program to spawn. On Windows, `spawn("git")` searches the child's working
 * directory before PATH (and tries `git.com` before `git.exe`), so a scanned repository holding
 * `git.exe` would run on the first git call. Here PATH is walked by hand instead: only absolute
 * entries that are not inside the repository or the current directory count, and only
 * `git.exe` is accepted (never `.com`, `.cmd` or `.bat`). Returns `null` when none is found.
 * Elsewhere the working directory is not searched, so plain `"git"` is returned.
 */
export function resolveGitExecutable(options: GitExecutableOptions = {}): string | null {
  const platform = options.platform ?? process.platform;
  if (platform !== "win32") return "git";
  const env = options.env ?? process.env;
  const pathValue = env.Path ?? env.PATH ?? env.path ?? "";
  const isFile = options.isFile ?? defaultIsFile;
  const realPath = options.realPath ?? defaultRealPath;
  const hasGitEntry = options.hasGitEntry ?? defaultHasGitEntry;
  const bases = [options.cwd, options.processCwd ?? process.cwd()].filter(
    (value): value is string => typeof value === "string" && value.length > 0,
  );
  // Started from a subfolder: the repository root is excluded too (#211), not only the subfolder.
  const root = options.cwd ? repositoryRootAbove(options.cwd, hasGitEntry) : null;
  if (root !== null) bases.push(root);
  const excluded = bases.flatMap((base) => spellings(base, realPath));
  for (const directory of trustedPathEntries(pathValue)) {
    const entries = spellings(directory, realPath);
    if (entries.some((entry) => excluded.some((base) => isSameOrInside(entry, base)))) continue;
    const candidate = win.join(directory, "git.exe");
    if (isFile(candidate)) return candidate;
  }
  return null;
}
