import { statSync } from "node:fs";
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
}

const win = path.win32;

function defaultIsFile(filePath: string): boolean {
  try {
    return statSync(filePath).isFile();
  } catch {
    return false;
  }
}

function isSameOrInside(candidate: string, base: string): boolean {
  const relative = win.relative(win.resolve(base), win.resolve(candidate));
  return relative === "" || (!relative.startsWith("..") && !win.isAbsolute(relative));
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
  const excluded = [options.cwd, options.processCwd ?? process.cwd()].filter(
    (value): value is string => typeof value === "string" && value.length > 0,
  );
  for (const directory of trustedPathEntries(pathValue)) {
    if (excluded.some((base) => isSameOrInside(directory, base))) continue;
    const candidate = win.join(directory, "git.exe");
    if (isFile(candidate)) return candidate;
  }
  return null;
}
