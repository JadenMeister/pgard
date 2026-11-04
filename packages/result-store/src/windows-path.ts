import path from "node:path";

/**
 * Path rules for the web folder chooser and its search scope on Windows (#477). Pure and
 * platform-independent: the platform is passed in, so every rule is tested on every OS.
 *
 * Windows has no user id or mode bits to check, so the equivalent protection is in the shape of
 * the path: only a local drive path is accepted (`C:\folder`). Network (UNC) and device
 * namespaces, drive-relative paths, alternate data streams and the names Windows rewrites or
 * hides (trailing dots and spaces, reserved device names) are refused before any file system
 * call, and the result of `realpath` is checked again (a mapped network drive resolves to a UNC
 * path, a junction or symbolic link resolves to its target).
 */

export type WindowsPathProblem =
  /** `\\server\share`: a network share. */
  | "unc"
  /** `\\?\C:\x`, `\\.\pipe`, `//?/`, `\??\`: the device namespace. */
  | "device"
  /** `C:folder` (relative to the drive's current folder) or `\folder` (relative to the drive). */
  | "drive_relative"
  | "not_absolute"
  /** `C:\file:stream`: an alternate data stream (or any colon after the drive). */
  | "stream"
  /** A name ending in a dot or a space, which Windows silently drops: `C:\code\app.` is `C:\code\app`. */
  | "trailing"
  /** `CON`, `NUL`, `COM1`, ... (also with an extension). */
  | "reserved"
  /** A character Windows does not allow in a name (`<>"|?*`) or a control character. */
  | "invalid_char";

const RESERVED_NAME =
  /^(?:con|prn|aux|nul|conin\$|conout\$|clock\$|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3])$/i;

/** Why one path segment is not a name Windows would keep as written, or `null`. */
export function windowsNameProblem(name: string): WindowsPathProblem | null {
  if (name === "." || name === "..") return null;
  // eslint-disable-next-line no-control-regex
  if (/[<>"|?*\u0000-\u001f]/.test(name)) return "invalid_char";
  if (name.includes(":")) return "stream";
  if (/[. ]$/.test(name)) return "trailing";
  // Windows ignores spaces before the extension and the extension itself: `nul .txt` is `nul`.
  if (RESERVED_NAME.test((name.split(".")[0] ?? "").trimEnd())) return "reserved";
  return null;
}

/**
 * Why `value` is not a plain absolute local-drive path (`C:\a\b`, `C:/a/b`), or `null`. Checked on
 * the text as written, before `normalize` could hide a `..` or a doubled separator.
 */
export function windowsPathProblem(value: string): WindowsPathProblem | null {
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f]/.test(value)) return "invalid_char";
  if (/^[\\/]{2}[?.]/.test(value) || /^\\\?\?\\/.test(value)) return "device";
  if (/^[\\/]{2}/.test(value)) return "unc";
  if (/^[\\/]/.test(value)) return "drive_relative";
  if (!/^[A-Za-z]:/.test(value)) return "not_absolute";
  if (!/^[A-Za-z]:[\\/]/.test(value)) return "drive_relative";
  for (const name of value.slice(3).split(/[\\/]+/)) {
    if (name.length === 0) continue;
    const problem = windowsNameProblem(name);
    if (problem !== null) return problem;
  }
  return null;
}

/** `C:\` or `C:/` at the start: the spelling of a local Windows path in any stored text. */
export function isWindowsDrivePath(value: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(value);
}

/**
 * `path.win32.normalize` with the trailing separator dropped (except on a drive root), or
 * `null` when the text is not a plain local-drive path.
 */
export function normalizeWindowsPath(value: string): string | null {
  if (windowsPathProblem(value) !== null) return null;
  const normalized = path.win32.normalize(value);
  const stripped = normalized.replace(/[\\/]+$/, "");
  const result = /^[A-Za-z]:$/.test(stripped) ? `${stripped}\\` : stripped;
  // `..` may have been collapsed into something new: check the result the same way.
  return windowsPathProblem(result) === null ? result : null;
}

/**
 * The path functions and comparison rules of one platform. The picker's file-system checks and
 * its string handling both take it, so nothing assumes `/`.
 */
export interface PathRules {
  windows: boolean;
  api: typeof path.posix;
  sep: string;
  /** Case folding for comparisons: Windows file systems are case-insensitive. */
  fold(text: string): string;
  /** `child` is by name strictly below `parent`. */
  isBelow(child: string, parent: string): boolean;
  /** The last name of an absolute path. */
  lastName(value: string): string;
}

const POSIX_RULES: PathRules = {
  windows: false,
  api: path.posix,
  sep: "/",
  fold: (text) => text,
  isBelow: (child, parent) => child.startsWith(parent.endsWith("/") ? parent : `${parent}/`),
  lastName: (value) => value.split("/").at(-1) ?? "",
};

const WINDOWS_RULES: PathRules = {
  windows: true,
  api: path.win32 as unknown as typeof path.posix,
  sep: "\\",
  fold: (text) => text.toLowerCase(),
  isBelow: (child, parent) => {
    const base = parent.toLowerCase();
    return child.toLowerCase().startsWith(base.endsWith("\\") ? base : `${base}\\`);
  },
  lastName: (value) => value.split(/[\\/]/).at(-1) ?? "",
};

export function pathRulesFor(platform: string): PathRules {
  return platform === "win32" ? WINDOWS_RULES : POSIX_RULES;
}

/**
 * Folders under which a project is never chosen on Windows: the operating system and the
 * program folders. On POSIX the ownership rule refuses `/usr/lib/x`; Windows has no such check
 * in Node, so these are named. Drawn from the environment (a plain drive path only), with the
 * default spellings as a floor.
 */
export function windowsSystemFolders(env: Readonly<Record<string, string | undefined>>): string[] {
  const folders = new Set<string>();
  const add = (value: string | undefined): void => {
    if (value === undefined || value.includes("..")) return;
    const normalized = normalizeWindowsPath(value);
    if (normalized !== null) folders.add(normalized);
  };
  add(env.SystemRoot ?? env.SYSTEMROOT ?? env.windir);
  add(env.ProgramFiles ?? env.PROGRAMFILES);
  add(env["ProgramFiles(x86)"] ?? env["PROGRAMFILES(X86)"]);
  add(env.ProgramW6432);
  add(env.ProgramData ?? env.PROGRAMDATA);
  for (const fallback of [
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
  ]) {
    folders.add(fallback);
  }
  return [...folders];
}
