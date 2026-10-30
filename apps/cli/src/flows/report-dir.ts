import { readFile, stat } from "node:fs/promises";
import path from "node:path";

/** What the default-folder lookup needs; tests inject every part. */
export interface ReportDirEnvironment {
  platform: NodeJS.Platform;
  env: Readonly<Record<string, string | undefined>>;
  /** The home folder, or `null` when it is not known. */
  home: string | null;
  isDirectory: (target: string) => Promise<boolean>;
  /** The text of a file, or `null` when it cannot be read. */
  readText: (target: string) => Promise<string | null>;
}

/** The real file system for {@link ReportDirEnvironment}. */
export const realFileAccess = {
  isDirectory: (target: string): Promise<boolean> =>
    stat(target).then(
      (info) => info.isDirectory(),
      () => false,
    ),
  readText: (target: string): Promise<string | null> =>
    readFile(target, "utf8").then(
      (text) => text,
      () => null,
    ),
};

/** `~`, `~/x` (and `~\x` on Windows) become the home folder; anything else is unchanged. */
export function expandHome(typed: string, home: string | null, platform: NodeJS.Platform): string {
  if (home === null || !typed.startsWith("~")) return typed;
  const rest = typed.slice(1);
  if (rest === "") return home;
  if (rest.startsWith("/") || (platform === "win32" && rest.startsWith("\\"))) {
    const pathModule = platform === "win32" ? path.win32 : path.posix;
    return pathModule.join(home, rest.slice(1));
  }
  return typed;
}

/** The value of `XDG_<name>_DIR` in the text of `user-dirs.dirs`, when it is simple. */
function xdgDirectory(text: string, name: string, home: string): string | null {
  const pattern = new RegExp(`^\\s*XDG_${name}_DIR\\s*=\\s*"([^"\\n]*)"\\s*$`, "m");
  const value = pattern.exec(text)?.[1];
  if (value === undefined || value === "") return null;
  const expanded = value.startsWith("$HOME") ? home + value.slice("$HOME".length) : value;
  return path.posix.isAbsolute(expanded) ? expanded : null;
}

/**
 * The folder offered for a saved report: the first existing one of Downloads, Documents and the
 * home folder. `null` only when home is not known.
 */
export async function defaultReportDir(environment: ReportDirEnvironment): Promise<string | null> {
  const { platform, env, home, isDirectory, readText } = environment;
  const profile = platform === "win32" ? env.USERPROFILE?.trim() || home : home;
  if (profile === null || profile === "") return home;
  const pathModule = platform === "win32" ? path.win32 : path.posix;
  const dirsFile =
    platform === "linux"
      ? await readText(path.posix.join(profile, ".config", "user-dirs.dirs"))
      : null;
  const candidates: string[] = [];
  for (const [xdgName, plain] of [
    ["DOWNLOAD", "Downloads"],
    ["DOCUMENTS", "Documents"],
  ] as const) {
    const configured = dirsFile === null ? null : xdgDirectory(dirsFile, xdgName, profile);
    if (configured !== null) candidates.push(configured);
    candidates.push(pathModule.join(profile, plain));
  }
  for (const candidate of candidates) {
    if (await isDirectory(candidate)) return candidate;
  }
  return home ?? profile;
}

/** The folder as the prompt shows it: a place under home is written with a leading `~`. */
export function shownDir(dir: string, home: string | null, platform: NodeJS.Platform): string {
  if (home === null) return dir;
  const pathModule = platform === "win32" ? path.win32 : path.posix;
  const relative = pathModule.relative(home, dir);
  if (relative === "") return "~";
  if (relative.startsWith("..") || pathModule.isAbsolute(relative)) return dir;
  return `~${pathModule.sep}${relative}`;
}
