import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { codeOnlyHome } from "../home-dir.js";

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

/** True when `child` is `parent` itself or lies inside it (lexically). */
export function isInside(child: string, parent: string, platform: NodeJS.Platform): boolean {
  const pathModule = platform === "win32" ? path.win32 : path.posix;
  const relative = pathModule.relative(parent, child);
  return relative === "" || (!relative.startsWith("..") && !pathModule.isAbsolute(relative));
}

/**
 * The value of `XDG_<name>_DIR` in the text of `user-dirs.dirs` (the last definition wins), only
 * when it is simple: `$HOME` at the start followed by `/` or the end, or an absolute path, with no
 * control characters, and lying inside home once normalized.
 */
function xdgDirectory(text: string, name: string, home: string): string | null {
  const pattern = new RegExp(`^\\s*XDG_${name}_DIR\\s*=\\s*"([^"\\n]*)"\\s*$`, "gm");
  let value: string | undefined;
  for (const match of text.matchAll(pattern)) value = match[1];
  if (value === undefined || value === "") return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(value)) return null;
  let expanded = value;
  if (value.startsWith("$HOME")) {
    const rest = value.slice("$HOME".length);
    if (rest !== "" && !rest.startsWith("/")) return null;
    expanded = home + rest;
  }
  if (expanded.includes("$") || !path.posix.isAbsolute(expanded)) return null;
  const normalized = path.posix.normalize(expanded);
  return isInside(normalized, home, "linux") ? normalized : null;
}

/**
 * The home folder used for the default, `~` expansion and the create check: on Windows
 * `USERPROFILE` first, then `HOME`; elsewhere `HOME` first (the same as the code-only path).
 */
export function reportHome(
  env: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform,
): string | null {
  return codeOnlyHome(
    platform === "win32" ? { HOME: env.USERPROFILE, USERPROFILE: env.HOME } : env,
  );
}

/**
 * The folder offered for a saved report: the first existing one of Downloads, Documents and the
 * home folder. `null` only when home is not known.
 */
export async function defaultReportDir(environment: ReportDirEnvironment): Promise<string | null> {
  const { platform, home, isDirectory, readText } = environment;
  if (home === null || home === "") return null;
  const pathModule = platform === "win32" ? path.win32 : path.posix;
  const dirsFile =
    platform === "linux"
      ? await readText(path.posix.join(home, ".config", "user-dirs.dirs"))
      : null;
  const candidates: string[] = [];
  for (const [xdgName, plain] of [
    ["DOWNLOAD", "Downloads"],
    ["DOCUMENTS", "Documents"],
  ] as const) {
    const configured = dirsFile === null ? null : xdgDirectory(dirsFile, xdgName, home);
    if (configured !== null) candidates.push(configured);
    candidates.push(pathModule.join(home, plain));
  }
  for (const candidate of candidates) {
    if (await isDirectory(candidate)) return candidate;
  }
  return home;
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
