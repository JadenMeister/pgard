import { lstat, realpath, readdir } from "node:fs/promises";
import path from "node:path";
import type { WebStorage } from "./web-files.js";

/**
 * Search scope of the `pgard web` picker. Roots are decided in the terminal only (`pgard web
 * scope add`), stored in `web/settings.json` and revalidated at every launch. Pure rules with an
 * injectable file-system object, shared by the CLI (prompts, `scope` commands) and the
 * dashboard's inspector.
 */

/** Common development folders under the home folder, used only when they exist. */
export const DEFAULT_SCOPE_FOLDERS: readonly string[] = [
  "code",
  "projects",
  "dev",
  "src",
  "workspace",
  "git",
  "Developer",
];

/** What the picker reads about a file system entry: metadata only, never contents. */
export interface ScopeStat {
  isDirectory: boolean;
  isFile: boolean;
  isSymbolicLink: boolean;
  uid: number;
  mode: number;
  dev: number;
  ino: number;
}

export interface ScopeFs {
  lstat(target: string): Promise<ScopeStat>;
  realpath(target: string): Promise<string>;
  readdir(target: string): Promise<ScopeDirent[]>;
}

export interface ScopeDirent {
  name: string;
  isDirectory: boolean;
  isSymbolicLink: boolean;
}

/** The real file system, with `lstat` (a symlink is reported, never followed). */
export const nodeScopeFs: ScopeFs = {
  async lstat(target) {
    const stat = await lstat(target);
    return {
      isDirectory: stat.isDirectory(),
      isFile: stat.isFile(),
      isSymbolicLink: stat.isSymbolicLink(),
      uid: stat.uid,
      mode: stat.mode,
      dev: stat.dev,
      ino: stat.ino,
    };
  },
  realpath: (target) => realpath(target),
  async readdir(target) {
    const entries = await readdir(target, { withFileTypes: true });
    return entries.map((entry) => ({
      name: entry.name,
      isDirectory: entry.isDirectory(),
      isSymbolicLink: entry.isSymbolicLink(),
    }));
  },
};

export type SafetyProblem = "not_owned_by_you" | "group_or_world_writable";

/**
 * T13: the entry must belong to the current user and have no group or other write bit. The
 * strict rule is never loosened for private-group systems.
 */
export function safetyProblemOf(stat: ScopeStat, uid: number | undefined): SafetyProblem | null {
  if (uid === undefined) return "not_owned_by_you";
  if (stat.uid !== uid) return "not_owned_by_you";
  if ((stat.mode & 0o022) !== 0) return "group_or_world_writable";
  return null;
}

export type RootRejection =
  | "not_absolute"
  | "missing"
  | "not_a_directory"
  | "symlink"
  | "too_shallow"
  | "not_owned_by_you"
  | "group_or_world_writable"
  | "unreadable"
  | "unsupported_platform";

export type RootValidation =
  { ok: true; path: string; dev: number; ino: number } | { ok: false; reason: RootRejection };

/** Path segments below `/` (`/` is 0, `/Users` is 1, `/Users/alice` is 2). */
export function pathDepth(absolutePath: string): number {
  return absolutePath.split("/").filter((segment) => segment.length > 0).length;
}

/**
 * A root must be absolute, exist, be a directory with safe ownership and mode (T13) and be at
 * least two levels deep (so not `/` or `/Users`). It is stored as its `realpath`.
 */
export async function validateSearchRoot(
  rawPath: string,
  fs: ScopeFs,
  uid: number | undefined,
  platform: NodeJS.Platform = process.platform,
): Promise<RootValidation> {
  if (platform === "win32") return { ok: false, reason: "unsupported_platform" };
  if (!path.posix.isAbsolute(rawPath) || rawPath.includes("\0")) {
    return { ok: false, reason: "not_absolute" };
  }
  let resolved: string;
  try {
    resolved = await fs.realpath(rawPath);
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    return {
      ok: false,
      reason: code === "ENOENT" || code === "ENOTDIR" ? "missing" : "unreadable",
    };
  }
  if (pathDepth(resolved) < 2) return { ok: false, reason: "too_shallow" };
  let stat: ScopeStat;
  try {
    stat = await fs.lstat(resolved);
  } catch {
    return { ok: false, reason: "unreadable" };
  }
  if (stat.isSymbolicLink) return { ok: false, reason: "symlink" };
  if (!stat.isDirectory) return { ok: false, reason: "not_a_directory" };
  const problem = safetyProblemOf(stat, uid);
  if (problem !== null) return { ok: false, reason: problem };
  return { ok: true, path: resolved, dev: stat.dev, ino: stat.ino };
}

export interface ScopeRoot {
  path: string;
  dev: number;
  ino: number;
}

export interface LoadedScope {
  roots: ScopeRoot[];
  /** Roots that were dropped for this session, with the reason (reported in the terminal). */
  dropped: Array<{ path: string; reason: RootRejection }>;
  /** `stored`: from `settings.json`; `default`: the default development folders that exist. */
  source: "stored" | "default";
  /** Set when `settings.json` existed but was ignored (damaged, unsafe or from a newer PGARD). */
  settingsIgnored: boolean;
}

/**
 * Roots for this launch: the stored ones when `settings.json` is readable, otherwise the default
 * development folders that exist. Every root is revalidated; an invalid one is dropped for the
 * session and reported, never repaired.
 */
export async function loadSearchScope(options: {
  storage: WebStorage | null;
  fs?: ScopeFs;
  uid: number | undefined;
  homeDir: string;
  platform?: NodeJS.Platform;
}): Promise<LoadedScope> {
  const fs = options.fs ?? nodeScopeFs;
  const read = options.storage === null ? null : await options.storage.readSettings();
  const stored = read?.status === "ok";
  const candidates = stored
    ? read.value.roots
    : path.posix.isAbsolute(options.homeDir)
      ? DEFAULT_SCOPE_FOLDERS.map((name) => path.posix.join(options.homeDir, name))
      : [];
  const roots: ScopeRoot[] = [];
  const dropped: LoadedScope["dropped"] = [];
  for (const candidate of candidates) {
    const checked = await validateSearchRoot(candidate, fs, options.uid, options.platform);
    if (checked.ok) {
      if (!roots.some((root) => root.path === checked.path)) {
        roots.push({ path: checked.path, dev: checked.dev, ino: checked.ino });
      }
    } else if (stored || checked.reason !== "missing") {
      // A default folder that does not exist is simply not offered.
      dropped.push({ path: candidate, reason: checked.reason });
    }
  }
  return {
    roots,
    dropped,
    source: stored ? "stored" : "default",
    settingsIgnored: read?.status === "ignored",
  };
}
