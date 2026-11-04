import { lstat, opendir, realpath } from "node:fs/promises";
import path from "node:path";
import type { WebStorage } from "./web-files.js";
import {
  normalizeWindowsPath,
  pathRulesFor,
  windowsPathProblem,
  windowsSystemFolders,
} from "./windows-path.js";

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

/**
 * A device or file id. The real file system reports it as a decimal string (read with
 * `bigint: true`): NTFS file ids use all 64 bits and would lose precision as a JS number, which
 * would weaken the identity re-checks. Tests may use plain numbers. Only compared and hashed.
 */
export type FileId = number | string;

/** What the picker reads about a file system entry: metadata only, never contents. */
export interface ScopeStat {
  isDirectory: boolean;
  isFile: boolean;
  isSymbolicLink: boolean;
  uid: number;
  mode: number;
  dev: FileId;
  ino: FileId;
}

export interface ScopeFs {
  lstat(target: string): Promise<ScopeStat>;
  realpath(target: string): Promise<string>;
  /** At most `limit` entries when given (never the whole of a huge directory). */
  readdir(target: string, limit?: number): Promise<ScopeDirent[]>;
}

export interface ScopeDirent {
  name: string;
  isDirectory: boolean;
  isSymbolicLink: boolean;
}

/** The real file system, with `lstat` (a symlink is reported, never followed). */
export const nodeScopeFs: ScopeFs = {
  async lstat(target) {
    const stat = await lstat(target, { bigint: true });
    return {
      isDirectory: stat.isDirectory(),
      isFile: stat.isFile(),
      isSymbolicLink: stat.isSymbolicLink(),
      uid: Number(stat.uid),
      mode: Number(stat.mode),
      dev: stat.dev.toString(),
      ino: stat.ino.toString(),
    };
  },
  realpath: (target) => realpath(target),
  async readdir(target, limit) {
    const directory = await opendir(target);
    const entries: ScopeDirent[] = [];
    try {
      for await (const entry of directory) {
        entries.push({
          name: entry.name,
          isDirectory: entry.isDirectory(),
          isSymbolicLink: entry.isSymbolicLink(),
        });
        if (limit !== undefined && entries.length >= limit) break;
      }
    } finally {
      await directory.close().catch(() => undefined);
    }
    return entries;
  },
};

export type SafetyProblem = "not_owned_by_you" | "group_or_world_writable";

/**
 * T13: the entry must belong to the current user and have no group or other write bit. The
 * strict rule is never loosened for private-group systems.
 */
export function safetyProblemOf(
  stat: ScopeStat,
  uid: number | undefined,
  platform: string = "posix",
): SafetyProblem | null {
  // Windows reports no owner and no meaningful mode bits; its protection is the path shape and
  // the reparse-point checks (see `windows-path.ts`).
  if (platform === "win32") return null;
  if (uid === undefined) return "not_owned_by_you";
  if (stat.uid !== uid) return "not_owned_by_you";
  if ((stat.mode & 0o022) !== 0) return "group_or_world_writable";
  return null;
}

/**
 * The web chooser's ownership and permission rule for one chosen folder, for `pgard scan
 * --code-only` (#427): every folder from the anchor (the home folder when the folder is inside
 * it, otherwise the highest folder above it that this user owns) down to `target` must be
 * owned by this user with no group or other write bit, and the folder above the anchor must not
 * let another user replace it (writable by others without the sticky bit). A folder that cannot
 * be read is skipped (nothing there can be scanned either). `null` when nothing is wrong.
 */
export async function folderSafetyProblem(
  target: string,
  home: string | null,
  uid: number | undefined,
  lstatOf: (target: string) => Promise<ScopeStat>,
): Promise<{ problem: SafetyProblem; path: string } | null> {
  const api = path.posix;
  let anchor: string;
  if (home !== null && home !== "" && target.startsWith(`${home}/`)) {
    anchor = home;
  } else {
    anchor = target;
    for (;;) {
      const parent = api.dirname(anchor);
      if (parent === "/" || parent === anchor) break;
      try {
        if (uid === undefined || (await lstatOf(parent)).uid !== uid) break;
      } catch {
        break;
      }
      anchor = parent;
    }
  }
  const above = api.dirname(anchor);
  if (above !== anchor) {
    try {
      const aboveStat = await lstatOf(above);
      if ((aboveStat.mode & 0o022) !== 0 && (aboveStat.mode & 0o1000) === 0) {
        return { problem: "group_or_world_writable", path: above };
      }
    } catch {
      // Not readable: nothing can be scanned there either.
    }
  }
  const names = target === anchor ? [] : target.slice(anchor.length + 1).split("/");
  let current = anchor;
  const chain: string[] = [];
  for (const name of names) {
    current = api.join(current, name);
    chain.push(current);
  }
  // The target itself is always checked, even when it is the anchor.
  if (chain.length === 0) chain.push(target);
  for (const entry of chain) {
    let stat: ScopeStat;
    try {
      stat = await lstatOf(entry);
    } catch {
      continue;
    }
    const problem = safetyProblemOf(stat, uid);
    if (problem !== null) return { problem, path: entry };
  }
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
  /** Windows: a network (UNC), device, stream or otherwise rewritten path, or a system folder. */
  | "unsafe_path";

export type RootValidation =
  { ok: true; path: string; dev: FileId; ino: FileId } | { ok: false; reason: RootRejection };

/** Path segments below `/` (`/` is 0, `/Users` is 1, `/Users/alice` is 2). */
export function pathDepth(absolutePath: string, platform: string = "posix"): number {
  const rules = pathRulesFor(platform);
  const root = rules.api.parse(absolutePath).root;
  return absolutePath
    .slice(root.length)
    .split(platform === "win32" ? /[\\/]/ : "/")
    .filter((segment) => segment.length > 0).length;
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
  /** A stored root must already be its own realpath: one that became a symlink is dropped. */
  requireCanonical = false,
  /** Windows only: folders no root may be inside (injected in tests). */
  systemFolders: readonly string[] = platform === "win32" ? windowsSystemFolders(process.env) : [],
): Promise<RootValidation> {
  const rules = pathRulesFor(platform);
  let wanted = rawPath;
  if (platform === "win32") {
    const problem = windowsPathProblem(rawPath);
    if (problem === "not_absolute" || problem === "drive_relative") {
      return { ok: false, reason: "not_absolute" };
    }
    const normalized = problem === null ? normalizeWindowsPath(rawPath) : null;
    if (normalized === null) return { ok: false, reason: "unsafe_path" };
    wanted = normalized;
  } else if (!path.posix.isAbsolute(rawPath) || rawPath.includes("\0")) {
    return { ok: false, reason: "not_absolute" };
  }
  let resolved: string;
  try {
    resolved = await fs.realpath(wanted);
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    return {
      ok: false,
      reason: code === "ENOENT" || code === "ENOTDIR" ? "missing" : "unreadable",
    };
  }
  if (platform === "win32") {
    // A mapped network drive or a junction into a share resolves to a UNC or device path.
    if (windowsPathProblem(resolved) !== null) return { ok: false, reason: "unsafe_path" };
    if (
      systemFolders.some(
        (folder) => rules.fold(resolved) === rules.fold(folder) || rules.isBelow(resolved, folder),
      )
    ) {
      return { ok: false, reason: "unsafe_path" };
    }
  }
  if (requireCanonical && rules.fold(resolved) !== rules.fold(rawPath)) {
    return { ok: false, reason: "symlink" };
  }
  if (pathDepth(resolved, platform) < 2) return { ok: false, reason: "too_shallow" };
  let stat: ScopeStat;
  try {
    stat = await fs.lstat(resolved);
  } catch {
    return { ok: false, reason: "unreadable" };
  }
  if (stat.isSymbolicLink) return { ok: false, reason: "symlink" };
  if (!stat.isDirectory) return { ok: false, reason: "not_a_directory" };
  const problem = safetyProblemOf(stat, uid, platform);
  if (problem !== null) return { ok: false, reason: problem };
  return { ok: true, path: resolved, dev: stat.dev, ino: stat.ino };
}

export interface ScopeRoot {
  path: string;
  dev: FileId;
  ino: FileId;
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

function defaultFolders(homeDir: string, platform: string): string[] {
  const home = platform === "win32" ? normalizeWindowsPath(homeDir) : homeDir;
  if (home === null || !pathRulesFor(platform).api.isAbsolute(home)) return [];
  const api = pathRulesFor(platform).api;
  return DEFAULT_SCOPE_FOLDERS.map((name) => api.join(home, name));
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
    : defaultFolders(options.homeDir, options.platform ?? process.platform);
  const roots: ScopeRoot[] = [];
  const dropped: LoadedScope["dropped"] = [];
  for (const candidate of candidates) {
    const checked = await validateSearchRoot(candidate, fs, options.uid, options.platform, stored);
    if (checked.ok) {
      const fold = pathRulesFor(options.platform ?? process.platform).fold;
      if (!roots.some((root) => fold(root.path) === fold(checked.path))) {
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
