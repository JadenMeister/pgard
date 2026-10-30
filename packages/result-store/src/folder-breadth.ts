import path from "node:path";

/**
 * Why a folder is too broad to scan as one project (#414): the file-system root, a top-level
 * folder (`/Users`, `/home`, `/Volumes`, `/etc`, `C:\Users`, ...), the home folder, or a folder
 * above it; or a virtual file system (`/proc`, `/sys`, `/dev` at any depth, #427). Shared by
 * `pgard scan code` and the web folder chooser so both refuse the same folders.
 */
export type TooBroadReason = "root" | "top_level" | "home" | "above_home" | "virtual";

export interface FolderBreadthOptions {
  /** `path.posix` in the web chooser's inspector; the platform's own by default. */
  pathApi?: typeof path.posix;
  /** Compare without case (macOS and Windows file systems usually ignore case). */
  ignoreCase?: boolean;
  /** Read Windows spellings (`\\?\C:\`, `\\host\C$\`); by default when `pathApi` is `path.win32`. */
  windows?: boolean;
}

/** `\\?\C:\x` and `\\.\C:\x` are `C:\x`; `\\?\UNC\h\s\x` is `\\h\s\x`. */
function stripWindowsPrefix(value: string): string {
  if (/^[\\/]{2}[?.][\\/]UNC[\\/]/i.test(value)) return `\\\\${value.slice(8)}`;
  if (/^[\\/]{2}[?.][\\/]/.test(value)) return value.slice(4);
  return value;
}

/**
 * The same folder spelled the short way. Windows: the `\\?\` and `\\.\` prefixes are dropped and
 * an administrative share (`\\host\C$\Users\me`, any host) is read as the drive it exposes
 * (`C:\Users\me`). macOS: `/System/Volumes/Data/...` is the firmlinked view of `/...`, so
 * `/System/Volumes/Data/Users/me` is `/Users/me`. Case is folded here.
 */
function canonicalSpelling(
  value: string,
  api: typeof path.posix,
  fold: (text: string) => string,
  windows: boolean,
): string {
  let text = value;
  if (windows) {
    text = stripWindowsPrefix(text);
    const share = /^[\\/]{2}[^\\/]+[\\/]([a-zA-Z])\$(?:[\\/]+(.*))?$/.exec(text);
    if (share !== null) text = `${share[1] ?? ""}:\\${share[2] ?? ""}`;
  }
  const resolved = fold(api.resolve(text));
  // Case-insensitive whatever `fold` does: the firmlink exists on macOS only, where the file
  // system ignores case, and a caller that forgot `ignoreCase` must not be let through.
  const data = "/system/volumes/data";
  const lower = resolved.toLowerCase();
  if (lower === data) return "/";
  if (lower.startsWith(`${data}/`)) return resolved.slice(data.length);
  return resolved;
}

const VIRTUAL_ROOTS = ["/proc", "/sys", "/dev"];

/**
 * Pure: `null` when `folder` may be scanned as a project, or why not. Both paths must already
 * be real paths (symbolic links resolved, as `realpath` returns them), so a linked home folder
 * or a different spelling cannot get past the comparison; the alias spellings that `realpath`
 * keeps (macOS firmlinks, Windows prefixes and admin shares) are read here. `home` is `null`
 * when unknown. `folderBreadthRefusal` adds the identity check.
 */
export function tooBroadToScan(
  folder: string,
  home: string | null,
  options: FolderBreadthOptions = {},
): TooBroadReason | null {
  const api = options.pathApi ?? path;
  const windows = options.windows ?? api === path.win32;
  const fold = (value: string): string =>
    options.ignoreCase === true ? value.toLowerCase() : value;
  const target = canonicalSpelling(folder, api, fold, windows);
  if (!windows && VIRTUAL_ROOTS.some((root) => target === root || target.startsWith(`${root}/`))) {
    return "virtual";
  }
  const root = api.parse(target).root;
  const parts = target
    .slice(root.length)
    .split(api.sep)
    .filter((part) => part.length > 0);
  const depth = parts.length;
  if (depth === 0) return "root";
  if (depth === 1) return "top_level";
  // macOS keeps `/etc`, `/tmp` and `/var` under `/private` (their real paths), so a folder
  // directly in `/private` is top-level too; `/System/Volumes/<volume>` is a volume's top.
  if (depth === 2 && root === "/" && parts[0] === fold("private")) return "top_level";
  if (
    depth <= 3 &&
    root === "/" &&
    parts[0]?.toLowerCase() === "system" &&
    parts[1]?.toLowerCase() === "volumes"
  ) {
    return "top_level";
  }
  if (home === null || home === "") return null;
  const resolvedHome = canonicalSpelling(home, api, fold, windows);
  if (target === resolvedHome) return "home";
  const prefix = target.endsWith(api.sep) ? target : `${target}${api.sep}`;
  return resolvedHome.startsWith(prefix) ? "above_home" : null;
}

/** The identity of a file-system object; `null` when it cannot be read. */
export type FileIdentity = { dev: number | bigint; ino: number | bigint } | null;

export interface FolderBreadthCheckOptions extends FolderBreadthOptions {
  /** `stat` of a path (following links): its device and inode. Injected in tests. */
  identityOf: (target: string) => Promise<FileIdentity>;
}

const sameObject = (a: FileIdentity, b: FileIdentity): boolean =>
  a !== null &&
  b !== null &&
  BigInt(a.ino) !== 0n && // some Windows file systems report no inode
  BigInt(a.dev) === BigInt(b.dev) &&
  BigInt(a.ino) === BigInt(b.ino);

/**
 * `tooBroadToScan` and an identity check (#427): the folder's device and inode are compared with
 * the file-system root, the home folder and each of its ancestors, so an alias the string
 * rules do not know (a firmlink, a bind mount, another spelling) is still refused. `null` when
 * the folder may be scanned.
 */
export async function folderBreadthRefusal(
  folder: string,
  home: string | null,
  options: FolderBreadthCheckOptions,
): Promise<TooBroadReason | null> {
  const known = tooBroadToScan(folder, home, options);
  if (known !== null) return known;
  const api = options.pathApi ?? path;
  const target = await options.identityOf(api.resolve(folder));
  if (target === null) return null;
  const candidates: Array<{ at: string; reason: TooBroadReason }> = [
    { at: api.parse(api.resolve(folder)).root, reason: "root" },
  ];
  if (home !== null && home !== "") {
    let current = api.resolve(home);
    candidates.push({ at: current, reason: "home" });
    for (;;) {
      const parent = api.dirname(current);
      if (parent === current) break;
      candidates.push({ at: parent, reason: "above_home" });
      current = parent;
    }
  }
  for (const candidate of candidates) {
    if (sameObject(target, await options.identityOf(candidate.at))) return candidate.reason;
  }
  return null;
}

/** What `kindOf` answers for a path, without following a symbolic link; `null` when missing. */
export type EntryKind = "file" | "directory" | "other" | null;

export interface GitLayoutOptions {
  /** `path.posix` in the web chooser's inspector; the platform's own by default. */
  pathApi?: typeof path.posix;
}

/** True for a folder that holds a Git directory's own files (`HEAD`, `objects`, `refs`, `config`). */
async function looksLikeGitDirectory(
  folder: string,
  kindOf: (entry: string) => Promise<EntryKind>,
  api: typeof path.posix,
): Promise<boolean> {
  const [head, objects, refs, config] = await Promise.all(
    ["HEAD", "objects", "refs", "config"].map((name) => kindOf(api.join(folder, name))),
  );
  return head === "file" && objects === "directory" && refs === "directory" && config === "file";
}

/**
 * True when `folder` is a Git directory (`.git`, a bare repository) or inside one (#414). Its
 * `config` can hold credentials and its objects are not the current files, so it is never
 * code-only scanned. Shared by `pgard scan code` and the web folder chooser.
 */
export async function isInsideGitDirectory(
  folder: string,
  kindOf: (entry: string) => Promise<EntryKind>,
  options: GitLayoutOptions = {},
): Promise<boolean> {
  const api = options.pathApi ?? path;
  let current = api.resolve(folder);
  for (;;) {
    if (api.basename(current) === ".git" || (await looksLikeGitDirectory(current, kindOf, api))) {
      return true;
    }
    const parent = api.dirname(current);
    if (parent === current) return false;
    current = parent;
  }
}

/**
 * The nearest folder above `folder` (not `folder` itself) that has a `.git` entry, searching up
 * to but not including `stopAt` (the home folder, so a dotfiles repository at home never
 * counts), or `null`. The web chooser scans a folder inside a repository as that repository.
 */
export async function enclosingRepositoryRoot(
  folder: string,
  stopAt: string | null,
  kindOf: (entry: string) => Promise<EntryKind>,
  options: GitLayoutOptions = {},
): Promise<string | null> {
  const api = options.pathApi ?? path;
  const stop = stopAt === null ? null : api.resolve(stopAt);
  let current = api.dirname(api.resolve(folder));
  for (;;) {
    if (current === stop) return null;
    const git = await kindOf(api.join(current, ".git"));
    if (git === "directory" || git === "file") return current;
    const parent = api.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

/**
 * The folder that holds the nearest `.git` entry at or above `folder` (the folder itself first),
 * found without running Git, so a repository's own `core.worktree` can redirect nothing (#427).
 * The search never goes above `stopAt` (the home folder, so a dotfiles repository at home never
 * makes a project folder inside it a repository), but `folder` itself is checked even when it is
 * `stopAt`, so the caller can refuse a repository at home. `null` when there is none.
 */
export async function repositoryRootOf(
  folder: string,
  stopAt: string | null,
  kindOf: (entry: string) => Promise<EntryKind>,
  options: GitLayoutOptions = {},
): Promise<string | null> {
  const api = options.pathApi ?? path;
  const start = api.resolve(folder);
  const own = await kindOf(api.join(start, ".git"));
  if (own === "directory" || own === "file") return start;
  return enclosingRepositoryRoot(start, stopAt, kindOf, options);
}
