import path from "node:path";

/**
 * Why a folder is too broad to scan as one project (#414): the file-system root, a top-level
 * folder (`/Users`, `/home`, `/Volumes`, `/etc`, `C:\Users`, ...), the home folder, or a folder
 * above it. Shared by `pgard scan code` and the web folder chooser so both refuse the same
 * folders.
 */
export type TooBroadReason = "root" | "top_level" | "home" | "above_home";

export interface FolderBreadthOptions {
  /** `path.posix` in the web chooser's inspector; the platform's own by default. */
  pathApi?: typeof path.posix;
  /** Compare without case (macOS and Windows file systems usually ignore case). */
  ignoreCase?: boolean;
}

/**
 * Pure: `null` when `folder` may be scanned as a project, or why not. Both paths must already
 * be real paths (symbolic links resolved, as `realpath` returns them), so a linked home folder
 * or a different spelling cannot get past the comparison. `home` is `null` when unknown.
 */
export function tooBroadToScan(
  folder: string,
  home: string | null,
  options: FolderBreadthOptions = {},
): TooBroadReason | null {
  const api = options.pathApi ?? path;
  const fold = (value: string): string =>
    options.ignoreCase === true ? value.toLowerCase() : value;
  const target = fold(api.resolve(folder));
  const root = api.parse(target).root;
  const depth = target
    .slice(root.length)
    .split(api.sep)
    .filter((part) => part.length > 0).length;
  if (depth === 0) return "root";
  if (depth === 1) return "top_level";
  // macOS keeps `/etc`, `/tmp` and `/var` under `/private` (their real paths), so a folder
  // directly in `/private` is top-level too.
  if (depth === 2 && root === "/" && target.startsWith(`${fold("/private")}/`)) return "top_level";
  if (home === null || home === "") return null;
  const resolvedHome = fold(api.resolve(home));
  if (target === resolvedHome) return "home";
  const prefix = target.endsWith(api.sep) ? target : `${target}${api.sep}`;
  return resolvedHome.startsWith(prefix) ? "above_home" : null;
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
