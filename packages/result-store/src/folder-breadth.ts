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
  if (home === null || home === "") return null;
  const resolvedHome = fold(api.resolve(home));
  if (target === resolvedHome) return "home";
  const prefix = target.endsWith(api.sep) ? target : `${target}${api.sep}`;
  return resolvedHome.startsWith(prefix) ? "above_home" : null;
}
