import { classifyDependencyVendorDirectory, findVendoredDirectoryIndexes } from "@pgard/findings";

/**
 * Vendored directory names that a package manager restores, so committing them is a hygiene
 * issue. `third_party/` is vendored for grouping but not listed here: it usually holds code
 * copied in on purpose that no package manager restores.
 */
const RESTORABLE_DIRECTORIES: ReadonlySet<string> = new Set([
  "node_modules",
  "bower_components",
  "jspm_packages",
  "vendor",
  "Pods",
]);

/** Empty placeholder files that keep a directory in Git (`rails new` commits `vendor/.keep`). */
const PLACEHOLDER_FILES: ReadonlySet<string> = new Set([".keep", ".gitkeep"]);

/** Directories named in the PG-HYGIENE-001 evidence; the rest are counted. */
export const MAX_LISTED_DEPENDENCY_DIRECTORIES = 5;

export interface CommittedDependencyDirectory {
  /** Repository-relative directory, e.g. `node_modules` or `packages/web/node_modules`. */
  root: string;
  /** Tracked files under it at the scanned revision. */
  fileCount: number;
  /**
   * Set only for the `vendor/` of a Rails importmap app: the loose files directly in it, sorted.
   * The fix lists these files instead of the directory, which also holds the pins.
   */
  looseFiles?: string[];
}

/** Loose `vendor/` files named in the suggested `git rm --cached`; the rest are counted. */
export const MAX_LISTED_LOOSE_FILES = 5;

/**
 * Dependency directories among the tracked file paths at a revision, one entry per root: the
 * outermost flagged vendored directory of each path (`node_modules/a/node_modules/b.js` belongs
 * to `node_modules`). Sorted by file count, largest first. Vendored directories follow
 * `findVendoredDirectoryIndexes` (so `src/vendor/` is first-party code), and of those:
 * - `node_modules/`, `bower_components/`, `jspm_packages/` and `Pods/` are always flagged;
 * - `vendor/` only at the repository root or next to a tracked `composer.json`, `go.mod` or
 *   `Gemfile`, and never for Go module vendoring (a tracked `vendor/modules.txt` next to a
 *   tracked `go.mod`);
 * - `third_party/` never.
 * When an outer directory is not flagged, a flagged one nested inside it still is
 * (`vendor/node_modules/` under Go module vendoring). Placeholder files (`.keep`, `.gitkeep`)
 * are not counted. In a Rails app that uses importmap-rails (a tracked `config/importmap.rb`
 * next to the `vendor/`), the pinned packages in `vendor/javascript/` are committed on purpose
 * and not counted; the other subdirectories are reported one by one (`vendor/bundle`), loose
 * files directly in `vendor/` count toward `vendor` itself (listed in `looseFiles`, so the fix
 * names them instead of the whole `vendor/`), and a dependency directory nested in
 * `vendor/javascript/` (`vendor/javascript/node_modules/`) is still flagged.
 */
export function findCommittedDependencyDirectories(
  trackedPaths: readonly string[],
): CommittedDependencyDirectory[] {
  const tracked = new Set(trackedPaths);
  const isFlaggedCache = new Map<string, boolean>();
  const isFlagged = (root: string): boolean => {
    let flagged = isFlaggedCache.get(root);
    if (flagged === undefined) {
      flagged = isFlaggedRoot(root, tracked);
      isFlaggedCache.set(root, flagged);
    }
    return flagged;
  };
  const counts = new Map<string, number>();
  const looseFiles = new Map<string, string[]>();
  for (const filePath of trackedPaths) {
    const segments = filePath.split("/");
    if (PLACEHOLDER_FILES.has(segments[segments.length - 1] ?? "")) continue;
    const directories = segments.slice(0, -1);
    for (const index of findVendoredDirectoryIndexes(directories)) {
      let root = directories.slice(0, index + 1).join("/");
      if (!isFlagged(root)) continue;
      if (directories[index] === "vendor" && usesImportmap(directories.slice(0, index), tracked)) {
        // Rails importmap pins in vendor/javascript/ are committed on purpose; report the other
        // vendor/ subdirectories (vendor/bundle/) one by one so the suggested `git rm` spares it.
        // Loose files directly in vendor/ still count toward vendor/ itself, and a dependency
        // directory nested in vendor/javascript/ (vendor/javascript/node_modules/) is still found.
        // Loose files are kept by name so the fix never targets the whole vendor/.
        const child = directories[index + 1];
        if (child === "javascript") continue;
        if (child !== undefined) root = `${root}/${child}`;
        else looseFiles.set(root, [...(looseFiles.get(root) ?? []), filePath]);
      }
      counts.set(root, (counts.get(root) ?? 0) + 1);
      break;
    }
  }
  return [...counts.entries()]
    .map(([root, fileCount]): CommittedDependencyDirectory => {
      const loose = looseFiles.get(root);
      return loose === undefined
        ? { root, fileCount }
        : { root, fileCount, looseFiles: loose.sort((a, b) => a.localeCompare(b, "en")) };
    })
    .sort((a, b) => b.fileCount - a.fileCount || a.root.localeCompare(b.root, "en"));
}

/** Whether the Rails app in `appDirectory` (segments; empty for the root) uses importmap-rails. */
function usesImportmap(appDirectory: readonly string[], tracked: ReadonlySet<string>): boolean {
  return tracked.has([...appDirectory, "config", "importmap.rb"].join("/"));
}

function isFlaggedRoot(root: string, tracked: ReadonlySet<string>): boolean {
  const segments = root.split("/");
  const name = segments[segments.length - 1] ?? "";
  if (!RESTORABLE_DIRECTORIES.has(name)) return false;
  if (name !== "vendor") return true;
  const parent = segments.slice(0, -1).join("/");
  const goMod = parent === "" ? "go.mod" : `${parent}/go.mod`;
  if (tracked.has(goMod) && tracked.has(`${root}/modules.txt`)) return false;
  return classifyDependencyVendorDirectory(root, (file) => tracked.has(file)) !== null;
}

/** Evidence and fix text for the single PG-HYGIENE-001 finding. */
export function describeCommittedDependencyDirectories(
  directories: readonly CommittedDependencyDirectory[],
  revision: string,
): { evidence: string; recommendation: string } {
  const listed = directories.slice(0, MAX_LISTED_DEPENDENCY_DIRECTORIES);
  const more = directories.length - listed.length;
  const files = (count: number) => `${count} tracked file${count === 1 ? "" : "s"}`;
  const describe = (entry: CommittedDependencyDirectory) =>
    entry.looseFiles === undefined
      ? `${entry.root}/ (${files(entry.fileCount)})`
      : `${entry.root}/ (${files(entry.fileCount)} directly in it; the importmap pins in ${entry.root}/javascript/ are kept on purpose)`;
  const evidence =
    `${directories.length} dependency director${directories.length === 1 ? "y is" : "ies are"} tracked in commit ${revision.slice(0, 12)}: ` +
    listed.map(describe).join(", ") +
    (more > 0 ? `, and ${more} more` : "");
  const directoryRoots = listed.filter((entry) => entry.looseFiles === undefined);
  const looseFiles = listed.flatMap((entry) => entry.looseFiles ?? []);
  if (looseFiles.length === 0) {
    const roots = directoryRoots.map((entry) => quoteShellWord(entry.root)).join(" ");
    const recommendation =
      `Remove ${listed.length === 1 ? "it" : "them"} from the Git index without deleting the local copy (git rm -r --cached ${roots}), ` +
      `add ${listed.length === 1 ? "the directory" : "the directories"} to .gitignore and commit; ${RESTORE_HINT}`;
    return { evidence, recommendation };
  }
  // Never target a whole importmap vendor/: name its loose files, keeping vendor/javascript/.
  const pinDirectories = listed
    .filter((entry) => entry.looseFiles !== undefined)
    .map((entry) => `${entry.root}/javascript/`)
    .join(", ");
  const namedFiles = looseFiles.slice(0, MAX_LISTED_LOOSE_FILES);
  const moreFiles = looseFiles.length - namedFiles.length;
  const commands = [
    ...(directoryRoots.length > 0
      ? [
          `git rm -r --cached ${directoryRoots.map((entry) => quoteShellWord(entry.root)).join(" ")}`,
        ]
      : []),
    `git rm --cached ${namedFiles.map(quoteShellWord).join(" ")}` +
      (moreFiles > 0 ? ` (and ${moreFiles} more loose file${moreFiles === 1 ? "" : "s"})` : ""),
  ];
  const recommendation =
    `Remove them from the Git index without deleting the local copies (${commands.join("; ")}), ` +
    `add them to .gitignore and commit, keeping the importmap pins in ${pinDirectories} tracked; ${RESTORE_HINT}`;
  return { evidence, recommendation };
}

const RESTORE_HINT =
  "let the package manager restore dependencies instead (npm ci, composer install, bundle install, pod install).";

/** Quotes a path for the suggested shell command when it holds anything but plain characters. */
function quoteShellWord(word: string): string {
  return /^[\w./@+-]+$/.test(word) ? word : `'${word.replace(/'/g, "'\\''")}'`;
}
