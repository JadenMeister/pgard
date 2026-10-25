import { findVendoredDirectoryIndexes } from "@pgard/findings";

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

/** Directories named in the PG-HYGIENE-001 evidence; the rest are counted. */
export const MAX_LISTED_DEPENDENCY_DIRECTORIES = 5;

export interface CommittedDependencyDirectory {
  /** Repository-relative directory, e.g. `node_modules` or `packages/web/node_modules`. */
  root: string;
  /** Tracked files under it at the scanned revision. */
  fileCount: number;
}

/** Manifests whose package manager fills a `vendor/` directory next to them. */
const VENDOR_MANIFESTS: readonly string[] = ["composer.json", "go.mod", "Gemfile"];

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
 * (`vendor/node_modules/` under Go module vendoring).
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
  for (const filePath of trackedPaths) {
    const directories = filePath.split("/").slice(0, -1);
    for (const index of findVendoredDirectoryIndexes(directories)) {
      const root = directories.slice(0, index + 1).join("/");
      if (!isFlagged(root)) continue;
      counts.set(root, (counts.get(root) ?? 0) + 1);
      break;
    }
  }
  return [...counts.entries()]
    .map(([root, fileCount]) => ({ root, fileCount }))
    .sort((a, b) => b.fileCount - a.fileCount || a.root.localeCompare(b.root, "en"));
}

function isFlaggedRoot(root: string, tracked: ReadonlySet<string>): boolean {
  const segments = root.split("/");
  const name = segments[segments.length - 1] ?? "";
  if (!RESTORABLE_DIRECTORIES.has(name)) return false;
  if (name !== "vendor") return true;
  const parent = segments.slice(0, -1).join("/");
  const sibling = (file: string) => tracked.has(parent === "" ? file : `${parent}/${file}`);
  if (sibling("go.mod") && tracked.has(`${root}/modules.txt`)) return false;
  return parent === "" || VENDOR_MANIFESTS.some(sibling);
}

/** Evidence and fix text for the single PG-HYGIENE-001 finding. */
export function describeCommittedDependencyDirectories(
  directories: readonly CommittedDependencyDirectory[],
  revision: string,
): { evidence: string; recommendation: string } {
  const listed = directories.slice(0, MAX_LISTED_DEPENDENCY_DIRECTORIES);
  const more = directories.length - listed.length;
  const files = (count: number) => `${count} tracked file${count === 1 ? "" : "s"}`;
  const evidence =
    `${directories.length} dependency director${directories.length === 1 ? "y is" : "ies are"} tracked in commit ${revision.slice(0, 12)}: ` +
    listed.map((entry) => `${entry.root}/ (${files(entry.fileCount)})`).join(", ") +
    (more > 0 ? `, and ${more} more` : "");
  const roots = listed.map((entry) => quoteShellWord(entry.root)).join(" ");
  const recommendation =
    `Remove ${listed.length === 1 ? "it" : "them"} from the Git index without deleting the local copy (git rm -r --cached ${roots}), ` +
    `add ${listed.length === 1 ? "the directory" : "the directories"} to .gitignore and commit; let the package manager restore dependencies instead (npm ci, composer install, pod install).`;
  return { evidence, recommendation };
}

/** Quotes a path for the suggested shell command when it holds anything but plain characters. */
function quoteShellWord(word: string): string {
  return /^[\w./@+-]+$/.test(word) ? word : `'${word.replace(/'/g, "'\\''")}'`;
}
