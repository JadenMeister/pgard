import { constants } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import path from "node:path";
import { classifyDependencyVendorDirectory, type DependencyVendorReason } from "@pgard/findings";

export type SourceLanguage = "javascript" | "typescript" | "vue" | "go";

export interface SourceFile {
  /** Absolute path (never reported). */
  absolutePath: string;
  /** Repository-relative POSIX path. */
  relativePath: string;
  language: SourceLanguage;
}

export interface SkippedDependencyDirectory {
  /** Repository-relative POSIX path of the directory, e.g. `node_modules` or `api/vendor`. */
  path: string;
  /** For `vendor/`: the manifest next to it, or `repository root`. */
  reason: DependencyVendorReason | null;
}

export interface WalkResult {
  files: SourceFile[];
  /** Relative paths of manifests used for ORM detection. */
  packageJsonPaths: string[];
  goModPaths: string[];
  skippedLarge: number;
  /** Dependency directories that were not entered, in walk order. */
  skippedDependencyDirectories: SkippedDependencyDirectory[];
  isTruncated: boolean;
}

/** Build output, caches and VCS metadata: never entered, at any depth. */
export const SKIPPED_DIRECTORIES = new Set([
  "dist",
  "build",
  "out",
  ".git",
  ".next",
  ".nuxt",
  ".output",
  ".svelte-kit",
  "coverage",
  ".turbo",
  ".cache",
]);

/** Dependency directories that are never entered, at any depth, and listed in coverage. */
export const SKIPPED_DEPENDENCY_DIRECTORIES = new Set(["node_modules", "bower_components"]);

export const MAX_FILE_BYTES = 1024 * 1024;
export const MAX_FILES = 20_000;

const EXTENSIONS: Record<string, SourceLanguage> = {
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".vue": "vue",
  ".go": "go",
};

/**
 * Lists analyzable source files under `root`, read-only. Skips build/cache directories,
 * `node_modules/` and `bower_components/` anywhere, and a `vendor/` only when it is a dependency
 * directory (`classifyDependencyVendorDirectory`: at the root or next to `composer.json`,
 * `go.mod` or `Gemfile`, never under `src/`, `app/` or `lib/`), so a first-party `src/vendor/`
 * module is analyzed; skipped dependency directories are reported. Also skips
 * symbolic links (never followed), minified bundles, `.d.ts` files and files over 1 MiB.
 */
export async function walkSourceTree(root: string): Promise<WalkResult> {
  const result: WalkResult = {
    files: [],
    packageJsonPaths: [],
    goModPaths: [],
    skippedLarge: 0,
    skippedDependencyDirectories: [],
    isTruncated: false,
  };
  const stack: string[] = [root];
  while (stack.length > 0) {
    const directory = stack.pop() as string;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    // Regular files only: a symlinked composer.json/go.mod/Gemfile is deliberately not trusted, so
    // it cannot hide a first-party vendor/ from analysis.
    const fileNames = new Set(entries.filter((entry) => entry.isFile()).map((entry) => entry.name));
    for (const entry of entries) {
      const absolutePath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      const relativePath = path.relative(root, absolutePath).split(path.sep).join("/");
      if (entry.isDirectory()) {
        if (SKIPPED_DIRECTORIES.has(entry.name)) continue;
        if (SKIPPED_DEPENDENCY_DIRECTORIES.has(entry.name)) {
          result.skippedDependencyDirectories.push({ path: relativePath, reason: null });
          continue;
        }
        if (entry.name === "vendor") {
          // The manifests next to this vendor/ are entries of the current directory.
          const reason = classifyDependencyVendorDirectory(relativePath, (filePath) =>
            fileNames.has(path.posix.basename(filePath)),
          );
          if (reason !== null) {
            result.skippedDependencyDirectories.push({ path: relativePath, reason });
            continue;
          }
        }
        stack.push(absolutePath);
        continue;
      }
      if (!entry.isFile()) continue;
      if (entry.name === "package.json") result.packageJsonPaths.push(relativePath);
      if (entry.name === "go.mod") result.goModPaths.push(relativePath);
      const language = EXTENSIONS[path.extname(entry.name)];
      if (!language || entry.name.endsWith(".d.ts") || /\.min\.(js|mjs|cjs)$/.test(entry.name))
        continue;
      const stats = await lstat(absolutePath).catch(() => null);
      if (!stats || !stats.isFile()) continue;
      if (stats.size > MAX_FILE_BYTES) {
        result.skippedLarge += 1;
        continue;
      }
      if (result.files.length >= MAX_FILES) {
        result.isTruncated = true;
        return result;
      }
      result.files.push({ absolutePath, relativePath, language });
    }
  }
  result.files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  return result;
}

/** Reads a text file read-only; returns `null` for binary content (NUL bytes) or errors. */
export async function readTextFile(
  absolutePath: string,
  maxBytes = MAX_FILE_BYTES,
): Promise<string | null> {
  let handle;
  try {
    // O_NOFOLLOW: a file swapped for a symlink after the directory walk is not followed.
    handle = await open(absolutePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const buffer = Buffer.alloc(maxBytes + 1);
    const { bytesRead } = await handle.read(buffer, 0, maxBytes + 1, 0);
    if (bytesRead > maxBytes) return null;
    const content = buffer.subarray(0, bytesRead);
    if (content.includes(0)) return null;
    return content.toString("utf8");
  } catch {
    return null;
  } finally {
    await handle?.close();
  }
}
