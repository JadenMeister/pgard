import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import path from "node:path";
import { classifyDependencyVendorDirectory, type DependencyVendorReason } from "@pgard/findings";
import {
  SKIPPED_DEPENDENCY_DIRECTORIES,
  SKIPPED_DIRECTORIES,
  generatedDirectoryReason,
  isVirtualenvDirectory,
  type GeneratedDirectoryReason,
} from "./walk-rules.js";

export type { GeneratedDirectoryReason };

import {
  TREE_SITTER_EXTENSIONS,
  TREE_SITTER_LANGUAGES,
  classifyManifest,
  type ManifestKind,
  type TreeSitterLanguage,
} from "./tree-sitter/languages.js";

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
  reason: DependencyVendorReason | GeneratedDirectoryReason | null;
}

/** A Java, Kotlin, Python or PHP file found by the walk. Not parsed by the walk itself. */
export interface TrackedFile {
  absolutePath: string;
  relativePath: string;
  /** Size in bytes from `lstat`; the parse step enforces the per-file limit with it. */
  size: number;
}

/** A dependency manifest used for framework detection. */
export interface ManifestFile {
  absolutePath: string;
  relativePath: string;
  kind: ManifestKind;
}

export interface WalkResult {
  files: SourceFile[];
  /** Files of the tree-sitter language track, per language. Not counted against `MAX_FILES`. */
  trackFiles: Record<TreeSitterLanguage, TrackedFile[]>;
  trackManifests: ManifestFile[];
  /**
   * `.xml` files that may be MyBatis mapper XML (every `.xml` except `pom.xml`); the scan reads
   * them and keeps only the ones that declare a `<mapper>`. Not counted against `MAX_FILES`.
   */
  xmlFiles: TrackedFile[];
  /**
   * Template files that the Java/Kotlin XSS rule reads (`.jsp`, Thymeleaf `.html`) or reports as
   * not analyzed (FreeMarker, Velocity, Mustache, Pebble); the scan keeps the `.html` files that
   * use Thymeleaf. Not counted against `MAX_FILES`.
   */
  templateFiles: TrackedFile[];
  /** The template list reached its cap (kept apart from `trackTruncated`, which is about source files). */
  templatesTruncated: boolean;
  /** True when a track list reached `MAX_TRACK_FILES` and further files were not listed. */
  trackTruncated: boolean;
  /** Relative paths of manifests used for ORM detection. */
  packageJsonPaths: string[];
  goModPaths: string[];
  /**
   * Analyzable source files (any language track) left out by the project's `exclude` patterns.
   * `digest` is a hash over their paths in walk order, so the set is comparable between scans
   * without listing it. `count` is 0 when no exclusion applies.
   */
  excluded: { count: number; digest: string };
  skippedLarge: number;
  /** Repository-relative paths of minified bundles (`*.min.js`, `*.min.mjs`, `*.min.cjs`) not analyzed. */
  skippedMinified: string[];
  /** Repository-relative paths of every symbolic link (file or directory); never followed. */
  skippedSymlinks: string[];
  /** Repository-relative paths of directories that could not be read ("." is the root). */
  unreadableDirectories: string[];
  /** Dependency directories that were not entered, in walk order. */
  skippedDependencyDirectories: SkippedDependencyDirectory[];
  /**
   * Build-output and cache directories (`dist`, `build`, `out`, `coverage`, ...) that were not
   * entered, as repository-relative paths in walk order. `.git` is not listed.
   */
  skippedBuildDirectories: string[];
  /** `.xml` files under a `res` or `target` path segment that were not checked for MyBatis mappers. */
  skippedResourceXml: string[];
  /**
   * Entries the walk would have analyzed but could not `lstat` (permission error, a file removed
   * during the walk), as repository-relative paths.
   */
  unreadableEntries: string[];
  /** FIFOs, sockets, devices and entries that were no longer regular files; never opened. */
  skippedSpecialFiles: string[];
  isTruncated: boolean;
}

export const MAX_FILE_BYTES = 1024 * 1024;
export const MAX_FILES = 20_000;
/** Cap per tree-sitter language and for manifests. */
export const MAX_TRACK_FILES = 20_000;
export const MAX_TRACK_MANIFESTS = 200;

/** Server-side template files of the Java stack (the XSS rule reads some, reports the rest). */
const TEMPLATE_EXTENSIONS: ReadonlySet<string> = new Set([
  ".jsp",
  ".jspx",
  ".jspf",
  ".tag",
  ".tagx",
  ".html",
  ".htm",
  ".ftl",
  ".ftlh",
  ".ftlx",
  ".vm",
  ".vtl",
  ".mustache",
  ".peb",
  ".pebble",
  ".jte",
]);

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
 * Minified bundles: the file name ends in `.min.js`, `.min.mjs` or `.min.cjs`. Only the naming
 * convention is used (no content sniffing), and these are the names the walk has always skipped.
 */
const MINIFIED_BUNDLE = /\.min\.(js|mjs|cjs)$/;

export interface WalkOptions {
  /**
   * Repository-relative POSIX path of an analyzable source file: true leaves it out (counted in
   * `WalkResult.excluded`). Only files that would be analyzed are asked; skipped directories,
   * symbolic links, declaration files are never listed either way. Minified bundles are asked about too; the ones
   * not excluded are reported in `WalkResult.skippedMinified`.
   */
  isExcluded?: (relativePath: string) => boolean;
}

/**
 * Lists analyzable source files under `root`, read-only. Skips build/cache directories,
 * `node_modules/` and `bower_components/` anywhere, and a `vendor/` only when it is a dependency
 * directory (`classifyDependencyVendorDirectory`: at the root or next to `composer.json`,
 * `go.mod` or `Gemfile`, never under `src/`, `app/` or `lib/`), so a first-party `src/vendor/`
 * module is analyzed; skipped dependency directories are reported. Also skips
 * symbolic links (never followed), minified bundles, `.d.ts` files and files over 1 MiB.
 */
export async function walkSourceTree(root: string, options: WalkOptions = {}): Promise<WalkResult> {
  const excludedHash = createHash("sha256");
  const noteExcluded = (relativePath: string) => {
    result.excluded.count += 1;
    excludedHash.update(`${relativePath}\n`);
  };
  const result: WalkResult = {
    files: [],
    trackFiles: { java: [], kotlin: [], python: [], php: [] },
    trackManifests: [],
    xmlFiles: [],
    templateFiles: [],
    templatesTruncated: false,
    trackTruncated: false,
    packageJsonPaths: [],
    goModPaths: [],
    excluded: { count: 0, digest: "" },
    skippedLarge: 0,
    skippedMinified: [],
    skippedSymlinks: [],
    unreadableDirectories: [],
    skippedDependencyDirectories: [],
    skippedBuildDirectories: [],
    skippedResourceXml: [],
    unreadableEntries: [],
    skippedSpecialFiles: [],
    isTruncated: false,
  };
  /** `lstat` of a file about to be analyzed; failures and non-regular files are counted, not dropped. */
  const statRegular = async (absolutePath: string, relativePath: string) => {
    let stats;
    try {
      stats = await lstat(absolutePath);
    } catch {
      result.unreadableEntries.push(relativePath);
      return null;
    }
    if (!stats.isFile()) {
      result.skippedSpecialFiles.push(relativePath);
      return null;
    }
    return stats;
  };
  const stack: string[] = [root];
  while (stack.length > 0) {
    const directory = stack.pop() as string;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      result.unreadableDirectories.push(
        path.relative(root, directory).split(path.sep).join("/") || ".",
      );
      continue;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    // A directory is a Python virtual environment only if it holds `pyvenv.cfg` (written by
    // `python -m venv` and virtualenv) and the layout of an environment (see looksLikeVirtualenv). The name alone proves nothing: `app/venv/server.js` and
    // `Lib/venv/__init__.py` are first-party. Its contents are third-party and not analyzed.
    if (directory !== root && (await isVirtualenvDirectory(directory, entries))) {
      result.skippedDependencyDirectories.push({
        path: path.relative(root, directory).split(path.sep).join("/"),
        reason: "Python virtual environment",
      });
      continue;
    }
    // Regular files only: a symlinked composer.json/go.mod/Gemfile is deliberately not trusted, so
    // it cannot hide a first-party vendor/ from analysis.
    const fileNames = new Set(entries.filter((entry) => entry.isFile()).map((entry) => entry.name));
    for (const entry of entries) {
      const absolutePath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        result.skippedSymlinks.push(path.relative(root, absolutePath).split(path.sep).join("/"));
        continue;
      }
      const relativePath = path.relative(root, absolutePath).split(path.sep).join("/");
      if (entry.isDirectory()) {
        if (entry.name === ".git") continue;
        if (SKIPPED_DIRECTORIES.has(entry.name)) {
          result.skippedBuildDirectories.push(relativePath);
          continue;
        }
        if (SKIPPED_DEPENDENCY_DIRECTORIES.has(entry.name)) {
          result.skippedDependencyDirectories.push({ path: relativePath, reason: null });
          continue;
        }
        const generated = generatedDirectoryReason(entry.name, relativePath, fileNames);
        if (generated !== null) {
          result.skippedDependencyDirectories.push({ path: relativePath, reason: generated });
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
      if (!entry.isFile()) {
        // FIFO, socket or device: never opened, counted once in a note.
        result.skippedSpecialFiles.push(relativePath);
        continue;
      }
      if (entry.name === "package.json") result.packageJsonPaths.push(relativePath);
      if (entry.name === "go.mod") result.goModPaths.push(relativePath);
      const manifestKind = classifyManifest(entry.name, path.basename(directory));
      if (manifestKind !== null) {
        if (result.trackManifests.length < MAX_TRACK_MANIFESTS) {
          result.trackManifests.push({ absolutePath, relativePath, kind: manifestKind });
        } else {
          result.trackTruncated = true;
        }
        // `setup.py` is both a manifest and Python source, so there is no `continue` here.
      }
      if (path.extname(entry.name) === ".xml" && entry.name !== "pom.xml") {
        // Android resources and build output hold no MyBatis mappers; they are counted, not read.
        const skipped = relativePath.split("/").some((part) => part === "res" || part === "target");
        if (skipped) {
          result.skippedResourceXml.push(relativePath);
          continue;
        }
        const stats = await statRegular(absolutePath, relativePath);
        if (stats) {
          // XML files count against the same file limit as source files.
          if (result.files.length + result.xmlFiles.length >= MAX_FILES) {
            result.isTruncated = true;
            result.trackTruncated = true;
          } else {
            result.xmlFiles.push({ absolutePath, relativePath, size: stats.size });
          }
        }
        continue;
      }
      if (TEMPLATE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
        const stats = await statRegular(absolutePath, relativePath);
        if (stats) {
          if (result.templateFiles.length >= MAX_TRACK_FILES) result.templatesTruncated = true;
          else result.templateFiles.push({ absolutePath, relativePath, size: stats.size });
        }
        continue;
      }
      const trackLanguage = TREE_SITTER_EXTENSIONS[path.extname(entry.name)];
      if (trackLanguage) {
        if (options.isExcluded?.(relativePath)) {
          noteExcluded(relativePath);
          continue;
        }
        const stats = await statRegular(absolutePath, relativePath);
        if (!stats) continue;
        const list = result.trackFiles[trackLanguage];
        if (list.length >= MAX_TRACK_FILES) result.trackTruncated = true;
        else list.push({ absolutePath, relativePath, size: stats.size });
        continue;
      }
      const language = EXTENSIONS[path.extname(entry.name)];
      if (!language || entry.name.endsWith(".d.ts")) continue;
      // The user's exclude comes first: an excluded minified bundle is counted as excluded, so an
      // exclude pattern clears the partial `source:minified` area.
      if (options.isExcluded?.(relativePath)) {
        noteExcluded(relativePath);
        continue;
      }
      if (MINIFIED_BUNDLE.test(entry.name)) {
        result.skippedMinified.push(relativePath);
        continue;
      }
      const stats = await statRegular(absolutePath, relativePath);
      if (!stats) continue;
      if (stats.size > MAX_FILE_BYTES) {
        result.skippedLarge += 1;
        continue;
      }
      if (result.files.length >= MAX_FILES) {
        result.isTruncated = true;
        // The walk stopped early, so the track lists are lower bounds too.
        result.trackTruncated = true;
        finishTrack(result);
        result.excluded.digest = excludedHash.digest("hex").slice(0, 16);
        return result;
      }
      result.files.push({ absolutePath, relativePath, language });
    }
  }
  finishTrack(result);
  result.excluded.digest = excludedHash.digest("hex").slice(0, 16);
  result.files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  return result;
}

function finishTrack(result: WalkResult): void {
  for (const language of TREE_SITTER_LANGUAGES) {
    result.trackFiles[language].sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  }
  result.trackManifests.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  result.xmlFiles.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  result.templateFiles.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
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
