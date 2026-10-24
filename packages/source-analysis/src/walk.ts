import { lstat, open, readdir } from "node:fs/promises";
import path from "node:path";

export type SourceLanguage = "javascript" | "typescript" | "vue" | "go";

export interface SourceFile {
  /** Absolute path (never reported). */
  absolutePath: string;
  /** Repository-relative POSIX path. */
  relativePath: string;
  language: SourceLanguage;
}

export interface WalkResult {
  files: SourceFile[];
  /** Relative paths of manifests used for ORM detection. */
  packageJsonPaths: string[];
  goModPaths: string[];
  skippedLarge: number;
  isTruncated: boolean;
}

export const SKIPPED_DIRECTORIES = new Set([
  "node_modules",
  "vendor",
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
  "bower_components",
]);

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
 * Lists analyzable source files under `root`, read-only. Skips dependency/build directories,
 * symbolic links (never followed), minified bundles, `.d.ts` files and files over 1 MiB.
 */
export async function walkSourceTree(root: string): Promise<WalkResult> {
  const result: WalkResult = {
    files: [],
    packageJsonPaths: [],
    goModPaths: [],
    skippedLarge: 0,
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
    for (const entry of entries) {
      const absolutePath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRECTORIES.has(entry.name)) stack.push(absolutePath);
        continue;
      }
      if (!entry.isFile()) continue;
      const relativePath = path.relative(root, absolutePath).split(path.sep).join("/");
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
    handle = await open(absolutePath, "r");
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
