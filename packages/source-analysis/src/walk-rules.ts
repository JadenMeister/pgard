import type { Dirent } from "node:fs";
import { lstat, readdir } from "node:fs/promises";
import path from "node:path";

// Light module (no compiler imports) so other packages can share the walker's ignore rules.

/** Build output, caches and VCS metadata: never entered, at any depth. */
export const SKIPPED_DIRECTORIES: ReadonlySet<string> = new Set([
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
export const SKIPPED_DEPENDENCY_DIRECTORIES: ReadonlySet<string> = new Set([
  "node_modules",
  "bower_components",
]);

/** Why a directory other than `node_modules` was skipped as generated or third-party. */
export type GeneratedDirectoryReason =
  "Python virtual environment" | "Python site-packages" | "Maven build output" | "Gradle cache";

/**
 * `site-packages` is third-party only where Python puts it: under `lib/python3.x/` (or `lib64`).
 * A first-party package that happens to be called `site-packages` is analyzed.
 */
export function isPythonSitePackages(relativePath: string): boolean {
  const segments = relativePath.split("/");
  const [name, parent, grandparent] = [segments.at(-1), segments.at(-2), segments.at(-3)];
  return (
    name === "site-packages" &&
    /^python\d[\d.]*$/i.test(parent ?? "") &&
    /^lib(64)?$/i.test(grandparent ?? "")
  );
}

/**
 * A virtualenv has `pyvenv.cfg` plus an activate script (`bin/activate`, `Scripts/activate`) or a
 * `site-packages` directory (`lib/python3.x/site-packages`, `Lib/site-packages`). An empty
 * `pyvenv.cfg` alone must not hide first-party code.
 */
export async function looksLikeVirtualenv(
  directory: string,
  entries: readonly Dirent[],
): Promise<boolean> {
  const isFile = async (...parts: string[]) =>
    (await lstat(path.join(directory, ...parts)).catch(() => null))?.isFile() === true;
  const isDirectory = async (...parts: string[]) =>
    (await lstat(path.join(directory, ...parts)).catch(() => null))?.isDirectory() === true;
  if ((await isFile("bin", "activate")) || (await isFile("Scripts", "activate"))) return true;
  for (const entry of entries) {
    if (!entry.isDirectory() || !/^lib(64)?$/i.test(entry.name)) continue;
    if (await isDirectory(entry.name, "site-packages")) return true;
    const children = await readdir(path.join(directory, entry.name)).catch(() => [] as string[]);
    for (const child of children) {
      if (/^python\d/i.test(child) && (await isDirectory(entry.name, child, "site-packages"))) {
        return true;
      }
    }
  }
  return false;
}

const GRADLE_FILES = ["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"];

export function generatedDirectoryReason(
  name: string,
  relativePath: string,
  siblingFiles: ReadonlySet<string>,
): GeneratedDirectoryReason | null {
  if (isPythonSitePackages(relativePath)) return "Python site-packages";
  if (name === "target" && siblingFiles.has("pom.xml")) return "Maven build output";
  if (name === ".gradle" && GRADLE_FILES.some((file) => siblingFiles.has(file))) {
    return "Gradle cache";
  }
  return null;
}

/**
 * A directory is a Python virtual environment only if it holds `pyvenv.cfg` (written by
 * `python -m venv` and virtualenv) and the layout of an environment. The name alone proves
 * nothing: `app/venv/server.js` and `Lib/venv/__init__.py` are first-party.
 */
export async function isVirtualenvDirectory(
  directory: string,
  entries: readonly Dirent[],
): Promise<boolean> {
  return (
    entries.some((entry) => entry.name === "pyvenv.cfg" && entry.isFile()) &&
    (await looksLikeVirtualenv(directory, entries))
  );
}
