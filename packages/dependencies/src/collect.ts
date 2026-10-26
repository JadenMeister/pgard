import { constants } from "node:fs";
import { open, readdir } from "node:fs/promises";
import path from "node:path";
import { classifyDependencyVendorDirectory } from "@pgard/findings";
import { SKIPPED_DEPENDENCY_DIRECTORIES, SKIPPED_DIRECTORIES } from "@pgard/source-analysis";
import { parseGoMod, parseGoSum } from "./lockfiles/go.js";
import { parseNpmLock } from "./lockfiles/npm.js";
import { parsePnpmLock } from "./lockfiles/pnpm.js";
import { parseYarnLock } from "./lockfiles/yarn.js";
import {
  MAX_LOCKFILE_BYTES,
  MAX_LOCKFILES,
  MAX_MANIFEST_BYTES,
  MAX_MANIFESTS,
  MAX_VISITED_ENTRIES,
} from "./limits.js";
import type {
  Dependency,
  DependencyCollection,
  DependencyCoverage,
  LockfileKind,
  ParsedLockfile,
} from "./types.js";

const SUPPORTED: Record<string, LockfileKind> = {
  "package-lock.json": "npm",
  "npm-shrinkwrap.json": "npm",
  "pnpm-lock.yaml": "pnpm",
  "yarn.lock": "yarn",
  "go.mod": "go.mod",
  "go.sum": "go.sum",
};

/** Lockfiles of ecosystems or package managers PGARD cannot read yet: reported, never "clean". */
const UNSUPPORTED = new Map<string, string>([
  ["bun.lock", "Bun"],
  ["bun.lockb", "Bun"],
  ["Cargo.lock", "Rust (Cargo)"],
  ["composer.lock", "PHP (Composer)"],
  ["Gemfile.lock", "Ruby (Bundler)"],
  ["poetry.lock", "Python (Poetry)"],
  ["Pipfile.lock", "Python (Pipenv)"],
  ["uv.lock", "Python (uv)"],
  ["pdm.lock", "Python (PDM)"],
  ["packages.lock.json", "NuGet"],
  ["mix.lock", "Elixir (Mix)"],
  ["pubspec.lock", "Dart (pub)"],
  ["Package.resolved", "Swift"],
  ["gradle.lockfile", "Gradle"],
  ["Podfile.lock", "CocoaPods"],
]);

interface Found {
  absolutePath: string;
  relativePath: string;
}

interface Discovered {
  lockfiles: (Found & { kind: LockfileKind })[];
  unsupported: (Found & { label: string })[];
  manifests: Found[];
  isTruncated: boolean;
}

async function discover(root: string): Promise<Discovered> {
  const result: Discovered = { lockfiles: [], unsupported: [], manifests: [], isTruncated: false };
  const stack = [root];
  let visited = 0;
  while (stack.length > 0) {
    const directory = stack.pop() as string;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    const fileNames = new Set(entries.filter((entry) => entry.isFile()).map((entry) => entry.name));
    for (const entry of entries) {
      visited += 1;
      if (visited > MAX_VISITED_ENTRIES) {
        result.isTruncated = true;
        return result;
      }
      if (entry.isSymbolicLink()) continue; // never followed
      const absolutePath = path.join(directory, entry.name);
      const relativePath = path.relative(root, absolutePath).split(path.sep).join("/");
      if (entry.isDirectory()) {
        if (SKIPPED_DIRECTORIES.has(entry.name)) continue;
        if (SKIPPED_DEPENDENCY_DIRECTORIES.has(entry.name)) continue;
        if (
          entry.name === "vendor" &&
          classifyDependencyVendorDirectory(relativePath, (filePath) =>
            fileNames.has(path.posix.basename(filePath)),
          ) !== null
        ) {
          continue;
        }
        stack.push(absolutePath);
        continue;
      }
      if (!entry.isFile()) continue;
      const kind = SUPPORTED[entry.name];
      const found = { absolutePath, relativePath };
      if (kind !== undefined) {
        if (result.lockfiles.length >= MAX_LOCKFILES) {
          result.isTruncated = true;
          continue;
        }
        result.lockfiles.push({ ...found, kind });
      } else if (UNSUPPORTED.has(entry.name)) {
        result.unsupported.push({ ...found, label: UNSUPPORTED.get(entry.name) as string });
      } else if (entry.name === "package.json" && result.manifests.length < MAX_MANIFESTS) {
        result.manifests.push(found);
      }
    }
  }
  result.lockfiles.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  return result;
}

type ReadOutcome = { text: string } | { error: "too-large" | "unreadable" };

/** Reads a file read-only without following a symlink swapped in after the walk; size-capped. */
async function readCapped(absolutePath: string, maxBytes: number): Promise<ReadOutcome> {
  let handle;
  try {
    handle = await open(absolutePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const stats = await handle.stat();
    if (!stats.isFile()) return { error: "unreadable" };
    if (stats.size > maxBytes) return { error: "too-large" };
    const buffer = Buffer.alloc(stats.size);
    const { bytesRead } = await handle.read(buffer, 0, stats.size, 0);
    return { text: buffer.subarray(0, bytesRead).toString("utf8") };
  } catch {
    return { error: "unreadable" };
  } finally {
    await handle?.close();
  }
}

function manifestDependencyNames(text: string): Set<string> | null {
  try {
    const value: unknown = JSON.parse(text);
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
    const names = new Set<string>();
    for (const section of [
      "dependencies",
      "devDependencies",
      "optionalDependencies",
      "peerDependencies",
    ]) {
      const entries = (value as Record<string, unknown>)[section];
      if (typeof entries === "object" && entries !== null) {
        for (const name of Object.keys(entries)) names.add(name);
      }
    }
    return names;
  } catch {
    return null;
  }
}

const dirOf = (relativePath: string): string => {
  const slash = relativePath.lastIndexOf("/");
  return slash === -1 ? "" : relativePath.slice(0, slash);
};
const isInside = (directory: string, parent: string): boolean =>
  parent === "" || directory === parent || directory.startsWith(`${parent}/`);

/**
 * Finds every supported lockfile under `root` (the Git root), parses it without running anything,
 * and reports coverage for every file it saw: unsupported lockfiles, oversized or malformed ones,
 * and `package.json` projects with no lockfile. "No dependencies found" is never the same as
 * "no coverage": callers must show `coverage`.
 *
 * Directory rules are the scanner's own: build/cache directories, `node_modules`, dependency
 * `vendor/` directories and symbolic links are never entered.
 */
export async function collectDependencies(root: string): Promise<DependencyCollection> {
  const found = await discover(root);
  const coverage: DependencyCoverage[] = [];
  const dependencies: Dependency[] = [];
  const seen = new Map<string, Dependency>();

  const manifestNames = new Map<string, Set<string>>();
  for (const manifest of found.manifests) {
    const read = await readCapped(manifest.absolutePath, MAX_MANIFEST_BYTES);
    if ("text" in read) {
      const names = manifestDependencyNames(read.text);
      if (names !== null) manifestNames.set(dirOf(manifest.relativePath), names);
    }
  }

  const goSumByDir = new Map(
    found.lockfiles
      .filter((file) => file.kind === "go.sum")
      .map((file) => [dirOf(file.relativePath), file]),
  );
  const goModDirs = new Set(
    found.lockfiles
      .filter((file) => file.kind === "go.mod")
      .map((file) => dirOf(file.relativePath)),
  );
  const coveredDirs: string[] = [];

  for (const file of found.lockfiles) {
    const directory = dirOf(file.relativePath);
    if (file.kind === "go.sum" && goModDirs.has(directory)) {
      continue; // read together with its go.mod
    }
    const read = await readCapped(file.absolutePath, MAX_LOCKFILE_BYTES);
    if ("error" in read) {
      coverage.push({
        path: file.relativePath,
        kind: file.kind,
        status: read.error === "too-large" ? "too-large" : "failed",
        dependencyCount: 0,
        note:
          read.error === "too-large"
            ? `Larger than ${MAX_LOCKFILE_BYTES / (1024 * 1024)} MiB; not read.`
            : "Could not be read.",
      });
      continue;
    }
    let parsed: ParsedLockfile;
    try {
      let goSumText: string | undefined;
      if (file.kind === "go.mod") {
        const sum = goSumByDir.get(directory);
        const sumRead =
          sum === undefined ? null : await readCapped(sum.absolutePath, MAX_LOCKFILE_BYTES);
        goSumText = sumRead !== null && "text" in sumRead ? sumRead.text : undefined;
      }
      parsed = parseOne(
        file.kind,
        read.text,
        file.kind === "yarn" ? declaredNames(directory, manifestNames) : undefined,
        goSumText,
      );
    } catch {
      parsed = { dependencies: [], notes: ["The file could not be parsed."], isComplete: false };
    }
    for (const dependency of parsed.dependencies) {
      const entry: Dependency = { ...dependency, path: file.relativePath };
      const id = `${entry.ecosystem}\0${entry.name}\0${entry.version}\0${entry.path}`;
      if (!seen.has(id)) {
        seen.set(id, entry);
        dependencies.push(entry);
      }
    }
    if (file.kind === "npm" || file.kind === "pnpm" || file.kind === "yarn") {
      if (parsed.isComplete) coveredDirs.push(directory);
    }
    coverage.push({
      path: file.relativePath,
      kind: file.kind,
      status: parsed.isComplete ? "parsed" : parsed.dependencies.length > 0 ? "partial" : "failed",
      dependencyCount: parsed.dependencies.length,
      note: parsed.notes.length === 0 ? null : parsed.notes.join(" "),
    });
  }

  for (const file of found.unsupported) {
    coverage.push({
      path: file.relativePath,
      kind: "unsupported",
      status: "unsupported",
      dependencyCount: 0,
      note: `${file.label} lockfiles are not supported yet; these dependencies were not checked.`,
    });
  }
  // A package.json that declares dependencies but has no readable lockfile at or above it.
  for (const manifest of found.manifests) {
    const directory = dirOf(manifest.relativePath);
    const names = manifestNames.get(directory);
    if (names === undefined || names.size === 0) continue;
    if (coveredDirs.some((covered) => isInside(directory, covered))) continue;
    coverage.push({
      path: manifest.relativePath,
      kind: "package.json",
      status: "missing-lockfile",
      dependencyCount: 0,
      note: "Declares dependencies but no package-lock.json, pnpm-lock.yaml or yarn.lock covers it; its exact versions are unknown and were not checked.",
    });
  }
  coverage.sort((a, b) => a.path.localeCompare(b.path));
  return { dependencies, coverage, isTruncated: found.isTruncated };
}

function parseOne(
  kind: LockfileKind,
  text: string,
  yarnDirectNames: ReadonlySet<string> | undefined,
  goSumText: string | undefined,
): ParsedLockfile {
  switch (kind) {
    case "npm":
      return parseNpmLock(text);
    case "pnpm":
      return parsePnpmLock(text);
    case "yarn":
      return parseYarnLock(text, yarnDirectNames);
    case "go.mod":
      return parseGoMod(text, goSumText);
    case "go.sum":
      return parseGoSum(text);
  }
}

/** Dependency names declared by every package.json at or below `directory` (a yarn workspace). */
function declaredNames(
  directory: string,
  manifestNames: ReadonlyMap<string, Set<string>>,
): Set<string> | undefined {
  const names = new Set<string>();
  let hasManifest = false;
  for (const [manifestDir, set] of manifestNames) {
    if (!isInside(manifestDir, directory)) continue;
    hasManifest = true;
    for (const name of set) names.add(name);
  }
  return hasManifest ? names : undefined;
}
