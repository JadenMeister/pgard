import { constants } from "node:fs";
import { open, readdir } from "node:fs/promises";
import path from "node:path";
import { classifyDependencyVendorDirectory } from "@pgard/findings";
import {
  SKIPPED_DEPENDENCY_DIRECTORIES,
  SKIPPED_DIRECTORIES,
  generatedDirectoryReason,
  isVirtualenvDirectory,
} from "@pgard/source-analysis/walk-rules";
import { parseGoMod, parseGoSum } from "./lockfiles/go.js";
import { parseNpmLock } from "./lockfiles/npm.js";
import { parsePnpmLock } from "./lockfiles/pnpm.js";
import { parseYarnLock } from "./lockfiles/yarn.js";
import {
  COLLECT_TIME_BUDGET_MS,
  MAX_LOCKFILE_BYTES,
  MAX_LOCKFILES,
  MAX_MANIFEST_BYTES,
  MAX_MANIFESTS,
  MAX_TOTAL_BYTES,
  MAX_TOTAL_DEPENDENCIES,
  MAX_VISITED_ENTRIES,
} from "./limits.js";
import type {
  Dependency,
  DependencyCollection,
  DependencyCoverage,
  CollectOptions,
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

async function discover(
  root: string,
  budget: Budget,
  maxVisited: number,
  maxLockfiles: number,
): Promise<Discovered> {
  const result: Discovered = { lockfiles: [], unsupported: [], manifests: [], isTruncated: false };
  const stack = [root];
  let visited = 0;
  while (stack.length > 0) {
    // The walk counts against the time budget too, and honours cancellation.
    if (budget.expired()) {
      result.isTruncated = true;
      break;
    }
    const directory = stack.pop() as string;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    // Same rule as the scanner: a Python virtual environment is third-party and not entered.
    if (directory !== root && (await isVirtualenvDirectory(directory, entries))) continue;
    const fileNames = new Set(entries.filter((entry) => entry.isFile()).map((entry) => entry.name));
    for (const entry of entries) {
      visited += 1;
      if (visited > maxVisited) {
        result.isTruncated = true;
        budget.note(
          `The directory walk stopped after ${maxVisited} entries; later files were not found.`,
        );
        return finishDiscovery(result);
      }
      if (entry.isSymbolicLink()) continue; // never followed
      const absolutePath = path.join(directory, entry.name);
      const relativePath = path.relative(root, absolutePath).split(path.sep).join("/");
      if (entry.isDirectory()) {
        if (SKIPPED_DIRECTORIES.has(entry.name)) continue;
        if (SKIPPED_DEPENDENCY_DIRECTORIES.has(entry.name)) continue;
        if (generatedDirectoryReason(entry.name, relativePath, fileNames) !== null) continue;
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
        if (result.lockfiles.length >= maxLockfiles) {
          result.isTruncated = true;
          budget.note(`More than ${maxLockfiles} lockfiles were found; the rest were not read.`);
          continue;
        }
        result.lockfiles.push({ ...found, kind });
      } else if (UNSUPPORTED.has(entry.name)) {
        result.unsupported.push({ ...found, label: UNSUPPORTED.get(entry.name) as string });
      } else if (entry.name === "package.json") {
        if (result.manifests.length < MAX_MANIFESTS) result.manifests.push(found);
        else result.isTruncated = true; // later manifests are not examined
      }
    }
  }
  return finishDiscovery(result);
}

function finishDiscovery(result: Discovered): Discovered {
  result.lockfiles.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  return result;
}

/** Counters shared by every read of one collection run. */
class Budget {
  bytesRead = 0;
  readonly notes: string[] = [];
  /** dev:ino of every file already read, so a hard link to it is not read again. */
  readonly seen = new Map<string, string>();
  private expiredNoted = false;
  private readonly startedAt: number;

  constructor(
    readonly options: CollectOptions,
    readonly maxTotalBytes: number,
  ) {
    this.startedAt = this.now();
  }

  now(): number {
    return (this.options.now ?? Date.now)();
  }

  /** Throws when cancelled; true once the time budget is used up (and says so once). */
  expired(): boolean {
    if (this.options.signal?.aborted === true) {
      throw new DOMException("The dependency collection was cancelled.", "AbortError");
    }
    const limit = this.options.timeBudgetMs ?? COLLECT_TIME_BUDGET_MS;
    const over = this.now() - this.startedAt > limit;
    if (over && !this.expiredNoted) {
      this.expiredNoted = true;
      this.notes.push("The time budget for reading lockfiles ran out; later files were not read.");
    }
    return over;
  }

  note(message: string): void {
    if (!this.notes.includes(message)) this.notes.push(message);
  }
}

type ReadOutcome =
  | { text: string }
  | { error: "too-large" | "unreadable" | "over-budget" }
  | { error: "duplicate"; of: string };

/**
 * Reads a regular file read-only: never follows a symlink (also not one swapped in after the
 * walk), never blocks on a FIFO swapped in, and never reads more than `maxBytes` or more than the
 * run's remaining byte budget. A hard link to a file that was already read (same device and
 * inode) is not read again.
 */
async function readCapped(
  absolutePath: string,
  relativePath: string,
  maxBytes: number,
  budget: Budget,
): Promise<ReadOutcome> {
  let handle;
  try {
    handle = await open(
      absolutePath,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
    );
    const stats = await handle.stat({ bigint: true });
    if (!stats.isFile()) return { error: "unreadable" };
    if (stats.ino !== 0n) {
      const key = `${stats.dev}:${stats.ino}`;
      const first = budget.seen.get(key);
      if (first !== undefined) return { error: "duplicate", of: first };
      budget.seen.set(key, relativePath);
    }
    if (stats.size > BigInt(maxBytes)) return { error: "too-large" };
    const size = Number(stats.size);
    if (budget.bytesRead + size > budget.maxTotalBytes) {
      budget.note(
        `The ${Math.round(budget.maxTotalBytes / (1024 * 1024))} MiB limit on all lockfile data was reached; later files were not read.`,
      );
      return { error: "over-budget" };
    }
    const buffer = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const { bytesRead } = await handle.read(buffer, offset, size - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    budget.bytesRead += offset;
    return { text: buffer.subarray(0, offset).toString("utf8") };
  } catch {
    return { error: "unreadable" };
  } finally {
    await handle?.close().catch(() => undefined);
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
export async function collectDependencies(
  root: string,
  options: CollectOptions = {},
): Promise<DependencyCollection> {
  const limits = {
    totalBytes: options.limits?.totalBytes ?? MAX_TOTAL_BYTES,
    totalDependencies: options.limits?.totalDependencies ?? MAX_TOTAL_DEPENDENCIES,
    lockfileBytes: options.limits?.lockfileBytes ?? MAX_LOCKFILE_BYTES,
    visitedEntries: options.limits?.visitedEntries ?? MAX_VISITED_ENTRIES,
    lockfiles: options.limits?.lockfiles ?? MAX_LOCKFILES,
  };
  const budget = new Budget(options, limits.totalBytes);
  const found = await discover(root, budget, limits.visitedEntries, limits.lockfiles);
  const coverage: DependencyCoverage[] = [];
  const dependencies: Dependency[] = [];
  const seen = new Set<string>();
  let isTruncated = found.isTruncated;
  let entriesCapped = false;

  const manifestNames = new Map<string, Set<string>>();
  /** Manifest content already parsed, by dev:ino path of its first reading (hard links). */
  const manifestByFirstPath = new Map<string, Set<string> | null>();
  for (const manifest of found.manifests) {
    if (budget.expired()) {
      isTruncated = true;
      break;
    }
    const read = await readCapped(
      manifest.absolutePath,
      manifest.relativePath,
      MAX_MANIFEST_BYTES,
      budget,
    );
    if ("error" in read && read.error === "duplicate") {
      const names = manifestByFirstPath.get(read.of);
      if (names !== undefined && names !== null) {
        manifestNames.set(dirOf(manifest.relativePath), names);
        continue;
      }
    }
    const names = "text" in read ? manifestDependencyNames(read.text) : null;
    if ("text" in read) manifestByFirstPath.set(manifest.relativePath, names);
    if (names !== null) {
      manifestNames.set(dirOf(manifest.relativePath), names);
      continue;
    }
    // A manifest that cannot be read cannot be shown to have no dependencies.
    const tooLarge = "error" in read && read.error === "too-large";
    const overBudget = "error" in read && read.error === "over-budget";
    coverage.push({
      path: manifest.relativePath,
      kind: "package.json",
      status: tooLarge ? "too-large" : overBudget ? "not-read" : "failed",
      dependencyCount: 0,
      note: tooLarge
        ? `Larger than ${MAX_MANIFEST_BYTES / (1024 * 1024)} MiB; not read, so its dependencies were not checked.`
        : overBudget
          ? "Not read because a limit on the amount of lockfile data was reached; its dependencies were not checked."
          : "Could not be read or is not a valid package.json; its dependencies were not checked.",
    });
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
    if (budget.expired() || entriesCapped) {
      isTruncated = true;
      coverage.push({
        path: file.relativePath,
        kind: file.kind,
        status: "not-read",
        dependencyCount: 0,
        note: entriesCapped
          ? `Not read: the limit of ${limits.totalDependencies} packages was reached.`
          : "Not read: the time budget for reading lockfiles ran out.",
      });
      continue;
    }
    const read = await readCapped(
      file.absolutePath,
      file.relativePath,
      limits.lockfileBytes,
      budget,
    );
    if ("error" in read) {
      if (read.error === "duplicate") {
        coverage.push({
          path: file.relativePath,
          kind: file.kind,
          status: "duplicate",
          dependencyCount: 0,
          note: `Hard link to ${read.of} (the same file); it was read once, there.`,
        });
        continue;
      }
      if (read.error === "over-budget") isTruncated = true;
      coverage.push({
        path: file.relativePath,
        kind: file.kind,
        status:
          read.error === "too-large"
            ? "too-large"
            : read.error === "over-budget"
              ? "not-read"
              : "failed",
        dependencyCount: 0,
        note:
          read.error === "too-large"
            ? `Larger than ${limits.lockfileBytes / (1024 * 1024)} MiB; not read.`
            : read.error === "over-budget"
              ? "Not read: the limit on the amount of lockfile data was reached."
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
          sum === undefined
            ? null
            : await readCapped(sum.absolutePath, sum.relativePath, limits.lockfileBytes, budget);
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
    let kept = 0;
    let isCut = false;
    for (const dependency of parsed.dependencies) {
      const entry: Dependency = { ...dependency, path: file.relativePath, lockfile: file.kind };
      const id = `${entry.ecosystem}\0${entry.name}\0${entry.version}\0${entry.path}`;
      if (seen.has(id)) continue;
      if (dependencies.length >= limits.totalDependencies) {
        isCut = true;
        entriesCapped = true;
        break;
      }
      seen.add(id);
      dependencies.push(entry);
      kept += 1;
    }
    const notes = [...parsed.notes];
    if (isCut) {
      isTruncated = true;
      notes.push(
        `Only the first ${limits.totalDependencies} packages across all lockfiles were kept; the rest were not checked.`,
      );
      budget.note(`The limit of ${limits.totalDependencies} packages was reached.`);
    }
    if (file.kind === "npm" || file.kind === "pnpm" || file.kind === "yarn") {
      if (parsed.isComplete && !isCut) coveredDirs.push(directory);
    }
    coverage.push({
      path: file.relativePath,
      kind: file.kind,
      status:
        parsed.isComplete && !isCut
          ? "parsed"
          : parsed.dependencies.length > 0
            ? "partial"
            : "failed",
      dependencyCount: kept,
      note: notes.length === 0 ? null : notes.join(" "),
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
  return {
    dependencies,
    coverage,
    isTruncated,
    limitNotes: budget.notes,
    bytesRead: budget.bytesRead,
  };
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
