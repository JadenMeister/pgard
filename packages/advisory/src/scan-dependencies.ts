import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import {
  createFindingFingerprint,
  type AdvisoryDbInfo,
  type AnalyzerOutput,
  type Coverage,
  type Finding,
  type Severity,
} from "@pgard/findings";
import { DEPENDENCY_RULE } from "./rules.js";
import {
  parseGoMod,
  parseGoSum,
  parsePackageLock,
  parsePnpmLock,
  parseYarnLock,
  type LockfileParseResult,
  type ResolvedPackage,
} from "./lockfiles.js";
import {
  firstFixedVersion,
  isVersionAffected,
  loadAdvisoryDb,
  peekAdvisoryDb,
  type Advisory,
  type Ecosystem,
} from "./osv-db.js";
import { isComparableVersion } from "./version.js";

export interface DependencyScanOptions {
  env?: Readonly<Record<string, string | undefined>>;
  now?: () => Date;
  /** Aborting stops between files and while loading the database. */
  signal?: AbortSignal;
}

export interface DependencyScanOutput extends AnalyzerOutput {
  advisoryDb: AdvisoryDbInfo;
}

const SKIPPED = new Set([
  "node_modules",
  "vendor",
  ".git",
  "dist",
  "build",
  "out",
  ".next",
  "coverage",
]);
const MAX_DEPTH = 8;
const MAX_LOCKFILE_BYTES = 64 * 1024 * 1024;
const NPM_LOCKFILES: Record<string, (text: string) => LockfileParseResult> = {
  "package-lock.json": parsePackageLock,
  "npm-shrinkwrap.json": parsePackageLock,
  "pnpm-lock.yaml": parsePnpmLock,
  "yarn.lock": parseYarnLock,
};

interface Manifests {
  npmLockfiles: string[];
  packageJsons: string[];
  goMods: string[];
  goSums: string[];
}

async function findManifests(root: string): Promise<Manifests> {
  const result: Manifests = { npmLockfiles: [], packageJsons: [], goMods: [], goSums: [] };
  const visit = async (directory: string, depth: number) => {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const full = path.join(directory, entry.name);
      const relative = path.relative(root, full).split(path.sep).join("/");
      if (entry.isDirectory()) {
        if (!SKIPPED.has(entry.name) && depth < MAX_DEPTH) await visit(full, depth + 1);
      } else if (entry.isFile()) {
        if (NPM_LOCKFILES[entry.name]) result.npmLockfiles.push(relative);
        else if (entry.name === "package.json") result.packageJsons.push(relative);
        else if (entry.name === "go.mod") result.goMods.push(relative);
        else if (entry.name === "go.sum") result.goSums.push(relative);
      }
    }
  };
  await visit(root, 0);
  return result;
}

/** Reads a manifest after checking its size in bytes (never loads an oversized file). */
async function readManifest(root: string, relative: string): Promise<string | null> {
  try {
    const file = path.join(root, relative);
    if ((await stat(file)).size > MAX_LOCKFILE_BYTES) return null;
    return await readFile(file, "utf8");
  } catch {
    return null;
  }
}

const MAX_LISTED_PATHS = 5;

/** Joins paths for a coverage note, listing at most MAX_LISTED_PATHS of them. */
function listPaths(paths: string[]): string {
  const listed = paths.slice(0, MAX_LISTED_PATHS).join(", ");
  const rest = paths.length - MAX_LISTED_PATHS;
  return rest > 0 ? `${listed} and ${rest} more` : listed;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new Error("aborted");
}

function severityOf(advisory: Advisory): Severity {
  return advisory.severity ?? "medium";
}

function createDependencyFinding(
  lockfile: string,
  pkg: ResolvedPackage,
  advisory: Advisory,
  affected: Advisory["affected"][number],
): Finding {
  const location = {
    kind: "dependency" as const,
    path: lockfile,
    line: null,
    url: null,
    commit: null,
  };
  const cves = advisory.aliases.filter((alias) => /^CVE-\d{4}-\d+$/.test(alias));
  const fixed = firstFixedVersion(affected, pkg.version);
  const summary = advisory.summary ? `: ${advisory.summary.slice(0, 160)}` : "";
  return {
    id: createFindingFingerprint({
      ruleId: DEPENDENCY_RULE.id,
      location,
      cause: `${advisory.id}:${pkg.name}@${pkg.version}`,
    }),
    ruleId: DEPENDENCY_RULE.id,
    title: `${pkg.name}@${pkg.version} has a known advisory (${advisory.id})`,
    category: DEPENDENCY_RULE.category,
    severity: severityOf(advisory),
    status: "confirmed",
    confidence: "high",
    location,
    evidence: `${pkg.ecosystem} ${pkg.name}@${pkg.version} resolved in ${lockfile} matches ${advisory.id}${cves.length > 0 ? ` (${cves.join(", ")})` : ""}${summary}. ${fixed ? `Fixed in ${fixed}.` : "No fixed version listed."} Reachability of the vulnerable code was not analyzed.`,
    impact: DEPENDENCY_RULE.impact,
    recommendation: fixed
      ? `Upgrade ${pkg.name} to ${fixed} or later. ${DEPENDENCY_RULE.recommendation}`
      : DEPENDENCY_RULE.recommendation,
    references: { cwe: [...DEPENDENCY_RULE.cwe], owasp: [...DEPENDENCY_RULE.owasp], cve: cves },
    sources: ["code"],
  };
}

/**
 * Compares resolved versions from npm-family lockfiles and Go modules against a local OSV
 * database. Nothing is installed, executed or sent over the network. Missing, invalid or stale
 * advisory data is recorded in coverage and never treated as "no vulnerabilities".
 */
export async function scanDependencies(
  projectRoot: string,
  options: DependencyScanOptions = {},
): Promise<DependencyScanOutput> {
  const manifests = await findManifests(projectRoot);
  throwIfAborted(options.signal);
  const findings: Finding[] = [];
  const coverage: Coverage[] = [];
  // go.mod vs go.sum is chosen per directory: a module's go.mod lists its selected versions,
  // and a go.sum is only used where no go.mod sits beside it.
  const goModDirectories = new Set(manifests.goMods.map((file) => path.posix.dirname(file)));
  const goFiles = [
    ...manifests.goMods,
    ...manifests.goSums.filter((file) => !goModDirectories.has(path.posix.dirname(file))),
  ];
  // The database is only loaded when there is something to compare (it can be large).
  const hasManifests =
    manifests.npmLockfiles.length > 0 || goFiles.length > 0 || manifests.packageJsons.length > 0;
  const env = options.env ?? process.env;
  const db = hasManifests ? await loadAdvisoryDb(env, options.now, options.signal) : null;
  // Without manifests the database is not needed for matching, but its state is still reported:
  // small databases are read for their metadata; large ones are only checked for presence.
  const peek = db === null ? await peekAdvisoryDb(env, options.now, options.signal) : null;
  const reportedStatus = db?.status ?? peek;
  const advisoryDb: AdvisoryDbInfo = {
    version: reportedStatus?.version ?? null,
    updatedAt: reportedStatus?.updatedAt ?? null,
  };
  const isDbUsable = db !== null && (db.status.status === "ok" || db.status.status === "stale");

  const collect = async (
    files: string[],
    parse: (file: string) => (text: string) => LockfileParseResult,
  ) => {
    const resolved: { file: string; packages: ResolvedPackage[] }[] = [];
    const errors: string[] = [];
    let uncomparable = 0;
    for (const file of files) {
      throwIfAborted(options.signal);
      const text = await readManifest(projectRoot, file);
      if (text === null) {
        errors.push(`${file} could not be read`);
        continue;
      }
      const result = parse(file)(text);
      if (result.error) errors.push(`${file}: ${result.error}`);
      uncomparable += result.uncomparable ?? 0;
      resolved.push({ file, packages: result.packages });
    }
    return { resolved, errors, uncomparable };
  };

  const npm = await collect(
    manifests.npmLockfiles,
    (file) => NPM_LOCKFILES[path.posix.basename(file)] ?? parsePackageLock,
  );
  const go = await collect(goFiles, (file) => (file.endsWith("go.sum") ? parseGoSum : parseGoMod));

  const match = (
    ecosystem: Ecosystem,
    resolved: { file: string; packages: ResolvedPackage[] }[],
  ) => {
    let checked = 0;
    let notComparable = 0;
    for (const { file, packages } of resolved) {
      for (const pkg of packages) {
        if (!isComparableVersion(pkg.version)) {
          notComparable += 1;
          continue;
        }
        checked += 1;
        for (const advisory of db?.index.get(`${ecosystem}\0${pkg.name}`) ?? []) {
          const affected = advisory.affected.find(
            (entry) =>
              entry.ecosystem === ecosystem &&
              entry.name === pkg.name &&
              isVersionAffected(pkg.version, entry),
          );
          if (affected) findings.push(createDependencyFinding(file, pkg, advisory, affected));
        }
      }
    }
    return { checked, notComparable };
  };

  const ecosystemCoverage = (
    area: string,
    label: string,
    files: string[],
    resolved: { file: string; packages: ResolvedPackage[] }[],
    errors: string[],
    extraProblems: string[],
    ecosystem: Ecosystem,
    uncomparable: number,
  ) => {
    if (files.length === 0 && extraProblems.length === 0) {
      coverage.push({
        area,
        scope: "code",
        status: "completed",
        ruleIds: [],
        note: `No ${label} lockfiles found.`,
      });
      return;
    }
    if (!isDbUsable) {
      coverage.push({
        area,
        scope: "code",
        status: "not_tested",
        ruleIds: [DEPENDENCY_RULE.id],
        note: `${label} dependencies were not checked: ${db?.status.note ?? "no advisory data"}`,
      });
      return;
    }
    const { checked, notComparable } = match(ecosystem, resolved);
    const skipped = uncomparable + notComparable;
    const problems = [
      ...errors,
      ...extraProblems,
      ...(skipped > 0
        ? [
            `${skipped} dependency entr${skipped === 1 ? "y" : "ies"} (git, file, link, workspace, local replace or non-registry versions) could not be compared`,
          ]
        : []),
      ...(db?.status.status === "stale" ? [db.status.note] : []),
    ];
    coverage.push({
      area,
      scope: "code",
      status: problems.length > 0 ? "partial" : "completed",
      ruleIds: [DEPENDENCY_RULE.id],
      note: `${checked} resolved ${label} package version(s) from ${files.join(", ") || "no lockfile"} compared with advisory data ${db?.status.version ?? ""}.${problems.length > 0 ? ` ${problems.join("; ")}.` : ""} A version match does not show the vulnerable code is reachable.`,
    });
  };

  // A package.json is covered when an npm-family lockfile sits in its directory or an ancestor
  // directory (workspace packages resolve through the root lockfile). Without one, its resolved
  // versions are unknown, so coverage must not be reported as completed (#114).
  const lockDirectories = [
    ...new Set(manifests.npmLockfiles.map((file) => path.posix.dirname(file))),
  ];
  const uncoveredPackages = manifests.packageJsons.filter((file) => {
    const directory = path.posix.dirname(file);
    return !lockDirectories.some(
      (lockDirectory) =>
        lockDirectory === "." ||
        directory === lockDirectory ||
        directory.startsWith(`${lockDirectory}/`),
    );
  });
  const uncoveredNote =
    uncoveredPackages.length > 0
      ? `package.json without a covering lockfile (${listPaths(uncoveredPackages)}): resolved versions are unknown, so those npm dependencies were not checked`
      : null;
  if (uncoveredNote !== null && manifests.npmLockfiles.length === 0) {
    coverage.push({
      area: "dependencies:npm",
      scope: "code",
      status: "not_tested",
      ruleIds: [DEPENDENCY_RULE.id],
      note: `No npm lockfiles found. ${uncoveredNote}.`,
    });
  } else {
    ecosystemCoverage(
      "dependencies:npm",
      "npm",
      manifests.npmLockfiles,
      npm.resolved,
      npm.errors,
      uncoveredNote !== null ? [uncoveredNote] : [],
      "npm",
      npm.uncomparable,
    );
  }
  ecosystemCoverage(
    "dependencies:go",
    "Go",
    goFiles,
    go.resolved,
    go.errors,
    [],
    "Go",
    go.uncomparable,
  );
  coverage.push(
    db === null
      ? {
          area: "dependencies:advisory-db",
          scope: "code",
          // A database that was only checked cheaply (not fully loaded) is never "completed".
          status:
            peek?.status === "ok" && peek.validated !== false
              ? "completed"
              : peek?.status === "ok" || peek?.status === "stale"
                ? "partial"
                : "not_tested",
          ruleIds: [],
          note: `No dependency manifests found, so no versions were compared. ${peek?.note ?? ""}`.trim(),
        }
      : {
          area: "dependencies:advisory-db",
          scope: "code",
          status:
            db.status.status === "ok"
              ? "completed"
              : db.status.status === "stale"
                ? "partial"
                : "not_tested",
          ruleIds: [DEPENDENCY_RULE.id],
          note: db.status.note,
        },
  );
  return { findings, coverage, advisoryDb };
}
