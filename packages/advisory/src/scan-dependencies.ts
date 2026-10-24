import { readFile, readdir } from "node:fs/promises";
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
  type Advisory,
  type Ecosystem,
} from "./osv-db.js";

export interface DependencyScanOptions {
  env?: Readonly<Record<string, string | undefined>>;
  now?: () => Date;
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

async function readManifest(root: string, relative: string): Promise<string | null> {
  try {
    const text = await readFile(path.join(root, relative), "utf8");
    return text.length > MAX_LOCKFILE_BYTES ? null : text;
  } catch {
    return null;
  }
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
  const db = await loadAdvisoryDb(options.env ?? process.env, options.now);
  const manifests = await findManifests(projectRoot);
  const findings: Finding[] = [];
  const coverage: Coverage[] = [];
  const advisoryDb: AdvisoryDbInfo = { version: db.status.version, updatedAt: db.status.updatedAt };
  const isDbUsable = db.status.status === "ok" || db.status.status === "stale";

  const collect = async (
    files: string[],
    parse: (file: string) => (text: string) => LockfileParseResult,
  ) => {
    const resolved: { file: string; packages: ResolvedPackage[] }[] = [];
    const errors: string[] = [];
    for (const file of files) {
      const text = await readManifest(projectRoot, file);
      if (text === null) {
        errors.push(`${file} could not be read`);
        continue;
      }
      const result = parse(file)(text);
      if (result.error) errors.push(`${file}: ${result.error}`);
      resolved.push({ file, packages: result.packages });
    }
    return { resolved, errors };
  };

  const npm = await collect(
    manifests.npmLockfiles,
    (file) => NPM_LOCKFILES[path.posix.basename(file)] ?? parsePackageLock,
  );
  const goFiles = manifests.goMods.length > 0 ? manifests.goMods : manifests.goSums;
  const go = await collect(goFiles, (file) => (file.endsWith("go.sum") ? parseGoSum : parseGoMod));

  const match = (
    ecosystem: Ecosystem,
    resolved: { file: string; packages: ResolvedPackage[] }[],
  ) => {
    let checked = 0;
    for (const { file, packages } of resolved) {
      for (const pkg of packages) {
        checked += 1;
        for (const advisory of db.index.get(`${ecosystem}\0${pkg.name}`) ?? []) {
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
    return checked;
  };

  const ecosystemCoverage = (
    area: string,
    label: string,
    files: string[],
    resolved: { file: string; packages: ResolvedPackage[] }[],
    errors: string[],
    extraProblems: string[],
    ecosystem: Ecosystem,
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
        note: `${label} dependencies were not checked: ${db.status.note}`,
      });
      return;
    }
    const checked = match(ecosystem, resolved);
    const problems = [
      ...errors,
      ...extraProblems,
      ...(db.status.status === "stale" ? [db.status.note] : []),
    ];
    coverage.push({
      area,
      scope: "code",
      status: problems.length > 0 ? "partial" : "completed",
      ruleIds: [DEPENDENCY_RULE.id],
      note: `${checked} resolved ${label} package version(s) from ${files.join(", ") || "no lockfile"} compared with advisory data ${db.status.version ?? ""}.${problems.length > 0 ? ` ${problems.join("; ")}.` : ""} A version match does not show the vulnerable code is reachable.`,
    });
  };

  const lockDirectories = new Set(manifests.npmLockfiles.map((file) => path.posix.dirname(file)));
  const unlockedPackages = manifests.packageJsons.filter(
    (file) => !lockDirectories.has(path.posix.dirname(file)) && path.posix.dirname(file) === ".",
  );
  ecosystemCoverage(
    "dependencies:npm",
    "npm",
    manifests.npmLockfiles,
    npm.resolved,
    npm.errors,
    unlockedPackages.length > 0 && manifests.npmLockfiles.length === 0
      ? [
          "package.json without a lockfile: resolved versions are unknown, so npm dependencies were not checked",
        ]
      : [],
    "npm",
  );
  ecosystemCoverage("dependencies:go", "Go", goFiles, go.resolved, go.errors, [], "Go");
  coverage.push({
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
  });
  return { findings, coverage, advisoryDb };
}
