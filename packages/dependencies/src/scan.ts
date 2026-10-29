import {
  createFindingFingerprint,
  redactEvidence,
  redactLocationPath,
  UNSAFE_DISPLAY_CHARACTERS,
  type Confidence,
  type Coverage,
  type Finding,
  type RuleStat,
  type Severity,
} from "@pgard/findings";
import { collectDependencies } from "./collect.js";
import { matchDependencies, type DependencyMatch, type MatchResult } from "./match/match.js";
import { readAdvisoryStatus, type EcosystemAdvisoryStatus } from "./osv/status.js";
import { OSV_ECOSYSTEMS } from "./osv/update.js";
import { readMeta } from "./osv/store.js";
import { osvDataDir } from "./app-data.js";
import { DEPENDENCY_RULE_ID, listDependencyRules } from "./rules.js";
import type {
  CollectOptions,
  DependencyCollection,
  DependencyCoverage,
  Ecosystem,
  LockfileKind,
} from "./types.js";

export const UPDATE_HINT = "Run `pgard advisories update` to download the OSV data.";

export interface ScanDependenciesOptions {
  /** The per-user data directory (advisory data is read from `<dir>/advisories/osv`). */
  appDataDir: string | null | undefined;
  signal?: AbortSignal;
  now?: () => number;
  /** Repository-relative paths for which this returns true are left out (`pgard.config.json` exclude). */
  isExcluded?: (relativePath: string) => boolean;
  collect?: CollectOptions;
  /** Time budget for reading the advisory data, in ms. */
  matchBudgetMs?: number;
}

export interface DependencyScanOutput {
  findings: Finding[];
  coverage: Coverage[];
  ruleStats: RuleStat[];
}

const ECOSYSTEM_OF_KIND: Record<string, Ecosystem> = {
  npm: "npm",
  pnpm: "npm",
  yarn: "npm",
  "package.json": "npm",
  "go.mod": "Go",
  "go.sum": "Go",
};

const NOT_A_GAP = new Set(["parsed", "duplicate"]);
const ruleIds = [DEPENDENCY_RULE_ID];

const day = (iso: string | null): string => (iso === null ? "unknown date" : iso.slice(0, 10));

function area(
  ecosystem: string,
  status: Coverage["status"],
  note: string,
  withRules = true,
): Coverage {
  return {
    area: `deps:${ecosystem}`,
    scope: "code",
    status,
    ruleIds: withRules ? [...ruleIds] : [],
    note,
  };
}

function cap(items: string[], limit: number): string {
  if (items.length <= limit) return items.join(" ");
  return `${items.slice(0, limit).join(" ")} (+${items.length - limit} more)`;
}

/** What a lockfile line that is not fully understood says, for the area note. */
function gapNotes(lines: readonly DependencyCoverage[]): string[] {
  return lines
    .filter((line) => !NOT_A_GAP.has(line.status))
    .map((line) => `${safe(line.path, 120)}: ${safe(line.note ?? line.status, 300)}`);
}

function describeData(
  status: EcosystemAdvisoryStatus,
  versionTag: string,
  advisories: number,
): string {
  return `OSV data for ${status.ecosystem}: downloaded ${day(status.fetchedAt)}${
    status.ageDays === null ? "" : ` (${status.ageDays} day(s) ago)`
  }, newest record ${day(status.modifiedMax)}, version ${versionTag}, ${advisories} advisories read.`;
}

function confidenceOf(match: DependencyMatch): Confidence {
  // A version match is never proof of impact, so it is never "high". Development-only packages
  // and a standalone go.sum (which lists versions the build may not select) are weaker still.
  if (match.dependency.dev === true) return "low";
  if (match.dependency.lockfile === "go.sum") return "low";
  return "medium";
}

/**
 * Names, versions and paths come from files in the repository (and ids from the advisory data):
 * untrusted text. Control, bidi and zero-width characters become visible `\uXXXX` text and the
 * length is capped, as for every other finding text, so a name cannot spoof a terminal, a report
 * or the dashboard.
 */
const UNSAFE = new RegExp(UNSAFE_DISPLAY_CHARACTERS, "g");
const safe = (text: string, maxLength = 200): string => {
  // Invisible characters become visible `\uXXXX` text (not stripped), so two names that differ
  // only by such a character stay two names with two finding ids. This is done first because
  // `redactSecrets` would drop zero-width characters before they could be marked.
  const marked = text
    .slice(0, maxLength * 4)
    .replace(UNSAFE, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
  const redacted = redactLocationPath(marked) ?? redactEvidence(marked, { maxLength });
  return redacted.length > maxLength ? `${redacted.slice(0, maxLength - 1)}…` : redacted;
};

function findingOf(rawMatch: DependencyMatch): Finding {
  const match: DependencyMatch = {
    ...rawMatch,
    advisoryId: safe(rawMatch.advisoryId, 100),
    aliases: rawMatch.aliases.map((alias) => safe(alias, 100)),
    affectedRange: safe(rawMatch.affectedRange, 200),
    fixedVersions: rawMatch.fixedVersions.map((version) => safe(version, 100)),
    dependency: {
      ...rawMatch.dependency,
      name: safe(rawMatch.dependency.name, 214),
      version: safe(rawMatch.dependency.version, 100),
    },
  };
  const rule = listDependencyRules()[0] as ReturnType<typeof listDependencyRules>[number];
  const { dependency } = match;
  const severity: Severity = match.severity.level ?? "medium";
  const location = {
    kind: "file" as const,
    path: dependency.path,
    line: null,
    url: null,
    commit: null,
  };
  const cves = [match.advisoryId, ...match.aliases].filter((id) => id.startsWith("CVE-"));
  const listedAliases = match.aliases.slice(0, 4);
  const ids =
    match.aliases.length > 0
      ? `${match.advisoryId} (${listedAliases.join(", ")}${match.aliases.length > listedAliases.length ? `, +${match.aliases.length - listedAliases.length} more` : ""})`
      : match.advisoryId;
  const sev =
    match.severity.source === "cvss"
      ? `${severity} (CVSS ${match.severity.score})`
      : match.severity.source === "database"
        ? `${severity} (advisory database label)`
        : "unknown in the advisory (shown as medium)";
  const parts = [
    // First, so the 500-character cap can never cut it off.
    "version-range match only; reachability and exploitability were not checked",
    `${dependency.name}@${dependency.version} (${dependency.ecosystem}) pinned in ${safe(dependency.path, 150)}`,
    `affected version: ${ids}, range ${match.affectedRange}`,
    match.fixedVersions.length > 0
      ? `fixed in ${match.fixedVersions.join(" or ")}`
      : "no fixed version listed",
    `severity ${sev}`,
    dependency.dev === true ? "development-only dependency" : null,
    dependency.direct === true ? "direct" : dependency.direct === false ? "transitive" : null,
  ].filter((part): part is string => part !== null);
  return {
    id: createFindingFingerprint({
      ruleId: DEPENDENCY_RULE_ID,
      location,
      cause: `${dependency.ecosystem}:${dependency.name}@${dependency.version}:${match.advisoryId}`,
    }),
    ruleId: DEPENDENCY_RULE_ID,
    title: rule.title,
    category: rule.category,
    severity,
    status: "suspected",
    confidence: confidenceOf(match),
    location,
    evidence: redactEvidence(parts.join(" | "), { maxLength: 500 }),
    impact: rule.impact,
    recommendation: rule.recommendation,
    references: { cwe: [...rule.cwe], owasp: [...rule.owasp], cve: cves },
    sources: ["code"],
    dependency: {
      ecosystem: dependency.ecosystem,
      name: dependency.name,
      version: dependency.version,
      ...(dependency.dev === true ? { dev: true } : {}),
      ...(dependency.direct === undefined ? {} : { direct: dependency.direct }),
      advisoryId: match.advisoryId,
      aliases: match.aliases,
      affectedRange: match.affectedRange,
      fixedVersions: match.fixedVersions,
      severitySource: match.severity.source,
      ...(match.severity.score === undefined ? {} : { score: match.severity.score }),
      ...(match.severity.vector === undefined ? {} : { vector: safe(match.severity.vector, 200) }),
    },
  };
}

/**
 * The dependency part of the `code` scope: reads the lockfiles (read-only, bounded), matches the
 * pinned versions against the OSV data already on disk (no network, ever) and reports one
 * `deps:<ecosystem>` coverage area per ecosystem that has a lockfile. Missing or damaged data is
 * `not_tested` with a hint; stale data and anything not understood make the area `partial`, so
 * "no findings" is never read as "clean". A match means the version is in the advisory's affected
 * range; it says nothing about reachability or exploitability.
 */
export async function scanDependencies(
  root: string,
  options: ScanDependenciesOptions,
): Promise<DependencyScanOutput> {
  const collected: DependencyCollection = await collectDependencies(root, {
    ...options.collect,
    ...(options.signal ? { signal: options.signal } : {}),
  });
  const excluded = options.isExcluded;
  const isKept = (path: string): boolean => excluded === undefined || !excluded(path);
  const lines = collected.coverage.filter((line) => isKept(line.path));
  const excludedCount = collected.coverage.length - lines.length;
  const dependencies = collected.dependencies.filter((dependency) => isKept(dependency.path));

  const byEcosystem = new Map<Ecosystem, DependencyCoverage[]>();
  const other: DependencyCoverage[] = [];
  for (const line of lines) {
    const ecosystem =
      line.kind === "unsupported" && /^Bun\b/.test(line.note ?? "")
        ? "npm"
        : ECOSYSTEM_OF_KIND[line.kind as LockfileKind | "package.json"];
    if (ecosystem === undefined) other.push(line);
    else byEcosystem.set(ecosystem, [...(byEcosystem.get(ecosystem) ?? []), line]);
  }

  const coverage: Coverage[] = [];
  const findings: Finding[] = [];
  const ruleStats: RuleStat[] = [];
  const now = options.now ?? Date.now;
  const advisoryStatus =
    options.appDataDir === null || options.appDataDir === undefined || byEcosystem.size === 0
      ? null
      : await readAdvisoryStatus(options.appDataDir, now()).catch(() => null);

  for (const ecosystem of OSV_ECOSYSTEMS) {
    const ecosystemLines = byEcosystem.get(ecosystem);
    if (ecosystemLines === undefined) continue;
    const packages = dependencies.filter((dependency) => dependency.ecosystem === ecosystem);
    const lockfileCount = ecosystemLines.filter((line) => line.kind !== "package.json").length;
    const status = advisoryStatus?.ecosystems.find((entry) => entry.ecosystem === ecosystem);
    const where = `${packages.length} package(s) from ${lockfileCount} lockfile(s)`;

    if (options.appDataDir === null || options.appDataDir === undefined) {
      coverage.push(
        area(
          ecosystem,
          "not_tested",
          `No per-user data folder is available, so no OSV advisory data can be read; ${where} were not checked.`,
        ),
      );
      continue;
    }
    if (status === undefined || status.state === "none") {
      coverage.push(
        area(
          ecosystem,
          "not_tested",
          `OSV data for ${ecosystem} has not been downloaded, so ${where} were not checked for known vulnerabilities. ${UPDATE_HINT}`,
        ),
      );
      continue;
    }
    if (status.state === "damaged") {
      coverage.push(
        area(
          ecosystem,
          "not_tested",
          `The stored OSV data for ${ecosystem} is damaged, so ${where} were not checked. Run \`pgard advisories update\` to replace it.`,
        ),
      );
      continue;
    }
    const meta = await readMeta(osvDataDir(options.appDataDir), ecosystem);
    if (meta === null) {
      coverage.push(
        area(
          ecosystem,
          "not_tested",
          `The OSV data for ${ecosystem} could not be read. ${UPDATE_HINT}`,
        ),
      );
      continue;
    }
    let result: MatchResult;
    try {
      result = await matchDependencies(options.appDataDir, meta, packages, {
        ...(options.signal ? { signal: options.signal } : {}),
        ...(options.matchBudgetMs === undefined ? {} : { timeBudgetMs: options.matchBudgetMs }),
        now,
      });
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") throw error;
      coverage.push(
        area(
          ecosystem,
          "not_tested",
          `The stored OSV data for ${ecosystem} could not be verified or read, so ${where} were not checked. Run \`pgard advisories update\` to replace it.`,
        ),
      );
      continue;
    }
    const matchFindings = result.matches.map(findingOf);
    findings.push(...matchFindings);

    const problems: string[] = [];
    const gaps = gapNotes(ecosystemLines);
    if (gaps.length > 0) problems.push(`Not fully understood: ${cap(gaps, 5)}`);
    if (result.notTested.length > 0) {
      const sample = result.notTested
        .slice(0, 3)
        .map((item) => safe(`${item.name}@${item.version}`, 80))
        .join(", ");
      problems.push(
        `${result.notTested.length} package(s) have an advisory but could not be compared (${safe(result.notTested[0]?.reason ?? "", 150)}), e.g. ${sample}.`,
      );
    }
    if (collected.isTruncated) {
      problems.push(
        `A limit was reached: ${collected.limitNotes.join(" ") || "more lockfiles may exist."}`,
      );
    }
    if (result.isIncomplete) problems.push("Reading the advisory data stopped at its time budget.");
    if (status.state === "stale") {
      problems.push(
        `The data is stale (downloaded ${status.ageDays} day(s) ago; newest record ${status.dataAgeDays ?? "unknown"} day(s) old), so recent advisories may be missing. ${UPDATE_HINT.replace("download the OSV data", "refresh it")}`,
      );
    }
    if (packages.length === 0 && ecosystemLines.every((line) => NOT_A_GAP.has(line.status))) {
      problems.push("No packages were found in the lockfiles.");
    }
    const parts = [
      `Checked ${result.stats.packagesChecked} package(s) from ${lockfileCount} lockfile(s) against local OSV data (version ranges only; reachability and exploitability are not checked). ${describeData(status, meta.archive.sha256.slice(0, 12), result.stats.advisoriesRead)}`,
      result.stats.withdrawnSkipped > 0
        ? `${result.stats.withdrawnSkipped} withdrawn advisories were ignored.`
        : null,
      excludedCount > 0 ? `${excludedCount} file(s) excluded by pgard.config.json.` : null,
      // Not partial: it would make every Go project partial for good; the note says what is not covered.
      ecosystem === "Go"
        ? "Go standard library and toolchain advisories are not checked (module versions only)."
        : null,
      ...problems,
    ].filter((part): part is string => part !== null);
    const areaStatus = problems.length > 0 ? "partial" : "completed";
    coverage.push(area(ecosystem, areaStatus, parts.join(" ")));
    ruleStats.push({
      ruleId: DEPENDENCY_RULE_ID,
      area: `deps:${ecosystem}`,
      scope: "code",
      status: areaStatus,
      targets: [{ unit: "packages", examined: result.stats.packagesChecked, reason: null }],
      findings: matchFindings.length,
    });
  }

  if (other.length > 0) {
    const labels = [
      ...new Set(
        other.map(
          (line) => (line.note ?? "").replace(/ lockfiles are not supported.*$/, "") || line.kind,
        ),
      ),
    ];
    coverage.push(
      area(
        "unsupported",
        "partial",
        `${other.length} lockfile(s) of other ecosystems (${labels.slice(0, 5).join(", ")}) are not supported yet; their dependencies were not checked.`,
        false,
      ),
    );
  }
  return { findings, coverage, ruleStats };
}
