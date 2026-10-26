import type {
  Coverage,
  RuleStat,
  ScanScope,
  StandardBreadth,
  StandardCheckState,
  StandardCoverageEntry,
  StandardsCoverage,
} from "./contract.js";
import { CWE_TOP25, OWASP_MAPPED_CWES, OWASP_TOP10_2025 } from "./standards/index.js";
import type { OwaspId } from "./standards/index.js";

/** What the map needs to know about a rule. `RuleDescriptor` fits; web rules are adapted. */
export interface StandardsRule {
  id: string;
  scope: ScanScope;
  metadata: { standards: { owasp: readonly string[]; cwe: readonly string[] } };
}

export interface StandardsCoverageInput {
  /** Every rule of this PGARD version, whether it ran in the scan or not. */
  rules: readonly StandardsRule[];
  coverage: readonly Coverage[];
  ruleStats: readonly RuleStat[];
}

/** Source languages that have an area `source:<language>`; both rule-bearing and detected-only. */
const SOURCE_LANGUAGES = [
  "javascript",
  "typescript",
  "vue",
  "go",
  "java",
  "kotlin",
  "python",
  "php",
] as const;
/** Project-level heuristics read the facts of the JavaScript family only. */
const HEURISTICS_LANGUAGES = ["javascript", "typescript", "vue"];
const HEURISTICS_AREA = "source:heuristics";

function sourceLanguage(area: string): string | null {
  const name = area.startsWith("source:") ? area.slice("source:".length) : "";
  return (SOURCE_LANGUAGES as readonly string[]).includes(name) ? name : null;
}

/** Languages whose files a rule examined in this area. `source:react` adds no language. */
function areaLanguages(area: string): string[] {
  if (area === HEURISTICS_AREA) return HEURISTICS_LANGUAGES;
  const language = sourceLanguage(area);
  return language === null ? [] : [language];
}

/**
 * Languages present in the project: an area with analyzed files (it lists its rules) or one that
 * was detected but has no rules yet (`not_tested`). "No files found" areas do not count.
 */
export function presentLanguages(coverage: readonly Coverage[]): string[] {
  const present = new Set<string>();
  for (const entry of coverage) {
    const language = sourceLanguage(entry.area);
    if (language === null || entry.scope !== "code") continue;
    if (entry.ruleIds.length > 0 || entry.status === "not_tested") present.add(language);
  }
  return SOURCE_LANGUAGES.filter((language) => present.has(language));
}

const list = (ids: readonly string[]): string => ids.join(", ");

/** File count of a language from its coverage note ("3 TypeScript file(s); ..."), if it has one. */
function languageFiles(coverage: readonly Coverage[], language: string): number | null {
  const note = coverage.find((entry) => entry.area === `source:${language}`)?.note ?? null;
  const match = note === null ? null : /(\d+) (?:[A-Za-z]+ )?file\(s\)/.exec(note);
  return match === null ? null : Number(match[1]);
}

function describeLanguage(coverage: readonly Coverage[], language: string): string {
  const files = languageFiles(coverage, language);
  return files === null ? language : `${language} (${files} file${files === 1 ? "" : "s"})`;
}

function whyScopeNotRun(scope: ScanScope, coverage: readonly Coverage[]): string {
  const entries = coverage.filter((entry) => entry.scope === scope);
  return entries.every((entry) => entry.status === "not_selected")
    ? "scope not selected"
    : "areas could not run";
}

/** True when every target the row reports was measured as zero: the rule looked at nothing. */
const examinedNothing = (row: RuleStat): boolean =>
  row.targets.length > 0 && row.targets.every((target) => target.examined === 0);

function judge(
  mapped: readonly StandardsRule[],
  input: StandardsCoverageInput,
  languages: readonly string[],
  unknownRuleIds: readonly string[],
): { state: StandardCheckState; ruleIds: string[]; reason: string } {
  if (mapped.length === 0) return { state: "no_rules", ruleIds: [], reason: "no rules" };
  const mappedIds = new Set(mapped.map((rule) => rule.id));
  const rows = input.ruleStats.filter(
    (row) => mappedIds.has(row.ruleId) && (row.status === "completed" || row.status === "partial"),
  );
  const ruleIds = [...new Set(rows.map((row) => row.ruleId))].sort();
  const mappedScopes = [...new Set(mapped.map((rule) => rule.scope))];
  if (rows.length === 0) {
    const why = mappedScopes.map((scope) => `${scope} ${whyScopeNotRun(scope, input.coverage)}`);
    return {
      state: "not_run",
      ruleIds,
      reason: `no mapped rule ran (${list(mapped.map((rule) => rule.id).sort())}: ${list(why)})`,
    };
  }
  const problems: string[] = [];
  const partialAreas = new Set(
    rows.filter((row) => row.status === "partial").map((row) => row.area),
  );
  // A code area that is partial limits every entry that code rules map to, whether or not the
  // area lists rules (large files, unreadable directories, an ORM that is not analyzed, ...).
  const isCodeEntry = mappedScopes.includes("code");
  if (isCodeEntry) {
    for (const entry of input.coverage) {
      if (entry.scope === "code" && entry.status === "partial") partialAreas.add(entry.area);
    }
  }
  if (partialAreas.size > 0) problems.push(`partial areas: ${list([...partialAreas].sort())}`);
  // A scope that has a mapped rule but ran none of them leaves part of the entry unexamined.
  for (const scope of mappedScopes) {
    if (!rows.some((row) => row.scope === scope)) {
      problems.push(`${scope} rules not run: ${whyScopeNotRun(scope, input.coverage)}`);
    }
  }
  // A rule that looked at nothing proves nothing.
  const idle = ruleIds.filter((id) =>
    rows.filter((row) => row.ruleId === id).every((row) => examinedNothing(row)),
  );
  if (idle.length > 0) problems.push(`examined 0 targets: ${list(idle)}`);
  const completed = rows.filter((row) => row.status === "completed" && !examinedNothing(row));
  // The language dimension applies to entries that code rules map to; history and web rules look
  // at tracked files and the running service whatever the language is.
  if (isCodeEntry) {
    const covered = new Set(
      completed.filter((row) => row.scope === "code").flatMap((row) => areaLanguages(row.area)),
    );
    const gaps = languages.filter((language) => !covered.has(language));
    if (gaps.length > 0) {
      problems.push(
        `no completed mapped rule covers ${list(gaps.map((language) => describeLanguage(input.coverage, language)))} (files that are not yours to scan can be left out with "exclude" in pgard.config.json)`,
      );
    }
  }
  const unknown = unknownRuleIds.length > 0;
  if (unknown) {
    problems.push(
      `rules not in the rule catalog ran (${list(unknownRuleIds)}), so the mapping may be incomplete`,
    );
  }
  if (completed.length > 0 && problems.length === 0) {
    return { state: "rules_ran", ruleIds, reason: "mapped rules ran to completion" };
  }
  return {
    state: "rules_partial",
    ruleIds,
    reason: problems.length > 0 ? problems.join("; ") : "no mapped area ran to completion",
  };
}

/**
 * Derives, per OWASP Top 10 2025 category and CWE Top 25 2025 entry, whether PGARD rules that map
 * to it ran in this scan. Pure: the answer comes from the rule mappings and from what the scan
 * recorded. It never says "safe" or "covered": `rules_ran` only means the mapped rules ran, and
 * `breadth` (OWASP) says how few of the category's CWEs have any rule.
 *
 * "Mapped" means the rule lists the id in its own `standards` (OWASP ids as written, CWE ids
 * exactly; no parent or child CWE is inferred). Advisories and dependency lookups are not rules of
 * a scan and never count. `rules_ran` is withheld, in favour of `rules_partial`, when a contributing
 * area or any code-scope area was partial, a scope with a mapped rule did not run, a language
 * present has no completed mapped rule, a rule looked at 0 targets, or a rule that ran is not in
 * the catalog (fail closed).
 */
export function computeStandardsCoverage(input: StandardsCoverageInput): StandardsCoverage {
  const languages = presentLanguages(input.coverage);
  const catalogIds = new Set(input.rules.map((rule) => rule.id));
  const unknownRuleIds = [
    ...new Set(
      input.ruleStats.filter((row) => !catalogIds.has(row.ruleId)).map((row) => row.ruleId),
    ),
  ].sort();
  const cweWithRules = new Set(input.rules.flatMap((rule) => rule.metadata.standards.cwe));
  const entry = (
    id: string,
    title: string,
    rank: number | null,
    mapped: readonly StandardsRule[],
    breadth: StandardBreadth | null,
  ): StandardCoverageEntry => {
    const judged = judge(mapped, input, languages, unknownRuleIds);
    return {
      id,
      title,
      rank,
      ...judged,
      breadth,
      mappedRuleIds: mapped.map((rule) => rule.id).sort(),
    };
  };
  return {
    owasp: OWASP_TOP10_2025.map((category) => {
      const cwes = OWASP_MAPPED_CWES[category.id as OwaspId];
      return entry(
        category.id,
        category.title,
        null,
        input.rules.filter((rule) => rule.metadata.standards.owasp.includes(category.id)),
        {
          cwesWithRules: cwes.filter((cwe) => cweWithRules.has(cwe)).length,
          cwesInCategory: cwes.length,
        },
      );
    }),
    cweTop25: CWE_TOP25.map((cwe) =>
      entry(
        cwe.id,
        cwe.name,
        cwe.rank,
        input.rules.filter((rule) => rule.metadata.standards.cwe.includes(cwe.id)),
        null,
      ),
    ),
  };
}

export type StandardsCounts = Record<StandardCheckState, number>;

export function countStandardStates(entries: readonly StandardCoverageEntry[]): StandardsCounts {
  const counts: StandardsCounts = { rules_ran: 0, rules_partial: 0, not_run: 0, no_rules: 0 };
  for (const entry of entries) counts[entry.state] += 1;
  return counts;
}
