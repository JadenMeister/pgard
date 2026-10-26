import type {
  Coverage,
  RuleStat,
  ScanScope,
  StandardCheckState,
  StandardCoverageEntry,
  StandardsCoverage,
} from "./contract.js";
import { CWE_TOP25, OWASP_TOP10_2025 } from "./standards/index.js";

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

function whyNotRun(mapped: readonly StandardsRule[], coverage: readonly Coverage[]): string {
  const scopes = [...new Set(mapped.map((rule) => rule.scope))];
  const entries = coverage.filter((entry) => scopes.includes(entry.scope));
  const reason =
    entries.length > 0 && entries.every((entry) => entry.status === "not_selected")
      ? `${scopes.join("/")} scope not selected`
      : "their areas were not selected or could not run";
  return `no mapped rule ran (${list(mapped.map((rule) => rule.id).sort())}: ${reason})`;
}

function judge(
  mapped: readonly StandardsRule[],
  input: StandardsCoverageInput,
  languages: readonly string[],
): { state: StandardCheckState; ruleIds: string[]; reason: string } {
  if (mapped.length === 0) return { state: "not_checked", ruleIds: [], reason: "no rules" };
  const mappedIds = new Set(mapped.map((rule) => rule.id));
  const rows = input.ruleStats.filter(
    (row) => mappedIds.has(row.ruleId) && (row.status === "completed" || row.status === "partial"),
  );
  const ruleIds = [...new Set(rows.map((row) => row.ruleId))].sort();
  if (rows.length === 0) {
    return { state: "not_checked", ruleIds, reason: whyNotRun(mapped, input.coverage) };
  }
  const partialAreas = [
    ...new Set(rows.filter((row) => row.status === "partial").map((row) => row.area)),
  ];
  const completed = rows.filter((row) => row.status === "completed");
  // The language dimension applies to entries that code rules map to; history and web rules look
  // at tracked files and the running service whatever the language is.
  const isCodeEntry = mapped.some((rule) => rule.scope === "code");
  const covered = new Set(
    completed.filter((row) => row.scope === "code").flatMap((row) => areaLanguages(row.area)),
  );
  const gaps = isCodeEntry ? languages.filter((language) => !covered.has(language)) : [];
  const problems = [
    ...(partialAreas.length > 0 ? [`partial areas: ${list(partialAreas)}`] : []),
    ...(gaps.length > 0 ? [`no completed mapped rule covers ${list(gaps)}`] : []),
  ];
  if (completed.length > 0 && problems.length === 0) {
    return { state: "checked", ruleIds, reason: "mapped rules ran to completion" };
  }
  return {
    state: "partial",
    ruleIds,
    reason: problems.length > 0 ? problems.join("; ") : "no mapped area ran to completion",
  };
}

/**
 * Derives, per OWASP Top 10 2025 category and CWE Top 25 2025 entry, whether this scan checked it.
 * Pure: the answer comes from the rule mappings and from what the scan recorded.
 *
 * "Mapped" means the rule lists the id in its own `standards` (OWASP ids as written, CWE ids
 * exactly; no parent or child CWE is inferred). Advisories and dependency lookups are not rules of
 * a scan and never count. `checked` is never reported while a contributing area was partial or a
 * language present has no completed mapped rule; an entry with no mapped rule is `not_checked`
 * with the reason "no rules".
 */
export function computeStandardsCoverage(input: StandardsCoverageInput): StandardsCoverage {
  const languages = presentLanguages(input.coverage);
  const entry = (
    id: string,
    title: string,
    rank: number | null,
    mapped: readonly StandardsRule[],
  ): StandardCoverageEntry => ({
    id,
    title,
    rank,
    ...judge(mapped, input, languages),
    mappedRuleIds: mapped.map((rule) => rule.id).sort(),
  });
  return {
    owasp: OWASP_TOP10_2025.map((category) =>
      entry(
        category.id,
        category.title,
        null,
        input.rules.filter((rule) => rule.metadata.standards.owasp.includes(category.id)),
      ),
    ),
    cweTop25: CWE_TOP25.map((cwe) =>
      entry(
        cwe.id,
        cwe.name,
        cwe.rank,
        input.rules.filter((rule) => rule.metadata.standards.cwe.includes(cwe.id)),
      ),
    ),
  };
}

export interface StandardsCounts {
  checked: number;
  partial: number;
  not_checked: number;
}

export function countStandardStates(entries: readonly StandardCoverageEntry[]): StandardsCounts {
  const counts: StandardsCounts = { checked: 0, partial: 0, not_checked: 0 };
  for (const entry of entries) counts[entry.state] += 1;
  return counts;
}
