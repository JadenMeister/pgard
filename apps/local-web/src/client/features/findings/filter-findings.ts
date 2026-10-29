import type {
  Coverage,
  Finding,
  FindingCategory,
  FindingLocation,
  FindingStatus,
  RuleStat,
  ScanScope,
  Severity,
} from "@pgard/findings";
import { SEVERITY_ORDER } from "../../components/charts/severity-scale";
import { en } from "../../i18n/en";
import type { Messages } from "../../i18n/types";

export interface FindingFilters {
  severity: Severity | null;
  status: FindingStatus | null;
  source: ScanScope | null;
  category: FindingCategory | null;
  /** Exact rule id, e.g. `PG-SQL-001`. */
  rule: string | null;
  /** Coverage area id, e.g. `source:typescript`: findings of the rules that ran in that area. */
  area: string | null;
  /** Exact repository-relative file path of the finding's location. */
  path: string | null;
  text: string;
}

export const EMPTY_FILTERS: FindingFilters = {
  severity: null,
  status: null,
  source: null,
  category: null,
  rule: null,
  area: null,
  path: null,
  text: "",
};

/**
 * File extensions (with dot) of the `source:<language>` areas, as the source analyzer assigns
 * them (`EXTENSIONS` in source-analysis `walk.ts` and `TREE_SITTER_EXTENSIONS`).
 */
const SOURCE_AREA_EXTENSIONS: Record<string, readonly string[]> = {
  "source:javascript": [".js", ".jsx", ".mjs", ".cjs"],
  "source:typescript": [".ts", ".tsx", ".mts", ".cts"],
  "source:vue": [".vue"],
  "source:go": [".go"],
  "source:java": [".java"],
  "source:kotlin": [".kt"],
  "source:python": [".py"],
  "source:php": [".php", ".phtml"],
};

function extensionOf(path: string | null): string {
  if (path === null) return "";
  const dot = path.lastIndexOf(".");
  return dot <= path.lastIndexOf("/") ? "" : path.slice(dot).toLowerCase();
}

/**
 * The test that says whether a finding belongs to a coverage area, or `null` when the finding
 * carries too little to tell (the area is then not offered as a filter). A rule id alone is not
 * enough: several areas run the same rules, so the finding's scope and where it was found must
 * agree with the area as the scanner produced it.
 *
 * - `source:<language>`: a code finding of one of the area's rules in a file of that language.
 * - `history:tracked-files` / `history:commits`: a history finding of the area's rules, without
 *   or with a commit (the history scanner files a finding with a commit under the commits area).
 * - Every other area (heuristics, ORM, web, configuration, ...) cannot be derived from a finding.
 */
export function areaMatcher(
  area: string,
  areaRules: AreaRules,
): ((finding: Finding) => boolean) | null {
  const rules = areaRules.get(area);
  if (rules === undefined) return null;
  const extensions = SOURCE_AREA_EXTENSIONS[area];
  if (extensions !== undefined) {
    return (finding) =>
      rules.has(finding.ruleId) &&
      finding.sources.includes("code") &&
      extensions.includes(extensionOf(finding.location.path));
  }
  if (area === "history:tracked-files" || area === "history:commits") {
    const wantsCommit = area === "history:commits";
    return (finding) =>
      rules.has(finding.ruleId) &&
      finding.sources.includes("history") &&
      (finding.location.kind === "commit" || finding.location.commit !== null) === wantsCommit;
  }
  return null;
}

/** Whether findings can be reliably attributed to the area (so it can be offered as a filter). */
export function isAreaFilterable(area: string, areaRules: AreaRules): boolean {
  return areaMatcher(area, areaRules) !== null;
}

/** Rule ids per coverage area: the area's own `ruleIds` plus the rules that ran there (`ruleStats`). */
export type AreaRules = ReadonlyMap<string, ReadonlySet<string>>;

export function buildAreaRules(
  coverage: readonly Pick<Coverage, "area" | "ruleIds">[],
  ruleStats: readonly Pick<RuleStat, "area" | "ruleId">[] | undefined,
): AreaRules {
  const areas = new Map<string, Set<string>>();
  const add = (area: string, ruleId: string): void => {
    const rules = areas.get(area) ?? new Set<string>();
    rules.add(ruleId);
    areas.set(area, rules);
  };
  for (const entry of coverage) {
    areas.set(entry.area, areas.get(entry.area) ?? new Set());
    for (const ruleId of entry.ruleIds) add(entry.area, ruleId);
  }
  for (const stat of ruleStats ?? []) add(stat.area, stat.ruleId);
  return areas;
}

/**
 * The change a click on a filter value makes: the value is set, or cleared when it is already the
 * active one (a second click undoes the first).
 */
export function toggleFilter(
  filters: FindingFilters,
  patch: Partial<FindingFilters>,
): Partial<FindingFilters> {
  const result: Partial<FindingFilters> = {};
  for (const key of Object.keys(patch) as Array<keyof FindingFilters>) {
    // Every key but `text` is a nullable id; `text` is never toggled.
    (result as Record<string, unknown>)[key] =
      filters[key] === patch[key] ? (key === "text" ? "" : null) : patch[key];
  }
  return result;
}

/** Findings per category, largest first; categories without findings are left out. */
export function countByCategory(
  findings: readonly Finding[],
): Array<{ category: FindingCategory; count: number }> {
  const counts = new Map<FindingCategory, number>();
  for (const finding of findings)
    counts.set(finding.category, (counts.get(finding.category) ?? 0) + 1);
  return [...counts]
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count || a.category.localeCompare(b.category));
}

export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    if (finding.severity in counts) counts[finding.severity] += 1;
  }
  return counts;
}

/**
 * Splits findings into regular code, test or fixture code (`context: "test"`) and suggestions in
 * committed third-party code (`context: "vendored"`), both set by the scan engine. Mirrors
 * `splitFindingsByContext` from @pgard/findings without bundling it.
 */
export function splitByContext(findings: readonly Finding[]): {
  primary: Finding[];
  test: Finding[];
  vendored: Finding[];
} {
  const primary: Finding[] = [];
  const test: Finding[] = [];
  const vendored: Finding[] = [];
  for (const finding of findings) {
    if (finding.context === "vendored") vendored.push(finding);
    else if (finding.context === "test") test.push(finding);
    else primary.push(finding);
  }
  return { primary, test, vendored };
}

/**
 * "3 suggestions in vendored code", plus the critical and high counts when there are any
 * ("1 suggestion in vendored code (1 critical)"). Same wording as `formatVendoredSuggestions` in
 * @pgard/report.
 */
export function formatVendoredSuggestions(
  vendored: readonly Pick<Finding, "severity">[],
  m: Messages = en,
): string {
  const count = vendored.length;
  const severe = (["critical", "high"] as const)
    .map((severity) => ({
      severity,
      count: vendored.filter((finding) => finding.severity === severity).length,
    }))
    .filter((entry) => entry.count > 0)
    .map((entry) => `${entry.count} ${m.severityInline[entry.severity]}`);
  return m.findings.vendoredSuggestions(count, severe.join(", "));
}

/**
 * Headline addition, e.g. "plus 2 in test or fixture code, 3 suggestions in vendored code
 * (1 high)"; empty when every finding is regular code. Same wording as `formatContextCounts` in
 * @pgard/report.
 */
export function formatContextCounts(
  groups: {
    test: number;
    vendored: readonly Pick<Finding, "severity">[];
  },
  m: Messages = en,
): string {
  const parts = [
    ...(groups.test === 0 ? [] : [m.findings.contextTest(groups.test)]),
    ...(groups.vendored.length === 0 ? [] : [formatVendoredSuggestions(groups.vendored, m)]),
  ];
  return parts.length === 0 ? "" : m.findings.plus(parts.join(", "));
}

/**
 * Splits off suppressed findings (they matched `suppressions` in pgard.config.json) and findings
 * in the baseline; suppressed wins. Mirrors `partitionFindings` from @pgard/findings.
 */
export function partitionFindings(findings: readonly Finding[]): {
  suppressed: Finding[];
  baseline: Finding[];
  rest: Finding[];
} {
  const suppressed: Finding[] = [];
  const baseline: Finding[] = [];
  const rest: Finding[] = [];
  for (const finding of findings) {
    if (finding.suppression !== undefined) suppressed.push(finding);
    else if (finding.inBaseline === true) baseline.push(finding);
    else rest.push(finding);
  }
  return { suppressed, baseline, rest };
}

/** A separate group listed after the regular findings: test code, vendored, suppressed, baseline. */
export interface ContextSection {
  kind: "test" | "vendored" | "suppressed" | "baseline";
  title: string;
  /** Every finding in the group (shown in the title), before filters. */
  total: number;
  /** The group's findings that match the filters, sorted. */
  visible: Finding[];
}

export interface FindingsView {
  /** Regular findings only: the headline count, the charts and the status split. */
  total: number;
  counts: Record<Severity, number>;
  statusCounts: Record<FindingStatus, number>;
  /** "plus 1 in test or fixture code, 2 suggestions in vendored code (1 high), 3 suppressed", or "". */
  contextNote: string;
  visible: Finding[];
  /** Shown instead of the regular list when it is empty; `null` when there is something to show. */
  emptyMessage: string | null;
  /** Non-empty groups only, in display order (test, vendored, suppressed, in baseline). */
  sections: ContextSection[];
}

/**
 * Everything the results panel shows, from the result's findings and the filters. Headline counts
 * and charts cover regular code; test findings and vendored suggestions are counted and listed
 * separately, never dropped. Filters apply to every group.
 */
export function buildFindingsView(
  findings: readonly Finding[],
  filters: FindingFilters,
  m: Messages = en,
  areaRules: AreaRules = new Map(),
): FindingsView {
  const parts = partitionFindings(findings);
  const groups = splitByContext(parts.rest);
  const statusCounts: Record<FindingStatus, number> = {
    confirmed: 0,
    suspected: 0,
    informational: 0,
  };
  for (const finding of groups.primary) {
    if (finding.status in statusCounts) statusCounts[finding.status] += 1;
  }
  const visible = filterFindings(groups.primary, filters, areaRules);
  const contextCounts = { test: groups.test.length, vendored: groups.vendored.length };
  const sections: ContextSection[] = [
    {
      kind: "test" as const,
      title: m.findings.testTitle(groups.test.length),
      total: groups.test.length,
      visible: filterFindings(groups.test, filters, areaRules),
    },
    {
      kind: "vendored" as const,
      title: m.findings.vendoredTitle(groups.vendored.length),
      total: groups.vendored.length,
      visible: filterFindings(groups.vendored, filters, areaRules),
    },
    {
      kind: "suppressed" as const,
      title: m.findings.suppressedTitle(parts.suppressed.length),
      total: parts.suppressed.length,
      visible: filterFindings(parts.suppressed, filters, areaRules),
    },
    {
      kind: "baseline" as const,
      title: m.findings.baselineTitle(parts.baseline.length),
      total: parts.baseline.length,
      visible: filterFindings(parts.baseline, filters, areaRules),
    },
  ].filter((section) => section.total > 0);
  const suppressedBreakdown = formatSeverityBreakdown(parts.suppressed, m);
  const extraParts = [
    ...(parts.suppressed.length === 0
      ? []
      : [m.findings.suppressedCount(parts.suppressed.length, suppressedBreakdown)]),
    ...(parts.baseline.length === 0 ? [] : [m.findings.baselineInBaseline(parts.baseline.length)]),
  ];
  const baseNote = formatContextCounts({ test: groups.test.length, vendored: groups.vendored }, m);
  const contextNote =
    extraParts.length === 0
      ? baseNote
      : baseNote === ""
        ? m.findings.plus(extraParts.join(", "))
        : `${baseNote}, ${extraParts.join(", ")}`;
  return {
    total: groups.primary.length,
    counts: countBySeverity(groups.primary),
    statusCounts,
    contextNote,
    visible,
    emptyMessage:
      visible.length > 0
        ? null
        : groups.primary.length === 0
          ? m.findings.noFindings(
              formatOutsideContexts(contextCounts, m),
              parts.suppressed.length,
              suppressedBreakdown,
            )
          : m.findings.noMatch,
    sections,
  };
}

/** "1 critical, 5 high": the non-zero severities, worst first; empty when there are none. */
export function formatSeverityBreakdown(findings: readonly Finding[], m: Messages = en): string {
  const counts = countBySeverity(findings);
  return SEVERITY_ORDER.filter((severity) => counts[severity] > 0)
    .map((severity) => `${counts[severity]} ${m.severityInline[severity]}`)
    .join(", ");
}

/** Same wording as `formatOutsideContexts` in @pgard/report. */
export function formatOutsideContexts(
  counts: { test: number; vendored: number },
  m: Messages = en,
): string {
  if (counts.test > 0 && counts.vendored > 0) return m.findings.outsideTestAndVendored;
  if (counts.test > 0) return m.findings.outsideTest;
  if (counts.vendored > 0) return m.findings.outsideVendored;
  return "";
}

export function formatLocation(location: FindingLocation, m: Messages = en): string {
  const text = m.findings.location;
  if (location.kind === "url") return location.url ?? text.unknownUrl;
  const fileAndLine =
    location.path === null
      ? null
      : location.line === null
        ? location.path
        : `${location.path}:${location.line}`;
  if (location.kind === "commit") {
    const commit =
      location.commit === null ? text.unknownCommit : text.commit(location.commit.slice(0, 12));
    return fileAndLine === null ? commit : `${fileAndLine} (${commit})`;
  }
  return fileAndLine ?? text.unknownLocation;
}

/** Applies the dashboard filters and sorts by severity, then confirmed before suspected. */
export function filterFindings(
  findings: readonly Finding[],
  filters: FindingFilters,
  areaRules: AreaRules = new Map(),
): Finding[] {
  // An area that cannot be told apart reliably (or an unknown one) matches nothing: never over-include.
  const inArea =
    filters.area === null ? null : (areaMatcher(filters.area, areaRules) ?? (() => false));
  const text = filters.text.trim().toLowerCase();
  const statusOrder: Record<string, number> = { confirmed: 0, suspected: 1, informational: 2 };
  return findings
    .filter((finding) => filters.severity === null || finding.severity === filters.severity)
    .filter((finding) => filters.status === null || finding.status === filters.status)
    .filter((finding) => filters.source === null || finding.sources.includes(filters.source))
    .filter((finding) => filters.category === null || finding.category === filters.category)
    .filter((finding) => filters.rule === null || finding.ruleId === filters.rule)
    .filter((finding) => filters.path === null || finding.location.path === filters.path)
    .filter((finding) => inArea === null || inArea(finding))
    .filter(
      (finding) =>
        text === "" ||
        `${finding.title} ${finding.ruleId} ${formatLocation(finding.location)}`
          .toLowerCase()
          .includes(text),
    )
    .sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
        (statusOrder[a.status] ?? 3) - (statusOrder[b.status] ?? 3) ||
        a.ruleId.localeCompare(b.ruleId),
    );
}
