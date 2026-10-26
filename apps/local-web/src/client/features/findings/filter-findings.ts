import type { Finding, FindingLocation, FindingStatus, ScanScope, Severity } from "@pgard/findings";
import { SEVERITY_ORDER } from "../../components/charts/severity-scale";
import { en } from "../../i18n/en";
import type { Messages } from "../../i18n/types";

export interface FindingFilters {
  severity: Severity | null;
  status: FindingStatus | null;
  source: ScanScope | null;
  text: string;
}

export const EMPTY_FILTERS: FindingFilters = {
  severity: null,
  status: null,
  source: null,
  text: "",
};

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
  const visible = filterFindings(groups.primary, filters);
  const contextCounts = { test: groups.test.length, vendored: groups.vendored.length };
  const sections: ContextSection[] = [
    {
      kind: "test" as const,
      title: m.findings.testTitle(groups.test.length),
      total: groups.test.length,
      visible: filterFindings(groups.test, filters),
    },
    {
      kind: "vendored" as const,
      title: m.findings.vendoredTitle(groups.vendored.length),
      total: groups.vendored.length,
      visible: filterFindings(groups.vendored, filters),
    },
    {
      kind: "suppressed" as const,
      title: m.findings.suppressedTitle(parts.suppressed.length),
      total: parts.suppressed.length,
      visible: filterFindings(parts.suppressed, filters),
    },
    {
      kind: "baseline" as const,
      title: m.findings.baselineTitle(parts.baseline.length),
      total: parts.baseline.length,
      visible: filterFindings(parts.baseline, filters),
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
export function filterFindings(findings: readonly Finding[], filters: FindingFilters): Finding[] {
  const text = filters.text.trim().toLowerCase();
  const statusOrder: Record<string, number> = { confirmed: 0, suspected: 1, informational: 2 };
  return findings
    .filter((finding) => filters.severity === null || finding.severity === filters.severity)
    .filter((finding) => filters.status === null || finding.status === filters.status)
    .filter((finding) => filters.source === null || finding.sources.includes(filters.source))
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
