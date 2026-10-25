import type { Finding, FindingLocation, FindingStatus, ScanScope, Severity } from "@pgard/findings";
import { SEVERITY_ORDER } from "../../components/charts/severity-scale";

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
export function formatVendoredSuggestions(vendored: readonly Pick<Finding, "severity">[]): string {
  const count = vendored.length;
  const severe = (["critical", "high"] as const)
    .map((severity) => ({
      severity,
      count: vendored.filter((finding) => finding.severity === severity).length,
    }))
    .filter((entry) => entry.count > 0)
    .map((entry) => `${entry.count} ${entry.severity}`);
  return (
    `${count} suggestion${count === 1 ? "" : "s"} in vendored code` +
    (severe.length === 0 ? "" : ` (${severe.join(", ")})`)
  );
}

/**
 * Headline addition, e.g. "plus 2 in test or fixture code, 3 suggestions in vendored code
 * (1 high)"; empty when every finding is regular code. Same wording as `formatContextCounts` in
 * @pgard/report.
 */
export function formatContextCounts(groups: {
  test: number;
  vendored: readonly Pick<Finding, "severity">[];
}): string {
  const parts = [
    ...(groups.test === 0 ? [] : [`${groups.test} in test or fixture code`]),
    ...(groups.vendored.length === 0 ? [] : [formatVendoredSuggestions(groups.vendored)]),
  ];
  return parts.length === 0 ? "" : `plus ${parts.join(", ")}`;
}

/** Same wording as `formatOutsideContexts` in @pgard/report. */
export function formatOutsideContexts(counts: { test: number; vendored: number }): string {
  if (counts.test > 0 && counts.vendored > 0) return " outside test, fixture or vendored code";
  if (counts.test > 0) return " outside test or fixture code";
  if (counts.vendored > 0) return " outside vendored code";
  return "";
}

export function formatLocation(location: FindingLocation): string {
  if (location.kind === "url") return location.url ?? "(unknown URL)";
  const fileAndLine =
    location.path === null
      ? null
      : location.line === null
        ? location.path
        : `${location.path}:${location.line}`;
  if (location.kind === "commit") {
    const commit =
      location.commit === null ? "unknown commit" : `commit ${location.commit.slice(0, 12)}`;
    return fileAndLine === null ? commit : `${fileAndLine} (${commit})`;
  }
  return fileAndLine ?? "(unknown location)";
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
