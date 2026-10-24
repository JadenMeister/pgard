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
 * Splits findings into regular code and test or fixture code (`context: "test"`, set by the scan
 * engine). Mirrors `splitFindingsByContext` from @pgard/findings without bundling it.
 */
export function splitByContext(findings: readonly Finding[]): {
  primary: Finding[];
  test: Finding[];
} {
  const primary: Finding[] = [];
  const test: Finding[] = [];
  for (const finding of findings) (finding.context === "test" ? test : primary).push(finding);
  return { primary, test };
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
