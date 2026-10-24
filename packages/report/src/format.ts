import {
  SEVERITIES,
  type Coverage,
  type CoverageStatus,
  type Finding,
  type FindingLocation,
  type OverallStatus,
  type ScanResult,
  type Severity,
} from "@pgard/findings";

export type SeverityCounts = Record<Severity, number>;

/** Field length caps keep both renderers fast and the report readable. */
export const MAX_EVIDENCE_CHARS = 2000;
export const MAX_FIELD_CHARS = 500;
export const TRUNCATION_MARKER = " (truncated)";

export function truncateField(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, maxLength)}${TRUNCATION_MARKER}` : value;
}

function truncateNullable(value: string | null, maxLength: number): string | null {
  return value === null ? null : truncateField(value, maxLength);
}

function truncateLocation(location: FindingLocation): FindingLocation {
  return {
    ...location,
    path: truncateNullable(location.path, MAX_FIELD_CHARS),
    url: truncateNullable(location.url, MAX_FIELD_CHARS),
    commit: truncateNullable(location.commit, MAX_FIELD_CHARS),
  };
}

/**
 * Copy of the result with every free-text field length-capped. Both renderers start from this
 * so HTML and PDF always show the same text.
 */
export function prepareReportResult(result: ScanResult): ScanResult {
  return {
    ...result,
    coverage: result.coverage.map((entry): Coverage => ({
      ...entry,
      area: truncateField(entry.area, MAX_FIELD_CHARS),
      note: truncateNullable(entry.note, MAX_FIELD_CHARS),
    })),
    findings: result.findings.map((finding): Finding => ({
      ...finding,
      title: truncateField(finding.title, MAX_FIELD_CHARS),
      evidence: truncateField(finding.evidence, MAX_EVIDENCE_CHARS),
      impact: truncateField(finding.impact, MAX_FIELD_CHARS),
      recommendation: truncateField(finding.recommendation, MAX_FIELD_CHARS),
      location: truncateLocation(finding.location),
    })),
    authorization: {
      ...result.authorization,
      checks: result.authorization.checks.map((check) => ({
        ...check,
        reason: truncateField(check.reason, MAX_FIELD_CHARS),
      })),
    },
  };
}

function isSeverity(value: unknown): value is Severity {
  return (SEVERITIES as readonly unknown[]).includes(value);
}

/**
 * Counts findings per severity, in contract order. Values outside the contract are ignored here
 * (they still render, with an "Unknown" label).
 */
export function countFindingsBySeverity(findings: readonly Finding[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    if (isSeverity(finding.severity)) counts[finding.severity] += 1;
  }
  return counts;
}

const STATUS_ORDER: Record<string, number> = { confirmed: 0, suspected: 1, informational: 2 };

function severityRank(severity: unknown): number {
  const index = (SEVERITIES as readonly unknown[]).indexOf(severity);
  return index === -1 ? SEVERITIES.length : index;
}

/** Sorts by severity (critical first), then confirmed before suspected, then rule id. */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      (STATUS_ORDER[a.status] ?? 3) - (STATUS_ORDER[b.status] ?? 3) ||
      String(a.ruleId).localeCompare(String(b.ruleId)),
  );
}

/** `path:line`, URL, commit or dependency location as one line of text. */
export function formatLocation(location: FindingLocation): string {
  const fileAndLine =
    location.path === null
      ? null
      : location.line === null
        ? location.path
        : `${location.path}:${location.line}`;
  switch (location.kind) {
    case "url":
      return location.url ?? "(unknown URL)";
    case "commit": {
      const commit =
        location.commit === null ? "unknown commit" : `commit ${location.commit.slice(0, 12)}`;
      return fileAndLine === null ? commit : `${fileAndLine} (${commit})`;
    }
    case "dependency":
    case "file":
      return fileAndLine ?? "(unknown location)";
    default:
      return fileAndLine ?? location.url ?? "(unknown location)";
  }
}

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const COVERAGE_LABELS: Record<CoverageStatus, string> = {
  completed: "Completed",
  partial: "Partial",
  not_tested: "Not tested",
  not_selected: "Not selected",
};

const OVERALL_STATUS_LABELS: Record<OverallStatus, string> = {
  completed: "Completed",
  partial: "Partial - some requested areas did not fully run",
  blocked: "Blocked by the authorization gate - no analysis ran",
  failed: "Failed - an internal error stopped the scan",
};

function lookupLabel(labels: Record<string, string>, value: unknown): string {
  return typeof value === "string" && Object.hasOwn(labels, value)
    ? (labels[value] ?? "Unknown")
    : "Unknown";
}

/** Labels with an "Unknown" fallback, since reports may later be built from JSON input. */
export function labelSeverity(severity: unknown): string {
  return lookupLabel(SEVERITY_LABELS, severity);
}

export function labelCoverageStatus(status: unknown): string {
  return lookupLabel(COVERAGE_LABELS, status);
}

export function labelOverallStatus(status: unknown): string {
  return lookupLabel(OVERALL_STATUS_LABELS, status);
}

/** Severity colors chosen to stay distinguishable in print and for common color-vision types. */
const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#7a1f2b",
  high: "#c2410c",
  medium: "#b7791f",
  low: "#2563eb",
  info: "#64748b",
};
const UNKNOWN_COLOR = "#64748b";

export function severityColor(severity: unknown): string {
  return isSeverity(severity) ? SEVERITY_COLORS[severity] : UNKNOWN_COLOR;
}

export const REPORT_DISCLAIMER =
  "PGARD reports what its supported rules detected in the selected scope at scan time. " +
  "No findings does not mean the project is secure. Areas marked Partial, Not tested or " +
  "Not selected were not fully checked, and suspected findings need manual review. HTTP " +
  "checks used anonymous GET requests only; PGARD does not guarantee they had no side effects. " +
  "This report was generated locally and may describe sensitive weaknesses: store it outside " +
  "the repository and share it only with people who are allowed to see it.";

export function formatAdvisoryDb(result: ScanResult): string {
  const { version, updatedAt } = result.advisoryDb;
  if (version === null) {
    return "No local advisory database was used (dependency advisories not checked).";
  }
  return `Advisory database ${version}${updatedAt === null ? "" : `, updated ${updatedAt}`}`;
}

export function summarizeStatusSplit(findings: readonly Finding[]): {
  confirmed: number;
  suspected: number;
  informational: number;
} {
  const split = { confirmed: 0, suspected: 0, informational: 0 };
  for (const finding of findings) {
    if (Object.hasOwn(split, finding.status)) split[finding.status] += 1;
  }
  return split;
}
