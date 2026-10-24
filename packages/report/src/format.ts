import {
  SEVERITIES,
  splitFindingsByContext,
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

function isHighSurrogate(code: number): boolean {
  return code >= 0xd800 && code <= 0xdbff;
}

export function truncateField(value: string, maxLength: number): string {
  if (value.length <= maxLength) return value;
  let cut = value.slice(0, maxLength);
  // Never leave half of a surrogate pair at the cut.
  if (cut.length > 0 && isHighSurrogate(cut.charCodeAt(cut.length - 1))) cut = cut.slice(0, -1);
  return `${cut}${TRUNCATION_MARKER}`;
}

/** Keys whose string values may be longer than `MAX_FIELD_CHARS`. */
const LONG_FIELD_LIMITS: Readonly<Record<string, number>> = { evidence: MAX_EVIDENCE_CHARS };

function capStrings(value: unknown, key: string | null): unknown {
  if (typeof value === "string") {
    return truncateField(
      value,
      (key === null ? undefined : LONG_FIELD_LIMITS[key]) ?? MAX_FIELD_CHARS,
    );
  }
  if (Array.isArray(value)) return value.map((entry) => capStrings(entry, key));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([entryKey, entry]) => [entryKey, capStrings(entry, entryKey)]),
    );
  }
  return value;
}

/**
 * Copy of the result with every string length-capped (evidence 2000, everything else 500
 * characters). Both renderers start from this so HTML and PDF always show the same text and
 * stay fast on hostile input.
 */
export function prepareReportResult(result: ScanResult): ScanResult {
  return capStrings(result, null) as ScanResult;
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

export const TEST_FINDINGS_TITLE = "In test or fixture code";
export const TEST_FINDINGS_NOTE =
  "Matches in test or fixture files (*.test.*, *.spec.*, *_test.go, test/, tests/, __tests__/, __mocks__/, fixtures/, __fixtures__/, testdata/). Their confidence is capped at low and they are not counted above, but they are not dropped: a real value committed in a test is still exposed.";

/** Sorted findings split into regular code (headline counts) and test or fixture code. */
export function groupReportFindings(findings: readonly Finding[]): {
  primary: Finding[];
  test: Finding[];
} {
  return splitFindingsByContext(sortFindings(findings));
}

/** One-line summary: regular findings by status, plus the separate test count when present. */
export function formatFindingSummary(findings: readonly Finding[]): string {
  const { primary, test } = groupReportFindings(findings);
  const split = summarizeStatusSplit(primary);
  return (
    `${primary.length} finding(s): ${split.confirmed} confirmed, ${split.suspected} suspected, ${split.informational} informational.` +
    (test.length === 0 ? "" : ` ${test.length} more in test or fixture code, listed separately.`)
  );
}
