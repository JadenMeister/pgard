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

/** How findings are decided, shown where reports used to name an advisory database. */
export const ANALYSIS_BASIS_NOTE =
  "PGARD does not ship or query a vulnerability database. Findings come from the code itself " +
  "(query statements, server code, configuration), Git history and, if selected, local HTTP " +
  "checks. Dependency versions are not checked against known vulnerabilities.";

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
  "Matches in files classified as test or fixture code by their path only: *.test.*, *.spec.*, *_test.go, and files under __tests__/, __mocks__/, fixtures/, __fixtures__/, testdata/, test/ or tests/ (config files such as .env, YAML, .tf, .properties, .ini, .toml and .json under test/ or tests/ are treated as real configuration). Their confidence is capped at low and they are not counted above, but they are not dropped: a real value committed in a test is still exposed.";

export const VENDORED_FINDINGS_TITLE = "Suggestions: in third-party/vendored code";
export const VENDORED_FINDINGS_NOTE =
  "This code is a committed dependency, not your code. Review it if it's unexpected; otherwise consider removing it from Git (git rm -r --cached <directory>, then add the directory to .gitignore).";
export const VENDORED_FINDINGS_DETAIL =
  "Classified by path only: files under a node_modules/, bower_components/, jspm_packages/, vendor/, third_party/ or Pods/ directory. Their confidence is capped at low and they are not counted above, but they are not dropped: a real secret committed there is still exposed.";

/**
 * Sorted findings split into regular code (headline counts), test or fixture code, and
 * suggestions in committed third-party (vendored) code.
 */
export function groupReportFindings(findings: readonly Finding[]): {
  primary: Finding[];
  test: Finding[];
  vendored: Finding[];
} {
  return splitFindingsByContext(sortFindings(findings));
}

function pluralSuggestions(count: number): string {
  return `${count} suggestion${count === 1 ? "" : "s"} in vendored code`;
}

/**
 * The part after the headline count, e.g. "plus 2 in test or fixture code, 3 suggestions in
 * vendored code"; empty when every finding is regular code.
 */
export function formatContextCounts(counts: { test: number; vendored: number }): string {
  const parts = [
    ...(counts.test === 0 ? [] : [`${counts.test} in test or fixture code`]),
    ...(counts.vendored === 0 ? [] : [pluralSuggestions(counts.vendored)]),
  ];
  return parts.length === 0 ? "" : `plus ${parts.join(", ")}`;
}

/**
 * The "No findings ... in the areas that ran" qualifier: empty, or " outside test or fixture
 * code", " outside vendored code", " outside test, fixture or vendored code".
 */
export function formatOutsideContexts(counts: { test: number; vendored: number }): string {
  if (counts.test > 0 && counts.vendored > 0) return " outside test, fixture or vendored code";
  if (counts.test > 0) return " outside test or fixture code";
  if (counts.vendored > 0) return " outside vendored code";
  return "";
}

/** One-line summary: regular findings by status, plus the separate test and vendored counts. */
export function formatFindingSummary(findings: readonly Finding[]): string {
  const { primary, test, vendored } = groupReportFindings(findings);
  const split = summarizeStatusSplit(primary);
  return (
    `${primary.length} finding(s): ${split.confirmed} confirmed, ${split.suspected} suspected, ${split.informational} informational.` +
    (test.length === 0 ? "" : ` ${test.length} more in test or fixture code, listed separately.`) +
    (vendored.length === 0 ? "" : ` ${pluralSuggestions(vendored.length)}, listed last.`)
  );
}
