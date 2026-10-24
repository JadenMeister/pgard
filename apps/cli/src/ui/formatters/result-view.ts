import {
  SEVERITIES,
  splitFindingsByContext,
  summarizeBySeverity,
  type AuthorizationSummary,
  type Coverage,
  type Finding,
  type FindingStatus,
  type ScanResult,
} from "@pgard/findings";
import {
  formatAdvisoryDb,
  formatLocation,
  labelCoverageStatus,
  labelOverallStatus,
  labelSeverity,
  sortFindings,
} from "@pgard/report";
import { AUTHORIZATION_CHECK_ORDER } from "@pgard/scan-core";
import { safeText, type Style } from "./style.js";

const BAR_WIDTH = 30;
const BAR_CHARACTER = "#";

/** Horizontal text bar chart of findings per severity. */
export function formatSeverityBars(findings: readonly Finding[], style: Style): string {
  const counts = summarizeBySeverity(findings);
  const maxCount = Math.max(1, ...Object.values(counts));
  return SEVERITIES.map((severity) => {
    const count = counts[severity];
    const width = count === 0 ? 0 : Math.max(1, Math.round((count / maxCount) * BAR_WIDTH));
    const label = labelSeverity(severity).padEnd(9);
    return `  ${label} ${style.severity(severity, BAR_CHARACTER.repeat(width))}${count === 0 ? "" : " "}${count}`;
  }).join("\n");
}

function formatFinding(finding: Finding, style: Style): string {
  const severity = style.severity(
    finding.severity,
    `[${labelSeverity(finding.severity).toUpperCase()}]`,
  );
  return [
    `  ${severity} ${style.bold(safeText(finding.title, 300))}`,
    `      ${safeText(formatLocation(finding.location), 500)}  ${style.dim(`${safeText(finding.ruleId, 40)} - confidence ${finding.confidence}`)}`,
    `      Evidence: ${safeText(finding.evidence, 500)}`,
    `      Fix: ${safeText(finding.recommendation, 500)}`,
  ].join("\n");
}

const STATUS_GROUPS: ReadonlyArray<{ status: FindingStatus; title: string }> = [
  { status: "confirmed", title: "Confirmed" },
  { status: "suspected", title: "Suspected (needs review)" },
  { status: "informational", title: "Informational" },
];

const TEST_GROUP_TITLE = "In test or fixture code";
const TEST_GROUP_NOTE =
  "Matches in files classified as test or fixture code by their path only (confidence capped at low). Review them: a real value committed in a test is still exposed.";

const COVERAGE_MARKS: Record<string, string> = {
  completed: "[ok]",
  partial: "[partial]",
  not_tested: "[not tested]",
  not_selected: "[not selected]",
};

export function formatCoverage(coverage: readonly Coverage[], style: Style): string {
  if (coverage.length === 0) return "  (no coverage recorded)";
  return coverage
    .map((entry) => {
      const mark = COVERAGE_MARKS[entry.status] ?? "[?]";
      const colored =
        entry.status === "completed"
          ? style.green(mark)
          : entry.status === "not_selected"
            ? style.dim(mark)
            : style.yellow(mark);
      const note = entry.note === null ? "" : style.dim(` - ${safeText(entry.note, 300)}`);
      return `  ${colored} ${safeText(entry.area, 80)} (${labelCoverageStatus(entry.status)})${note}`;
    })
    .join("\n");
}

const CHECK_STATUS_MARKS: Record<string, string> = {
  passed: "[passed]",
  failed: "[failed]",
  unverifiable: "[unverifiable]",
};

/** Per-check authorization reasons, in the policy's evaluation order. */
export function formatAuthorization(summary: AuthorizationSummary, style: Style): string {
  const ordered = [...summary.checks].sort(
    (a, b) => AUTHORIZATION_CHECK_ORDER.indexOf(a.id) - AUTHORIZATION_CHECK_ORDER.indexOf(b.id),
  );
  const lines = ordered.map((check) => {
    const mark = CHECK_STATUS_MARKS[check.status] ?? "[?]";
    const colored = check.status === "passed" ? style.green(mark) : style.red(mark);
    return `  ${colored} ${check.id.replace(/_/g, " ")}: ${safeText(check.reason, 400)}`;
  });
  const decision =
    summary.decision === "allowed"
      ? style.green("Authorization: allowed")
      : style.red("Authorization: blocked - no analysis ran");
  return `${style.bold(decision)}\n${lines.join("\n")}`;
}

/** Full terminal result view: status, chart, findings by status, coverage, data sources. */
export function formatScanResult(result: ScanResult, style: Style): string {
  const sections: string[] = [];
  const target = result.target;
  sections.push(
    `${style.bold("PGARD scan result")} - ${labelOverallStatus(result.overallStatus)}`,
    style.dim(
      `Repository ${safeText(target.repo ?? "unknown", 120)} @ ${safeText((target.revision ?? "unknown").slice(0, 12), 20)}` +
        (target.webOrigin === null ? "" : ` - web ${safeText(target.webOrigin, 60)}`) +
        ` - scopes: ${result.requestedScopes.join(", ")}`,
    ),
  );
  if (result.overallStatus === "blocked") {
    sections.push("", formatAuthorization(result.authorization, style));
    return sections.join("\n");
  }
  // Headline counts cover regular code; test and fixture findings follow in their own group.
  const { primary, test } = splitFindingsByContext(sortFindings(result.findings));
  sections.push(
    "",
    style.bold(`Findings by severity (${primary.length} total)`) +
      (test.length === 0 ? "" : style.dim(` - plus ${test.length} in test or fixture code`)),
    formatSeverityBars(primary, style),
  );
  for (const group of STATUS_GROUPS) {
    const groupFindings = primary.filter((finding) => finding.status === group.status);
    if (groupFindings.length === 0) continue;
    sections.push("", style.bold(`${group.title} (${groupFindings.length})`));
    sections.push(groupFindings.map((finding) => formatFinding(finding, style)).join("\n\n"));
  }
  if (primary.length === 0) {
    sections.push(
      "",
      test.length === 0
        ? "No findings in the areas that ran. This does not mean the project is secure; see coverage."
        : "No findings outside test or fixture code in the areas that ran. This does not mean the project is secure; see coverage.",
    );
  }
  if (test.length > 0) {
    sections.push(
      "",
      style.bold(`${TEST_GROUP_TITLE} (${test.length})`),
      style.dim(`  ${TEST_GROUP_NOTE}`),
      test.map((finding) => formatFinding(finding, style)).join("\n\n"),
    );
  }
  sections.push("", style.bold("Coverage"), formatCoverage(result.coverage, style));
  sections.push("", style.dim(safeText(formatAdvisoryDb(result), 300)));
  return sections.join("\n");
}
