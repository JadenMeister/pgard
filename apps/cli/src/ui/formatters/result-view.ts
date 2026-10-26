import {
  SEVERITIES,
  splitFindingsByContext,
  summarizeBySeverity,
  type AuthorizationSummary,
  type Coverage,
  type Finding,
  type ScanResult,
} from "@pgard/findings";
import {
  ANALYSIS_BASIS_NOTE,
  formatContextCounts,
  formatLocation,
  formatOutsideContexts,
  labelCoverageStatus,
  labelOverallStatus,
  labelSeverity,
  VENDORED_FINDINGS_NOTE,
  VENDORED_FINDINGS_TITLE,
} from "@pgard/report";
import { AUTHORIZATION_CHECK_ORDER, AUTHORIZATION_REASON_MAX_LENGTH } from "@pgard/scan-core";
import {
  COLLAPSE_THRESHOLD,
  groupFindings,
  MAX_REPRESENTATIVE_LOCATIONS,
  shouldCollapse,
  sortBySeverity,
  summarizeCollapsed,
  type FindingGroup,
} from "./result-groups.js";
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

/** How to see everything that was collapsed or shortened. */
export const SHOW_ALL_HINT =
  "Run again with --all-findings to list everything, or save a report (--report html --output-dir <dir>).";

const MAX_SUMMARY_RULES = 10;

function formatGroup(group: FindingGroup, style: Style, allFindings: boolean): string {
  const finding = group.representative;
  const count = group.findings.length;
  const severity = style.severity(
    finding.severity,
    `[${labelSeverity(finding.severity).toUpperCase()}]`,
  );
  const detail = `${finding.status}${count > 1 ? `, ${count} locations` : ""}`;
  const lines = [
    `  ${severity} ${style.bold(safeText(finding.title, 300))} ${style.dim(`(${detail})`)}`,
  ];
  const rule = style.dim(`${safeText(finding.ruleId, 40)} - confidence ${finding.confidence}`);
  const places = group.findings.map((member) => safeText(formatLocation(member.location), 500));
  if (count === 1) {
    lines.push(`      ${places[0]}  ${rule}`);
  } else if (allFindings) {
    lines.push(`      ${rule}`, ...places.map((place) => `      - ${place}`));
  } else {
    const shown = places.slice(0, MAX_REPRESENTATIVE_LOCATIONS);
    const rest = count - shown.length;
    lines.push(`      ${shown.join(", ")}${rest > 0 ? ` and ${rest} more` : ""}  ${rule}`);
  }
  lines.push(
    `      ${count > 1 ? "Example evidence" : "Evidence"}: ${safeText(finding.evidence, 500)}`,
    `      Fix: ${safeText(finding.recommendation, 500)}`,
  );
  return lines.join("\n");
}

function formatGroups(findings: readonly Finding[], style: Style, allFindings: boolean): string {
  return groupFindings(findings)
    .map((group) => formatGroup(group, style, allFindings))
    .join("\n\n");
}

function hasShortenedGroup(findings: readonly Finding[]): boolean {
  return groupFindings(findings).some(
    (group) => group.findings.length > MAX_REPRESENTATIVE_LOCATIONS,
  );
}

/** Summary that replaces the listing of test, fixture and vendored findings. */
function formatCollapsed(findings: readonly Finding[], style: Style): string {
  const summary = summarizeCollapsed(findings);
  const rules = summary.byRule.slice(0, MAX_SUMMARY_RULES);
  const moreRules = summary.byRule.length - rules.length;
  return [
    style.bold(`Test, fixture and vendored code (${summary.count} findings not listed)`),
    style.dim(
      `  Collapsed because there are more than ${COLLAPSE_THRESHOLD}. Findings in your own code are always listed.`,
    ),
    `  By context: ${summary.byContext.map((entry) => `${entry.context} ${entry.count}`).join(", ")}`,
    `  By rule: ${rules.map((entry) => `${safeText(entry.ruleId, 40)} x${entry.count}`).join(", ")}${moreRules > 0 ? ` and ${moreRules} more rules` : ""}`,
    `  By severity: ${summary.bySeverity.map((entry) => `${entry.count} ${labelSeverity(entry.severity).toLowerCase()}`).join(", ")}`,
    `  ${SHOW_ALL_HINT}`,
  ].join("\n");
}

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
    return `  ${colored} ${check.id.replace(/_/g, " ")}: ${safeText(check.reason, AUTHORIZATION_REASON_MAX_LENGTH)}`;
  });
  const decision =
    summary.decision === "allowed"
      ? style.green("Authorization: allowed")
      : style.red("Authorization: blocked - no analysis ran");
  return `${style.bold(decision)}\n${lines.join("\n")}`;
}

/** Full terminal result view: status, chart, findings by status, coverage, analysis basis. */
export function formatScanResult(
  result: ScanResult,
  style: Style,
  options: { allFindings?: boolean } = {},
): string {
  const allFindings = options.allFindings === true;
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
  // Headline counts cover regular code; test and fixture findings follow in their own group and
  // suggestions in vendored code come last.
  const { primary, test, vendored } = splitFindingsByContext(sortBySeverity(result.findings));
  const contextCounts = { test: test.length, vendored: vendored.length };
  const extra = formatContextCounts({ test: test.length, vendored });
  sections.push(
    "",
    style.bold(`Findings by severity (${primary.length} total)`) +
      (extra === "" ? "" : style.dim(` - ${extra}`)),
    formatSeverityBars(primary, style),
  );
  if (primary.length > 0) {
    sections.push("", style.bold(`Findings (${primary.length})`));
    sections.push(formatGroups(primary, style, allFindings));
  }
  if (primary.length === 0) {
    sections.push(
      "",
      `No findings${formatOutsideContexts(contextCounts)} in the areas that ran. This does not mean the project is secure; see coverage.`,
    );
  }
  const nonReal = [...test, ...vendored];
  const isCollapsed = shouldCollapse(nonReal.length, allFindings);
  if (isCollapsed) {
    sections.push("", formatCollapsed(nonReal, style));
  } else {
    if (test.length > 0) {
      sections.push(
        "",
        style.bold(`${TEST_GROUP_TITLE} (${test.length})`),
        style.dim(`  ${TEST_GROUP_NOTE}`),
        formatGroups(test, style, allFindings),
      );
    }
    if (vendored.length > 0) {
      sections.push(
        "",
        style.bold(`${VENDORED_FINDINGS_TITLE} (${vendored.length})`),
        style.dim(`  ${VENDORED_FINDINGS_NOTE}`),
        formatGroups(vendored, style, allFindings),
      );
    }
  }
  if (!allFindings && !isCollapsed && hasShortenedGroup(result.findings)) {
    sections.push(
      "",
      style.dim(
        `Groups show up to ${MAX_REPRESENTATIVE_LOCATIONS} locations. Run again with --all-findings to list every location.`,
      ),
    );
  }
  sections.push("", style.bold("Coverage"), formatCoverage(result.coverage, style));
  sections.push("", style.dim(ANALYSIS_BASIS_NOTE));
  return sections.join("\n");
}
