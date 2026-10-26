import {
  SEVERITIES,
  countStandardStates,
  projectConfigNotices,
  configTestGroupNote,
  splitFindingsByContext,
  summarizeBySeverity,
  type AuthorizationSummary,
  type Coverage,
  type Finding,
  type ScanResult,
  type StandardCheckState,
  type StandardsCoverage,
} from "@pgard/findings";
import {
  ANALYSIS_BASIS_NOTE,
  formatVendoredSuggestions,
  formatLocation,
  formatOutsideContexts,
  labelCoverageStatus,
  labelOverallStatus,
  labelSeverity,
  summarizeStatusSplit,
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

function allSame(values: readonly string[]): boolean {
  return values.every((value) => value === values[0]);
}

function formatGroup(group: FindingGroup, style: Style, allFindings: boolean): string {
  const finding = group.representative;
  const members = group.findings;
  const count = members.length;
  const severity = style.severity(
    finding.severity,
    `[${labelSeverity(finding.severity).toUpperCase()}]`,
  );
  const detail = `${finding.status}${count > 1 ? `, ${count} locations` : ""}`;
  const lines = [
    `  ${severity} ${style.bold(safeText(finding.title, 300))} ${style.dim(`(${detail})`)}`,
  ];
  const rule = style.dim(`${safeText(finding.ruleId, 40)} - confidence ${finding.confidence}`);
  const places = members.map((member) => safeText(formatLocation(member.location), 500));
  const evidence = (member: Finding): string => safeText(member.evidence, 500);
  const fix = (member: Finding): string => safeText(member.recommendation, 500);
  const isFixShared = allSame(members.map(fix));
  if (count === 1) {
    lines.push(
      `      ${places[0]}  ${rule}`,
      `      Evidence: ${evidence(finding)}`,
      `      Fix: ${fix(finding)}`,
    );
  } else if (allFindings) {
    // Every location with its own evidence: nothing is shown for one member on behalf of others.
    lines.push(`      ${rule}`);
    members.forEach((member, index) => {
      lines.push(`      - ${places[index]}`, `          Evidence: ${evidence(member)}`);
      if (!isFixShared) lines.push(`          Fix: ${fix(member)}`);
    });
    if (isFixShared) lines.push(`      Fix: ${fix(finding)}`);
  } else {
    const shown = places.slice(0, MAX_REPRESENTATIVE_LOCATIONS);
    const rest = count - shown.length;
    lines.push(`      ${shown.join(", ")}${rest > 0 ? ` and ${rest} more` : ""}  ${rule}`);
    lines.push(
      allSame(members.map(evidence))
        ? `      Evidence: ${evidence(finding)}`
        : "      Evidence: varies by location (run with --all-findings to see each)",
      isFixShared
        ? `      Fix: ${fix(finding)}`
        : "      Fix: varies by location (run with --all-findings to see each)",
    );
  }
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

const isSevere = (finding: Pick<Finding, "severity">): boolean =>
  finding.severity === "critical" || finding.severity === "high";

/** Summary that replaces the listing of lower-severity test, fixture and vendored findings. */
function formatCollapsed(findings: readonly Finding[], style: Style): string {
  const summary = summarizeCollapsed(findings);
  const rules = summary.byRule.slice(0, MAX_SUMMARY_RULES);
  const moreRules = summary.byRule.length - rules.length;
  return [
    style.bold(
      `Test, fixture and vendored code (${summary.count} lower-severity findings not listed)`,
    ),
    style.dim(
      `  Collapsed because there are more than ${COLLAPSE_THRESHOLD} in this code. Findings in your own code, and critical or high findings anywhere, are always listed. Review these too: a real value committed in a test is still exposed.`,
    ),
    `  By context: ${summary.byContext.map((entry) => `${entry.context} ${entry.count}`).join(", ")}`,
    `  By rule: ${rules.map((entry) => `${safeText(entry.ruleId, 40)} x${entry.count}`).join(", ")}${moreRules > 0 ? ` and ${moreRules} more rules` : ""}`,
    `  By severity: ${summary.bySeverity.map((entry) => `${entry.count} ${labelSeverity(entry.severity).toLowerCase()}`).join(", ")}`,
    `  ${SHOW_ALL_HINT}`,
  ].join("\n");
}

/** "3 in test or fixture code (1 critical, 2 high)" so severe matches are not hidden in a total. */
function formatTestCount(test: readonly Finding[]): string {
  const severe = (["critical", "high"] as const)
    .map((severity) => ({ severity, count: test.filter((f) => f.severity === severity).length }))
    .filter((entry) => entry.count > 0)
    .map((entry) => `${entry.count} ${entry.severity}`);
  return `${test.length} in test or fixture code${severe.length === 0 ? "" : ` (${severe.join(", ")})`}`;
}

function formatStatusCounts(findings: readonly Finding[]): string {
  const split = summarizeStatusSplit(findings);
  return [
    split.confirmed > 0 ? `${split.confirmed} confirmed` : null,
    split.suspected > 0 ? `${split.suspected} suspected (needs review)` : null,
    split.informational > 0 ? `${split.informational} informational` : null,
  ]
    .filter((part) => part !== null)
    .join(", ");
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

/**
 * Prominent lines for the project configuration file, shown above the findings so exclusions are
 * never missed in the coverage list: "N files excluded by pgard.config.json ..." and any warning
 * or problem with the file itself.
 */
export function formatConfigNotices(coverage: readonly Coverage[], style: Style): string[] {
  return projectConfigNotices(coverage).map((notice) => {
    const text = safeText(notice.text, 300);
    return notice.tone === "warning"
      ? style.yellow(style.bold(`! ${text}`))
      : style.dim(`  ${text}`);
  });
}

const STANDARD_MARKS: Record<StandardCheckState, string> = {
  checked: "[checked]",
  partial: "[partial]",
  not_checked: "[not checked]",
};
const MAX_LISTED_RULES = 4;

/** Standards coverage notice shown under the lines, so a reader does not read "checked" as "safe". */
export const STANDARDS_NOTE =
  "Checked means a mapped rule ran to completion in this scan; it does not mean the weakness is absent. Full detail per entry: --format json (standardsCoverage, ruleStats).";

/**
 * Compact "Standards coverage" section: one line per OWASP Top 10 2025 category with its state
 * and the rules behind it (or the reason), then counts for the CWE Top 25 2025.
 */
export function formatStandardsCoverage(standards: StandardsCoverage, style: Style): string {
  const lines = standards.owasp.map((entry) => {
    const mark = STANDARD_MARKS[entry.state];
    const colored =
      entry.state === "checked"
        ? style.green(mark)
        : entry.state === "partial"
          ? style.yellow(mark)
          : style.dim(mark);
    const listed = entry.ruleIds.slice(0, MAX_LISTED_RULES).join(", ");
    const rest = entry.ruleIds.length - MAX_LISTED_RULES;
    const rules = entry.ruleIds.length === 0 ? "" : ` (${listed}${rest > 0 ? ` +${rest}` : ""})`;
    const detail = entry.state === "checked" ? rules.trim() : `${entry.reason}${rules}`;
    return `  ${colored} ${safeText(entry.id.replace(":2025", ""), 8)} ${safeText(entry.title, 60)} ${style.dim(`- ${safeText(detail, 200)}`)}`;
  });
  const counts = countStandardStates(standards.cweTop25);
  lines.push(
    `  CWE Top 25 2025: ${counts.checked} checked, ${counts.partial} partial, ${counts.not_checked} not checked`,
  );
  return lines.join("\n");
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
  const configNotices = formatConfigNotices(result.coverage, style);
  if (configNotices.length > 0) sections.push("", ...configNotices);
  // Headline counts cover regular code; test and fixture findings follow in their own group and
  // suggestions in vendored code come last.
  const { primary, test, vendored } = splitFindingsByContext(sortBySeverity(result.findings));
  const contextCounts = { test: test.length, vendored: vendored.length };
  const extra = [
    ...(test.length === 0 ? [] : [formatTestCount(test)]),
    ...(vendored.length === 0 ? [] : [formatVendoredSuggestions(vendored)]),
  ];
  sections.push(
    "",
    style.bold(`Findings by severity (${primary.length} total)`) +
      (extra.length === 0 ? "" : style.dim(` - plus ${extra.join(", ")}`)),
    formatSeverityBars(primary, style),
  );
  if (primary.length > 0) {
    sections.push("", style.bold(`Findings (${primary.length}): ${formatStatusCounts(primary)}`));
    sections.push(formatGroups(primary, style, allFindings));
  }
  if (primary.length === 0) {
    sections.push(
      "",
      `No findings${formatOutsideContexts(contextCounts)} in the areas that ran. This does not mean the project is secure; see coverage.`,
    );
  }
  const nonReal = [...test, ...vendored];
  const isCollapsing = shouldCollapse(nonReal.length, allFindings);
  // Critical and high findings are listed in full even when the rest is collapsed.
  const testShown = isCollapsing ? test.filter(isSevere) : test;
  const vendoredShown = isCollapsing ? vendored.filter(isSevere) : vendored;
  const collapsed = isCollapsing ? nonReal.filter((finding) => !isSevere(finding)) : [];
  const severeNote = isCollapsing ? " Critical and high findings are always listed." : "";
  if (testShown.length > 0) {
    sections.push(
      "",
      style.bold(`${TEST_GROUP_TITLE} (${testShown.length})`),
      style.dim(`  ${TEST_GROUP_NOTE}${configTestGroupNote(result.coverage)}${severeNote}`),
      formatGroups(testShown, style, allFindings),
    );
  }
  if (vendoredShown.length > 0) {
    sections.push(
      "",
      style.bold(`${VENDORED_FINDINGS_TITLE} (${vendoredShown.length})`),
      style.dim(`  ${VENDORED_FINDINGS_NOTE}${severeNote}`),
      formatGroups(vendoredShown, style, allFindings),
    );
  }
  if (collapsed.length > 0) sections.push("", formatCollapsed(collapsed, style));
  const listed = [...primary, ...testShown, ...vendoredShown];
  if (!allFindings && hasShortenedGroup(listed)) {
    sections.push(
      "",
      style.dim(
        `Groups show up to ${MAX_REPRESENTATIVE_LOCATIONS} locations. Run again with --all-findings to list every location.`,
      ),
    );
  }
  sections.push("", style.bold("Coverage"), formatCoverage(result.coverage, style));
  if (result.standardsCoverage !== undefined) {
    sections.push(
      "",
      style.bold("Standards coverage (OWASP Top 10 2025)"),
      formatStandardsCoverage(result.standardsCoverage, style),
      style.dim(`  ${STANDARDS_NOTE}`),
    );
  }
  sections.push("", style.dim(ANALYSIS_BASIS_NOTE));
  return sections.join("\n");
}
