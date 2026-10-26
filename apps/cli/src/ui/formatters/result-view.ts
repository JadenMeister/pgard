import {
  baselineNotices,
  countBySeverity,
  partitionFindings,
  suppressionNotices,
  countStandardStates,
  projectConfigNotices,
  configTestFindingCount,
  splitFindingsByContext,
  type AuthorizationSummary,
  type Coverage,
  type Finding,
  type RuleTextCatalog,
  type ScanResult,
  type Severity,
  type StandardCheckState,
  type StandardsCoverage,
  type SuppressionNotice,
} from "@pgard/findings";
import { formatLocation, summarizeStatusSplit } from "@pgard/report";
import { AUTHORIZATION_CHECK_ORDER, AUTHORIZATION_REASON_MAX_LENGTH } from "@pgard/scan-core";
import { renderChart } from "./charts.js";
import { CLI_TEXT, type CliText } from "../i18n/cli-text.js";
import { maxDisplayWidth, padEndWidth, truncateWidth } from "../i18n/display-width.js";
import {
  COLLAPSE_THRESHOLD,
  groupFindings,
  MAX_REPRESENTATIVE_LOCATIONS,
  shouldCollapse,
  sortBySeverity,
  summarizeCollapsed,
  type FindingGroup,
} from "./result-groups.js";
import {
  formatSecondaryCharts,
  formatSummaryBlock,
  severityChartRows,
  type RenderContext,
  type ScanDiff,
} from "./result-summary.js";
import { safeText, type Style } from "./style.js";

export type { ScanDiff } from "./result-summary.js";

const DEFAULT_WIDTH = 80;
const EN = CLI_TEXT.en;

function contextOf(
  style: Style,
  t: CliText = EN,
  extra: Partial<Omit<RenderContext, "style" | "t">> = {},
): RenderContext {
  return { style, t, width: DEFAULT_WIDTH, allFindings: false, ...extra };
}

/** Horizontal bar chart of findings per severity, sized to `width` columns. */
export function formatSeverityBars(
  findings: readonly Finding[],
  style: Style,
  t: CliText = EN,
  width = DEFAULT_WIDTH,
): string {
  return renderChart(severityChartRows(findings, style, t), {
    width,
    isColor: style.enabled,
  }).join("\n");
}

/** How to see everything that was collapsed or shortened (English; see `CliText.showAllHint`). */
export const SHOW_ALL_HINT = EN.showAllHint;

const MAX_SUMMARY_RULES = 10;
const MAX_STANDARD_LINKS = 5;

function allSame(values: readonly string[]): boolean {
  return values.every((value) => value === values[0]);
}

/** Official standards of a rule, one per line with its link; only https links are shown. */
function standardLines(ruleId: string, ctx: RenderContext): string[] {
  const links = (ctx.ruleTexts?.get(ruleId)?.details?.standards ?? []).filter((link) =>
    link.url.startsWith("https://"),
  );
  if (links.length === 0) return [];
  const shown = links.slice(0, MAX_STANDARD_LINKS).map((link) => {
    const title = link.title === null ? "" : ` ${truncateWidth(safeText(link.title, 200), 40)}`;
    const via = link.viaCwe === undefined ? "" : ` (${ctx.t.report.viaCwe(link.viaCwe)})`;
    return `        ${safeText(link.id, 20)}${title}${via} ${ctx.style.dim(safeText(link.url, 200))}`;
  });
  const rest = links.length - shown.length;
  return [
    `      ${ctx.t.standards}:`,
    ...shown,
    ...(rest > 0 ? [ctx.style.dim(`        +${rest}`)] : []),
  ];
}

function formatGroup(group: FindingGroup, ctx: RenderContext): string {
  const { style, t } = ctx;
  const finding = group.representative;
  const members = group.findings;
  const count = members.length;
  const severity = style.severity(
    finding.severity,
    `[${t.report.severity[finding.severity].toUpperCase()}]`,
  );
  const status = t.report.findingStatus[finding.status] ?? finding.status;
  const lines = [
    `  ${severity} ${style.bold(safeText(finding.title, 300))} ${style.dim(`(${t.locationsDetail(status, count)})`)}`,
  ];
  const rule = style.dim(
    `${safeText(finding.ruleId, 40)} - ${t.confidence} ${t.report.confidenceLevel[finding.confidence] ?? finding.confidence}`,
  );
  const places = members.map((member) => safeText(formatLocation(member.location), 500));
  const evidence = (member: Finding): string => safeText(member.evidence, 500);
  const fix = (member: Finding): string => safeText(member.recommendation, 500);
  const isFixShared = allSame(members.map(fix));
  if (count === 1) {
    lines.push(
      `      ${places[0]}  ${rule}`,
      `      ${t.evidence}: ${evidence(finding)}`,
      `      ${t.fix}: ${fix(finding)}`,
    );
  } else if (ctx.allFindings) {
    // Every location with its own evidence: nothing is shown for one member on behalf of others.
    lines.push(`      ${rule}`);
    members.forEach((member, index) => {
      lines.push(`      - ${places[index]}`, `          ${t.evidence}: ${evidence(member)}`);
      if (!isFixShared) lines.push(`          ${t.fix}: ${fix(member)}`);
    });
    if (isFixShared) lines.push(`      ${t.fix}: ${fix(finding)}`);
  } else {
    const shown = places.slice(0, MAX_REPRESENTATIVE_LOCATIONS);
    const rest = count - shown.length;
    lines.push(`      ${shown.join(", ")}${rest > 0 ? t.andMore(rest) : ""}  ${rule}`);
    lines.push(
      allSame(members.map(evidence))
        ? `      ${t.evidence}: ${evidence(finding)}`
        : `      ${t.evidence}: ${t.variesByLocation}`,
      isFixShared ? `      ${t.fix}: ${fix(finding)}` : `      ${t.fix}: ${t.variesByLocation}`,
    );
  }
  lines.push(...standardLines(finding.ruleId, ctx));
  return lines.join("\n");
}

function formatGroups(findings: readonly Finding[], ctx: RenderContext): string {
  return groupFindings(findings)
    .map((group) => formatGroup(group, ctx))
    .join("\n\n");
}

function hasShortenedGroup(findings: readonly Finding[]): boolean {
  return groupFindings(findings).some(
    (group) => group.findings.length > MAX_REPRESENTATIVE_LOCATIONS,
  );
}

const isSevere = (finding: Pick<Finding, "severity">): boolean =>
  finding.severity === "critical" || finding.severity === "high";

function breakdownCounts(findings: readonly Pick<Finding, "severity">[]): Record<Severity, number> {
  return countBySeverity(findings);
}

/** Only the critical and high counts, so severe matches are not hidden in a total. */
function severeBreakdown(findings: readonly Finding[], t: CliText): string {
  const counts = breakdownCounts(findings);
  return t.breakdown({ ...counts, medium: 0, low: 0, info: 0 });
}

/** "(1 critical, 5 high)" for a list, or "" when the list is empty. */
function breakdownOf(findings: readonly Finding[], t: CliText): string {
  return t.breakdown(breakdownCounts(findings));
}

function formatContextName(context: string, t: CliText): string {
  return t.contextName[context] ?? safeText(context, 20);
}

/** Summary that replaces the listing of lower-severity test, fixture and vendored findings. */
function formatCollapsed(findings: readonly Finding[], ctx: RenderContext): string {
  const { style, t } = ctx;
  const summary = summarizeCollapsed(findings);
  const rules = summary.byRule.slice(0, MAX_SUMMARY_RULES);
  const moreRules = summary.byRule.length - rules.length;
  return [
    style.bold(t.collapsedTitle(summary.count)),
    style.dim(t.collapsedNote(COLLAPSE_THRESHOLD)),
    `  ${t.byContext}: ${summary.byContext.map((entry) => `${formatContextName(entry.context, t)} ${entry.count}`).join(", ")}`,
    `  ${t.byRule}: ${rules.map((entry) => `${safeText(entry.ruleId, 40)} x${entry.count}`).join(", ")}${moreRules > 0 ? t.moreRules(moreRules) : ""}`,
    `  ${t.bySeverity}: ${summary.bySeverity.map((entry) => `${t.report.severity[entry.severity as Severity] ?? entry.severity} ${entry.count}`).join(", ")}`,
    `  ${t.showAllHint}`,
  ].join("\n");
}

function formatCoverageMark(status: string, t: CliText): string {
  return `[${(t.coverageMark as Record<string, string>)[status] ?? "?"}]`;
}

export function formatCoverage(
  coverage: readonly Coverage[],
  style: Style,
  t: CliText = EN,
): string {
  if (coverage.length === 0) return `  ${t.noCoverage}`;
  return coverage
    .map((entry) => {
      const mark = formatCoverageMark(entry.status, t);
      const colored =
        entry.status === "completed"
          ? style.green(mark)
          : entry.status === "not_selected"
            ? style.dim(mark)
            : style.yellow(mark);
      const note = entry.note === null ? "" : style.dim(` - ${safeText(entry.note, 300)}`);
      const label = (t.report.coverageStatus as Record<string, string>)[entry.status] ?? "?";
      return `  ${colored} ${safeText(entry.area, 80)} (${label})${note}`;
    })
    .join("\n");
}

const EXCLUDED_PATTERN = /^(\d+) files? excluded by pgard\.config\.json(.*)$/s;

function localizedConfigNoticeText(
  notice: ReturnType<typeof projectConfigNotices>[number],
  t: CliText,
): string {
  if (t.locale === "en") return notice.text;
  if (notice.kind === "demoted") return t.configDemoted(notice.count ?? 0);
  if (notice.kind === "excluded") {
    const match = EXCLUDED_PATTERN.exec(notice.text);
    if (match !== null) return t.configExcluded(Number(match[1]), match[2] ?? "");
  }
  // The detail (counts, quoted patterns) is the scan's own wording; only the frame is translated.
  return `${t.configNoticePrefix}${notice.text}`;
}

/**
 * Prominent lines for the project configuration file, shown above the findings so exclusions are
 * never missed in the coverage list: "N files excluded by pgard.config.json ..." and any warning
 * or problem with the file itself.
 */
export function formatConfigNotices(
  coverage: readonly Coverage[],
  style: Style,
  t: CliText = EN,
): string[] {
  return projectConfigNotices(coverage).map((notice) => {
    const text = safeText(localizedConfigNoticeText(notice, t), 300);
    return notice.tone === "warning"
      ? style.yellow(style.bold(`! ${text}`))
      : style.dim(`  ${text}`);
  });
}

function suppressionNoticeText(notice: SuppressionNotice, t: CliText): string {
  const texts = t.report.notices;
  if (texts === null) return notice.text;
  const rule = notice.ruleId ?? "";
  const path = notice.path ?? "";
  const count = notice.count ?? 0;
  switch (notice.kind) {
    case "severe":
      return texts.severe(count, notice.high ?? 0, notice.critical ?? 0);
    case "everything":
      return texts.everything(count);
    case "incomplete":
      return texts.incomplete;
    case "expired":
      return texts.expired(rule, path, notice.expires ?? "?");
    case "far":
      return texts.far(rule, path, notice.expires ?? "?");
    case "wildcard":
      return texts.wildcard(rule, path, count);
    case "total":
      return texts.total(count);
    case "broad":
      return texts.broad(rule, path, count);
    case "noexpiry":
      return t.notices.noExpiry(count);
  }
}

/**
 * Prominent `!` lines for what the suppressions of pgard.config.json did (critical findings,
 * wildcards, broad or expired entries), and for a baseline that is incomplete. Shown above the
 * findings, like the config notices.
 */
export function formatSuppressionNotices(
  result: ScanResult,
  style: Style,
  t: CliText = EN,
): string[] {
  const texts = t.report.notices;
  const line = (tone: "warning" | "info", text: string): string =>
    tone === "warning"
      ? style.yellow(style.bold(`! ${safeText(text, 400)}`))
      : style.dim(`  ${safeText(text, 400)}`);
  return [
    ...suppressionNotices(result).map((notice) =>
      line(notice.tone, suppressionNoticeText(notice, t)),
    ),
    ...baselineNotices(result.baseline).map((notice) =>
      line(
        notice.tone,
        texts === null
          ? notice.text
          : notice.kind === "uncertain"
            ? texts.baselineUncertain(notice.count ?? 0)
            : texts.baselineTool,
      ),
    ),
  ];
}

/** The always-visible count lines: suppressed (with critical) and baseline. */
export function formatSuppressionAndBaselineCounts(
  result: ScanResult,
  style: Style,
  t: CliText = EN,
): string[] {
  const lines: string[] = [];
  if (result.suppressions !== undefined) {
    lines.push(
      style.bold(
        t.suppressedCountLine(
          result.suppressions.suppressed,
          breakdownOf(
            result.findings.filter((f) => f.suppression !== undefined),
            t,
          ),
        ),
      ),
    );
  }
  if (result.baseline !== undefined) {
    const when = safeText(result.baseline.setAt.slice(0, 10), 10);
    lines.push(
      style.bold(
        t.baselineCountLine(
          result.baseline.matched,
          result.baseline.new,
          breakdownOf(partitionFindings(result.findings).baseline, t),
          when,
        ),
      ),
    );
  }
  return lines;
}

const isCritical = (finding: Pick<Finding, "severity">): boolean => finding.severity === "critical";

/** Suppressed findings in full, each bucket under the reason the config gave. */
function formatSuppressedGroups(findings: readonly Finding[], ctx: RenderContext): string {
  const buckets = new Map<string, Finding[]>();
  for (const finding of findings) {
    const suppression = finding.suppression;
    const key = `${suppression?.reason ?? ""}\u001f${suppression?.expires ?? ""}`;
    const members = buckets.get(key);
    if (members === undefined) buckets.set(key, [finding]);
    else members.push(finding);
  }
  return [...buckets.values()]
    .map((members) => {
      const suppression = members[0]?.suppression;
      const expires = suppression?.expires === undefined ? "" : safeText(suppression.expires, 10);
      return [
        ctx.style.dim(
          `  ${ctx.t.suppressedReason(JSON.stringify(safeText(suppression?.reason ?? "", 300)), expires)}`,
        ),
        formatGroups(members, ctx),
      ].join("\n");
    })
    .join("\n\n");
}

/** Counts by severity and rule, for a group that is not listed in full. */
function formatGroupSummary(findings: readonly Finding[], ctx: RenderContext): string[] {
  const { t } = ctx;
  const summary = summarizeCollapsed(findings);
  const rules = summary.byRule.slice(0, MAX_SUMMARY_RULES);
  const more = summary.byRule.length - rules.length;
  return [
    `  ${t.byRule}: ${rules.map((entry) => `${safeText(entry.ruleId, 40)} x${entry.count}`).join(", ")}${more > 0 ? t.moreRules(more) : ""}`,
    `  ${t.bySeverity}: ${summary.bySeverity.map((entry) => `${t.report.severity[entry.severity as Severity] ?? entry.severity} ${entry.count}`).join(", ")}`,
    ctx.style.dim(`  ${t.showAllHint}`),
  ];
}

/**
 * A group that is listed only on request, except critical findings, which are always listed:
 * the count in the title is always shown, the rest as a summary.
 */
function formatOptionalGroup(
  title: string,
  note: string,
  findings: readonly Finding[],
  ctx: RenderContext,
  list: (members: readonly Finding[]) => string,
): string[] {
  const { style, t } = ctx;
  const critical = findings.filter(isCritical);
  const others = findings.filter((finding) => !isCritical(finding));
  const lines = ["", style.bold(`${title} (${findings.length})`), style.dim(`  ${note}`)];
  if (ctx.allFindings) {
    lines.push(list(findings));
    return lines;
  }
  if (critical.length > 0) lines.push(list(critical));
  if (others.length > 0) {
    lines.push(
      style.dim(`  ${t.notListedHere(others.length, critical.length > 0)}`),
      ...formatGroupSummary(others, ctx),
    );
  }
  return lines;
}

/** The standards line states, in the order a reader scans them. */
const STANDARD_STATES: readonly StandardCheckState[] = [
  "rules_ran",
  "rules_partial",
  "not_run",
  "no_rules",
];
const MAX_LISTED_RULES = 4;

/** Shown under the lines so a reader does not take "rules ran" for "safe" or "covered". */
export const STANDARDS_NOTE = EN.standardsNote;

/**
 * Compact "Standards coverage" section: one line per OWASP Top 10 2025 category with its state,
 * how many of the category's CWEs have a rule, and the rules behind it (or the reason), then
 * counts for the CWE Top 25 2025. Nothing is coloured green: a rule that ran is not a pass.
 * Columns are padded by display width, so Korean state words line up.
 */
export function formatStandardsCoverage(
  standards: StandardsCoverage,
  style: Style,
  t: CliText = EN,
): string {
  const marks = Object.fromEntries(
    STANDARD_STATES.map((state) => [state, `[${t.standardMark[state]}]`]),
  ) as Record<StandardCheckState, string>;
  const markWidth = maxDisplayWidth(Object.values(marks));
  const lines = standards.owasp.map((entry) => {
    const mark = padEndWidth(marks[entry.state], markWidth);
    const colored =
      entry.state === "rules_ran"
        ? mark
        : entry.state === "rules_partial"
          ? style.yellow(mark)
          : style.dim(mark);
    const listed = entry.ruleIds.slice(0, MAX_LISTED_RULES).join(", ");
    const rest = entry.ruleIds.length - MAX_LISTED_RULES;
    const rules = entry.ruleIds.length === 0 ? "" : ` (${listed}${rest > 0 ? ` +${rest}` : ""})`;
    const breadth =
      entry.breadth === null
        ? ""
        : t.standardsBreadth(entry.breadth.cwesWithRules, entry.breadth.cwesInCategory);
    // Rule ids come before the reason, so a long reason is what gets cut, never the rules.
    const head = entry.state === "no_rules" ? entry.reason : `${breadth}${rules}`;
    const tail =
      entry.state === "rules_ran" || entry.state === "no_rules" ? "" : `; ${entry.reason}`;
    const detail = `${head}${tail}`;
    return `  ${colored} ${safeText(entry.id.replace(":2025", ""), 8)} ${safeText(entry.title, 60)} ${style.dim(`- ${safeText(detail, 240)}`)}`;
  });
  lines.push(`  ${t.cweTop25Line(countStandardStates(standards.cweTop25))}`);
  return lines.join("\n");
}

/** Per-check authorization reasons, in the policy's evaluation order. */
export function formatAuthorization(
  summary: AuthorizationSummary,
  style: Style,
  t: CliText = EN,
): string {
  const ordered = [...summary.checks].sort(
    (a, b) => AUTHORIZATION_CHECK_ORDER.indexOf(a.id) - AUTHORIZATION_CHECK_ORDER.indexOf(b.id),
  );
  const lines = ordered.map((check) => {
    const word = (t.checkStatus as Record<string, string>)[check.status];
    const mark = word === undefined ? "[?]" : `[${word}]`;
    const colored = check.status === "passed" ? style.green(mark) : style.red(mark);
    const name = t.checkName[check.id] ?? check.id.replace(/_/g, " ");
    return `  ${colored} ${name}: ${safeText(check.reason, AUTHORIZATION_REASON_MAX_LENGTH)}`;
  });
  const decision =
    summary.decision === "allowed"
      ? style.green(t.authorizationAllowed)
      : style.red(t.authorizationBlocked);
  return `${style.bold(decision)}\n${lines.join("\n")}`;
}

export interface ScanResultOptions {
  /** List every finding and location. */
  allFindings?: boolean;
  /** Language of the fixed screen text. Default English. */
  locale?: "en" | "ko";
  /** Terminal columns; charts shrink to fit, and below 60 become plain count lines. */
  width?: number;
  /** Rule catalog, for the standards links shown with each finding. */
  ruleTexts?: RuleTextCatalog;
  /** The comparison with the previous stored scan, shown in the summary. */
  diff?: ScanDiff | null;
}

function outsideContexts(counts: { test: number; vendored: number }) {
  if (counts.test > 0 && counts.vendored > 0) return "both" as const;
  if (counts.test > 0) return "test" as const;
  if (counts.vendored > 0) return "vendored" as const;
  return "none" as const;
}

/** Full terminal result view: status, summary, charts, findings, coverage, analysis basis. */
export function formatScanResult(
  result: ScanResult,
  style: Style,
  options: ScanResultOptions = {},
): string {
  const t = CLI_TEXT[options.locale ?? "en"];
  const ctx = contextOf(style, t, {
    allFindings: options.allFindings === true,
    width: options.width ?? DEFAULT_WIDTH,
    ruleTexts: options.ruleTexts,
  });
  const allFindings = ctx.allFindings;
  const sections: string[] = [];
  const target = result.target;
  sections.push(
    `${style.bold(t.scanResult)} - ${t.report.overall[result.overallStatus] ?? t.unknown}`,
    style.dim(
      `${t.repository} ${safeText(target.repo ?? t.unknown, 120)} @ ${safeText((target.revision ?? t.unknown).slice(0, 12), 20)}` +
        (target.webOrigin === null ? "" : ` - ${t.web} ${safeText(target.webOrigin, 60)}`) +
        ` - ${t.scopes}: ${result.requestedScopes.join(", ")}`,
    ),
  );
  if (result.overallStatus === "blocked") {
    sections.push("", formatAuthorization(result.authorization, style, t));
    return sections.join("\n");
  }
  const configNotices = formatConfigNotices(result.coverage, style, t);
  if (configNotices.length > 0) sections.push("", ...configNotices);
  const suppressionLines = formatSuppressionNotices(result, style, t);
  if (suppressionLines.length > 0) sections.push("", ...suppressionLines);
  const countLines = formatSuppressionAndBaselineCounts(result, style, t);
  if (countLines.length > 0) sections.push("", ...countLines);
  const summaryLines = formatSummaryBlock(result, options.diff ?? null, ctx);
  if (summaryLines.length > 0) sections.push("", ...summaryLines);
  // Suppressed findings and findings in the baseline are listed in their own groups; headline
  // counts cover the rest, where test and fixture findings follow in their own group and
  // suggestions in vendored code come last.
  const partition = partitionFindings(sortBySeverity(result.findings));
  const { primary, test, vendored } = splitFindingsByContext(partition.rest);
  const hasBaseline = result.baseline !== undefined;
  const contextCounts = { test: test.length, vendored: vendored.length };
  const extra = [
    ...(test.length === 0 ? [] : [t.testCount(test.length, severeBreakdown(test, t))]),
    ...(vendored.length === 0
      ? []
      : [t.vendoredCount(vendored.length, severeBreakdown(vendored, t))]),
    ...(partition.suppressed.length === 0
      ? []
      : [t.suppressedCount(partition.suppressed.length, breakdownOf(partition.suppressed, t))]),
    ...(partition.baseline.length === 0 ? [] : [t.baselineCount(partition.baseline.length)]),
  ];
  sections.push(
    "",
    style.bold(t.chartBySeverity(hasBaseline, primary.length)) +
      (extra.length === 0 ? "" : style.dim(t.plus(extra))),
    formatSeverityBars(primary, style, t, ctx.width),
    ...formatSecondaryCharts(primary, result.requestedScopes, ctx),
  );
  if (primary.length > 0) {
    const split = summarizeStatusSplit(primary);
    sections.push(
      "",
      style.bold(
        t.findingsHeading(
          hasBaseline,
          primary.length,
          t.statusCounts(split.confirmed, split.suspected, split.informational),
        ),
      ),
    );
    sections.push(formatGroups(primary, ctx));
  }
  if (primary.length === 0) {
    sections.push(
      "",
      t.noFindings({
        isNew: hasBaseline,
        hasUnsuppressed: partition.suppressed.length > 0,
        outside: outsideContexts(contextCounts),
        suppressed: partition.suppressed.length,
        suppressedBreakdown: breakdownOf(partition.suppressed, t),
      }),
    );
  }
  const nonReal = [...test, ...vendored];
  const isCollapsing = shouldCollapse(nonReal.length, allFindings);
  // Critical and high findings are listed in full even when the rest is collapsed.
  const testShown = isCollapsing ? test.filter(isSevere) : test;
  const vendoredShown = isCollapsing ? vendored.filter(isSevere) : vendored;
  const collapsed = isCollapsing ? nonReal.filter((finding) => !isSevere(finding)) : [];
  const severeNote = isCollapsing ? t.severeAlwaysListed : "";
  if (testShown.length > 0) {
    const configCount = configTestFindingCount(result.coverage);
    sections.push(
      "",
      style.bold(`${t.testGroupTitle} (${testShown.length})`),
      style.dim(
        `  ${t.testGroupNote}${configCount === 0 ? "" : t.configTestNote(configCount)}${severeNote}`,
      ),
      formatGroups(testShown, ctx),
    );
  }
  if (vendoredShown.length > 0) {
    sections.push(
      "",
      style.bold(`${t.report.vendoredTitle} (${vendoredShown.length})`),
      style.dim(`  ${t.report.vendoredNote}${severeNote}`),
      formatGroups(vendoredShown, ctx),
    );
  }
  if (collapsed.length > 0) sections.push("", formatCollapsed(collapsed, ctx));
  if (partition.suppressed.length > 0) {
    sections.push(
      ...formatOptionalGroup(
        t.report.suppressedTitle,
        t.report.suppressedNote,
        partition.suppressed,
        ctx,
        (members) => formatSuppressedGroups(members, ctx),
      ),
    );
  }
  if (partition.baseline.length > 0) {
    sections.push(
      ...formatOptionalGroup(
        t.report.baselineTitle,
        t.report.baselineNote,
        partition.baseline,
        ctx,
        (members) => formatGroups(members, ctx),
      ),
    );
  }
  const listed = [...primary, ...testShown, ...vendoredShown];
  if (!allFindings && hasShortenedGroup(listed)) {
    sections.push("", style.dim(t.shortenedGroupsHint(MAX_REPRESENTATIVE_LOCATIONS)));
  }
  sections.push("", style.bold(t.coverageTitle), formatCoverage(result.coverage, style, t));
  if (result.standardsCoverage !== undefined) {
    sections.push(
      "",
      style.bold(t.standardsTitle),
      formatStandardsCoverage(result.standardsCoverage, style, t),
      style.dim(`  ${t.standardsNote}`),
    );
  }
  sections.push("", style.dim(t.report.analysisBasisNote));
  return sections.join("\n");
}
