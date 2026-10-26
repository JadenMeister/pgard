import {
  SEVERITIES,
  getOwaspCategory,
  OWASP_ID_PATTERN,
  summarizeBySeverity,
  type Finding,
  type RuleTextCatalog,
  type ScanComparison,
  type ScanResult,
} from "@pgard/findings";
import { formatScanTime } from "../../flows/scan-diff-summary.js";
import { padEndWidth, maxDisplayWidth } from "../i18n/display-width.js";
import type { CliText } from "../i18n/cli-text.js";
import { renderChart, type ChartRow } from "./charts.js";
import { safeText, type Style } from "./style.js";

/** What every section renderer needs: colours, language, width and the rule catalog. */
export interface RenderContext {
  style: Style;
  t: CliText;
  /** Terminal columns. */
  width: number;
  allFindings: boolean;
  ruleTexts?: RuleTextCatalog | undefined;
}

/** The comparison with the previous stored scan, when there is one. */
export interface ScanDiff {
  comparison: ScanComparison;
  previousSavedAt: Date;
}

/** Areas that report a scan setting rather than analysis, not counted as scanned areas. */
const CONFIG_AREA = /^source:config(-|$)/;

function distinct<T>(values: Iterable<T>): Set<T> {
  return new Set(values);
}

/** The largest count any rule recorded for a unit: the size of the target, not a sum over rules. */
function targetSize(result: ScanResult, unit: string): number | null {
  let largest: number | null = null;
  for (const stat of result.ruleStats ?? []) {
    for (const target of stat.targets) {
      if (target.unit === unit && target.examined !== null) {
        largest = Math.max(largest ?? 0, target.examined);
      }
    }
  }
  return largest;
}

/** Seconds between the two timestamps, or null when either is not a valid time. */
function elapsedMilliseconds(result: ScanResult): number | null {
  const start = Date.parse(result.startedAt);
  const end = Date.parse(result.finishedAt);
  return Number.isNaN(start) || Number.isNaN(end) || end < start ? null : end - start;
}

export function compactDiff(diff: ScanDiff, t: CliText): string {
  const comparison = diff.comparison;
  const unclear = comparison.uncertainAreas.length > 0 || comparison.notComparable.length > 0;
  return `${t.diffCompact(comparison.new.length, comparison.noLongerReported.length, unclear)} (${formatScanTime(diff.previousSavedAt)})`;
}

/**
 * "Summary": areas scanned and their status, how many rules ran, the size of the target, how long
 * it took and (when there is an earlier stored scan) what changed since. A row is left out when
 * its data is not in the result (results of PGARD 1.0 have no `ruleStats`).
 */
export function formatSummaryBlock(
  result: ScanResult,
  diff: ScanDiff | null,
  ctx: RenderContext,
): string[] {
  const { t, style } = ctx;
  const rows: Array<[string, string]> = [];
  const areas = result.coverage.filter((entry) => !CONFIG_AREA.test(entry.area));
  const count = (status: string): number => areas.filter((entry) => entry.status === status).length;
  const scanned = areas.filter((entry) => entry.status !== "not_selected");
  if (areas.length > 0) {
    rows.push([
      t.summaryLabels.areas,
      t.areasValue({
        total: scanned.length,
        completed: count("completed"),
        partial: count("partial"),
        notTested: count("not_tested"),
        notSelected: count("not_selected"),
      }),
    ]);
  }
  const stats = result.ruleStats;
  if (stats !== undefined) {
    const ran = distinct(stats.map((stat) => stat.ruleId));
    const partial = distinct(
      stats.filter((stat) => stat.status === "partial").map((stat) => stat.ruleId),
    );
    rows.push([t.summaryLabels.rules, t.rulesValue(ran.size, partial.size)]);
  }
  const files = targetSize(result, "files");
  const commits = targetSize(result, "commits");
  const pages = targetSize(result, "pages");
  if (files !== null || commits !== null || pages !== null) {
    rows.push([t.summaryLabels.target, t.targetValue({ files, commits, pages })]);
  }
  const elapsed = elapsedMilliseconds(result);
  if (elapsed !== null) rows.push([t.summaryLabels.elapsed, t.elapsedValue(elapsed)]);
  if (diff !== null) rows.push([t.summaryLabels.sinceLast, compactDiff(diff, t)]);
  if (rows.length === 0) return [];
  const labelWidth = maxDisplayWidth(rows.map(([label]) => label));
  return [
    style.bold(t.summaryTitle),
    ...rows.map(([label, value]) => `  ${padEndWidth(label, labelWidth)}  ${safeText(value, 300)}`),
  ];
}

/** Counts of findings per OWASP Top 10 2025 category (a finding counts once per category). */
export function owaspChartRows(findings: readonly Finding[], t: CliText): ChartRow[] {
  const counts = new Map<string, number>();
  let unmapped = 0;
  for (const finding of findings) {
    const ids = distinct(finding.references.owasp);
    if (ids.size === 0) unmapped += 1;
    for (const id of ids) counts.set(id, (counts.get(id) ?? 0) + 1);
  }
  const rows: ChartRow[] = [...counts.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([id, count]) => {
      const title = OWASP_ID_PATTERN.test(id) ? getOwaspCategory(id)?.title : undefined;
      const short = OWASP_ID_PATTERN.test(id) ? id.replace(":2025", "") : safeText(id, 20);
      return { label: title === undefined ? short : `${short} ${title}`, count };
    });
  if (unmapped > 0) rows.push({ label: t.chartUnmapped, count: unmapped });
  return rows;
}

/** Counts of findings per scope (code, history, web): the areas a finding came from. */
export function areaChartRows(
  findings: readonly Finding[],
  requested: ScanResult["requestedScopes"],
  t: CliText,
): ChartRow[] {
  return (["code", "history", "web"] as const)
    .filter((scope) => requested.includes(scope) || findings.some((f) => f.sources.includes(scope)))
    .map((scope) => ({
      label: t.scopeName[scope],
      count: findings.filter((finding) => finding.sources.includes(scope)).length,
    }));
}

export function severityChartRows(
  findings: readonly Finding[],
  style: Style,
  t: CliText,
): ChartRow[] {
  const counts = summarizeBySeverity(findings);
  return SEVERITIES.map((severity) => ({
    label: t.report.severity[severity],
    count: counts[severity],
    paint: (text: string) => style.severity(severity, text),
  }));
}

/** The OWASP and area charts; empty when there are no findings to chart. */
export function formatSecondaryCharts(
  findings: readonly Finding[],
  requested: ScanResult["requestedScopes"],
  ctx: RenderContext,
): string[] {
  if (findings.length === 0) return [];
  const options = { width: ctx.width, isColor: ctx.style.enabled };
  return [
    "",
    ctx.style.bold(ctx.t.chartByOwasp),
    ...renderChart(owaspChartRows(findings, ctx.t), options),
    "",
    ctx.style.bold(ctx.t.chartByArea),
    ...renderChart(areaChartRows(findings, requested, ctx.t), options),
  ];
}
