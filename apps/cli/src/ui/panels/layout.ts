import { formatLocation } from "@pgard/report";
import type { Finding } from "@pgard/findings";
import { cliText, type CliText } from "../i18n/cli-text.js";
import {
  displayWidth,
  maxDisplayWidth,
  padEndWidth,
  stripAnsi,
  truncateWidth,
  wrapWidth,
} from "../i18n/display-width.js";
import { renderChart, type ChartOptions } from "../formatters/charts.js";
import {
  areaChartRows,
  formatSummaryBlock,
  owaspChartRows,
  severityChartRows,
  type RenderContext,
} from "../formatters/result-summary.js";
import { createStyle, MIN_CHART_WIDTH, safeText, type Style } from "../formatters/style.js";
import {
  CHROME_ROWS,
  MIN_SIZE,
  NARROW_COLUMNS,
  PANEL_IDS,
  type PanelId,
  type PanelsState,
  type Size,
} from "./types.js";

export interface RenderOptions {
  /** Colours; default plain (no colour codes), which is what `NO_COLOR` and a pipe get. */
  style?: Style;
  /** Block characters and Unicode punctuation allowed; default: ASCII only. */
  unicode?: boolean;
}

const PLAIN = createStyle(false);

/** Lines available to the panel body. */
export function bodyHeight(size: Size): number {
  return Math.max(1, size.rows - CHROME_ROWS);
}

export function isTooSmall(size: Size): boolean {
  return size.columns < MIN_SIZE.columns || size.rows < MIN_SIZE.rows;
}

/** A line never runs past the terminal width: when cut, colour codes are dropped. */
function fit(line: string, columns: number): string {
  return displayWidth(line) <= columns ? line : truncateWidth(stripAnsi(line), columns);
}

/** Charts become plain count lines under 60 columns; the narrow layout is 60 and fewer. */
function chartWidth(columns: number): number {
  return columns <= NARROW_COLUMNS ? Math.min(columns, MIN_CHART_WIDTH - 1) : columns;
}

function chartOptions(columns: number, style: Style, unicode: boolean | undefined): ChartOptions {
  return {
    width: chartWidth(columns),
    isColor: style.enabled,
    ...(unicode === undefined ? {} : { unicode }),
  };
}

function contextOf(
  columns: number,
  style: Style,
  t: CliText,
  unicode: boolean | undefined,
): RenderContext {
  return { style, t, width: columns, allFindings: false, unicode };
}

function overviewLines(state: PanelsState, size: Size, opts: RenderOptions): string[] {
  const style = opts.style ?? PLAIN;
  const t = cliText(state.locale);
  const ctx = contextOf(size.columns, style, t, opts.unicode);
  const summary = formatSummaryBlock(state.result, null, ctx);
  return [
    ...summary,
    ...(summary.length > 0 ? [""] : []),
    style.bold(t.chartBySeverity(false, state.findings.length)),
    ...renderChart(
      severityChartRows(state.findings, style, t),
      chartOptions(size.columns, style, opts.unicode),
    ),
  ];
}

function chartsLines(state: PanelsState, size: Size, opts: RenderOptions): string[] {
  const style = opts.style ?? PLAIN;
  const t = cliText(state.locale);
  if (state.findings.length === 0) return [t.panels.noFindings];
  const options = chartOptions(size.columns, style, opts.unicode);
  return [
    style.bold(t.chartByOwasp),
    ...renderChart(owaspChartRows(state.findings, t), options),
    "",
    style.bold(t.chartByArea),
    ...renderChart(areaChartRows(state.findings, state.result.requestedScopes, t), options),
  ];
}

function coverageLines(state: PanelsState, size: Size, opts: RenderOptions): string[] {
  const style = opts.style ?? PLAIN;
  const t = cliText(state.locale);
  const coverage = state.result.coverage;
  if (coverage.length === 0) return [t.noCoverage];
  const lines = [style.bold(t.coverageTitle)];
  for (const entry of coverage) {
    const mark = `[${t.coverageMark[entry.status] ?? "?"}]`;
    // Never green: a completed area is not a pass.
    const painted =
      entry.status === "completed"
        ? mark
        : entry.status === "not_selected"
          ? style.dim(mark)
          : style.yellow(mark);
    const label = t.report.coverageStatus[entry.status] ?? "?";
    const head = truncateWidth(`${safeText(entry.area, 80)} (${label})`, size.columns - 4);
    lines.push(`  ${painted} ${head}`);
    if (entry.note !== null) {
      const note = t.scanText(safeText(entry.note, 300));
      for (const part of wrapWidth(note, Math.max(10, size.columns - 6))) {
        lines.push(style.dim(`      ${part}`));
      }
    }
  }
  return lines;
}

function helpLines(state: PanelsState, size: Size, opts: RenderOptions): string[] {
  const style = opts.style ?? PLAIN;
  const t = cliText(state.locale);
  return [
    style.bold(t.panels.helpTitle),
    "",
    ...t.panels.helpLines.flatMap((line) => {
      const [first = "", ...rest] = wrapWidth(line, Math.max(10, size.columns - 1));
      return [first, ...rest.map((part) => `  ${part}`)];
    }),
  ];
}

/** Body lines of every panel except the findings list (which is windowed, see `findingRow`). */
export function panelLines(state: PanelsState, size: Size, opts: RenderOptions = {}): string[] {
  switch (state.panel) {
    case "overview":
      return overviewLines(state, size, opts);
    case "charts":
      return chartsLines(state, size, opts);
    case "coverage":
      return coverageLines(state, size, opts);
    case "findings":
      return [];
  }
}

/** How many scrollable lines (rows for the findings list) the panel has. */
export function panelLength(state: PanelsState, size: Size): number {
  if (state.overlay === "help") return helpLines(state, size, {}).length;
  return state.panel === "findings" ? state.findings.length : panelLines(state, size).length;
}

interface RowColumns {
  tag: number;
  status: number;
}

function severityTag(finding: Finding, t: CliText): string {
  return `[${(t.report.severity[finding.severity] ?? finding.severity).toUpperCase()}]`;
}

function statusWord(finding: Finding, t: CliText): string {
  return t.report.findingStatus[finding.status] ?? finding.status;
}

function rowColumns(findings: readonly Finding[], t: CliText): RowColumns {
  return {
    tag: maxDisplayWidth(findings.map((finding) => severityTag(finding, t))),
    status: maxDisplayWidth(findings.map((finding) => statusWord(finding, t))),
  };
}

/**
 * One list row: severity, status, `file:line`, and (unless narrow) the title. Only fields the
 * result screen also prints are used, all through `safeText`; evidence is deliberately absent
 * (M6-3 shows it in the detail view, redacted like the result screen).
 */
function findingRow(
  finding: Finding,
  isSelected: boolean,
  columns: RowColumns,
  size: Size,
  t: CliText,
  style: Style,
): string {
  const tag = padEndWidth(severityTag(finding, t), columns.tag);
  const status = padEndWidth(statusWord(finding, t), columns.status);
  const place = safeText(formatLocation(finding.location), 300);
  const flag =
    finding.suppression !== undefined
      ? `(${t.panels.suppressed}) `
      : finding.inBaseline === true
        ? `(${t.panels.inBaseline}) `
        : "";
  const isNarrow = size.columns <= NARROW_COLUMNS;
  const title = isNarrow ? "" : `  ${flag}${safeText(finding.title, 200)}`;
  const marker = isSelected ? ">" : " ";
  const fixed = 1 + 1 + columns.tag + 1 + columns.status + 1;
  const rest = truncateWidth(
    `${isNarrow ? flag : ""}${place}${title}`,
    Math.max(4, size.columns - fixed),
  );
  if (isSelected) {
    const line = `${marker} ${tag} ${status} ${rest}`;
    return style.inverse(style.enabled ? padEndWidth(line, size.columns) : line);
  }
  return `${marker} ${style.severity(finding.severity, tag)} ${style.dim(status)} ${rest}`;
}

function tabBar(state: PanelsState, size: Size, style: Style): string {
  const t = cliText(state.locale);
  const labels = PANEL_IDS.map((id: PanelId) =>
    id === "findings" ? `${t.panels.tabs[id]} (${state.findings.length})` : t.panels.tabs[id],
  );
  const plain = PANEL_IDS.map((id, index) =>
    id === state.panel ? `[${labels[index]}]` : (labels[index] ?? ""),
  ).join("  ");
  if (displayWidth(plain) > size.columns) {
    return truncateWidth(`[${labels[PANEL_IDS.indexOf(state.panel)]}]`, size.columns);
  }
  return PANEL_IDS.map((id, index) =>
    id === state.panel
      ? style.bold(style.inverse(`[${labels[index]}]`))
      : style.dim(labels[index] ?? ""),
  ).join("  ");
}

function footer(
  state: PanelsState,
  size: Size,
  from: number,
  to: number,
  total: number,
  style: Style,
): string {
  const t = cliText(state.locale);
  if (state.overlay === "confirm-cancel") return style.yellow(t.panels.confirmCancel);
  const position =
    total > to - from + 1 && state.overlay === "none" ? t.panels.position(from, to, total) : "";
  const room = size.columns - (position === "" ? 0 : displayWidth(position) + 1);
  const hints = padEndWidth(truncateWidth(t.panels.hints, Math.max(0, room)), Math.max(0, room));
  return style.dim(position === "" ? hints.trimEnd() : `${hints} ${position}`);
}

function titleLine(state: PanelsState, size: Size, style: Style): string {
  const t = cliText(state.locale);
  const target = state.result.target;
  const repo = safeText(target.repo ?? t.unknown, 120);
  const revision = safeText((target.revision ?? t.unknown).slice(0, 12), 20);
  const status = t.report.overall[state.result.overallStatus] ?? t.unknown;
  return style.bold(
    truncateWidth(`${t.panels.title}  ${repo} @ ${revision}  ${status}`, size.columns),
  );
}

/**
 * Pure: the whole screen as exactly `size.rows` lines, none wider than `size.columns`. Colour
 * codes appear only when `opts.style` has colour. The terminal is not touched here.
 */
export function renderFrame(state: PanelsState, size: Size, opts: RenderOptions = {}): string[] {
  const style = opts.style ?? PLAIN;
  const t = cliText(state.locale);
  if (isTooSmall(size)) {
    const message = t.panels.tooSmall(size.columns, size.rows, MIN_SIZE.columns, MIN_SIZE.rows);
    const lines = wrapWidth(message, Math.max(1, size.columns)).map((line) =>
      fit(line, size.columns),
    );
    return Array.from({ length: size.rows }, (_, index) => lines[index] ?? "");
  }
  const height = bodyHeight(size);
  let body: string[];
  let total: number;
  let top: number;
  if (state.overlay === "help") {
    const lines = helpLines(state, size, opts);
    total = lines.length;
    top = Math.min(state.helpScroll, Math.max(0, total - height));
    body = lines.slice(top, top + height);
  } else if (state.panel === "findings") {
    total = state.findings.length;
    top = Math.min(state.scroll.findings, Math.max(0, total - height));
    if (total === 0) {
      body = [t.panels.noFindings];
    } else {
      const columns = rowColumns(state.findings, t);
      body = state.findings
        .slice(top, top + height)
        .map((finding, index) =>
          findingRow(finding, top + index === state.selected, columns, size, t, style),
        );
    }
  } else {
    const lines = panelLines(state, size, opts);
    total = lines.length;
    top = Math.min(state.scroll[state.panel], Math.max(0, total - height));
    body = lines.slice(top, top + height);
  }
  const shown = Math.min(top + height, total);
  const frame = [
    titleLine(state, size, style),
    tabBar(state, size, style),
    ...body.map((line) => fit(line, size.columns)),
  ];
  while (frame.length < size.rows - 1) frame.push("");
  frame.push(footer(state, size, top + 1, shown, total, style));
  return frame.map((line) => fit(line, size.columns));
}
