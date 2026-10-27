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
import { fitLines } from "../formatters/fit-lines.js";
import {
  areaChartRows,
  formatSummaryBlock,
  owaspChartRows,
  severityChartRows,
  type RenderContext,
} from "../formatters/result-summary.js";
import { createStyle, MIN_CHART_WIDTH, safeText, type Style } from "../formatters/style.js";
import { hasFilters } from "./filter.js";
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
  if (state.overlay === "detail") return detailLines(state, size, {}).length;
  return state.panel === "findings" ? state.visible.length : panelLines(state, size).length;
}

/** Lines for the count and the severity, area and rule filters; the search has its own line. */
const MAX_HEADER_LINES = 3;
/** Longest rule id shown in the header. */
const MAX_HEADER_RULE = 24;

/** The end of `text` that fits `room` columns, with `...` in front when the start was cut. */
function tailWidth(text: string, room: number): string {
  if (displayWidth(text) <= room) return text;
  const chars = Array.from(text);
  let tail = "";
  let used = 3;
  for (let i = chars.length - 1; i >= 0; i -= 1) {
    const char = chars[i] ?? "";
    const next = displayWidth(char);
    if (used + next > room) break;
    tail = char + tail;
    used += next;
  }
  return `...${tail}`;
}

/** Breaks `text` into pieces of at most `width` columns, cutting anywhere and adding nothing. */
function hardBreak(text: string, width: number): string[] {
  const pieces: string[] = [];
  let piece = "";
  let used = 0;
  for (const char of text) {
    const next = displayWidth(char);
    if (used + next > width && piece !== "") {
      pieces.push(piece);
      piece = "";
      used = 0;
    }
    piece += char;
    used += next;
  }
  if (piece !== "") pieces.push(piece);
  return pieces;
}

/**
 * The line(s) above the findings list: how many of all findings it shows and which filters are
 * active (or the search being typed). Plain text, none when the scan has no findings at all. The
 * count and the severity, area and rule filters take at most three lines (a rule id is cut at
 * `MAX_HEADER_RULE`); the search gets one line of its own, shows the END of the typed text (cut
 * from the left with `...`) and always shows the cursor, so a long search never hides a filter
 * and a filter never hides the cursor.
 */
export function filterHeader(state: PanelsState, size: Size): string[] {
  if (state.findings.length === 0) return [];
  const t = cliText(state.locale);
  const { filters } = state;
  const isTyping = state.overlay === "filter";
  const parts: string[] = [];
  if (filters.severity !== null) {
    parts.push(`${t.panels.filter.names.severity}: ${t.report.severity[filters.severity]}`);
  }
  if (filters.area !== null) {
    parts.push(`${t.panels.filter.names.area}: ${t.scopeName[filters.area]}`);
  }
  if (filters.rule !== null) {
    parts.push(`${t.panels.filter.names.rule}: ${safeText(filters.rule, MAX_HEADER_RULE)}`);
  }
  const count = t.panels.filter.count(state.visible.length, state.findings.length);
  const active = parts.length === 0 ? t.panels.filter.none : parts.join(", ");
  const lines = wrapWidth(`${count} | ${t.panels.filter.label}: ${active}`, size.columns).slice(
    0,
    MAX_HEADER_LINES,
  );
  if (filters.text !== "" || isTyping) {
    const cursor = isTyping ? "_" : "";
    const frame = `${t.panels.filter.names.search}: ""`;
    const room = Math.max(4, size.columns - displayWidth(frame) - cursor.length);
    lines.push(
      `${t.panels.filter.names.search}: "${tailWidth(safeText(filters.text, 200), room)}${cursor}"`,
    );
  }
  return lines;
}

/** Rows the findings list can show: the body minus the filter header. */
export function listHeight(state: PanelsState, size: Size): number {
  return Math.max(1, bodyHeight(size) - filterHeader(state, size).length);
}

/** Longest standards list shown for one finding. */
const MAX_STANDARD_LINKS = 5;

/**
 * The opened finding. Every text that comes from the scan goes through `safeText` and a length
 * cap; the evidence is the redacted text the result screen prints (never anything more). Only
 * https links are shown, and the standards come from PGARD's rule catalog, not from the finding.
 */
export function detailLines(state: PanelsState, size: Size, opts: RenderOptions = {}): string[] {
  const finding = state.visible[state.selected];
  if (finding === undefined) return [];
  const style = opts.style ?? PLAIN;
  const t = cliText(state.locale);
  const width = Math.max(10, size.columns);
  const lines: string[] = [];
  const add = (...text: string[]): void => {
    for (const line of text) lines.push(...fitLines(line, width));
  };
  const tag = `${severityTag(finding, t)} ${statusWord(finding, t)}`;
  lines.push(...fitLines(tag, width).map((line) => style.severity(finding.severity, line)));
  lines.push(...fitLines(safeText(finding.title, 200), width).map((line) => style.bold(line)));
  add(
    `${t.panels.detail.rule}: ${safeText(finding.ruleId, 60)}`,
    `${t.panels.detail.where}: ${safeText(formatLocation(finding.location), 300)}`,
    "",
    `${t.evidence}: ${safeText(finding.evidence, 500)}`,
    "",
    `${t.fix}: ${safeText(finding.recommendation, 500)}`,
  );
  const ids = [...finding.references.owasp, ...finding.references.cwe, ...finding.references.cve];
  if (ids.length > 0) {
    add("", `${t.panels.detail.references}: ${ids.map((id) => safeText(id, 30)).join(", ")}`);
  }
  const links = (state.ruleTexts?.get(finding.ruleId)?.details?.standards ?? []).filter((link) =>
    link.url.startsWith("https://"),
  );
  if (links.length > 0) {
    add("", `${t.standards}:`);
    for (const link of links.slice(0, MAX_STANDARD_LINKS)) {
      const title = link.title === null ? "" : ` ${safeText(link.title, 80)}`;
      const via = link.viaCwe === undefined ? "" : ` (${t.report.viaCwe(link.viaCwe)})`;
      add(`  ${safeText(link.id, 20)}${title}${via}`);
      // A link is never shortened (a cut link cannot be copied): it is broken at the width with
      // nothing added, so the lines joined are the whole address.
      lines.push(...hardBreak(safeText(link.url, 200), width));
    }
    const rest = links.length - MAX_STANDARD_LINKS;
    if (rest > 0) add(`  +${rest}`);
  }
  return lines;
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
  const findingsCount = hasFilters(state.filters)
    ? t.panels.filter.count(state.visible.length, state.findings.length)
    : String(state.findings.length);
  const labels = PANEL_IDS.map((id: PanelId) =>
    id === "findings" ? `${t.panels.tabs[id]} (${findingsCount})` : t.panels.tabs[id],
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

/**
 * The hints that fit: they are written most important first (Esc, `?`), separated by two
 * spaces, and whole hints are dropped from the end instead of one being cut in the middle.
 */
function fitHints(text: string, room: number): string {
  let out = "";
  for (const hint of text.split("  ")) {
    const next = out === "" ? hint : `${out}  ${hint}`;
    if (displayWidth(next) > room) break;
    out = next;
  }
  return out === "" ? truncateWidth(text, room) : out;
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
    total > to - from + 1 && state.overlay !== "help" ? t.panels.position(from, to, total) : "";
  const room = size.columns - (position === "" ? 0 : displayWidth(position) + 1);
  const hintText =
    state.overlay === "filter" || state.overlay === "detail" || state.overlay === "help"
      ? t.panels.hints[state.overlay]
      : state.panel !== "findings"
        ? t.panels.hints.default
        : state.visible.length === 0 && state.findings.length > 0
          ? t.panels.hints.noMatch
          : t.panels.hints.findings;
  const hints = padEndWidth(fitHints(hintText, Math.max(0, room)), Math.max(0, room));
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
  let pageRows = height;
  if (state.overlay === "help") {
    const lines = helpLines(state, size, opts);
    total = lines.length;
    top = Math.min(state.helpScroll, Math.max(0, total - height));
    body = lines.slice(top, top + height);
  } else if (state.overlay === "detail") {
    const lines = detailLines(state, size, opts);
    total = lines.length;
    top = Math.min(state.detailScroll, Math.max(0, total - height));
    body = lines.slice(top, top + height);
  } else if (state.panel === "findings") {
    total = state.visible.length;
    const header = filterHeader(state, size);
    pageRows = Math.max(1, height - header.length);
    top = Math.min(state.scroll.findings, Math.max(0, total - pageRows));
    if (state.findings.length === 0) {
      body = [t.panels.noFindings];
    } else if (total === 0) {
      body = [
        ...header.map((line) => style.bold(line)),
        ...wrapWidth(t.panels.filter.noMatch(state.findings.length), size.columns),
      ];
    } else {
      const columns = rowColumns(state.visible, t);
      body = [
        ...header.map((line) => style.bold(line)),
        ...state.visible
          .slice(top, top + pageRows)
          .map((finding, index) =>
            findingRow(finding, top + index === state.selected, columns, size, t, style),
          ),
      ];
    }
  } else {
    const lines = panelLines(state, size, opts);
    total = lines.length;
    top = Math.min(state.scroll[state.panel], Math.max(0, total - height));
    body = lines.slice(top, top + height);
  }
  const shown = Math.min(top + pageRows, total);
  const frame = [
    titleLine(state, size, style),
    tabBar(state, size, style),
    ...body.map((line) => fit(line, size.columns)),
  ];
  while (frame.length < size.rows - 1) frame.push("");
  frame.push(footer(state, size, top + 1, shown, total, style));
  return frame.map((line) => fit(line, size.columns));
}
