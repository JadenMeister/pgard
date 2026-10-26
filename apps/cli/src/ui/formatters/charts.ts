import {
  displayWidth,
  maxDisplayWidth,
  padEndWidth,
  truncateWidth,
} from "../i18n/display-width.js";
import { isUnicodeTerminal, MIN_CHART_WIDTH } from "./style.js";

export interface ChartRow {
  label: string;
  count: number;
  /** Colours the bar (and nothing else). Plain text when the style has no colour. */
  paint?: (text: string) => string;
}

export interface ChartOptions {
  /** Terminal width in columns. */
  width: number;
  /** Colour is on: bars use block characters. Off (`NO_COLOR`, pipe): ASCII `#` bars. */
  isColor: boolean;
  unicode?: boolean;
}

const INDENT = 2;
const MAX_BAR = 30;
const MIN_BAR = 6;
const MAX_LABEL = 30;

/**
 * Horizontal bar chart, one row per entry, sized to the terminal.
 * - Colour on and Unicode available: `█` bars, painted per row.
 * - No colour (`NO_COLOR`, not a TTY): `#` bars, readable as plain text.
 * - Narrower than 60 columns: no bars, only "label  count" lines, so nothing wraps.
 * Labels are padded and cut by display width, so Korean (two columns per character) lines up.
 */
export function renderChart(rows: readonly ChartRow[], options: ChartOptions): string[] {
  if (rows.length === 0) return [];
  const countWidth = Math.max(...rows.map((row) => String(row.count).length));
  const isNarrow = options.width < MIN_CHART_WIDTH;
  const labelLimit = Math.min(MAX_LABEL, Math.max(8, options.width - INDENT - countWidth - 2));
  const labels = rows.map((row) => truncateWidth(row.label, labelLimit));
  const labelWidth = maxDisplayWidth(labels);
  const lead = " ".repeat(INDENT);
  if (isNarrow) {
    return rows.map(
      (row, index) => `${lead}${padEndWidth(labels[index] ?? "", labelWidth)} ${row.count}`,
    );
  }
  const room = options.width - INDENT - labelWidth - 1 - 1 - countWidth;
  const barMax = Math.max(MIN_BAR, Math.min(MAX_BAR, room));
  const maxCount = Math.max(1, ...rows.map((row) => row.count));
  const unicode = options.unicode ?? isUnicodeTerminal();
  const barCharacter = options.isColor && unicode ? "█" : "#";
  return rows.map((row, index) => {
    const length = row.count === 0 ? 0 : Math.max(1, Math.round((row.count / maxCount) * barMax));
    const bar = barCharacter.repeat(length);
    const painted = options.isColor && row.paint !== undefined ? row.paint(bar) : bar;
    return `${lead}${padEndWidth(labels[index] ?? "", labelWidth)} ${painted}${length === 0 ? "" : " "}${row.count}`;
  });
}

/** Width of the widest line of a chart, for tests. */
export function chartWidth(lines: readonly string[]): number {
  return lines.reduce((max, line) => Math.max(max, displayWidth(line)), 0);
}
