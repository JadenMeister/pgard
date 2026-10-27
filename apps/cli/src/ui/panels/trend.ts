import type { Severity } from "@pgard/findings";

/** Most severe first: the order of the bar segments and the table columns. */
export const SEVERITY_ORDER_DESC: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

const UNICODE_SYMBOL: Record<Severity, string> = {
  critical: "█",
  high: "▓",
  medium: "▒",
  low: "░",
  info: "·",
};
const ASCII_SYMBOL: Record<Severity, string> = {
  critical: "#",
  high: "=",
  medium: "+",
  low: "-",
  info: ":",
};

/** Local `YYYY-MM-DD`, plus ` HH:mm` when `withTime`. */
export function trendDate(epochMs: number, withTime: boolean): string {
  const date = new Date(epochMs);
  if (Number.isNaN(date.getTime())) return "????-??-??";
  const pad = (value: number): string => String(value).padStart(2, "0");
  const day = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
  return withTime ? `${day} ${pad(date.getHours())}:${pad(date.getMinutes())}` : day;
}

/** The character that stands for a severity, `count` times. Shape, not colour, tells them apart. */
export function trendSymbol(severity: Severity, count: number, unicode: boolean): string {
  return (unicode ? UNICODE_SYMBOL : ASCII_SYMBOL)[severity].repeat(count);
}

export interface BarPart {
  severity: Severity;
  text: string;
}

/**
 * One stacked bar of at most `width` characters, scaled so `maxTotal` fills `width`. A severity
 * with any findings gets at least one character; if that overflows, the longest segments give up
 * characters first.
 */
export function trendBarRow(
  counts: Readonly<Record<Severity, number>>,
  maxTotal: number,
  width: number,
  unicode: boolean,
): BarPart[] {
  const lengths = SEVERITY_ORDER_DESC.map((severity) => {
    const count = counts[severity];
    return count > 0 ? Math.max(1, Math.round((count / Math.max(1, maxTotal)) * width)) : 0;
  });
  let excess = lengths.reduce((sum, length) => sum + length, 0) - width;
  while (excess > 0) {
    let longest = 0;
    lengths.forEach((length, index) => {
      if (length > (lengths[longest] ?? 0)) longest = index;
    });
    if ((lengths[longest] ?? 0) <= 1) break;
    lengths[longest] = (lengths[longest] ?? 0) - 1;
    excess -= 1;
  }
  return SEVERITY_ORDER_DESC.map((severity, index) => ({
    severity,
    text: trendSymbol(severity, lengths[index] ?? 0, unicode),
  })).filter((part) => part.text !== "");
}
