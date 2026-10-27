import { displayWidth, splitAnsiWord, stripAnsi, wrapWidth } from "../i18n/display-width.js";

const ESC = String.fromCharCode(27);
const LEAD = new RegExp(`^((?:${ESC}\\[[0-9;]*m)*)( *)`);
/** A label the text hangs under: "! ", "- ", "[partial] ", "Evidence: ". */
const LABEL = /^(?:[!-]|\[[^\]]*\]|[\p{L}]{1,14}:) /u;
const URL_WORD = /^\(?https?:\/\//;
/**
 * PGARD's own reference links (the standards listed with a rule). They are fixed and may stay
 * whole, even when they run past the width, because a cut link cannot be copied. Any other URL
 * (it can come from the scanned code or a web page) is shortened with an ellipsis.
 */
const STANDARDS_URL =
  /^\(?https:\/\/(?:top10\.owasp\.org|owasp\.org|cwe\.mitre\.org|cmu-sei\.github\.io|wiki\.sei\.cmu\.edu)\//;
/** Other URLs are kept up to this many times the width. */
const URL_WIDTH_FACTOR = 2;

/**
 * Longest hanging indent as a share of the width; a deeper indent would leave no room for text.
 */
const MAX_HANG_SHARE = 0.4;

/**
 * Makes a word fit: a long word is cut into pieces by grapheme (colour kept per piece, no escape
 * sequence split); PGARD's standards links stay whole; any other URL is shortened to
 * `URL_WIDTH_FACTOR` times the width with an ellipsis.
 */
function breakWord(word: string, room: number, width: number): string[] {
  // A URL may take the whole line plus the room it would have after a hanging indent.
  const visible = stripAnsi(word);
  if (STANDARDS_URL.test(visible)) return [word];
  if (URL_WORD.test(visible)) {
    const limit = Math.min(width * URL_WIDTH_FACTOR, width + room);
    if (displayWidth(visible) <= limit) return [word];
    return [`${splitAnsiWord(word, limit - 3)[0] ?? ""}...`];
  }
  if (displayWidth(word) <= room) return [word];
  return splitAnsiWord(word, room);
}

/**
 * Wraps one line to `width` columns. The continuation lines hang under the text: below the
 * line's own indent and, when it starts with a label ("! ", "[partial] ", "Evidence: "), under
 * the words after that label. Only spaces break a line; a longer word is cut into pieces. A URL is
 * not cut: PGARD's own standards links stay whole (and may run past `width`), other URLs are
 * shortened with an ellipsis.
 */
export function fitLine(line: string, width: number): string[] {
  if (displayWidth(line) <= width) return [line];
  const lead = LEAD.exec(line);
  const colour = lead?.[1] ?? "";
  const indent = lead?.[2] ?? "";
  const rest = line.slice(colour.length + indent.length);
  const label = LABEL.exec(stripAnsi(rest));
  const labelWidth = label === null ? 0 : displayWidth(label[0]);
  const first = indent.length;
  const maxHang = Math.max(first, Math.floor(width * MAX_HANG_SHARE));
  const hang = Math.min(first + labelWidth, maxHang);
  const room = Math.max(10, width - hang);
  const words = rest.split(" ").flatMap((word) => breakWord(word, room, width));
  const wrapped = wrapWidth(words.join(" "), room);
  return wrapped.map((text, index) =>
    index === 0 ? `${colour}${indent}${text}` : `${" ".repeat(hang)}${text}`,
  );
}

/** Wraps every line of `text` (which may hold several lines) to `width` columns. */
export function fitLines(text: string, width: number): string[] {
  return text.split("\n").flatMap((line) => fitLine(line, width));
}
