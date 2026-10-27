import { displayWidth, stripAnsi, wrapWidth } from "../i18n/display-width.js";

const ESC = String.fromCharCode(27);
const LEAD = new RegExp(`^((?:${ESC}\\[[0-9;]*m)*)( *)`);
/** A label the text hangs under: "! ", "- ", "[partial] ", "Evidence: ". */
const LABEL = /^(?:[!-]|\[[^\]]*\]|[\p{L}]{1,14}:) /u;
const URL_WORD = /^(?:\S*\u001b\[[0-9;]*m)*\(?https?:\/\//;

/**
 * Longest hanging indent as a share of the width; a deeper indent would leave no room for text.
 */
const MAX_HANG_SHARE = 0.4;

/** Cuts a long word with no spaces into pieces of `room` columns, so it cannot run past the edge. */
function breakWord(word: string, room: number): string[] {
  // Colour codes and URLs stay whole: a cut URL cannot be copied.
  if (word.includes(ESC) || URL_WORD.test(word) || displayWidth(word) <= room) return [word];
  const pieces: string[] = [];
  let piece = "";
  for (const char of word) {
    if (displayWidth(piece + char) > room) {
      pieces.push(piece);
      piece = "";
    }
    piece += char;
  }
  return [...pieces, piece];
}

/**
 * Wraps one line to `width` columns. The continuation lines hang under the text: below the
 * line's own indent and, when it starts with a label ("! ", "[partial] ", "Evidence: "), under
 * the words after that label. Only spaces break a line; a longer word is cut into pieces unless
 * it is a URL, which stays whole and may run past `width`.
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
  const words = rest.split(" ").flatMap((word) => breakWord(word, room));
  const wrapped = wrapWidth(words.join(" "), room);
  return wrapped.map((text, index) =>
    index === 0 ? `${colour}${indent}${text}` : `${" ".repeat(hang)}${text}`,
  );
}

/** Wraps every line of `text` (which may hold several lines) to `width` columns. */
export function fitLines(text: string, width: number): string[] {
  return text.split("\n").flatMap((line) => fitLine(line, width));
}
