/**
 * Display width of terminal text. Korean (Hangul), other CJK and full-width characters take two
 * columns, combining marks and zero-width characters none, everything else one. Colour escape
 * sequences take no width either. Used to pad and cut columns so Korean text lines up.
 */

const ANSI_PATTERN = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, "g");

export function stripAnsi(text: string): string {
  return text.replace(ANSI_PATTERN, "");
}

function isZeroWidth(code: number): boolean {
  return (
    (code >= 0x0300 && code <= 0x036f) ||
    (code >= 0x200b && code <= 0x200f) ||
    (code >= 0xfe00 && code <= 0xfe0f) ||
    code === 0x2060 ||
    code === 0xfeff
  );
}

function isWide(code: number): boolean {
  return (
    (code >= 0x1100 && code <= 0x115f) ||
    (code >= 0x2e80 && code <= 0xa4cf) ||
    (code >= 0xac00 && code <= 0xd7a3) ||
    (code >= 0xf900 && code <= 0xfaff) ||
    (code >= 0xfe30 && code <= 0xfe6f) ||
    (code >= 0xff00 && code <= 0xff60) ||
    (code >= 0xffe0 && code <= 0xffe6) ||
    (code >= 0x1f300 && code <= 0x1f64f) ||
    (code >= 0x1f900 && code <= 0x1f9ff) ||
    (code >= 0x20000 && code <= 0x3fffd)
  );
}

/** Columns one character takes. */
export function charWidth(char: string): 0 | 1 | 2 {
  const code = char.codePointAt(0) ?? 0;
  if (code < 0x20 || (code >= 0x7f && code < 0xa0) || isZeroWidth(code)) return 0;
  return isWide(code) ? 2 : 1;
}

/** Columns the text takes on screen (colour codes ignored). */
export function displayWidth(text: string): number {
  let width = 0;
  for (const char of stripAnsi(text)) width += charWidth(char);
  return width;
}

/** Pads with spaces on the right up to `width` columns; never cuts. */
export function padEndWidth(text: string, width: number): string {
  return text + " ".repeat(Math.max(0, width - displayWidth(text)));
}

/** Pads with spaces on the left up to `width` columns; never cuts. */
export function padStartWidth(text: string, width: number): string {
  return " ".repeat(Math.max(0, width - displayWidth(text))) + text;
}

/** Cuts plain text (no colour codes) to at most `width` columns, ending in `...` when cut. */
export function truncateWidth(text: string, width: number, ellipsis = "..."): string {
  if (displayWidth(text) <= width) return text;
  const room = Math.max(0, width - displayWidth(ellipsis));
  let out = "";
  let used = 0;
  for (const char of text) {
    const next = charWidth(char);
    if (used + next > room) break;
    out += char;
    used += next;
  }
  return out + ellipsis;
}

/** The widest of the texts, in columns. */
export function maxDisplayWidth(texts: readonly string[]): number {
  return texts.reduce((max, text) => Math.max(max, displayWidth(text)), 0);
}

/**
 * Breaks text at spaces into lines of at most `width` columns (a single longer word stays whole).
 * Used for summary rows, so a long value continues under itself instead of wrapping to column 0.
 */
export function wrapWidth(text: string, width: number): string[] {
  return carryColour(wrapPlain(text, width));
}

const SGR_PATTERN = new RegExp(`${String.fromCharCode(27)}\\[([0-9;]*)m`, "g");
const RESET = `${String.fromCharCode(27)}[0m`;

/** The attribute family a single SGR code belongs to: its close code resets the family. */
function attributeFamily(value: number): string | null {
  if (value === 1 || value === 2 || value === 22) return "weight";
  if (value === 3 || value === 23) return "italic";
  if (value === 4 || value === 24) return "underline";
  if (value === 7 || value === 27) return "inverse";
  if ((value >= 30 && value <= 39) || (value >= 90 && value <= 97)) return "foreground";
  if ((value >= 40 && value <= 49) || (value >= 100 && value <= 107)) return "background";
  return null;
}

const CLOSE_CODES = new Set([22, 23, 24, 27, 39, 49]);

/**
 * Applies one `ESC[...m` sequence to the set of open attributes. Compound sequences work:
 * `1;31` is two codes, and the extended colours `38;5;n` and `38;2;r;g;b` (and `48;...`) are
 * one attribute with their arguments.
 */
function applySgr(open: Map<string, string>, params: string): void {
  const tokens = params === "" ? ["0"] : params.split(";");
  for (let index = 0; index < tokens.length; index += 1) {
    const value = Number(tokens[index]);
    if (value === 0) {
      open.clear();
    } else if (value === 38 || value === 48) {
      const length = tokens[index + 1] === "5" ? 3 : tokens[index + 1] === "2" ? 5 : 1;
      open.set(
        value === 38 ? "foreground" : "background",
        tokens.slice(index, index + length).join(";"),
      );
      index += length - 1;
    } else {
      const family = attributeFamily(value);
      if (family === null) continue;
      if (CLOSE_CODES.has(value)) open.delete(family);
      else open.set(family, String(value));
    }
  }
}

/**
 * A colour opened on one wrapped line must not run on into the indent of the next: each line
 * that ends inside a colour is closed, and the next line opens it again after its own indent.
 */
function carryColour(lines: string[]): string[] {
  const open = new Map<string, string>();
  return lines.map((line) => {
    const reopened = [...open.values()].map((code) => `${String.fromCharCode(27)}[${code}m`);
    for (const match of line.matchAll(SGR_PATTERN)) applySgr(open, match[1] ?? "");
    return `${reopened.join("")}${line}${open.size > 0 ? RESET : ""}`;
  });
}

function wrapPlain(text: string, width: number): string[] {
  const lines: string[] = [];
  let line = "";
  for (const word of text.split(" ")) {
    if (line === "") line = word;
    else if (displayWidth(line) + 1 + displayWidth(word) <= width) line += ` ${word}`;
    else {
      lines.push(line);
      line = word;
    }
  }
  lines.push(line);
  return lines;
}

const segmenter =
  typeof Intl.Segmenter === "function"
    ? new Intl.Segmenter(undefined, { granularity: "grapheme" })
    : null;

/** Whole characters as a reader sees them: a ZWJ emoji or a letter with its marks is one. */
function graphemes(text: string): string[] {
  return segmenter === null
    ? [...text]
    : Array.from(segmenter.segment(text), (segment) => segment.segment);
}

const SGR_SPLIT = new RegExp(`(${String.fromCharCode(27)}\\[[0-9;]*m)`);
const SGR_ONLY = new RegExp(`^${String.fromCharCode(27)}\\[([0-9;]*)m$`);

/**
 * Cuts a word without spaces into pieces of at most `room` columns. It cuts the visible text by
 * grapheme and never inside an escape sequence; every piece that ends inside a colour is closed
 * and the next piece opens it again, so each piece is styled on its own.
 */
export function splitAnsiWord(word: string, room: number): string[] {
  const limit = Math.max(1, room);
  const open = new Map<string, string>();
  const pieces: string[] = [];
  let piece = "";
  let width = 0;
  const reopen = (): string =>
    [...open.values()].map((code) => `${String.fromCharCode(27)}[${code}m`).join("");
  for (const part of word.split(SGR_SPLIT)) {
    if (part === "") continue;
    const sgr = SGR_ONLY.exec(part);
    if (sgr !== null) {
      piece += part;
      applySgr(open, sgr[1] ?? "");
      continue;
    }
    for (const cluster of graphemes(part)) {
      const clusterWidth = displayWidth(cluster);
      if (width + clusterWidth > limit && width > 0) {
        pieces.push(piece + (open.size > 0 ? RESET : ""));
        piece = reopen();
        width = 0;
      }
      piece += cluster;
      width += clusterWidth;
    }
  }
  pieces.push(piece);
  return pieces;
}
