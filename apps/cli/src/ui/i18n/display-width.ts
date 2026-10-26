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
