import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

/**
 * The PDF embeds a pre-subset Noto Sans KR (SIL OFL 1.1; see fonts/OFL.txt and the NOTICE file).
 * PDFKit then subsets it again per document, so a report only carries the glyphs it uses. The
 * font files ship inside this package (no network access at runtime) and are verified against
 * the checksums below when they are loaded.
 */
const FONT_FILES = {
  regular: {
    file: "PgardNotoSansKR-Regular.ttf",
    sha256: "e1a4564bbbb0676ea20c72ba7cc130917096c5f43655ca99f06c99efcec2fdfb",
  },
  bold: {
    file: "PgardNotoSansKR-Bold.ttf",
    sha256: "ff1968fc53fb9abf71041d8c9a9783518de3f85ef2e49ca713ca9a03770aa894",
  },
} as const;

/**
 * Code points that have a glyph in the shipped subset: the exact cmap (a test walks every one).
 * Keep in sync with fonts/subset.py.
 */
const SUPPORTED_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x20, 0x7e],
  [0xa0, 0xff],
  [0x2010, 0x2016],
  [0x2018, 0x201a],
  [0x201c, 0x201e],
  [0x2020, 0x2022],
  [0x2025, 0x2027],
  [0x2030, 0x2030],
  [0x2032, 0x2033],
  [0x2035, 0x2035],
  [0x2039, 0x203a],
  [0x20ac, 0x20ac],
  [0x2190, 0x2193],
  [0x3000, 0x303f],
  [0x3131, 0x318e],
  [0xac00, 0xd7a3],
  [0xff01, 0xff5e],
];

export interface PdfFonts {
  regular: Buffer;
  bold: Buffer;
}

export type PdfFontLoad = { ok: true; fonts: PdfFonts } | { ok: false; reason: string };

let cached: PdfFontLoad | undefined;

class FontChecksumError extends Error {}

function readVerified(spec: { file: string; sha256: string }): Buffer {
  const data = readFileSync(new URL(`../fonts/${spec.file}`, import.meta.url));
  if (createHash("sha256").update(data).digest("hex") !== spec.sha256) {
    throw new FontChecksumError(`${spec.file} does not match its pinned checksum`);
  }
  return data;
}

/** Loads (once) the bundled font; never throws. On failure the PDF falls back to Latin-1. */
export function loadPdfFonts(): PdfFontLoad {
  if (cached === undefined) {
    try {
      cached = {
        ok: true,
        fonts: { regular: readVerified(FONT_FILES.regular), bold: readVerified(FONT_FILES.bold) },
      };
    } catch (error) {
      cached = {
        ok: false,
        // Only the checksum message or an error code: Node's own messages contain file paths.
        reason:
          error instanceof FontChecksumError
            ? error.message
            : `font file unreadable: ${(error as NodeJS.ErrnoException).code ?? "unknown error"}`,
      };
    }
  }
  return cached;
}

/** Test hook: forget the cached font so the next load runs again. */
export function resetPdfFontCache(): void {
  cached = undefined;
}

/** True when the bundled font has a glyph for this code point. */
export const PDF_FONT_RANGES = SUPPORTED_RANGES;

export function isPdfFontCodePoint(codePoint: number): boolean {
  return SUPPORTED_RANGES.some(([from, to]) => codePoint >= from && codePoint <= to);
}

const WORD_JOINER = "\u2060";
// Hangul syllables and compatibility Jamo.
const HANGUL = "\\u3131-\\u318e\\uac00-\\ud7a3";
// Between two Hangul characters, and between Hangul and a letter or digit on either side
// ("40개", "json의", "API를"), where PDFKit would otherwise break a word at the right margin.
const JOIN_POINTS = new RegExp(
  `(?<=[${HANGUL}])(?=[${HANGUL}\\p{L}\\p{N}])|(?<=[\\p{L}\\p{N}])(?=[${HANGUL}])`,
  "gu",
);

/**
 * PDFKit may break a line between any two Hangul syllables, and between a digit or Latin letter
 * and Hangul, so a word is cut at the right margin ("규칙이 있/음", "40/개"). A word joiner
 * (U+2060) there forbids the break and leaves the spaces as the only break points. The bundled
 * font has no glyph for U+2060 (it would print as a box), so `hideWordJoiners` makes the font
 * ignore it when it lays out and encodes text; apply this only when that returned true.
 * Apply this after `toFontText`, which would turn U+2060 into "?".
 */
export function joinHangulSyllables(text: string): string {
  return text.replace(JOIN_POINTS, WORD_JOINER);
}

interface LayoutFont {
  layout: (text: string, ...rest: unknown[]) => unknown;
}

/**
 * Makes the registered fonts drop U+2060 before PDFKit lays text out, so it takes no width and
 * has no glyph, yet the line breaker (which runs on the original text) still honours it.
 *
 * This reaches into PDFKit's `_font.font.layout`, which is not public API; it was checked against
 * the pinned `pdfkit` 0.20.2 (packages/report/package.json). Returns false when the hook is not
 * there (a PDFKit upgrade changed it): the caller then keeps the joiners out of the text, so the
 * PDF is still made, and a test fails so the change is noticed.
 */
export function hideWordJoiners(doc: PDFKit.PDFDocument, fontNames: readonly string[]): boolean {
  for (const name of fontNames) {
    doc.font(name);
    const embedded = (doc as unknown as { _font?: { font?: LayoutFont } })._font;
    const fontkit = embedded?.font;
    if (fontkit === undefined || typeof fontkit.layout !== "function") return false;
    const original = fontkit.layout.bind(fontkit);
    fontkit.layout = (text, ...rest) => original(text.split(WORD_JOINER).join(""), ...rest);
  }
  return true;
}

/** Replaces control characters and characters outside the bundled font with "?". */
export function toFontText(value: string): string {
  let out = "";
  for (const char of value) {
    out += char === "\n" || isPdfFontCodePoint(char.codePointAt(0) ?? 0) ? char : "?";
  }
  return out;
}

/** True when any string inside `value` (an object, array or string) is altered by `toFontText`. */
export function hasStringOutsideFont(value: unknown): boolean {
  if (typeof value === "string") return hasCharactersOutsideFont(value);
  if (Array.isArray(value)) return value.some(hasStringOutsideFont);
  if (typeof value === "object" && value !== null) {
    return Object.values(value).some(hasStringOutsideFont);
  }
  return false;
}

/** True when the value contains text outside the bundled font (see `toFontText`). */
export function hasCharactersOutsideFont(value: string): boolean {
  for (const char of value) {
    if (char !== "\n" && !isPdfFontCodePoint(char.codePointAt(0) ?? 0)) return true;
  }
  return false;
}
