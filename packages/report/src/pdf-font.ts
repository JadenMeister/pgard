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
    sha256: "5ef492dc3174bde922db398255dfa1d6232449be408ac260e152606121481cc5",
  },
  bold: {
    file: "PgardNotoSansKR-Bold.ttf",
    sha256: "dcb6fe1df7eaf3f0fd0695cf3504cf9be389b19b55c5815c3c56a00a656a49d0",
  },
} as const;

/** Code point ranges present in the shipped subset (keep in sync with fonts/subset.py). */
const SUPPORTED_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x20, 0x7e],
  [0xa0, 0xff],
  [0x2010, 0x2027],
  [0x2030, 0x203a],
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
export function isPdfFontCodePoint(codePoint: number): boolean {
  return SUPPORTED_RANGES.some(([from, to]) => codePoint >= from && codePoint <= to);
}

/** Replaces control characters and characters outside the bundled font with "?". */
export function toFontText(value: string): string {
  let out = "";
  for (const char of value) {
    out += char === "\n" || isPdfFontCodePoint(char.codePointAt(0) ?? 0) ? char : "?";
  }
  return out;
}

/** True when the value contains text outside the bundled font (see `toFontText`). */
export function hasCharactersOutsideFont(value: string): boolean {
  for (const char of value) {
    if (char !== "\n" && !isPdfFontCodePoint(char.codePointAt(0) ?? 0)) return true;
  }
  return false;
}
