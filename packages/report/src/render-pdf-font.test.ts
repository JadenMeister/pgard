import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  hasCharactersOutsideFont,
  hasStringOutsideFont,
  PDF_FONT_RANGES,
  isPdfFontCodePoint,
  joinHangulSyllables,
  loadPdfFonts,
  resetPdfFontCache,
  toFontText,
} from "./pdf-font.js";
import {
  PDF_FONT_REPLACEMENT_NOTICE,
  PDF_REPLACEMENT_NOTICE,
  renderPdfReport,
} from "./render-pdf.js";
import { DETAIL_RULE_TEXTS, scanResultV11 } from "./test-fixtures-details.js";
import { finding, scanResult } from "./test-fixtures.js";
import { extractEmbeddedFontText } from "./test-pdf-text.js";

const KOREAN_TITLE = "사용자 입력이 SQL 질의에 직접 연결됩니다";

describe("PDF with the bundled Korean-capable font", () => {
  it("renders Korean text that can be extracted back (not '?')", async () => {
    const pdf = await renderPdfReport(
      scanResult({
        findings: [
          finding({
            title: KOREAN_TITLE,
            impact: "공격자가 질의 구조를 바꿀 수 있습니다.",
            recommendation: "매개변수화된 쿼리를 사용하세요.",
          }),
        ],
      }),
      { compress: false },
    );
    const text = extractEmbeddedFontText(pdf).join("\n");
    expect(text).toContain(KOREAN_TITLE);
    expect(text).toContain("Impact: 공격자가 질의 구조를 바꿀 수 있습니다.");
    expect(text).toContain("Recommendation: 매개변수화된 쿼리를 사용하세요.");
    expect(text).not.toContain("?");
    expect(text).not.toContain("�");
    expect(text).not.toContain(PDF_REPLACEMENT_NOTICE);
  });

  it("renders a mixed Korean and English report", async () => {
    const pdf = await renderPdfReport(
      scanResult({
        target: { repo: "owner/이름", revision: "abc123", webOrigin: null },
        findings: [
          finding({ id: "a", title: "Hardcoded secret" }),
          finding({
            id: "b",
            title: "하드코딩된 비밀 값 (hardcoded)",
            evidence: "키 AKIA... (redacted)",
          }),
        ],
      }),
      { compress: false },
    );
    const lines = extractEmbeddedFontText(pdf);
    const text = lines.join("\n");
    expect(text).toContain("PGARD security report");
    expect(text).toContain("Repository: owner/이름");
    expect(text).toContain("Hardcoded secret");
    expect(text).toContain("하드코딩된 비밀 값 (hardcoded)");
    expect(text).toContain("Evidence (redacted): 키 AKIA... (redacted)");
    expect(text).not.toContain("?");
  });

  it("embeds a small subset, not the whole font", async () => {
    const small = await renderPdfReport(scanResult());
    const korean = await renderPdfReport(
      scanResult({ findings: [finding({ title: KOREAN_TITLE })] }),
    );
    expect(small.length).toBeLessThan(150_000);
    expect(korean.length).toBeLessThan(250_000);
  });

  it("degrades emoji and other scripts to '?' with a notice, without crashing", async () => {
    const pdf = await renderPdfReport(
      scanResult({
        findings: [finding({ title: "Rocket \u{1F680} and 中文 and الع and tab\there" })],
      }),
      { compress: false },
    );
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    const text = extractEmbeddedFontText(pdf).join("\n");
    expect(text).toContain("Rocket ? and ?? and ??? and tab?here");
    expect(extractEmbeddedFontText(pdf).join(" ").replace(/\s+/g, " ")).toContain(
      PDF_FONT_REPLACEMENT_NOTICE,
    );
  });

  it("covers every Hangul syllable the subset claims", () => {
    expect(isPdfFontCodePoint(0xac00)).toBe(true);
    expect(isPdfFontCodePoint(0xd7a3)).toBe(true);
    expect(isPdfFontCodePoint(0x1f680)).toBe(false);
    expect(toFontText("a\u001b\u{1F680}\ud83d한\n")).toBe("a???한\n");
    expect(hasCharactersOutsideFont("한글 English")).toBe(false);
    expect(hasCharactersOutsideFont("中")).toBe(true);
  });

  it("ships font files that match their pinned checksums and the license text", () => {
    const loaded = loadPdfFonts();
    expect(loaded.ok).toBe(true);
    const license = readFileSync(new URL("../fonts/OFL.txt", import.meta.url));
    expect(createHash("sha256").update(license).digest("hex")).toBe(
      "1c05c68c34f9708415aada51f17e1b0092d2cea709bf4a94cd38114f9e73d7d9",
    );
  });
});

describe("claimed glyph coverage", () => {
  it("has a real glyph in both fonts for every claimed code point, and none for the gaps", () => {
    const fontkit = createRequire(import.meta.url)("fontkit") as {
      create: (buffer: Buffer) => { hasGlyphForCodePoint: (codePoint: number) => boolean };
    };
    for (const name of ["Regular", "Bold"]) {
      const font = fontkit.create(
        readFileSync(new URL(`../fonts/PgardNotoSansKR-${name}.ttf`, import.meta.url)),
      );
      for (const [from, to] of PDF_FONT_RANGES) {
        for (let cp = from; cp <= to; cp++) {
          expect(font.hasGlyphForCodePoint(cp), `${name} U+${cp.toString(16)}`).toBe(true);
        }
      }
      for (const cp of [
        0x2017, 0x201b, 0x201f, 0x2023, 0x2024, 0x2031, 0x2034, 0x2036, 0x2037, 0x2038,
      ]) {
        expect(isPdfFontCodePoint(cp)).toBe(false);
        expect(toFontText(String.fromCodePoint(cp))).toBe("?");
      }
    }
  });
});

describe("notice for replaced characters", () => {
  it("notices a tab or ESC in a text field, which JSON would hide as an escape", async () => {
    expect(hasStringOutsideFont({ a: ["x", { b: "tab\there" }] })).toBe(true);
    expect(hasStringOutsideFont({ a: ["x", { b: "line\nbreak 한" }] })).toBe(false);
    for (const evidence of ["a\tb", "a\u001b[31mb"]) {
      const pdf = await renderPdfReport(scanResult({ findings: [finding({ evidence })] }), {
        compress: false,
      });
      const text = extractEmbeddedFontText(pdf).join(" ").replace(/\s+/g, " ");
      expect(text).toContain(PDF_FONT_REPLACEMENT_NOTICE);
    }
  });
});

describe("PDF text extraction helper", () => {
  it("throws instead of returning placeholders for unmapped glyphs or a missing CMap", async () => {
    const pdf = await renderPdfReport(scanResult(), { compress: false });
    expect(() => extractEmbeddedFontText(pdf)).not.toThrow();
    const source = pdf.toString("latin1");
    const noMappings = Buffer.from(source.replaceAll("beginbfrange", "beginbfrangX"), "latin1");
    expect(() => extractEmbeddedFontText(noMappings)).toThrow(/unmapped/);
    const noCmap = Buffer.from(source.replaceAll("/ToUnicode", "/ToUnicodX"), "latin1");
    expect(() => extractEmbeddedFontText(noCmap)).toThrow(/no ToUnicode/);
  });
});

describe("PDF when the font cannot be loaded", () => {
  afterEach(() => {
    vi.doUnmock("node:fs");
    vi.resetModules();
    resetPdfFontCache();
  });

  it("falls back to Latin-1, says so in the PDF and reports it, without crashing", async () => {
    vi.resetModules();
    vi.doMock("node:fs", async (importOriginal) => {
      const actual = await importOriginal<typeof import("node:fs")>();
      return {
        ...actual,
        readFileSync: () => {
          throw Object.assign(new Error("ENOENT: /secret/path"), { code: "ENOENT" });
        },
      };
    });
    const { renderPdfReport: render } = await import("./render-pdf.js");
    const messages: Array<string | null> = [];
    const pdf = await render(scanResult({ findings: [finding({ title: "한글 title" })] }), {
      compress: false,
      onFontFallback: (message) => messages.push(message),
    });
    const source = pdf.toString("latin1");
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    expect(messages).toHaveLength(1);
    expect(messages[0]).toContain("Korean-capable PDF font could not be loaded");
    expect(messages[0]).toContain("ENOENT");
    expect(messages[0]).not.toContain("/secret/path");
    expect(source).toContain("/Subject");
    expect(source).toContain("uses a built-in Latin-1 font");
    expect(source).toContain("/Helvetica");
  });

  it("asks for Korean without the font: fixed words and catalog texts are English, no '?'", async () => {
    vi.resetModules();
    vi.doMock("node:fs", async (importOriginal) => {
      const actual = await importOriginal<typeof import("node:fs")>();
      return {
        ...actual,
        readFileSync: () => {
          throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
        },
      };
    });
    const { renderPdfReport: render } = await import("./render-pdf.js");
    const pdf = await render(scanResultV11(), {
      lang: "ko",
      ruleTexts: DETAIL_RULE_TEXTS,
      compress: false,
    });
    // Built-in font strings are hex groups in TJ arrays: join the groups of each line.
    const text = [...pdf.toString("latin1").matchAll(/\[((?:<[0-9a-f]*>|[-\d.\s])*)\] TJ/g)]
      .map((match) =>
        [...(match[1] ?? "").matchAll(/<([0-9a-f]*)>/g)]
          .map((group) => Buffer.from(group[1] ?? "", "hex").toString("latin1"))
          .join(""),
      )
      .join("\n");
    expect(text).toContain("PGARD security report");
    expect(text).toContain("Appendix B: examples for the rules that reported findings");
    // Rule catalog text in English too (examples' note, rationale, remediation).
    expect(text).toContain("A quote in a changes the query.");
    expect(text).toContain("Query structure may change");
    expect(text).toContain("Use parameters");
    expect(text).not.toContain("?");
    expect(text).not.toContain("PGARD 보안");
  });

  it("falls back when a font file fails its checksum", async () => {
    vi.resetModules();
    vi.doMock("node:fs", async (importOriginal) => {
      const actual = await importOriginal<typeof import("node:fs")>();
      return { ...actual, readFileSync: () => Buffer.from("not the font") };
    });
    const { renderPdfReport: render } = await import("./render-pdf.js");
    const messages: Array<string | null> = [];
    const pdf = await render(scanResult({ findings: [finding({ title: "한글" })] }), {
      compress: false,
      onFontFallback: (message) => messages.push(message),
    });
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    expect(messages[0]).toContain("does not match its pinned checksum");
    expect(pdf.toString("latin1")).toContain("/Helvetica");
  });
});

describe("PDF Korean word wrapping", () => {
  const WORDS = ["규칙이", "있음", "매개변수화된", "쿼리를", "사용하세요", "끝까지", "실행됨"];

  it("puts a word joiner only between two Hangul syllables", () => {
    expect(joinHangulSyllables("규칙이 있음")).toBe("규⁠칙⁠이 있⁠음");
    expect(joinHangulSyllables("a규b R-1 가")).toBe("a규b R-1 가");
    expect(joinHangulSyllables("")).toBe("");
  });

  it("never splits a Korean word at the right margin and prints no joiner glyph", async () => {
    const sentence = Array.from({ length: 60 }, (_, i) => WORDS[i % WORDS.length]).join(" ");
    const pdf = await renderPdfReport(scanResult({ findings: [finding({ impact: sentence })] }), {
      compress: false,
    });
    const all = extractEmbeddedFontText(pdf);
    const body = all.filter((line) => WORDS.some((word) => line.includes(word)));
    // The sentence wraps over several lines, and every line holds whole words only.
    expect(body.length).toBeGreaterThanOrEqual(3);
    for (const line of body) {
      for (const part of line.split(" ")) {
        if (part === "" || part === "Impact:") continue;
        expect(WORDS).toContain(part);
      }
    }
    const text = all.join("\n");
    expect(text).not.toContain("⁠");
    expect(text).not.toContain("?");
  });
});
