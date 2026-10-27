import { describe, expect, it } from "vitest";
import type { Finding } from "@pgard/findings";
import { testFinding } from "../../test-support.js";
import { displayWidth, splitAnsiWord, stripAnsi } from "../i18n/display-width.js";
import { fitLine } from "./fit-lines.js";
import { realRepoResult } from "./result-fixture.js";
import { formatScanResult } from "./result-view.js";
import { createStyle } from "./style.js";

const colored = createStyle(true);
const ESC = String.fromCharCode(27);

function render(findings: Finding[], width: number, locale: "en" | "ko" = "en"): string {
  return formatScanResult({ ...realRepoResult(), findings }, colored, {
    locale,
    width,
    unicode: true,
    isTerminal: true,
  });
}

/** Every escape in the text must be a complete colour sequence. */
function brokenEscapes(text: string): string[] {
  return text
    .split(ESC)
    .slice(1)
    .filter((rest) => !/^\[[0-9;]*m/.test(rest));
}

describe("hostile text in the compact result", () => {
  const title = `${ESC}[31mRED${ESC}]0;pwned\u0007 \u009b2J ‮evil title`;
  const path = `src/${ESC}]8;;http://evil\u0007x${ESC}[2Jy‮/file.ts`;
  const hostile = testFinding({
    id: "h1",
    ruleId: `PG-${ESC}]0;rule\u0007\u202e-001`,
    title,
    severity: "critical",
    location: { kind: "file", path, line: 3, url: null, commit: null },
  });

  for (const width of [40, 60, 80]) {
    it(`strips control and bidi characters from title and path at ${width} columns`, () => {
      const text = render([hostile], width);
      expect(brokenEscapes(text)).toEqual([]);
      const visible = stripAnsi(text);
      expect(visible).not.toContain(ESC);
      expect(visible).not.toContain("\u0007");
      expect(visible).not.toContain("\u009b");
      expect(visible).not.toContain("‮");
      expect(visible).not.toContain("pwned]");
      expect(visible).toContain("evil title");
      for (const line of visible.split("\n")) {
        expect(displayWidth(line), line).toBeLessThanOrEqual(width);
      }
    });
  }
});

describe("long words in colour", () => {
  const longTitle = (character: string, count: number) =>
    testFinding({
      id: "l1",
      title: character.repeat(count),
      severity: "high",
      location: {
        kind: "file",
        path: `src/${"d".repeat(120)}/${character.repeat(40)}.ts`,
        line: 1,
        url: null,
        commit: null,
      },
    });

  for (const [locale, character, count] of [
    ["en", "A", 200],
    ["ko", "가", 100],
  ] as const) {
    for (const width of [40, 60, 80]) {
      it(`wraps a ${count}-character title and a long path at ${width} columns (${locale})`, () => {
        const text = render([longTitle(character, count)], width, locale);
        expect(brokenEscapes(text)).toEqual([]);
        for (const line of stripAnsi(text).split("\n")) {
          expect(displayWidth(line), line).toBeLessThanOrEqual(width);
        }
        // Nothing was lost: the pieces of the title add up.
        const joined = stripAnsi(text).replaceAll("\n", "").replaceAll(" ", "");
        expect(joined).toContain(character.repeat(count));
      });
    }
  }
});

describe("splitAnsiWord", () => {
  it("never cuts inside an escape sequence and styles every piece on its own", () => {
    const word = colored.bold("x".repeat(53));
    const pieces = splitAnsiWord(word, 10);
    expect(pieces).toHaveLength(6);
    for (const piece of pieces) {
      expect(brokenEscapes(piece)).toEqual([]);
      expect(displayWidth(piece)).toBeLessThanOrEqual(10);
      // Each piece opens and closes its own bold.
      expect(piece.startsWith(`${ESC}[1m`)).toBe(true);
      expect(piece.endsWith(`${ESC}[0m`) || piece.endsWith(`${ESC}[22m`)).toBe(true);
    }
    expect(pieces.map(stripAnsi).join("")).toBe("x".repeat(53));
  });

  it("keeps a ZWJ emoji and a letter with its combining mark in one piece", () => {
    const family = "\u{1F468}‍\u{1F469}‍\u{1F467}";
    const word = `${family}é${family}é${family}`;
    for (const room of [2, 3, 4, 5]) {
      const pieces = splitAnsiWord(word, room);
      expect(pieces.join("")).toBe(word);
      for (const piece of pieces) {
        expect(piece.startsWith("‍")).toBe(false);
        expect(piece.startsWith("́")).toBe(false);
        expect(piece.endsWith("‍")).toBe(false);
      }
    }
  });

  it("is what fitLine uses for a long coloured word", () => {
    const lines = fitLine(`  ${colored.bold("y".repeat(120))}`, 30);
    for (const line of lines) {
      expect(displayWidth(line)).toBeLessThanOrEqual(30);
      expect(brokenEscapes(line)).toEqual([]);
    }
  });
});

describe("suppressed and baseline findings in the compact result", () => {
  it("shows the suppression reason with a suppressed critical finding", () => {
    const suppressed = testFinding({
      id: "s1",
      title: "Accepted injection",
      severity: "critical",
      suppression: {
        reason: "accepted by the security review of 2026-09",
        expires: "2027-01-01",
        source: "pgard.config.json",
      },
    });
    const text = stripAnsi(render([suppressed], 100)).replace(/\s+/g, " ");
    expect(text).toContain("accepted by the security review of 2026-09");
    expect(text).toContain("[CRITICAL] Accepted injection");
  });
});
