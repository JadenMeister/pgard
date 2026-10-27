import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { testFinding } from "../../test-support.js";
import { getRuleTextCatalog } from "../../rule-texts.js";
import { displayWidth, splitAnsiWord, stripAnsi } from "../i18n/display-width.js";
import { fitLine } from "./fit-lines.js";
import { realRepoResult } from "./result-fixture.js";
import { formatScanResult } from "./result-view.js";
import { createStyle } from "./style.js";

// Text from the scan is cut with a Unicode ellipsis only where the console can show it; the
// snapshots must not depend on the machine that runs them (Windows CI, TERM=dumb).
const platform = Object.getOwnPropertyDescriptor(process, "platform");
beforeAll(() => {
  Object.defineProperty(process, "platform", { value: "darwin" });
  vi.stubEnv("TERM", "xterm-256color");
});
afterAll(() => {
  if (platform !== undefined) Object.defineProperty(process, "platform", platform);
  vi.unstubAllEnvs();
});

const plain = createStyle(false);
const colored = createStyle(true);

type Locale = "en" | "ko";

function render(
  locale: Locale,
  width: number,
  options: { allFindings?: boolean; isTerminal?: boolean; color?: boolean } = {},
): string {
  return formatScanResult(realRepoResult(), options.color === true ? colored : plain, {
    locale,
    width,
    unicode: true,
    ruleTexts: getRuleTextCatalog(),
    allFindings: options.allFindings === true,
    isTerminal: options.isTerminal ?? true,
  });
}

const STANDARDS_URL_PATTERN =
  /https:\/\/(?:top10\.owasp\.org|owasp\.org|cwe\.mitre\.org|cmu-sei\.github\.io|wiki\.sei\.cmu\.edu)\/\S*/g;

/**
 * Lines that break the width rule. Only PGARD's own standards links (fixed reference URLs) may run
 * past the width, and any other URL is cut at twice the width. Everything else must fit.
 */
function overWideLines(text: string, width: number): string[] {
  return stripAnsi(text)
    .split("\n")
    .filter((line) => {
      if (displayWidth(line) <= width) return false;
      if (displayWidth(line.replace(STANDARDS_URL_PATTERN, "")) <= width) return false;
      return !(/https?:\/\//.test(line) && displayWidth(line) <= width * 2);
    });
}

/** The text after the last blank line: the closing "Next" paragraph. */
function lastParagraph(text: string): string {
  return text.trimEnd().split("\n\n").at(-1) ?? "";
}

/** The text with wrapping undone, for phrases that may be split across lines. */
function flat(text: string): string {
  return stripAnsi(text).replace(/\s+/g, " ");
}

const CASES: ReadonlyArray<[Locale, number]> = [
  ["en", 80],
  ["en", 120],
  ["ko", 80],
  ["ko", 120],
];

describe("terminal result, compact (default)", () => {
  for (const [locale, width] of CASES) {
    it(`matches the reviewed layout: ${locale}, ${width} columns, NO_COLOR`, () => {
      expect(render(locale, width)).toMatchSnapshot();
    });
  }

  it("lists at most 10 groups, most severe first, then says what was left out", () => {
    const text = render("en", 80);
    const real = text.slice(text.indexOf("Findings ("), text.indexOf("In test or fixture code"));
    const titles = real
      .split("\n")
      .filter((line) => /^\s{2}\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/.test(line));
    expect(titles).toHaveLength(10);
    expect(titles[0]).toContain("[CRITICAL]");
    expect(titles[1]).toContain("[CRITICAL]");
    expect(text).toMatch(/\+\d+ more findings \(Medium \d+, Low \d+\) - run with --all-findings/);
    // Critical and high are all listed before anything lower.
    expect(titles.filter((line) => /\[(CRITICAL|HIGH)\]/.test(line))).toHaveLength(7);
  });

  it("lists a secret beyond the 10 groups, and says nothing is hidden about it", () => {
    const base = realRepoResult();
    const many = Array.from({ length: 12 }, (_, i) =>
      testFinding({
        id: `x${i}`,
        ruleId: `PG-XYZ-${String(i).padStart(3, "0")}`,
        title: `Medium issue ${i}`,
        severity: "high",
        location: { kind: "file", path: `src/x${i}.ts`, line: 1, url: null, commit: null },
      }),
    );
    const secret = testFinding({
      id: "s1",
      ruleId: "PG-SECRET-001",
      title: "Hardcoded credential",
      severity: "low",
      location: { kind: "file", path: "src/very-last-secret.ts", line: 3, url: null, commit: null },
    });
    const text = formatScanResult({ ...base, findings: [...many, secret] }, plain, {
      locale: "en",
      width: 80,
      unicode: true,
      isTerminal: true,
    });
    expect(text).toContain("src/very-last-secret.ts");
    expect(text).toContain("+2 more findings (High 2) - run with --all-findings");
  });

  it("puts findings first and ends on the summary, charts, coverage and the next step", () => {
    const text = render("en", 80);
    const at = (needle: string): number => text.indexOf(needle);
    expect(at("Findings (")).toBeGreaterThan(-1);
    expect(at("Findings (")).toBeLessThan(at("Summary"));
    expect(at("Summary")).toBeLessThan(at("Findings by severity"));
    expect(at("Findings by severity")).toBeLessThan(at("By OWASP Top 10 2025 category"));
    expect(at("By OWASP Top 10 2025 category")).toBeLessThan(at("Coverage"));
    expect(at("Coverage")).toBeLessThan(at("Next:"));
    expect(lastParagraph(text)).toMatch(/^Next:/);
  });

  it("keeps the header short: repository, revision, scopes and status", () => {
    const [title = "", ...rest] = render("en", 80).split("\n");
    const repo = flat(rest.slice(0, 2).join("\n"));
    expect(title).toMatch(/^PGARD scan result - Partial/);
    expect(repo).toContain("acme-corp/storefront-platform-monorepo @ 9f3c2a1b7d4e");
    expect(repo).toContain("scopes: code, history, web");
  });

  it("never hides partial or not-tested coverage or the not-a-safe-result warnings", () => {
    const text = flat(render("en", 80));
    expect(text).toContain("2 ok, 1 partial, 1 not tested, 1 not selected");
    expect(text).toMatch(/\[partial\] history:secrets/);
    expect(text).toMatch(/\[not tested\] web:anonymous/);
    expect(text).toContain("older secrets are not checked");
    expect(text).toContain("pass --port to include it");
    expect(text).toContain("Not a safe result");
    // The standards caveat and the analysis basis stay too.
    expect(text).toContain("It does not mean the project is safe");
    expect(text).toContain("OWASP Top 10 2025:");
    const ko = flat(render("ko", 80));
    expect(ko).toContain("안전하다는 결과가 아닙니다");
    expect(ko).toContain("history:secrets");
    expect(ko).toContain("web:anonymous");
  });

  it("does not wrap a coverage note in the middle of a word", () => {
    const text = render("en", 80);
    const note = stripAnsi(text)
      .split("\n")
      .filter((line) => /history:secrets|^\s{4,}\S/.test(line));
    const joined = note.map((line) => line.trim()).join(" ");
    expect(joined).toContain("Only the last 500 commits were read because the repository history");
  });

  it("keeps test, fixture and vendored code apart, counted by severity", () => {
    const text = flat(render("en", 80));
    expect(text).toContain("In test or fixture code (14): High 2, Medium 4, Low 8");
    expect(text).toMatch(/Suggestions: in third-party\/vendored code \(11\): Low 6, Info 5/);
    expect(text).toContain("plus 14 in test or fixture code (2 high)");
  });

  it("still names critical and high findings in test code, and every secret", () => {
    for (const width of [60, 80, 120]) {
      const text = flat(render("en", width));
      // The high PG-SECRET-001 findings in test/fixtures/ are listed, not only counted.
      expect(text, String(width)).toContain("[HIGH] Hardcoded credential");
      expect(text, String(width)).toContain("test/fixtures/aws.json");
      expect(text, String(width)).toContain("PG-SECRET-001");
    }
    const ko = flat(render("ko", 80));
    expect(ko).toContain("test/fixtures/aws.json");
  });

  it("lists critical and high vendored findings under the vendored line, with their own cap", () => {
    const base = realRepoResult();
    const severe = Array.from({ length: 8 }, (_, i) =>
      testFinding({
        id: `v${i}`,
        ruleId: `PG-VND-${i}`,
        title: `Vendored problem ${i}`,
        severity: "critical",
        context: "vendored",
        location: { kind: "file", path: `vendor/v${i}.js`, line: 1, url: null, commit: null },
      }),
    );
    const text = flat(
      formatScanResult({ ...base, findings: severe }, plain, {
        locale: "en",
        width: 100,
        unicode: true,
        isTerminal: true,
      }),
    );
    expect(text).toContain("vendor/v0.js");
    expect(text).toContain("vendor/v4.js");
    expect(text).not.toContain("vendor/v5.js");
    expect(text).toContain("+3 more findings (Critical 3) - run with --all-findings");
  });

  it("shows no evidence, fix or standards lines", () => {
    const text = render("en", 120);
    expect(text).not.toMatch(/^\s+Evidence:/m);
    expect(text).not.toMatch(/^\s+Fix:/m);
    expect(text).not.toMatch(/^\s+Standards:/m);
    expect(text).toContain("Evidence, fix and standards for each finding: --all-findings");
  });

  it("is much shorter than the full form", () => {
    expect(render("en", 80).split("\n").length).toBeLessThan(
      render("en", 80, { allFindings: true }).split("\n").length / 2,
    );
  });
});

describe("terminal result, --all-findings", () => {
  for (const [locale, width] of CASES) {
    it(`matches the reviewed layout: ${locale}, ${width} columns, NO_COLOR`, () => {
      expect(render(locale, width, { allFindings: true })).toMatchSnapshot();
    });
  }

  it("lists every finding in full and still ends on the summary", () => {
    const text = render("en", 120, { allFindings: true });
    expect(text).toContain("Evidence:");
    expect(text).toContain("Fix:");
    expect(text).toContain("Standards:");
    expect(text).toContain("Standards coverage (OWASP Top 10 2025)");
    expect(text).toContain("In test or fixture code (14)");
    expect(text).toContain("in third-party/vendored code (11)");
    expect(text).not.toContain("more findings");
    expect(lastParagraph(text)).toMatch(/^Next:/);
    expect(text.indexOf("Evidence:")).toBeLessThan(text.indexOf("Findings by severity"));
  });
});

describe("width invariant", () => {
  const widths = [60, 80, 100, 120];
  for (const locale of ["en", "ko"] as const) {
    for (const allFindings of [false, true]) {
      for (const width of widths) {
        it(`no line is wider than ${width} columns except URLs: ${locale}${allFindings ? ", all findings" : ""}`, () => {
          for (const color of [false, true]) {
            const text = render(locale, width, { allFindings, color });
            expect(overWideLines(text, width)).toEqual([]);
          }
        });
      }
    }
  }

  it("keeps PGARD's standards links whole and cuts any other URL at twice the width", () => {
    const text = render("en", 60, { allFindings: true });
    const lines = stripAnsi(text).split("\n");
    const wide = lines.filter((line) => displayWidth(line) > 60);
    expect(wide.length).toBeGreaterThan(0);
    expect(text).toContain("https://cwe.mitre.org/data/definitions/78.html");
    const cut = lines.find((line) => line.includes("shop.example.com")) ?? "";
    expect(displayWidth(cut)).toBeLessThanOrEqual(120);
    expect(cut.endsWith("...")).toBe(true);
    expect(overWideLines(text, 60)).toEqual([]);
  });

  it("does not let a hostile URL push a line to hundreds of columns", () => {
    const url = `https://evil.example/${"a".repeat(500)}`;
    for (const width of [40, 60, 80]) {
      const lines = fitLine(`  src/${url}`, width);
      for (const line of lines) expect(displayWidth(line)).toBeLessThanOrEqual(width * 2);
    }
  });

  it("hangs a wrapped line under its text, not at column 0", () => {
    const lines = fitLine(
      "  [partial] history:secrets (partial) - Only the last 500 commits were read because of a long history",
      60,
    );
    expect(lines.length).toBeGreaterThan(1);
    for (const line of lines.slice(1)) expect(line.startsWith("            ")).toBe(true);
    expect(lines.every((line) => displayWidth(line) <= 60)).toBe(true);
  });

  it("cuts a long word that is not a URL, and keeps colour codes balanced", () => {
    const lines = fitLine(`  Evidence: ${"x".repeat(150)}`, 60);
    expect(lines.every((line) => displayWidth(line) <= 60)).toBe(true);
    const bold = fitLine(
      `  ${colored.dim("a long dim sentence that needs to be wrapped at some width")}`,
      30,
    );
    for (const line of bold) expect(displayWidth(line)).toBeLessThanOrEqual(30);
  });
});

describe("the stable form (no terminal)", () => {
  it("keeps the summary first and every finding in full, as before", () => {
    const text = render("en", 80, { isTerminal: false });
    expect(text.indexOf("Summary")).toBeLessThan(text.indexOf("Findings ("));
    expect(text).toContain("Evidence:");
    expect(text).not.toContain("Next:");
    expect(lastParagraph(text)).toContain("PGARD does not ship or query a vulnerability database");
  });

  it("is the same with and without the terminal option left unset", () => {
    const unset = formatScanResult(realRepoResult(), plain, {
      locale: "en",
      width: 80,
      unicode: true,
      ruleTexts: getRuleTextCatalog(),
    });
    expect(render("en", 80, { isTerminal: false })).toBe(unset);
  });
});
