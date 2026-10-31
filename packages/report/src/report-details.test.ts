import { readFileSync } from "node:fs";
import type { ScanResult } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { formatFindingSummary } from "./format.js";
import { renderHtmlReport } from "./render-html.js";
import {
  PDF_FONT_REPLACEMENT_NOTICE,
  PDF_REPLACEMENT_NOTICE,
  renderPdfReport,
} from "./render-pdf.js";
import { isPdfFontCodePoint } from "./pdf-font.js";
import { REPORT_TEXT } from "./report-text.js";
import { summaryLine, reportContext } from "./report-view.js";
import {
  DETAIL_RULE_TEXTS,
  EXAMPLE_SAFE,
  EXAMPLE_VULNERABLE,
  scanResultV11,
} from "./test-fixtures-details.js";
import { finding, scanResult } from "./test-fixtures.js";
import { extractEmbeddedFontText } from "./test-pdf-text.js";

const EN = { lang: "en", ruleTexts: DETAIL_RULE_TEXTS } as const;
const KO = { lang: "ko", ruleTexts: DETAIL_RULE_TEXTS } as const;

function hrefs(html: string): string[] {
  return [...html.matchAll(/<a [^>]*href="([^"]*)"/g)].map((match) => match[1] ?? "");
}

describe("HTML hardening and size", () => {
  it("escapes the state and rank of forged coverage entries", () => {
    const result = scanResultV11();
    const map = result.standardsCoverage!;
    const forged = {
      ...result,
      standardsCoverage: {
        ...map,
        owasp: map.owasp.map((entry) => ({ ...entry, state: '"><b id=x>' })),
        cweTop25: map.cweTop25.map((entry) => ({
          ...entry,
          state: '"><i id=y>',
          rank: "<u id=z>",
        })),
      },
    } as unknown as ScanResult;
    const html = renderHtmlReport(forged, EN);
    expect(html).not.toContain("<b id=x>");
    expect(html).not.toContain("<i id=y>");
    expect(html).not.toContain("<u id=z>");
    expect(html).toContain("state-&quot;&gt;&lt;b id=x&gt;");
    expect(html).toContain("&lt;u id=z&gt;");
  });

  it("writes the examples and guidance of a rule once, however many findings it has", () => {
    const base = scanResultV11();
    const findings = Array.from({ length: 5 }, (_, index) =>
      finding({
        id: `f${index}`,
        impact: "Own impact",
      }),
    );
    const html = renderHtmlReport({ ...base, findings }, EN);
    expect(html.match(/<details class="examples">/g)).toHaveLength(1);
    expect(html.match(/class="guidance"/g) ?? []).toHaveLength(1);
    expect(html.match(/<article class="finding/g)).toHaveLength(5);
    expect(html.match(/<div class="standards">/g)).toHaveLength(5);
    // The first finding is the anchor; the other four link to it, in both languages.
    expect(html.match(/ id="rule-PG-SQL-001"/g)).toHaveLength(1);
    expect(html.match(/href="#rule-PG-SQL-001"/g)).toHaveLength(4);
    expect(html).toContain("Examples and guidance: see the first PG-SQL-001 finding");
    const ko = renderHtmlReport({ ...base, findings }, KO);
    expect(ko).toContain("예시와 안내: 첫 번째 PG-SQL-001 발견 항목을 참고하세요");
    expect(ko.match(/href="#rule-PG-SQL-001"/g)).toHaveLength(4);
    // The anchor comes before every link to it.
    expect(html.indexOf(' id="rule-PG-SQL-001"')).toBeLessThan(html.indexOf('href="#rule-'));
  });

  it("names the licence of the CERT rules by URL and uses the upstream trademark wording", () => {
    for (const lang of ["en", "ko"] as const) {
      const text = REPORT_TEXT[lang].licenseCert;
      expect(text).toContain("https://creativecommons.org/licenses/by/4.0/");
      expect(text).toMatch(/Carnegie Mellon( and |과 ?)CERT/);
      expect(text).not.toContain("SEI CERT are registered");
    }
  });
});

describe("HTML per-finding details", () => {
  for (const options of [EN, KO]) {
    it(`escapes the example code (${options.lang})`, () => {
      const html = renderHtmlReport(scanResultV11(), options);
      expect(html).toContain("<summary>");
      // The hostile code appears only in its escaped form.
      expect(html).not.toContain("<img src=x");
      expect(html).not.toContain("<b>");
      expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
      expect(html).toContain("&quot;quoted&quot; &amp; &lt;b&gt;");
      expect(html).toContain('<pre class="code"><code>');
      expect(EXAMPLE_VULNERABLE).toContain("<img");
      expect(EXAMPLE_SAFE).toContain("<b>");
    });
  }

  it("puts examples in a collapsed details element, in the chosen language", () => {
    const en = renderHtmlReport(scanResultV11(), EN);
    expect(en).toContain('<details class="examples"><summary>Examples (1)</summary>');
    expect(en).toContain("<strong>Vulnerable</strong>");
    expect(en).not.toContain('<details class="examples" open');
    const ko = renderHtmlReport(scanResultV11(), KO);
    expect(ko).toContain('<details class="examples"><summary>예시 (1)</summary>');
    expect(ko).toContain("<strong>취약한 코드</strong>");
    expect(ko).toContain("a의 따옴표가 쿼리를 바꿉니다.");
  });

  it("links the standards to official pages only, without opener or referrer", () => {
    const html = renderHtmlReport(scanResultV11(), EN);
    const links = hrefs(html);
    expect(links).toContain("https://top10.owasp.org/2025/A05_2025-Injection/");
    expect(links).toContain("https://cwe.mitre.org/data/definitions/89.html");
    expect(
      links.some((link) => link.startsWith("https://cmu-sei.github.io/secure-coding-standards/")),
    ).toBe(true);
    for (const link of links) {
      expect(link).toMatch(
        /^https:\/\/(top10\.owasp\.org\/2025\/|cwe\.mitre\.org\/data\/definitions\/\d+\.html|cmu-sei\.github\.io\/secure-coding-standards\/)/,
      );
    }
    for (const anchor of html.match(/<a [^>]*>/g) ?? []) {
      expect(anchor).toContain('rel="noopener noreferrer"');
      expect(anchor).toContain('target="_blank"');
    }
    expect(html).toContain("(indirect, via CWE-89)");
    expect(renderHtmlReport(scanResultV11(), KO)).toContain("(간접, CWE-89 경유)");
  });

  it("shows the rule's general text only when the finding carries its own different text", () => {
    const own = scanResultV11({
      findings: [finding({ recommendation: "Remove the query builder here" })],
    });
    const html = renderHtmlReport(own, KO);
    expect(html).toContain("<dt>권장 조치</dt><dd>Remove the query builder here</dd>");
    expect(html).toContain("<dt>일반적인 조치</dt><dd>매개변수를 사용하세요</dd>");
    // Default texts are not repeated.
    expect(renderHtmlReport(scanResultV11(), KO)).not.toContain("일반적인 조치");
  });
});

describe("HTML per-scan sections", () => {
  it("renders the standards coverage map with states and breadth, in neutral colours", () => {
    const html = renderHtmlReport(scanResultV11(), EN);
    expect(html).toContain("<h2>Standards coverage (OWASP Top 10 2025)</h2>");
    expect(html).toMatch(/A05[^]*Injection[^]*Rules ran/);
    expect(html).toContain("No rules");
    expect(html).toMatch(/\d+ of \d+ mapped CWEs have rules/);
    expect(html).toContain("does not mean the project is safe");
    expect(html).toContain('class="pill state-rules_ran"');
    expect(html).not.toMatch(/green/i);
    expect(html).not.toMatch(/#(?:16a34a|22c55e|15803d|059669)/i);
    expect(html).toContain("CWE Top 25 2025: ");
  });

  it("renders the rule statistics in a collapsed section with unknown counts explained", () => {
    const html = renderHtmlReport(scanResultV11(), EN);
    expect(html).toContain('<details class="group rule-stats">');
    expect(html).toContain("<summary>Rule statistics (2)</summary>");
    expect(html).toContain("12 files");
    expect(html).toContain("unknown (history was truncated)");
    expect(html).toContain("<th>Targets examined</th>");
    expect(html).toContain("User input concatenated into SQL");
  });

  it("localizes the headings, table headers, disclaimer and notices for Korean", () => {
    const html = renderHtmlReport(scanResultV11(), KO);
    for (const text of [
      "<h1>PGARD 보안 보고서</h1>",
      "<h2>요약</h2>",
      "<h2>검사 범위</h2>",
      "<h2>표준 매핑 현황 (OWASP Top 10 2025)</h2>",
      "<summary>규칙 통계 (2)</summary>",
      "<th>살펴본 대상</th>",
      "규칙 실행됨",
      "규칙 없음",
      "매핑된 CWE",
      "<h2>권한 확인</h2>",
      "<h2>분석 근거</h2>",
      "프로젝트가 안전하다는 뜻은 아닙니다",
      "CC BY-SA 4.0",
    ]) {
      expect(html).toContain(text);
    }
    expect(html).not.toContain("<h2>Summary</h2>");
    expect(html).not.toContain("Standards coverage");
  });

  it("states the licensing attribution in the footer", () => {
    const html = renderHtmlReport(scanResultV11(), EN);
    expect(html).toContain("OWASP Top 10:2025");
    expect(html).toContain("CC BY-SA 4.0");
    expect(html).toContain("The MITRE Corporation");
    expect(html).toContain("Carnegie Mellon University");
    expect(html).toContain("not endorsed");
  });

  it("localizes suppression and baseline notices in Korean", () => {
    const base = scanResultV11();
    const result: ScanResult = {
      ...base,
      baseline: {
        setAt: "2026-10-01T00:00:00.000Z",
        scanId: "b",
        revision: null,
        total: 1,
        matched: 0,
        new: 1,
        newInUncertainAreas: 1,
        toolVersionChanged: true,
      },
    };
    const html = renderHtmlReport(result, KO);
    expect(html).toContain("기준선이 충분히 다루지 못한 영역");
    expect(html).toContain("기준선을 설정한 뒤 PGARD가 업데이트");
    expect(html).toContain("<h2>새 발견 항목 (기준선 이후)</h2>");
    expect(html).toContain("기준선: 기준선에 있음 0건, 새 항목 1건.");
  });

  it("keeps the English summary line identical to the CLI's", () => {
    const result = scanResultV11();
    expect(summaryLine(result, reportContext({ lang: "en" }))).toBe(
      formatFindingSummary(result.findings, result),
    );
  });
});

describe("results written by schema 1.0", () => {
  const old = JSON.parse(
    readFileSync(new URL("../../findings/src/fixtures/result-1.0.json", import.meta.url), "utf8"),
  ) as ScanResult;

  for (const lang of ["en", "ko"] as const) {
    it(`renders HTML without the new fields (${lang})`, () => {
      const html = renderHtmlReport(old, { lang, ruleTexts: DETAIL_RULE_TEXTS });
      expect(html).toContain("<!doctype html>");
      expect(html).not.toContain("rule-stats");
      expect(html).not.toMatch(/<table class="[^"]*\bstandards-map\b/);
      expect(html).toContain(lang === "en" ? "were not recorded" : "기록되어 있지 않습니다");
    });
  }

  it("renders the PDF without the new fields", async () => {
    const pdf = await renderPdfReport(old, { compress: false, ruleTexts: DETAIL_RULE_TEXTS });
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
  });

  it("renders a 1.1 result whose findings have no catalog entry", () => {
    const html = renderHtmlReport(scanResultV11(), { lang: "ko" });
    expect(html).not.toContain('class="examples"');
    expect(html).toContain("<h2>표준 매핑 현황 (OWASP Top 10 2025)</h2>");
  });
});

describe("PDF with the new sections", () => {
  it("extracts Korean chrome, standards map and appendices without a fallback notice", async () => {
    let fallback: string | null | undefined;
    const pdf = await renderPdfReport(scanResultV11(), {
      ...KO,
      compress: false,
      onFontFallback: (message) => {
        fallback = message;
      },
    });
    const text = extractEmbeddedFontText(pdf).join("\n");
    expect(fallback).toBeNull();
    expect(text).not.toContain(PDF_FONT_REPLACEMENT_NOTICE);
    expect(text).not.toContain(PDF_REPLACEMENT_NOTICE);
    expect(text).not.toContain("?");
    for (const expected of [
      "PGARD 보안 보고서",
      "표준 매핑 현황 (OWASP Top 10 2025)",
      "규칙 실행됨",
      "매핑된 CWE",
      "CWE Top 25 2025",
      "부록 A: 규칙 통계",
      "규칙 통계 (2)",
      "알 수 없음 (history was truncated)",
      "부록 B: 발견 항목이 있는 규칙의 예시",
      "취약한 코드 (javascript)",
      "부록 C: 표준 링크",
      "표준:",
      "표준 데이터와 출처 표기",
      "프로젝트가 안전하다는 뜻은 아닙니다",
    ]) {
      expect(text).toContain(expected);
    }
    // Links are annotations with the full official URL, and the URL is printed in appendix C.
    const raw = pdf.toString("latin1");
    expect(raw).toContain("https://cwe.mitre.org/data/definitions/89.html");
    expect(raw).toContain("https://top10.owasp.org/2025/A05_2025-Injection/");
  });

  it("points every /URI link annotation at an official standards page", async () => {
    const pdf = await renderPdfReport(scanResultV11(), { ...EN, compress: false });
    const uris = [...pdf.toString("latin1").matchAll(/\/URI \(([^)]*)\)/g)].map(
      (match) => match[1] ?? "",
    );
    // Findings' standards line, the OWASP table rows and appendix C all carry annotations.
    expect(uris.length).toBeGreaterThan(10);
    for (const uri of uris) {
      expect(uri).toMatch(
        /^https:\/\/(top10\.owasp\.org\/2025\/A\d\d_2025-[A-Za-z_]+\/|cwe\.mitre\.org\/data\/definitions\/[1-9]\d*\.html|cmu-sei\.github\.io\/secure-coding-standards\/[a-z0-9/-]+)$/,
      );
    }
    const unique = new Set(uris);
    expect(unique).toContain("https://cwe.mitre.org/data/definitions/89.html");
    expect(unique).toContain("https://top10.owasp.org/2025/A05_2025-Injection/");
    expect([...unique].some((uri) => uri.startsWith("https://top10.owasp.org/2025/A01_"))).toBe(
      true,
    );
    expect([...unique].some((uri) => uri.startsWith("https://cmu-sei.github.io/"))).toBe(true);
  });

  it("keeps English chrome and the new sections for en", async () => {
    const pdf = await renderPdfReport(scanResultV11(), { ...EN, compress: false });
    const text = extractEmbeddedFontText(pdf).join("\n");
    expect(text).toContain("Standards coverage (OWASP Top 10 2025)");
    expect(text).toContain("Appendix A: rule statistics");
    expect(text).toContain("Standards:");
    expect(text).toContain("12 files");
  });

  it("is unchanged for results without the new data", async () => {
    const pdf = await renderPdfReport(scanResult(), { compress: false });
    const text = extractEmbeddedFontText(pdf).join("\n");
    expect(text).not.toContain("Appendix A");
  });
});

describe("report chrome and the PDF font", () => {
  /** Every string a fixed-text entry can produce, calling the template functions with samples. */
  function strings(value: unknown, out: string[] = []): string[] {
    if (typeof value === "string") out.push(value);
    else if (typeof value === "function") {
      const counts = { rules_ran: 1, rules_partial: 2, not_run: 3, no_rules: 4 };
      for (const args of [
        [3, "x", 5, 6, 7],
        ["a", "b", "c"],
        [counts],
        [2, 3, "a, b", true],
        ["a", 4, "b", false],
      ]) {
        try {
          const text = (value as (...a: unknown[]) => unknown)(...args);
          if (typeof text === "string") out.push(text);
        } catch {
          // Wrong sample shape for this function: another sample fits.
        }
      }
    } else if (value !== null && typeof value === "object") {
      for (const entry of Object.values(value)) strings(entry, out);
    }
    return out;
  }

  it("uses only characters the bundled Korean font has", () => {
    for (const lang of ["ko", "en"] as const) {
      const missing = new Set<string>();
      for (const text of strings(REPORT_TEXT[lang])) {
        for (const char of text) {
          if (char !== "\n" && !isPdfFontCodePoint(char.codePointAt(0) ?? 0)) missing.add(char);
        }
      }
      expect([...missing]).toEqual([]);
    }
  });

  it("defines every key in both languages", () => {
    expect(Object.keys(REPORT_TEXT.ko).sort()).toEqual(Object.keys(REPORT_TEXT.en).sort());
  });
});
