import { describe, expect, it } from "vitest";
import { renderHtmlReport } from "./render-html.js";
import { renderPdfReport } from "./render-pdf.js";
import { renderReport } from "./write-report.js";
import { FIXTURE_RULE_TEXTS, finding, scanResult } from "./test-fixtures.js";
import { extractEmbeddedFontText } from "./test-pdf-text.js";

const ONE = (): ReturnType<typeof scanResult> => scanResult({ findings: [finding({})] });
const KO = { lang: "ko", ruleTexts: FIXTURE_RULE_TEXTS } as const;

describe("report language", () => {
  it("renders the HTML rule texts and finding labels in Korean and sets <html lang>", () => {
    const html = renderHtmlReport(ONE(), KO);
    expect(html).toContain('<html lang="ko">');
    expect(html).toContain("<h3>SQL에 이어 붙인 사용자 입력</h3>");
    expect(html).toContain("<dt>영향</dt><dd>쿼리 구조가 바뀔 수 있습니다</dd>");
    expect(html).toContain("<dt>권장 조치</dt><dd>매개변수를 사용하세요</dd>");
    expect(html).not.toContain("Use parameters");
    // The report chrome follows the language too.
    expect(html).toContain("<h1>PGARD 보안 보고서</h1>");
    expect(html).not.toContain("PGARD security report");
  });

  it("is unchanged by default and for en", () => {
    const plain = renderHtmlReport(scanResult());
    expect(plain).toContain('<html lang="en">');
    expect(plain).toContain("<dt>Impact</dt><dd>Query structure may change</dd>");
    expect(renderHtmlReport(scanResult(), { lang: "en", ruleTexts: FIXTURE_RULE_TEXTS })).toBe(
      plain,
    );
  });

  it("keeps a finding's own text instead of a translated default that would contradict it", () => {
    const html = renderHtmlReport(
      scanResult({ findings: [finding({ recommendation: "Remove node_modules from Git" })] }),
      KO,
    );
    expect(html).toContain("<dt>권장 조치</dt><dd>Remove node_modules from Git</dd>");
    expect(html).toContain("<dt>영향</dt><dd>쿼리 구조가 바뀔 수 있습니다</dd>");
  });

  it("extracts Korean rule text from the PDF (embedded font, ToUnicode)", async () => {
    const pdf = await renderPdfReport(ONE(), { ...KO, compress: false });
    const text = extractEmbeddedFontText(pdf).join("\n");
    expect(text).toContain("SQL에 이어 붙인 사용자 입력");
    expect(text).toContain("영향: 쿼리 구조가 바뀔 수 있습니다");
    expect(text).toContain("권장 조치: 매개변수를 사용하세요");
    expect(text).not.toContain("Use parameters");
  });

  it("passes the language through renderReport", async () => {
    const html = await renderReport(scanResult(), "html", undefined, KO);
    expect(String(html)).toContain('<html lang="ko">');
  });
});
