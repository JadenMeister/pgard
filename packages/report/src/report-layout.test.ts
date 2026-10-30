import { describe, expect, it } from "vitest";
import { renderHtmlReport } from "./render-html.js";
import { standardReasonText } from "./standards-reason-text.js";
import { DETAIL_RULE_TEXTS, scanResultV11 } from "./test-fixtures-details.js";
import { finding } from "./test-fixtures.js";

const EN = { lang: "en", ruleTexts: DETAIL_RULE_TEXTS } as const;
const KO = { lang: "ko", ruleTexts: DETAIL_RULE_TEXTS } as const;

const css = (html: string): string => /<style>([\s\S]*?)<\/style>/.exec(html)?.[1] ?? "";

describe("report table layout", () => {
  const html = renderHtmlReport(scanResultV11(), KO);

  it("keeps badges, IDs, ranks and scopes on one line", () => {
    const styles = css(html);
    expect(styles).toMatch(/\.nw[^{]*\.pill[^{]*\{[^}]*white-space: nowrap/);
    expect(styles).toMatch(/td\.token \{[^}]*overflow-wrap: anywhere/);
    expect(html).toMatch(/<th class="nw">ID<\/th>/);
    expect(html).toMatch(/<td class="nw"><a href="[^"]*"[^>]*>CWE-/);
    expect(html).toMatch(/<td class="nw"><span class="pill state-rules_ran">/);
    expect(html).toMatch(/<td class="nw">code<\/td>/);
    expect(html).toMatch(/<th class="nw">순위<\/th>/);
  });

  it("breaks Korean text between words and uses a wide page", () => {
    const styles = css(html);
    expect(styles).toMatch(/word-break: keep-all/);
    expect(styles).toMatch(/main \{ max-width: 1200px/);
  });

  it("wraps every data table in a horizontal scroll box", () => {
    const tables = html.match(/<table\b/g)?.length ?? 0;
    const wrapped = html.match(/<div class="table-scroll"><table\b/g)?.length ?? 0;
    expect(tables).toBeGreaterThanOrEqual(4);
    expect(wrapped).toBe(tables);
    expect(css(html)).toMatch(/\.table-scroll \{ overflow-x: auto/);
  });

  it("lets a long area name break only after a colon", () => {
    const base = scanResultV11();
    const result = {
      ...base,
      coverage: [{ ...base.coverage[0]!, area: "source:javascript" }, ...base.coverage.slice(1)],
    };
    const out = renderHtmlReport(result, EN);
    expect(out).toContain('<td class="token">source:<wbr>javascript</td>');
  });

  it("scales print tables down instead of breaking words", () => {
    const print = css(html).slice(css(html).indexOf("@media print"));
    expect(print).toContain(".table-scroll { overflow: visible; }");
    expect(print).toMatch(/\.standards-map[^{]*\{ font-size: 10px/);
  });

  it("still escapes finding and area text and keeps the CSP", () => {
    const base = scanResultV11({ findings: [finding({ title: "<b>x</b>" })] });
    const result = {
      ...base,
      coverage: [{ ...base.coverage[0]!, area: "a<i>:b" }, ...base.coverage.slice(1)],
    };
    const out = renderHtmlReport(result, KO);
    expect(out).toContain("a&lt;i&gt;:<wbr>b");
    expect(out).not.toContain("<i>:");
    expect(out).toContain("Content-Security-Policy");
  });
});

describe("Korean standards-map reasons", () => {
  it("renders the stored reasons in Korean in a KO report and keeps English as is", () => {
    const ko = renderHtmlReport(scanResultV11(), KO);
    expect(ko).toContain("매핑된 규칙이 끝까지 실행됨");
    expect(ko).not.toContain("mapped rules ran to completion");
    const en = renderHtmlReport(scanResultV11(), EN);
    expect(en).toContain("mapped rules ran to completion");
  });

  it("translates every sentence shape of the findings catalog", () => {
    const ko = (reason: string): string => standardReasonText(reason, "ko");
    expect(ko("no rules")).toBe("규칙 없음");
    expect(ko("partial areas: source:go, source:javascript")).toBe(
      "일부만 실행된 영역: source:go, source:javascript",
    );
    expect(ko("web rules not run: scope not selected")).toBe(
      "web 규칙 실행 안 됨: 범위를 선택하지 않음",
    );
    expect(ko("code rules not run: areas could not run")).toBe(
      "code 규칙 실행 안 됨: 영역을 실행하지 못함",
    );
    expect(
      ko("no mapped rule ran (R-A, R-B: web scope not selected, code areas could not run)"),
    ).toBe(
      "실행된 매핑 규칙이 없음 (R-A, R-B: web 범위를 선택하지 않음, code 영역을 실행하지 못함)",
    );
    expect(
      ko(
        'partial areas: source:go; no completed mapped rule covers java (3 files), go (1 file) (files that are not yours to scan can be left out with "exclude" in pgard.config.json)',
      ),
    ).toBe(
      '일부만 실행된 영역: source:go; 끝까지 실행된 매핑 규칙이 다루지 못하는 언어: java (3개 파일), go (1개 파일) (검사 대상이 아닌 파일은 pgard.config.json의 "exclude"로 제외할 수 있음)',
    );
    expect(ko("examined 0 targets: R-A")).toBe("살펴본 대상이 0개: R-A");
    expect(ko("no mapped area ran to completion")).toBe("끝까지 실행된 매핑 영역이 없음");
    expect(ko("rules not in the rule catalog ran (X-1), so the mapping may be incomplete")).toBe(
      "규칙 목록에 없는 규칙이 실행됨 (X-1), 매핑이 불완전할 수 있음",
    );
  });

  it("leaves an unknown sentence and the English language untouched", () => {
    expect(standardReasonText("something new", "ko")).toBe("something new");
    expect(standardReasonText("no rules", "en")).toBe("no rules");
  });
});
