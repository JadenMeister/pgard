import { describe, expect, it } from "vitest";
import { coverageNote, type Coverage, type ScanResult } from "@pgard/findings";
import { renderHtmlReport } from "./render-html.js";
import { renderPdfReport } from "./render-pdf.js";
import { FIXTURE_RULE_TEXTS, scanResult } from "./test-fixtures.js";
import { extractEmbeddedFontText } from "./test-pdf-text.js";

const KO = { lang: "ko", ruleTexts: FIXTURE_RULE_TEXTS } as const;

const REASON =
  'The PGARD GitHub App is installed by the owner account "acme" and includes acme/app.';

function withNotes(coverage: Coverage[]): ScanResult {
  return scanResult({
    coverage,
    authorization: {
      decision: "allowed",
      checks: [
        {
          id: "repository",
          status: "passed",
          reason: 'Git repository with remote "origin" -> github.com/acme/app.',
        },
        { id: "owner_approval", status: "passed", reason: REASON },
        { id: "contribution", status: "unverifiable", reason: "A reason nobody translated." },
      ],
    },
  });
}

const CODED: Coverage[] = [
  {
    area: "source:large-files",
    scope: "code",
    status: "partial",
    ruleIds: [],
    ...coverageNote("large_files_skipped", { count: 3 }),
  },
  {
    area: "web",
    scope: "web",
    status: "not_tested",
    ruleIds: [],
    ...coverageNote("web_target_missing"),
  },
  // An old result: free text, no code.
  {
    area: "source:legacy",
    scope: "code",
    status: "completed",
    ruleIds: [],
    note: "Legacy English note",
  },
];

describe("Korean report: coverage notes and the authorization section (#449)", () => {
  it("shows catalog texts, labels and translated reasons in the HTML report", () => {
    const html = renderHtmlReport(withNotes(CODED), KO);
    expect(html).toContain("1 MiB를 넘는 소스 파일 3개를 건너뛰었습니다.");
    expect(html).toContain("확인된 로컬 웹 대상이 선택되지 않았습니다.");
    expect(html).not.toContain("source file(s) over 1 MiB");
    // A note without a code keeps its stored English text.
    expect(html).toContain("Legacy English note");
    expect(html).toContain("<p>결정: 허용됨</p>");
    expect(html).toContain('<td class="nw">저장소</td><td class="nw">통과</td>');
    expect(html).toContain('<td class="nw">소유자 승인</td>');
    expect(html).toContain('<td class="nw">확인 불가</td><td>A reason nobody translated.</td>');
    expect(html).toContain(
      "소유자 계정 &quot;acme&quot;이(가) PGARD GitHub App을 설치했고 acme/app이(가) 포함되어 있습니다.",
    );
    expect(html).not.toContain(">owner_approval<");
    expect(html).not.toContain(">passed<");
  });

  it("keeps the English report unchanged: stored note, raw ids and statuses", () => {
    const html = renderHtmlReport(withNotes(CODED), { lang: "en", ruleTexts: FIXTURE_RULE_TEXTS });
    expect(html).toContain("3 source file(s) over 1 MiB were skipped.");
    expect(html).toContain("<p>Decision: allowed</p>");
    expect(html).toContain('<td class="nw">owner_approval</td><td class="nw">passed</td>');
    expect(html).toContain(REASON.replace(/"/g, "&quot;"));
  });

  it("escapes a tampered code and params: markup never reaches the output", () => {
    const evil = "<img src=x onerror=alert(1)>";
    const tampered: Coverage[] = [
      {
        area: "a1",
        scope: "code",
        status: "partial",
        ruleIds: [],
        note: `Stored <b>${evil}</b>`,
        noteCode: "orm_unsupported",
        noteParams: { library: evil },
      },
      {
        area: "a2",
        scope: "code",
        status: "partial",
        ruleIds: [],
        note: `Stored two ${evil}`,
        noteCode: `<script>${evil}</script>`,
        noteParams: { count: 1 },
      },
    ];
    const result = withNotes(tampered);
    result.authorization.checks[0] = {
      id: "repository",
      status: "passed",
      reason: `Signed in to GitHub as ${evil}.`,
    };
    for (const options of [KO, { lang: "en" as const, ruleTexts: FIXTURE_RULE_TEXTS }]) {
      const html = renderHtmlReport(result, options);
      expect(html).not.toContain("<img src=x");
      expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    }
  });

  it("falls back to the stored text for an unknown code", () => {
    const html = renderHtmlReport(
      withNotes([
        {
          area: "a",
          scope: "code",
          status: "completed",
          ruleIds: [],
          note: "Stored text",
          noteCode: "from_the_future",
          noteParams: { x: 1 },
        },
      ]),
      KO,
    );
    expect(html).toContain("Stored text");
  });

  it("shows the same Korean texts in the PDF report", async () => {
    const pdf = await renderPdfReport(withNotes(CODED), { ...KO, compress: false });
    const text = extractEmbeddedFontText(pdf).join("\n");
    expect(text).toContain("1 MiB를 넘는 소스 파일 3개를 건너뛰었습니다.");
    expect(text).toContain("결정: 허용됨");
    expect(text).toContain("소유자 승인: 통과");
    expect(text).toContain("Legacy English note");
    expect(text).not.toContain("owner_approval");
  });
});
