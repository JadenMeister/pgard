import { coverageNote, type Coverage } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { CLI_TEXT } from "../i18n/cli-text.js";
import { formatAuthorization, formatCoverage } from "./result-view.js";
import { createStyle } from "./style.js";

const plain = createStyle(false);
const KO = CLI_TEXT.ko;
const EN = CLI_TEXT.en;

function entry(overrides: Partial<Coverage>): Coverage {
  return {
    area: "source:x",
    scope: "code",
    status: "partial",
    ruleIds: [],
    note: null,
    ...overrides,
  };
}

describe("Korean CLI coverage view and authorization (#449)", () => {
  const coded = entry({
    area: "source:large-files",
    ...coverageNote("large_files_skipped", { count: 3 }),
  });
  const legacy = entry({ area: "source:legacy", note: "Legacy English note" });
  const tampered = entry({
    area: "source:orm:x",
    note: "Stored note",
    noteCode: "orm_unsupported",
    noteParams: { library: "<script>alert(1)</script>" },
  });

  it("shows the catalog text without parentheses, and the stored text in parentheses otherwise", () => {
    const view = formatCoverage([coded, legacy, tampered], plain, KO);
    expect(view).toContain("1 MiB를 넘는 소스 파일 3개를 건너뛰었습니다.");
    expect(view).not.toContain("source file(s)");
    expect(view).toContain("(Legacy English note)");
    expect(view).toContain("(Stored note)");
    expect(view).not.toContain("<script>");
  });

  it("is unchanged in English", () => {
    const view = formatCoverage([coded, legacy], plain, EN);
    expect(view).toContain("3 source file(s) over 1 MiB were skipped.");
    expect(view).toContain("- Legacy English note");
  });

  it("translates the checks, statuses and the fixed reasons, and parenthesizes an unknown one", () => {
    const text = formatAuthorization(
      {
        decision: "allowed",
        checks: [
          {
            id: "repository",
            status: "passed",
            reason: 'Git repository with remote "origin" -> github.com/acme/app.',
          },
          { id: "owner_approval", status: "passed", reason: "Owner approved" },
          { id: "contribution", status: "failed", reason: "Signed in to GitHub as <b>x</b>." },
        ],
      },
      plain,
      KO,
    );
    expect(text).toContain(
      '[통과] 저장소: Git 저장소입니다. 원격 "origin"이(가) github.com/acme/app을(를) 가리킵니다.',
    );
    expect(text).toContain("[통과] 소유자 승인 (Owner approved)");
    expect(text).toContain("[실패] 기여 (Signed in to GitHub as <b>x</b>.)");
  });
});
