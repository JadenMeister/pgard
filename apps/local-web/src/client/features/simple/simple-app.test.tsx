import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { GateReason, ScanStatus } from "../../../shared/api-types";
import type { Finding } from "@pgard/findings";
import {
  GatePanel,
  NotAuthorizedLabel,
  scanButtonLabel,
  scanOutcome,
  simpleFindingText,
} from "./SimpleApp";
import { simpleText } from "./simple-text";

const REASONS: GateReason[] = [
  "no_approval",
  "not_signed_in",
  "no_github_remote",
  "not_a_git_repository",
  "check_failed",
];

function status(overrides: Partial<ScanStatus>): ScanStatus {
  return {
    status: "done",
    scopes: ["code"],
    progress: [],
    result: null,
    message: null,
    deviceCode: null,
    codeOnly: false,
    gateReason: null,
    ...overrides,
  } as ScanStatus;
}

const RESULT = {
  findings: [],
  overallStatus: "completed",
  authorization: { decision: "allowed", checks: [] },
  scanBasis: { mode: "authorized", authorization: "verified", reason: null },
} as unknown as ScanStatus["result"];
const UNVERIFIED = {
  ...RESULT!,
  authorization: { decision: "blocked", checks: [] },
  scanBasis: { mode: "code_only", authorization: "not_verified", reason: "no_approval" },
} as unknown as ScanStatus["result"];

function gate(reason: GateReason, language: "en" | "ko" = "en") {
  const onCodeOnly = vi.fn();
  const onSignIn = vi.fn();
  const html = renderToStaticMarkup(
    <GatePanel
      reason={reason}
      t={simpleText(language)}
      appSlug="pgard-app"
      isBusy={false}
      onCodeOnly={onCodeOnly}
      onSignIn={onSignIn}
      onOpenFull={() => undefined}
    />,
  );
  return { html, onCodeOnly, onSignIn };
}

describe("scanOutcome", () => {
  it("shows nothing while idle or running", () => {
    expect(scanOutcome(null).result).toBeNull();
    expect(scanOutcome(status({ status: "running", result: RESULT })).result).toBeNull();
  });

  it("shows the gate's reason and hides the blocked result", () => {
    const outcome = scanOutcome(status({ gateReason: "no_approval", result: RESULT }));
    expect(outcome).toEqual({
      gateReason: "no_approval",
      result: null,
      isCodeOnly: false,
      isAuthorized: false,
    });
  });

  it("shows an authorized result without the label and a code-only one with it", () => {
    expect(scanOutcome(status({ result: RESULT }))).toEqual({
      gateReason: null,
      result: RESULT,
      isCodeOnly: false,
      isAuthorized: true,
    });
    const codeOnly = scanOutcome(status({ result: UNVERIFIED, codeOnly: true }));
    expect(codeOnly.isCodeOnly).toBe(true);
    expect(codeOnly.isAuthorized).toBe(false);
  });

  it("never calls a result authorized only because there is no gate reason", () => {
    expect(scanOutcome(status({ result: UNVERIFIED })).isAuthorized).toBe(false);
  });
});

describe("the one primary button", () => {
  const t = simpleText("ko");
  it("says Check again after a gate, Check approval again after a code-only result", () => {
    expect(scanButtonLabel(t, scanOutcome(null))).toBe("검사");
    expect(scanButtonLabel(t, scanOutcome(status({ gateReason: "no_approval" })))).toBe(
      "다시 확인",
    );
    expect(scanButtonLabel(t, scanOutcome(status({ result: UNVERIFIED, codeOnly: true })))).toBe(
      "승인 다시 확인",
    );
    expect(scanButtonLabel(t, scanOutcome(status({ result: RESULT })))).toBe("다시 검사");
  });
});

describe("finding titles", () => {
  const texts = {
    "PG-SQL-001": {
      title: { en: "SQL injection", ko: "SQL 인젝션" },
      impact: { en: "i", ko: "영향" },
      recommendation: { en: "r", ko: "조치" },
    },
  };
  const finding = (title: string) =>
    ({ ruleId: "PG-SQL-001", title, impact: "i", recommendation: "r" }) as unknown as Finding;
  it("are Korean in the Korean page, also when the finding wrote its own title", () => {
    expect(simpleFindingText(finding("SQL injection"), texts, "ko").title).toBe("SQL 인젝션");
    expect(simpleFindingText(finding("SQL built in pg query"), texts, "ko").title).toBe(
      "SQL 인젝션",
    );
    expect(simpleFindingText(finding("SQL built in pg query"), texts, "en").title).toBe(
      "SQL built in pg query",
    );
    expect(simpleFindingText(finding("x"), null, "ko").title).toBe("x");
  });
});

describe("GatePanel", () => {
  it("says why in one line, in both languages, for every reason", () => {
    for (const language of ["en", "ko"] as const) {
      const t = simpleText(language);
      for (const reason of REASONS) {
        const { html } = gate(reason, language);
        expect(t.gateReasons[reason].length).toBeGreaterThan(0);
        expect(html).toContain(t.gateReasons[reason]);
        expect(html).toContain(t.codeOnlyButton);
      }
    }
    expect(simpleText("ko").codeOnlyButton).toBe("코드만 검사 (권한 미확인)");
    expect(simpleText("ko").howToApprove).toBe("승인 방법 보기");
    expect(simpleText("ko").signInLink).toBe("로그인하고 승인 확인");
  });

  it("has no primary button: Check again is the page's only one", () => {
    const { html } = gate("no_approval");
    expect(html).not.toContain("btn-primary");
  });

  it("says when it hides earlier code-only findings", () => {
    const t = simpleText("en");
    const html = renderToStaticMarkup(
      <GatePanel
        reason="no_approval"
        t={t}
        appSlug={null}
        isBusy={false}
        hidesPrevious
        onCodeOnly={() => undefined}
        onSignIn={() => undefined}
        onOpenFull={() => undefined}
      />,
    );
    expect(html).toContain(t.previousHidden);
  });

  it("offers How to approve when the gate refused, and runs nothing on its own", () => {
    const t = simpleText("en");
    const { html, onCodeOnly, onSignIn } = gate("no_approval");
    expect(html).toContain(t.howToApprove);
    expect(html).not.toContain(t.signInLink);
    expect(onCodeOnly).not.toHaveBeenCalled();
    expect(onSignIn).not.toHaveBeenCalled();
  });

  it("does not push sign-in: a quiet link next to the code-only button", () => {
    const t = simpleText("en");
    const { html, onSignIn } = gate("not_signed_in");
    expect(html).toContain(t.signInLink);
    expect(html).toContain('class="link-button"');
    expect(html).not.toContain(t.howToApprove);
    expect(onSignIn).not.toHaveBeenCalled();
  });
});

describe("NotAuthorizedLabel", () => {
  it("names the reason in plain words", () => {
    const t = simpleText("en");
    const html = renderToStaticMarkup(
      <NotAuthorizedLabel t={t} reason="no_approval" onConnect={() => undefined} />,
    );
    expect(html).toContain(t.badge);
    expect(html).toContain(t.badgeReason("no_approval"));
    expect(simpleText("ko").badgeTitle).toBe("코드만 검사했습니다 (Git 기록·저장 제외)");
    // Two lines: the label with what was scanned, then the reason with the link.
    expect(html.match(/<p/g)?.length).toBe(2);
    expect(t.badgeReason("check_failed")).not.toBe(t.badgeReason("unknown"));
  });
});
