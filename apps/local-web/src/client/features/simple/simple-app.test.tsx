import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { GateReason, ScanStatus } from "../../../shared/api-types";
import { GatePanel, NotAuthorizedLabel, scanOutcome } from "./SimpleApp";
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

const RESULT = { findings: [], overallStatus: "completed" } as unknown as ScanStatus["result"];

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
    expect(outcome).toEqual({ gateReason: "no_approval", result: null, isCodeOnly: false });
  });

  it("shows an authorized result without the label and a code-only one with it", () => {
    expect(scanOutcome(status({ result: RESULT }))).toEqual({
      gateReason: null,
      result: RESULT,
      isCodeOnly: false,
    });
    expect(scanOutcome(status({ result: RESULT, codeOnly: true })).isCodeOnly).toBe(true);
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
    expect(t.badgeReason("check_failed")).not.toBe(t.badgeReason("unknown"));
  });
});
