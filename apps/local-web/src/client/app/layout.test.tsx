import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Coverage, ScanResult } from "@pgard/findings";
import type { AuthStatus } from "../../shared/api-types";
import { authState } from "../features/onboarding/auth-state";
import type { Authorization } from "../features/onboarding/use-authorization";
import { AuthorizationSection } from "../features/onboarding/AuthorizationSection";
import { coverageCounts, statusLine } from "../features/findings/result-summary";
import { ScanStrip } from "../features/scan/ScanStrip";
import type { ScanControl } from "../features/scan/use-scan";
import { I18nProvider } from "../i18n/I18nProvider";
import { ko } from "../i18n/ko";
import { viewFromHash, VIEWS } from "./views";

afterEach(() => {
  vi.unstubAllGlobals();
});

const blocked: AuthStatus = {
  status: "done",
  deviceCode: null,
  summary: {
    decision: "blocked",
    checks: [
      { id: "repository", status: "passed", reason: "Found o/private" },
      { id: "owner_approval", status: "failed", reason: "The PGARD GitHub App is not installed" },
    ],
  },
  repo: "o/private",
  message: null,
  storedSignIn: { status: "stored", login: "dev" },
  remedy: null,
  accessNote: null,
  signInNotice: null,
  expiresAt: null,
  installWaitEndsAt: null,
} as AuthStatus;

const authorization = (status: AuthStatus | null): Authorization => ({
  status,
  error: null,
  verify: async () => undefined,
  signOut: async () => undefined,
});

const control: ScanControl = {
  scan: null,
  scopes: ["code", "history", "web"],
  toggleScope: () => undefined,
  isRunning: false,
  elapsedSeconds: 0,
  error: null,
  start: async () => undefined,
  cancel: async () => undefined,
};

const area = (status: Coverage["status"]): Coverage =>
  ({ area: `a-${status}`, scope: "code", status, ruleIds: [], note: null }) as Coverage;

describe("views", () => {
  it("maps each hash to its view and anything else to the overview", () => {
    for (const view of VIEWS) expect(viewFromHash(`#${view}`)).toBe(view);
    expect(viewFromHash("")).toBe("overview");
    expect(viewFromHash("#token=abc")).toBe("overview");
    expect(viewFromHash("#nope")).toBe("overview");
  });
});

describe("header strip", () => {
  it("names the gate state in one word", () => {
    expect(authState(null)).toBe("none");
    expect(authState(blocked)).toBe("blocked");
    expect(authState({ ...blocked, status: "running", summary: null })).toBe("checking");
    expect(authState({ ...blocked, summary: { decision: "allowed", checks: [] } })).toBe("allowed");
  });

  it("shows the repository, a blocked state, compact scope toggles and the web-target guidance", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const html = renderToStaticMarkup(
      <I18nProvider>
        <ScanStrip
          projectName="private"
          authorization={authorization(blocked)}
          control={control}
          target={null}
          onShowAuthorization={() => undefined}
        />
      </I18nProvider>,
    );
    expect(html).toContain('<h1 class="strip-title">o/private</h1>');
    expect(html).toContain('<span class="auth-state auth-blocked">Blocked</span>');
    expect(html.split('type="checkbox"').length - 1).toBe(3);
    expect(html).toContain("No web target");
    expect(html).toContain("Check again");
  });
});

describe("authorization section", () => {
  it("opens the check table for a blocked check so the failing reason is visible", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const html = renderToStaticMarkup(
      <I18nProvider>
        <AuthorizationSection
          session={{ githubApp: { source: "default" }, githubAppWarning: null } as never}
          authorization={authorization(blocked)}
        />
      </I18nProvider>,
    );
    expect(html).toContain('<details class="disclosure" open="">');
    expect(html).toContain("The PGARD GitHub App is not installed");
    expect(html).toContain('id="authorization"');
  });
});

describe("result status line", () => {
  const result = (overallStatus: ScanResult["overallStatus"], coverage: Coverage[]) =>
    ({ overallStatus, coverage }) as ScanResult;

  it("counts the requested areas by outcome", () => {
    expect(
      coverageCounts([
        area("completed"),
        area("partial"),
        area("not_tested"),
        area("not_selected"),
      ]),
    ).toEqual({ completed: 1, partial: 1, notTested: 1 });
  });

  it("says how many areas did not finish, in English and Korean", () => {
    const partial = result("partial", [area("completed"), area("partial"), area("not_tested")]);
    expect(statusLine(partial)).toBe("Partial · 2 areas did not finish");
    expect(statusLine(partial, ko)).toBe("부분 완료 · 2개 영역이 끝나지 않음");
    expect(statusLine(result("completed", [area("completed")]))).toBe("Completed");
    expect(statusLine(result("blocked", []))).toBe("Blocked · no analysis ran");
  });
});
