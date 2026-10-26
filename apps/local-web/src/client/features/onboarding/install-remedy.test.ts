import { describe, expect, it } from "vitest";
import type { InstallRemedyDto } from "../../../shared/api-types";
import {
  describeInstallRemedy,
  INSTALL_POLL_INTERVAL_MS,
  isInstallWaitOver,
  nextInstallStep,
} from "./install-remedy";

const URL =
  "https://github.com/apps/pgard-jadenmeister/installations/new/permissions?suggested_target_id=42&repository_ids%5B%5D=555";

function remedy(overrides: Partial<InstallRemedyDto> = {}): InstallRemedyDto {
  return {
    kind: "install_app",
    missing: "installation",
    account: { login: "acme", type: "Organization" },
    url: URL,
    canApprove: "yes",
    unavailableReason: null,
    ...overrides,
  };
}

describe("dashboard install remedy", () => {
  it("offers the install button to a user who can approve", () => {
    const view = describeInstallRemedy(remedy());
    expect(view).toMatchObject({ kind: "install", url: URL });
    expect(view.text).toContain('"Only select repositories"');
    expect(view.text).toContain("PGARD cannot install it for you");
  });

  it("shows the same ask-owner wording as the CLI to a user who cannot approve", () => {
    expect(describeInstallRemedy(remedy({ canApprove: "no" }))).toEqual({
      kind: "ask_owner",
      url: URL,
      text: "Ask an owner of acme to install the PGARD GitHub App:",
    });
  });

  it("guides an unknown organization role like an owner, with the CLI wording", () => {
    expect(describeInstallRemedy(remedy({ canApprove: "unknown" }))).toEqual({
      kind: "install",
      url: URL,
      text: `If you are an owner of acme, install the App on the install page; otherwise ask an owner to install it there: ${URL}`,
    });
  });

  it("shows why there is no link, and never links outside github.com", () => {
    expect(
      describeInstallRemedy(
        remedy({
          url: null,
          canApprove: "no",
          unavailableReason: "Set PGARD_GITHUB_APP_SLUG to enable the guided install.",
        }),
      ),
    ).toEqual({
      kind: "unavailable",
      text: "Set PGARD_GITHUB_APP_SLUG to enable the guided install.",
    });
    expect(describeInstallRemedy(remedy({ url: "https://evil.test/" })).kind).toBe("unavailable");
  });

  it("runs the full check again once owner approval changed, and waits otherwise", () => {
    expect(nextInstallStep({ status: "passed", reason: "ok", remedy: null })).toBe("reverify");
    expect(nextInstallStep({ status: "unverifiable", reason: "403", remedy: null })).toBe(
      "reverify",
    );
    expect(nextInstallStep({ status: "failed", reason: "missing", remedy: remedy() })).toBe(
      "keep_waiting",
    );
    expect(INSTALL_POLL_INTERVAL_MS).toBe(5_000);
  });

  it("stops waiting at the server's deadline, so a remount never restarts the 10 minutes", () => {
    expect(isInstallWaitOver(2_000, 1_999)).toBe(false);
    expect(isInstallWaitOver(2_000, 2_000)).toBe(true);
    // No server deadline: nothing to wait for.
    expect(isInstallWaitOver(null, 0)).toBe(true);
  });
});
