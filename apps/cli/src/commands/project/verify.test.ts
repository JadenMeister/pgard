import type { AuthorizationOutcome, OwnerApprovalRecheck } from "@pgard/scan-core";
import { describe, expect, it, vi } from "vitest";
import {
  ALLOWED,
  BLOCKED,
  createTestContext,
  createTestDeps,
  createTestIo,
} from "../../test-support.js";
import { UserCancelledError } from "../../ui/components/prompts.js";
import { runProjectVerify } from "./verify.js";

describe("runProjectVerify", () => {
  it("shows each check and exits 3 when blocked", async () => {
    const captured = createTestIo();
    const code = await runProjectVerify(
      createTestContext(
        captured,
        createTestDeps({
          verifyProject: async () => ({ summary: BLOCKED, repo: "owner/name", revision: null }),
        }),
      ),
    );
    expect(code).toBe(3);
    const stdout = captured.stdout();
    expect(stdout).toContain("[passed] repository");
    expect(stdout).toContain("[unverifiable] owner approval: Not evaluated.");
    expect(stdout).toContain("not stored");
  });

  it("exits 0 when allowed and names an override App once on stderr", async () => {
    const captured = createTestIo({ env: { PGARD_GITHUB_APP_CLIENT_ID: "Iv23liExample" } });
    expect(await runProjectVerify(createTestContext(captured, createTestDeps()))).toBe(0);
    expect(captured.stderr().split("\n")).toContain(
      "Using GitHub App Iv23liExample from PGARD_GITHUB_APP_CLIENT_ID (override).",
    );
    expect(captured.stdout()).not.toContain("Using GitHub App");
  });

  it("does not mention the App when the built-in PGARD App is used", async () => {
    const captured = createTestIo();
    expect(await runProjectVerify(createTestContext(captured, createTestDeps()))).toBe(0);
    expect(captured.stderr()).not.toContain("Using GitHub App");
  });

  it("ends as a cancellation when Ctrl+C aborted the sign-in wait", async () => {
    const captured = createTestIo();
    const controller = new AbortController();
    const context = {
      ...createTestContext(
        captured,
        createTestDeps({
          verifyProject: async () => {
            controller.abort();
            return { summary: BLOCKED, repo: null, revision: null };
          },
        }),
      ),
      signal: controller.signal,
    };
    await expect(runProjectVerify(context)).rejects.toBeInstanceOf(UserCancelledError);
    expect(captured.stdout()).not.toContain("[unverifiable]");
  });
});

const INSTALL_URL =
  "https://github.com/apps/pgard-jadenmeister/installations/new/permissions?suggested_target_id=1001";

/** current_access failed on a 404; owner approval and contribution were not evaluated. */
const HIDDEN_REPO: AuthorizationOutcome = {
  summary: {
    decision: "blocked",
    checks: [
      { id: "repository", status: "passed", reason: "GitHub remote me/app" },
      { id: "github_identity", status: "passed", reason: "Signed in" },
      { id: "owner_approval", status: "unverifiable", reason: "Not evaluated." },
      { id: "current_access", status: "failed", reason: "GitHub returned no access to me/app." },
      { id: "contribution", status: "unverifiable", reason: "Not evaluated." },
    ],
  },
  repo: "me/app",
  revision: "abc",
  remedy: {
    kind: "install_app",
    missing: "access",
    account: { login: "me", type: "User" },
    url: INSTALL_URL,
    canApprove: "yes",
    unavailableReason: null,
  },
};

const STILL_HIDDEN: OwnerApprovalRecheck = {
  status: "failed",
  reason: "GitHub returned no access to me/app.",
  remedy: HIDDEN_REPO.remedy ?? null,
};

describe("runProjectVerify: private repository outside the App installation", () => {
  function tty(options: { canOpenBrowser?: boolean } = {}) {
    const captured = createTestIo({ isTTY: true });
    return { captured, canOpen: options.canOpenBrowser ?? true };
  }

  it("opens the install page, keeps waiting on not_found, then re-runs the FULL authorization", async () => {
    const { captured, canOpen } = tty();
    const verifyProject = vi
      .fn<() => Promise<AuthorizationOutcome>>()
      .mockResolvedValueOnce(HIDDEN_REPO)
      .mockResolvedValueOnce({ summary: ALLOWED, repo: "me/app", revision: "abc" });
    const recheck = vi
      .fn<() => Promise<OwnerApprovalRecheck>>()
      .mockResolvedValueOnce(STILL_HIDDEN)
      .mockResolvedValueOnce(STILL_HIDDEN)
      .mockResolvedValueOnce({ status: "passed", reason: "installed", remedy: null });
    const openBrowser = vi.fn(async () => true);
    const context = {
      ...createTestContext(
        captured,
        createTestDeps({ verifyProject, recheckOwnerApproval: recheck, openBrowser }),
      ),
      canOpenBrowser: canOpen,
    };
    expect(await runProjectVerify(context)).toBe(0);
    expect(openBrowser).toHaveBeenCalledWith(INSTALL_URL);
    expect(recheck).toHaveBeenCalledTimes(3);
    // The recheck passing is not an authorization: the whole gate ran a second time.
    expect(verifyProject).toHaveBeenCalledTimes(2);
    expect(captured.stderr()).toContain("GitHub shows no access to me/app");
  });

  it("does not open a browser with --no-browser, but still waits and re-checks", async () => {
    const { captured } = tty();
    const verifyProject = vi
      .fn<() => Promise<AuthorizationOutcome>>()
      .mockResolvedValueOnce(HIDDEN_REPO)
      .mockResolvedValueOnce(HIDDEN_REPO);
    const recheck = vi
      .fn<() => Promise<OwnerApprovalRecheck>>()
      .mockResolvedValue({ status: "passed", reason: "x", remedy: null });
    const openBrowser = vi.fn(async () => true);
    const context = {
      ...createTestContext(
        captured,
        createTestDeps({ verifyProject, recheckOwnerApproval: recheck, openBrowser }),
      ),
      canOpenBrowser: false,
    };
    // Still blocked after the re-run: the gate, not the install, decides.
    expect(await runProjectVerify(context)).toBe(3);
    expect(openBrowser).not.toHaveBeenCalled();
    expect(captured.stderr()).toContain(INSTALL_URL);
    expect(verifyProject).toHaveBeenCalledTimes(2);
  });

  it("does not wait outside a terminal", async () => {
    const captured = createTestIo({ isTTY: false });
    const recheck = vi.fn();
    const context = createTestContext(
      captured,
      createTestDeps({
        verifyProject: async () => HIDDEN_REPO,
        recheckOwnerApproval: recheck as never,
      }),
    );
    expect(await runProjectVerify(context)).toBe(3);
    expect(recheck).not.toHaveBeenCalled();
    expect(captured.stderr()).toContain("Not a terminal");
  });

  it("offers nothing when the owner lookup failed (no remedy)", async () => {
    const captured = createTestIo({ isTTY: true });
    const recheck = vi.fn();
    const context = createTestContext(
      captured,
      createTestDeps({
        verifyProject: async () => ({ ...HIDDEN_REPO, remedy: null }),
        recheckOwnerApproval: recheck as never,
      }),
    );
    expect(await runProjectVerify(context)).toBe(3);
    expect(recheck).not.toHaveBeenCalled();
    expect(captured.stderr()).not.toContain(INSTALL_URL);
  });
});

describe("runProjectVerify: App already installed, repository not included", () => {
  const CONFIGURE_URL = "https://github.com/settings/installations/77";
  const configure: AuthorizationOutcome = {
    ...HIDDEN_REPO,
    repo: "JadenMeister/photo-dump",
    remedy: {
      kind: "install_app",
      missing: "repository_access",
      account: { login: "JadenMeister", type: "User" },
      url: CONFIGURE_URL,
      canApprove: "yes",
      unavailableReason: null,
    },
  };

  it("tells the owner to add the repository to the installation, not to install again", async () => {
    const captured = createTestIo({ isTTY: false });
    const context = createTestContext(
      captured,
      createTestDeps({ verifyProject: async () => configure }),
    );
    expect(await runProjectVerify(context)).toBe(3);
    const stderr = captured.stderr();
    expect(stderr).toContain(
      "GitHub shows no access to JadenMeister/photo-dump. The PGARD GitHub App is already installed on JadenMeister, but its repository access does not include this repository (or your account has no access to it).",
    );
    expect(stderr).toContain(
      "Owner approval: add JadenMeister/photo-dump to the PGARD GitHub App's repository access.",
    );
    expect(stderr).toContain(`1. Open ${CONFIGURE_URL}`);
    expect(stderr).toContain(
      'Under "Repository access", choose "Only select repositories", add JadenMeister/photo-dump, then click Save.',
    );
    expect(stderr).toContain(
      "Changing the App's repository access is the owner approval; PGARD cannot change it for you.",
    );
    expect(stderr).not.toContain("click Install");
  });

  it("guides an organization with an unknown role, and asks for an owner otherwise", async () => {
    const org = { ...configure.remedy!, account: { login: "acme", type: "Organization" as const } };
    const unknown = createTestIo({ isTTY: false });
    await runProjectVerify(
      createTestContext(
        unknown,
        createTestDeps({
          verifyProject: async () => ({ ...configure, remedy: { ...org, canApprove: "unknown" } }),
        }),
      ),
    );
    expect(unknown.stderr()).toContain(
      "If you are an owner of acme, add JadenMeister/photo-dump to the PGARD GitHub App's repository access on its settings page; otherwise ask an owner to do it there:",
    );
    const no = createTestIo({ isTTY: true });
    const recheck = vi.fn();
    await runProjectVerify(
      createTestContext(
        no,
        createTestDeps({
          verifyProject: async () => ({ ...configure, remedy: { ...org, canApprove: "no" } }),
          recheckOwnerApproval: recheck as never,
        }),
      ),
    );
    expect(no.stderr()).toContain(
      `Ask an owner of acme to add JadenMeister/photo-dump to the PGARD GitHub App's repository access: ${CONFIGURE_URL}`,
    );
    expect(recheck).not.toHaveBeenCalled();
  });

  it("says plainly that the install page pre-selects All repositories", async () => {
    const captured = createTestIo({ isTTY: false });
    await runProjectVerify(
      createTestContext(captured, createTestDeps({ verifyProject: async () => HIDDEN_REPO })),
    );
    expect(captured.stderr()).toContain(
      'The page pre-selects "All repositories". To limit PGARD to this repository, choose "Only select repositories" and pick me/app, then click Install.',
    );
  });
});
