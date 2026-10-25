/**
 * The authorization gate hands owner evidence to the contribution check only when owner approval
 * passed. `evaluateOwnerApproval` itself never returns evidence on a non-passing path, so this
 * test stubs it to do exactly that and checks that `authorizeProject` still grants no exemption.
 */
import type { AuthorizationCheckStatus } from "@pgard/findings";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createGitFixture,
  type GitFixture,
} from "../../git-history/src/test-support/git-fixture.js";
import { authorizeProject, isAuthorizationAllowed } from "./authorize-project.js";
import type { OwnerApprovalResult } from "./checks.js";
import {
  ME,
  createMockGitHub,
  ownerInstallation,
  sessionProvider,
  userRepository,
} from "./test-support/mock-github.js";

const stub = vi.hoisted(() => ({
  override: null as null | ((real: OwnerApprovalResult) => OwnerApprovalResult),
}));

vi.mock("./checks.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./checks.js")>();
  return {
    ...actual,
    evaluateOwnerApproval: async (...args: Parameters<typeof actual.evaluateOwnerApproval>) => {
      const real = await actual.evaluateOwnerApproval(...args);
      return stub.override ? stub.override(real) : real;
    },
  };
});

let fixture: GitFixture | null = null;
afterEach(() => {
  stub.override = null;
  fixture?.cleanup();
  fixture = null;
});

async function authorizeOwner() {
  fixture = createGitFixture({ remotes: { origin: "git@github.com:me/app.git" } });
  fixture.commit({ authorName: "Me Person", authorEmail: "me@example.com" });
  // `ME` owns `me/app` and installed the App; no merged PR and no signed commit.
  const { session } = createMockGitHub({
    user: ME,
    repository: userRepository(),
    installations: [ownerInstallation()],
    installationRepositories: { 77: [555] },
    pulls: {},
    commits: {},
    compare: {},
  });
  return authorizeProject(fixture.root, { getGitHubSession: sessionProvider(async () => session) });
}

function contribution(outcome: Awaited<ReturnType<typeof authorizeProject>>) {
  return outcome.summary.checks.find((check) => check.id === "contribution");
}

describe("authorizeProject: owner evidence gate", () => {
  it("uses the evidence when owner approval passed (stub is transparent)", async () => {
    stub.override = (real) => real;
    const outcome = await authorizeOwner();
    expect(isAuthorizationAllowed(outcome)).toBe(true);
    expect(contribution(outcome)?.reason).toContain("a separate contribution is not required");
  });

  // Mutation sanity: fails if authorize-project passes `ownerApproval.ownerEvidence` ungated.
  it.each<AuthorizationCheckStatus>(["failed", "unverifiable"])(
    "grants no exemption when owner approval is %s, even with owner evidence attached",
    async (status) => {
      stub.override = (real) => {
        expect(real.ownerEvidence).not.toBeNull();
        return { ...real, check: { status, reason: "Owner approval did not pass (stub)." } };
      };
      const outcome = await authorizeOwner();
      expect(outcome.summary.decision).toBe("blocked");
      expect(isAuthorizationAllowed(outcome)).toBe(false);
      expect(outcome.summary.checks.find((check) => check.id === "owner_approval")?.status).toBe(
        status,
      );
      expect(contribution(outcome)?.status).toBe("failed");
      expect(contribution(outcome)?.reason).not.toContain("not required");
      expect(contribution(outcome)?.reason).toMatch(/^No qualifying contribution found/);
    },
  );
});
