import { GitHubAuthError, GUIDED_INSTALL_NEEDS_SLUG_MESSAGE } from "@pgard/github-auth";
import { afterEach, describe, expect, it } from "vitest";
import {
  createGitFixture,
  type GitFixture,
} from "../../git-history/src/test-support/git-fixture.js";
import {
  authorizeProject,
  guidedInstallRemedy,
  isAuthorizationAllowed,
  recheckOwnerApproval,
} from "./authorize-project.js";
import {
  ME,
  createMockGitHub,
  orgInstallation,
  orgMembership,
  orgRepository,
  ownerInstallation,
  sessionProvider,
  userRepository,
  type MockGitHubState,
} from "./test-support/mock-github.js";

const SLUG = "pgard-jadenmeister";
const PERSONAL_URL =
  "https://github.com/apps/pgard-jadenmeister/installations/new/permissions?suggested_target_id=1001&repository_ids%5B%5D=555";
const ORG_URL =
  "https://github.com/apps/pgard-jadenmeister/installations/new/permissions?suggested_target_id=42&repository_ids%5B%5D=555";

let fixture: GitFixture | null = null;
afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

function project(remote = "git@github.com:me/app.git"): { root: string; head: string } {
  fixture = createGitFixture({ remotes: { origin: remote } });
  const head = fixture.commit({ authorName: "Me Person", authorEmail: "me@example.com" });
  return { root: fixture.root, head };
}

/** Everything passes except owner approval: no installation at all. */
function personalState(head: string, overrides: Partial<MockGitHubState> = {}): MockGitHubState {
  return {
    user: ME,
    repository: userRepository(),
    installations: [],
    installationRepositories: {},
    pulls: {},
    commits: { [head]: { sha: head, authorId: ME.id, committerId: ME.id, isVerified: true } },
    compare: { [head]: "identical" },
    ...overrides,
  };
}

function orgState(head: string, overrides: Partial<MockGitHubState> = {}): MockGitHubState {
  return personalState(head, {
    repository: orgRepository(),
    memberships: { acme: orgMembership() },
    ...overrides,
  });
}

async function authorize(root: string, state: MockGitHubState, appSlug: string | null = SLUG) {
  const { session, calls } = createMockGitHub(state);
  const outcome = await authorizeProject(root, {
    getGitHubSession: sessionProvider(async () => session),
    appSlug,
  });
  return { outcome, calls };
}

function approval(outcome: Awaited<ReturnType<typeof authorize>>["outcome"]) {
  return outcome.summary.checks.find((check) => check.id === "owner_approval");
}

describe("owner approval remedy: personal repositories", () => {
  it("offers the preselected install link to the owner when the App is not installed", async () => {
    const { root, head } = project();
    const { outcome } = await authorize(root, personalState(head));
    expect(isAuthorizationAllowed(outcome)).toBe(false);
    // The reason text is exactly today's; the remedy is extra, structured data.
    expect(approval(outcome)).toEqual({
      id: "owner_approval",
      status: "failed",
      reason: 'No PGARD GitHub App installation on the owner account "me" was found for me/app.',
    });
    expect(outcome.remedy).toEqual({
      kind: "install_app",
      missing: "installation",
      account: { login: "me", type: "User" },
      url: PERSONAL_URL,
      canApprove: "yes",
      unavailableReason: null,
    });
    expect(guidedInstallRemedy(outcome)).toEqual(outcome.remedy);
  });

  it("reports an installation that does not include the repository", async () => {
    const { root, head } = project();
    const { outcome } = await authorize(
      root,
      personalState(head, {
        installations: [ownerInstallation()],
        installationRepositories: { 77: [1] },
      }),
    );
    expect(approval(outcome)?.status).toBe("failed");
    expect(outcome.remedy).toMatchObject({ missing: "repository", canApprove: "yes" });
  });

  it("does not let a collaborator approve someone else's personal repository", async () => {
    const { root, head } = project();
    const { outcome } = await authorize(
      root,
      personalState(head, { user: { ...ME, id: 2002, login: "collab" } }),
    );
    expect(outcome.remedy).toMatchObject({ canApprove: "no", url: PERSONAL_URL });
  });

  it("has no link, and says how to enable one, when no slug is configured", async () => {
    const { root, head } = project();
    const { outcome } = await authorize(root, personalState(head), null);
    expect(approval(outcome)?.reason).toBe(
      'No PGARD GitHub App installation on the owner account "me" was found for me/app.',
    );
    expect(outcome.remedy).toMatchObject({
      url: null,
      unavailableReason: GUIDED_INSTALL_NEEDS_SLUG_MESSAGE,
    });
    expect(GUIDED_INSTALL_NEEDS_SLUG_MESSAGE).toBe(
      "Set PGARD_GITHUB_APP_SLUG to enable the guided install.",
    );
  });

  it("has no remedy when owner approval passes or fails for another reason", async () => {
    const { root, head } = project();
    const passed = await authorize(
      root,
      personalState(head, {
        installations: [ownerInstallation()],
        installationRepositories: { 77: [555] },
      }),
    );
    expect(isAuthorizationAllowed(passed.outcome)).toBe(true);
    expect(passed.outcome.remedy).toBeNull();
    expect(guidedInstallRemedy(passed.outcome)).toBeNull();

    const listFails = createMockGitHub(personalState(head));
    const failing = await authorizeProject(root, {
      getGitHubSession: sessionProvider(async () => ({
        ...listFails.session,
        client: {
          ...listFails.session.client,
          listUserInstallations: async () => {
            throw new GitHubAuthError("rate_limited", "rate limited", 429);
          },
        },
      })),
      appSlug: SLUG,
    });
    expect(approval(failing)?.status).toBe("unverifiable");
    expect(failing.remedy).toBeNull();
  });

  it("is not offered when another check also fails", async () => {
    const { root, head } = project();
    const { outcome } = await authorize(root, personalState(head, { commits: {}, compare: {} }));
    expect(outcome.summary.checks.find((check) => check.id === "contribution")?.status).toBe(
      "failed",
    );
    expect(outcome.remedy).not.toBeNull();
    expect(guidedInstallRemedy(outcome)).toBeNull();
  });
});

describe("owner approval remedy: organization repositories", () => {
  const ORG_REMOTE = "git@github.com:acme/app.git";

  it("lets an active organization owner install it", async () => {
    const { root, head } = project(ORG_REMOTE);
    const { outcome } = await authorize(root, orgState(head));
    expect(approval(outcome)?.status).toBe("failed");
    expect(outcome.remedy).toEqual({
      kind: "install_app",
      missing: "installation",
      account: { login: "acme", type: "Organization" },
      url: ORG_URL,
      canApprove: "yes",
      unavailableReason: null,
    });
  });

  it("tells a member GitHub shows is not an owner to ask an owner (canApprove no)", async () => {
    const { root, head } = project(ORG_REMOTE);
    const cases: NonNullable<MockGitHubState["memberships"]>[] = [
      { acme: orgMembership({ role: "member" }) },
      { acme: orgMembership({ role: "billing_manager" }) },
      { acme: orgMembership({ state: "pending" }) },
    ];
    for (const memberships of cases) {
      const { outcome } = await authorize(root, orgState(head, { memberships }));
      expect(approval(outcome)?.status).toBe("failed");
      expect(outcome.remedy).toMatchObject({ canApprove: "no", url: ORG_URL });
    }
  });

  it("is unknown when the membership cannot be read or does not match (before the install)", async () => {
    const { root, head } = project(ORG_REMOTE);
    const cases: NonNullable<MockGitHubState["memberships"]>[] = [
      { acme: new GitHubAuthError("forbidden", "forbidden", 403) },
      {},
      { acme: new GitHubAuthError("rate_limited", "rate limited", 429) },
      { acme: orgMembership({ user: { id: 9, login: "someone" } }) },
      { acme: orgMembership({ organization: { id: 4242, login: "other" } }) },
    ];
    for (const memberships of cases) {
      const { outcome } = await authorize(root, orgState(head, { memberships }));
      // Never a pass: the check is failed exactly as without a remedy.
      expect(approval(outcome)).toEqual({
        id: "owner_approval",
        status: "failed",
        reason:
          'No PGARD GitHub App installation on the organization "acme" was found for acme/app. An owner of acme must install the App on the organization and include the repository.',
      });
      expect(outcome.remedy).toMatchObject({ canApprove: "unknown", url: ORG_URL });
    }
  });

  it("guides an owner whose org installation lacks the repository", async () => {
    const { root, head } = project(ORG_REMOTE);
    const { outcome } = await authorize(
      root,
      orgState(head, { installations: [orgInstallation()], installationRepositories: { 88: [] } }),
    );
    expect(outcome.remedy).toMatchObject({ missing: "repository", canApprove: "yes" });
  });
});

describe("recheckOwnerApproval", () => {
  it("re-evaluates owner approval only, and passes once the App includes the repository", async () => {
    const { root, head } = project();
    const state = personalState(head);
    const { session, calls } = createMockGitHub(state);
    const deps = { getGitHubSession: sessionProvider(async () => session), appSlug: SLUG };

    const before = await recheckOwnerApproval(root, deps);
    expect(before).toMatchObject({ status: "failed", remedy: { url: PERSONAL_URL } });

    state.installations = [ownerInstallation()];
    state.installationRepositories = { 77: [555] };
    const after = await recheckOwnerApproval(root, deps);
    expect(after).toMatchObject({ status: "passed", remedy: null });
    // Never looks at contributions: that is the full authorization's job.
    expect(calls.some((call) => call.startsWith("pulls:") || call.startsWith("commit:"))).toBe(
      false,
    );
  });

  it("reports sign-in and repository errors without a remedy", async () => {
    const { root } = project();
    const denied = await recheckOwnerApproval(root, {
      getGitHubSession: sessionProvider(async () => {
        throw new GitHubAuthError("access_denied", "denied");
      }),
      appSlug: SLUG,
    });
    expect(denied).toEqual({
      status: "failed",
      reason: "GitHub sign-in was denied.",
      remedy: null,
    });
  });
});
