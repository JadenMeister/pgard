import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { AuthorizationCheckId } from "@pgard/findings";
import {
  GitHubAuthError,
  createDeviceFlowSessionProvider,
  resolveGitHubAppClientId,
} from "@pgard/github-auth";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createGitFixture,
  type GitFixture,
} from "../../git-history/src/test-support/git-fixture.js";
import { authorizeProject, isAuthorizationAllowed } from "./authorize-project.js";
import {
  ME,
  ORG,
  createMockGitHub,
  orgInstallation,
  orgMembership,
  orgRepository,
  ownerInstallation,
  sessionProvider,
  userRepository,
  type MockGitHubState,
} from "./test-support/mock-github.js";
import type { AuthorizationOutcome } from "./types.js";
import { AUTHORIZATION_CHECK_ORDER } from "./types.js";

let fixture: GitFixture | null = null;
afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

function repoWithCommits(
  remotes: Record<string, string> = { origin: "git@github.com:me/app.git" },
) {
  fixture = createGitFixture({ remotes });
  const other = fixture.commit({ authorName: "Someone", authorEmail: "someone@example.com" });
  const mine = fixture.commit({ authorName: "Me Person", authorEmail: "me@example.com" });
  return { root: fixture.root, other, mine };
}

function baseState(overrides: Partial<MockGitHubState> = {}): MockGitHubState {
  return {
    user: ME,
    repository: userRepository(),
    installations: [ownerInstallation()],
    installationRepositories: { 77: [555] },
    pulls: {},
    commits: {},
    compare: {},
    ...overrides,
  };
}

function statusOf(outcome: AuthorizationOutcome, id: AuthorizationCheckId) {
  return outcome.summary.checks.find((check) => check.id === id)?.status;
}

async function authorize(root: string, state: MockGitHubState, maxCandidates?: number) {
  const { session, calls } = createMockGitHub(state);
  const getGitHubSession = vi.fn(async () => session);
  const outcome = await authorizeProject(root, {
    getGitHubSession: sessionProvider(getGitHubSession),
    ...(maxCandidates ? { maxContributionCandidates: maxCandidates } : {}),
  });
  return { outcome, calls, getGitHubSession };
}

function expectBlocked(outcome: AuthorizationOutcome) {
  expect(outcome.summary.decision).toBe("blocked");
  expect(isAuthorizationAllowed(outcome)).toBe(false);
  expect(outcome.summary.checks.map((check) => check.id)).toEqual(AUTHORIZATION_CHECK_ORDER);
}

describe("authorizeProject: allowed paths", () => {
  it("allows a user-owned repo with owner installation, access and a merged PR", async () => {
    const { root, mine } = repoWithCommits();
    const { outcome } = await authorize(
      root,
      baseState({
        pulls: {
          [mine]: [
            {
              number: 4,
              userId: ME.id,
              mergedAt: "2026-10-01T00:00:00Z",
              baseRef: "main",
              baseRepositoryId: 555,
            },
          ],
        },
        compare: { [mine]: "ahead" },
      }),
    );
    expect(outcome.summary.decision).toBe("allowed");
    expect(isAuthorizationAllowed(outcome)).toBe(true);
    expect(outcome.repo).toBe("me/app");
    expect(outcome.revision).toBe(mine);
  });

  it("allows a signature-verified commit committed by the user in the default branch", async () => {
    const { root, mine } = repoWithCommits();
    const { outcome } = await authorize(
      root,
      baseState({
        commits: { [mine]: { sha: mine, authorId: ME.id, committerId: ME.id, isVerified: true } },
        compare: { [mine]: "identical" },
      }),
    );
    expect(outcome.summary.decision).toBe("allowed");
  });
});

describe("authorizeProject: blocked paths", () => {
  it("blocks without an owner installation", async () => {
    const { root, mine } = repoWithCommits();
    const { outcome } = await authorize(
      root,
      baseState({
        installations: [],
        pulls: {
          [mine]: [
            {
              number: 4,
              userId: ME.id,
              mergedAt: "2026-10-01T00:00:00Z",
              baseRef: "main",
              baseRepositoryId: 555,
            },
          ],
        },
        compare: { [mine]: "ahead" },
      }),
    );
    expectBlocked(outcome);
    expect(statusOf(outcome, "owner_approval")).toBe("failed");
  });

  it("blocks when the installation belongs to another account", async () => {
    const { root, mine } = repoWithCommits();
    const { outcome } = await authorize(
      root,
      baseState({
        installations: [ownerInstallation(9999)],
        installationRepositories: { 77: [555] },
        pulls: {
          [mine]: [
            {
              number: 4,
              userId: ME.id,
              mergedAt: "2026-10-01T00:00:00Z",
              baseRef: "main",
              baseRepositoryId: 555,
            },
          ],
        },
        compare: { [mine]: "ahead" },
      }),
    );
    expectBlocked(outcome);
    expect(statusOf(outcome, "owner_approval")).toBe("failed");
  });

  it("blocks when the owner's installation does not include the repository", async () => {
    const { root } = repoWithCommits();
    const { outcome } = await authorize(root, baseState({ installationRepositories: { 77: [1] } }));
    expectBlocked(outcome);
    expect(statusOf(outcome, "owner_approval")).toBe("failed");
  });

  it("blocks when the user cannot see the repository", async () => {
    const { root } = repoWithCommits();
    const { outcome } = await authorize(root, baseState({ repository: null }));
    expectBlocked(outcome);
    expect(statusOf(outcome, "current_access")).toBe("failed");
  });

  it("blocks when the user has no pull permission", async () => {
    const { root } = repoWithCommits();
    const { outcome, calls } = await authorize(
      root,
      baseState({
        repository: userRepository({
          permissions: { admin: false, maintain: false, push: false, triage: false, pull: false },
        }),
      }),
    );
    expectBlocked(outcome);
    expect(statusOf(outcome, "current_access")).toBe("failed");
    expect(calls.some((call) => call.startsWith("pulls:"))).toBe(false);
  });

  it("blocks without any contribution evidence", async () => {
    const { root } = repoWithCommits();
    const { outcome } = await authorize(root, baseState());
    expectBlocked(outcome);
    expect(statusOf(outcome, "contribution")).toBe("failed");
  });

  it.each([
    ["merged into a release branch", { baseRef: "release-1.x", baseRepositoryId: 555 }],
    ["merged into a fork", { baseRef: "main", baseRepositoryId: 999 }],
    ["missing base information", { baseRef: null, baseRepositoryId: null }],
  ])("blocks a PR %s even if its commit reaches the default branch", async (_label, base) => {
    const { root, mine } = repoWithCommits();
    const { outcome } = await authorize(
      root,
      baseState({
        pulls: {
          [mine]: [{ number: 4, userId: ME.id, mergedAt: "2026-10-01T00:00:00Z", ...base }],
        },
        compare: { [mine]: "ahead" },
      }),
    );
    expectBlocked(outcome);
    expect(statusOf(outcome, "contribution")).toBe("failed");
  });

  it("reports truncated GitHub listings as unverifiable, not failed", async () => {
    const { root } = repoWithCommits();
    const { session } = createMockGitHub(baseState());
    const truncated = new GitHubAuthError("result_truncated", "too many installations");
    const outcome = await authorizeProject(root, {
      getGitHubSession: sessionProvider(async () => ({
        ...session,
        client: {
          ...session.client,
          listUserInstallations: async () => {
            throw truncated;
          },
          listPullRequestsForCommit: async () => {
            throw truncated;
          },
        },
      })),
    });
    expectBlocked(outcome);
    expect(statusOf(outcome, "owner_approval")).toBe("unverifiable");
    expect(statusOf(outcome, "contribution")).toBe("unverifiable");
  });

  it("uses GitHub's canonical repository name for API calls and the result", async () => {
    const { root, mine } = repoWithCommits();
    const { outcome, calls } = await authorize(
      root,
      baseState({
        repository: userRepository({ fullName: "me/app-renamed" }),
        pulls: {
          [mine]: [
            {
              number: 4,
              userId: ME.id,
              mergedAt: "2026-10-01T00:00:00Z",
              baseRef: "main",
              baseRepositoryId: 555,
            },
          ],
        },
        compare: { [mine]: "ahead" },
      }),
    );
    expect(outcome.summary.decision).toBe("allowed");
    expect(outcome.repo).toBe("me/app-renamed");
    expect(calls).toContain(`pulls:me/app-renamed:${mine}`);
  });

  it("blocks when the user's PR was never merged", async () => {
    const { root, mine } = repoWithCommits();
    const { outcome } = await authorize(
      root,
      baseState({
        pulls: {
          [mine]: [
            { number: 4, userId: ME.id, mergedAt: null, baseRef: "main", baseRepositoryId: 555 },
          ],
        },
        compare: { [mine]: "ahead" },
      }),
    );
    expectBlocked(outcome);
    expect(statusOf(outcome, "contribution")).toBe("failed");
  });

  it("blocks a forged author email without a merged PR or verified signature", async () => {
    const { root, mine } = repoWithCommits();
    const { outcome } = await authorize(
      root,
      baseState({
        // The commit claims me@example.com, is in main, but GitHub attributes nothing to me.
        pulls: {
          [mine]: [
            {
              number: 9,
              userId: 4242,
              mergedAt: "2026-10-01T00:00:00Z",
              baseRef: "main",
              baseRepositoryId: 555,
            },
          ],
        },
        commits: { [mine]: { sha: mine, authorId: ME.id, committerId: ME.id, isVerified: false } },
        compare: { [mine]: "ahead" },
      }),
    );
    expectBlocked(outcome);
    expect(statusOf(outcome, "contribution")).toBe("failed");
  });

  it("blocks a verified commit whose committer is someone else", async () => {
    const { root, mine } = repoWithCommits();
    const { outcome } = await authorize(
      root,
      baseState({
        commits: { [mine]: { sha: mine, authorId: ME.id, committerId: 4242, isVerified: true } },
        compare: { [mine]: "ahead" },
      }),
    );
    expectBlocked(outcome);
  });

  it("ignores qualifying commits outside HEAD's history (orphan checkout)", async () => {
    const { mine } = repoWithCommits();
    fixture?.git("checkout", "-q", "--orphan", "unrelated");
    fixture?.commit({ files: { "other.txt": "x" } });
    const { outcome, calls } = await authorize(
      fixture?.root ?? "",
      baseState({
        pulls: {
          [mine]: [
            {
              number: 4,
              userId: ME.id,
              mergedAt: "2026-10-01T00:00:00Z",
              baseRef: "main",
              baseRepositoryId: 555,
            },
          ],
        },
        compare: { [mine]: "ahead" },
      }),
    );
    expectBlocked(outcome);
    expect(calls.some((call) => call.endsWith(mine))).toBe(false);
  });

  it("blocks a local-only commit even with a matching identity", async () => {
    const { root } = repoWithCommits();
    const { outcome } = await authorize(root, baseState({ compare: {} }));
    expectBlocked(outcome);
    expect(statusOf(outcome, "contribution")).toBe("failed");
  });

  it("blocks a merged PR whose commit is not in the default branch history", async () => {
    const { root, mine } = repoWithCommits();
    for (const comparison of [undefined, "diverged", "behind"] as const) {
      const { outcome } = await authorize(
        root,
        baseState({
          pulls: {
            [mine]: [
              {
                number: 4,
                userId: ME.id,
                mergedAt: "2026-10-01T00:00:00Z",
                baseRef: "main",
                baseRepositoryId: 555,
              },
            ],
          },
          compare: comparison ? { [mine]: comparison } : {},
        }),
      );
      expectBlocked(outcome);
    }
  });

  it("reports unverifiable when the candidate cap is reached", async () => {
    const { root, other } = repoWithCommits();
    // Only the older, non-matching commit qualifies; with a cap of 1 it is never examined.
    const { outcome, calls } = await authorize(
      root,
      baseState({
        pulls: {
          [other]: [
            {
              number: 4,
              userId: ME.id,
              mergedAt: "2026-10-01T00:00:00Z",
              baseRef: "main",
              baseRepositoryId: 555,
            },
          ],
        },
        compare: { [other]: "ahead" },
      }),
      1,
    );
    expectBlocked(outcome);
    expect(statusOf(outcome, "contribution")).toBe("unverifiable");
    expect(calls.filter((call) => call.startsWith("pulls:"))).toHaveLength(1);
  });

  it("reports GitHub API failures as unverifiable", async () => {
    const { root } = repoWithCommits();
    const { session } = createMockGitHub(baseState());
    const { session: failing } = createMockGitHub(
      baseState({
        failWith: new GitHubAuthError("network_error", "Could not reach the GitHub API."),
      }),
    );
    const outcome = await authorizeProject(root, {
      getGitHubSession: sessionProvider(async () => ({
        ...session,
        client: { ...failing.client, getAuthenticatedUser: session.client.getAuthenticatedUser },
      })),
    });
    expectBlocked(outcome);
    expect(statusOf(outcome, "current_access")).toBe("unverifiable");
  });
});

describe("authorizeProject: repository and identity", () => {
  it.each([
    [
      "ambiguous GitHub remotes",
      { origin: "git@github.com:me/app.git", up: "git@github.com:x/app.git" },
    ],
    ["non-GitHub remote", { origin: "https://gitlab.com/me/app.git" }],
    ["unparsable remote", { origin: "not a url" }],
    ["no remote", {}],
    ["malformed percent-encoded remote", { origin: "https://github.com/me/app%E0" }],
  ])("blocks %s before any sign-in", async (_label, remotes) => {
    const { root } = repoWithCommits(remotes);
    const { outcome, getGitHubSession } = await authorize(root, baseState());
    expectBlocked(outcome);
    expect(statusOf(outcome, "repository")).toBe("failed");
    expect(getGitHubSession).not.toHaveBeenCalled();
    for (const id of AUTHORIZATION_CHECK_ORDER.slice(1)) {
      expect(statusOf(outcome, id)).toBe("unverifiable");
    }
  });

  it("blocks a directory that is not the Git root", async () => {
    const { root } = repoWithCommits();
    const nested = path.join(root, "sub");
    mkdirSync(nested);
    const { outcome, getGitHubSession } = await authorize(nested, baseState());
    expectBlocked(outcome);
    expect(getGitHubSession).not.toHaveBeenCalled();
  });

  it("blocks a repository that borrows objects through alternates", async () => {
    const { root, mine } = repoWithCommits();
    writeFileSync(path.join(root, ".git", "objects", "info", "alternates"), "/elsewhere/objects\n");
    const { outcome, getGitHubSession } = await authorize(
      root,
      baseState({
        pulls: {
          [mine]: [
            {
              number: 4,
              userId: ME.id,
              mergedAt: "2026-10-01T00:00:00Z",
              baseRef: "main",
              baseRepositoryId: 555,
            },
          ],
        },
        compare: { [mine]: "ahead" },
      }),
    );
    expectBlocked(outcome);
    expect(statusOf(outcome, "repository")).toBe("failed");
    expect(getGitHubSession).not.toHaveBeenCalled();
  });

  it("blocks a repository without commits", async () => {
    fixture = createGitFixture({ remotes: { origin: "git@github.com:me/app.git" } });
    const { outcome } = await authorize(fixture.root, baseState());
    expectBlocked(outcome);
    expect(statusOf(outcome, "repository")).toBe("failed");
  });

  it("blocks with github_identity unverifiable when the built-in App cannot reach GitHub", async () => {
    const { root } = repoWithCommits();
    const fetch = vi.fn(async () => {
      throw new Error("offline");
    });
    const provider = createDeviceFlowSessionProvider({
      clientId: resolveGitHubAppClientId({}).clientId,
      onUserCode: () => {},
      fetch,
    });
    const outcome = await authorizeProject(root, { getGitHubSession: provider });
    expectBlocked(outcome);
    const identity = outcome.summary.checks.find((check) => check.id === "github_identity");
    expect(identity?.status).toBe("unverifiable");
    expect(identity?.reason).toBe(
      "GitHub identity could not be verified: Could not reach GitHub for sign-in.",
    );
    // A configured client id alone never lets the later checks pass.
    expect(statusOf(outcome, "owner_approval")).not.toBe("passed");
    expect(statusOf(outcome, "current_access")).not.toBe("passed");
    expect(statusOf(outcome, "contribution")).not.toBe("passed");
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(outcome.repo).toBe("me/app");
  });

  it("blocks with github_identity unverifiable when the override is malformed", async () => {
    const { root } = repoWithCommits();
    const fetch = vi.fn(async () => {
      throw new Error("must not be called");
    });
    const provider = createDeviceFlowSessionProvider({
      clientId: resolveGitHubAppClientId({ PGARD_GITHUB_APP_CLIENT_ID: '"bad id"' }).clientId,
      onUserCode: () => {},
      fetch,
    });
    const outcome = await authorizeProject(root, { getGitHubSession: provider });
    expectBlocked(outcome);
    const identity = outcome.summary.checks.find((check) => check.id === "github_identity");
    expect(identity).toEqual({
      id: "github_identity",
      status: "unverifiable",
      reason:
        "PGARD_GITHUB_APP_CLIENT_ID is set but is not a valid client id; unset it to use the built-in PGARD App.",
    });
    expect(statusOf(outcome, "owner_approval")).not.toBe("passed");
    expect(fetch).not.toHaveBeenCalled();
    expect(JSON.stringify(outcome)).not.toContain("bad id");
  });

  it("blocks with github_identity unverifiable when the slug override is malformed", async () => {
    const { root } = repoWithCommits();
    const fetch = vi.fn(async () => {
      throw new Error("must not be called");
    });
    const app = resolveGitHubAppClientId({ PGARD_GITHUB_APP_SLUG: "Bad Slug" });
    expect(app.source).toBe("invalid");
    const provider = createDeviceFlowSessionProvider({
      clientId: app.clientId,
      ...(app.source === "invalid" ? { invalidClientIdMessage: app.message } : {}),
      onUserCode: () => {},
      fetch,
    });
    const outcome = await authorizeProject(root, { getGitHubSession: provider });
    expectBlocked(outcome);
    expect(outcome.summary.checks.find((check) => check.id === "github_identity")).toEqual({
      id: "github_identity",
      status: "unverifiable",
      reason:
        'PGARD_GITHUB_APP_SLUG is set but is not a valid GitHub App slug (lowercase letters, digits and "-"); fix or unset it.',
    });
    expect(fetch).not.toHaveBeenCalled();
    expect(JSON.stringify(outcome)).not.toContain("Bad Slug");
  });

  it("blocks when sign-in is denied", async () => {
    const { root } = repoWithCommits();
    const outcome = await authorizeProject(root, {
      getGitHubSession: sessionProvider(async () => {
        throw new GitHubAuthError("access_denied", "denied");
      }),
    });
    expectBlocked(outcome);
    expect(statusOf(outcome, "github_identity")).toBe("failed");
  });
});

describe("isAuthorizationAllowed", () => {
  const passed = AUTHORIZATION_CHECK_ORDER.map((id) => ({
    id,
    status: "passed" as const,
    reason: "",
  }));
  const outcome = (decision: "allowed" | "blocked", checks: typeof passed) => ({
    summary: { decision, checks },
    repo: "o/r",
    revision: null,
  });

  it("requires every check to pass, not just the decision flag", () => {
    expect(isAuthorizationAllowed(outcome("allowed", passed))).toBe(true);
    expect(
      isAuthorizationAllowed(
        outcome(
          "allowed",
          passed.map((check, index) =>
            index === 4 ? { ...check, status: "unverifiable" as never } : check,
          ),
        ),
      ),
    ).toBe(false);
    expect(isAuthorizationAllowed(outcome("allowed", passed.slice(0, 4)))).toBe(false);
    expect(isAuthorizationAllowed(outcome("blocked", passed))).toBe(false);
  });

  it("rejects duplicate or reordered check ids even when all are passed", () => {
    const duplicates = passed.map((check) => ({ ...check, id: "repository" as never }));
    expect(isAuthorizationAllowed(outcome("allowed", duplicates))).toBe(false);
    expect(isAuthorizationAllowed(outcome("allowed", [...passed].reverse()))).toBe(false);
  });
});

describe("authorizeProject: organization repositories", () => {
  const ORG_REMOTE = { origin: "git@github.com:acme/app.git" };

  function orgState(mine: string, overrides: Partial<MockGitHubState> = {}): MockGitHubState {
    return baseState({
      repository: orgRepository(),
      installations: [orgInstallation()],
      installationRepositories: { 88: [555] },
      memberships: { acme: orgMembership() },
      pulls: {
        [mine]: [
          {
            number: 4,
            userId: ME.id,
            mergedAt: "2026-10-01T00:00:00Z",
            baseRef: "main",
            baseRepositoryId: 555,
          },
        ],
      },
      compare: { [mine]: "ahead" },
      ...overrides,
    });
  }

  function approval(outcome: AuthorizationOutcome) {
    return outcome.summary.checks.find((check) => check.id === "owner_approval");
  }

  it("allows an organization owner when the org installation includes the repository", async () => {
    const { root, mine } = repoWithCommits(ORG_REMOTE);
    const { outcome, calls } = await authorize(root, orgState(mine));
    expect(outcome.summary.decision).toBe("allowed");
    expect(isAuthorizationAllowed(outcome)).toBe(true);
    expect(outcome.repo).toBe("acme/app");
    expect(approval(outcome)).toEqual({
      id: "owner_approval",
      status: "passed",
      reason:
        'me is an owner of the organization "acme", and the organization\'s PGARD GitHub App installation includes acme/app.',
    });
    expect(calls).toContain("membership:acme");
    expect(calls).toContain("installation-repos:88");
  });

  it("keeps current access and contribution checks unchanged for organization repos", async () => {
    const { root, mine } = repoWithCommits(ORG_REMOTE);
    const noAccess = await authorize(
      root,
      orgState(mine, {
        repository: orgRepository({
          permissions: { admin: false, maintain: false, push: false, triage: false, pull: false },
        }),
      }),
    );
    expectBlocked(noAccess.outcome);
    expect(statusOf(noAccess.outcome, "owner_approval")).toBe("passed");
    expect(statusOf(noAccess.outcome, "current_access")).toBe("failed");
    expect(statusOf(noAccess.outcome, "contribution")).toBe("unverifiable");

    const noContribution = await authorize(root, orgState(mine, { pulls: {}, compare: {} }));
    expectBlocked(noContribution.outcome);
    expect(statusOf(noContribution.outcome, "owner_approval")).toBe("passed");
    expect(statusOf(noContribution.outcome, "contribution")).toBe("failed");
  });

  // Mutation sanity: this and the next test fail if the `role === "admin"` check is removed.
  it("blocks a plain member", async () => {
    const { root, mine } = repoWithCommits(ORG_REMOTE);
    const { outcome } = await authorize(
      root,
      orgState(mine, { memberships: { acme: orgMembership({ role: "member" }) } }),
    );
    expectBlocked(outcome);
    expect(approval(outcome)).toMatchObject({
      status: "failed",
      reason: "me is not an owner of acme (role: member); an organization owner must run the scan.",
    });
  });

  it("blocks a billing manager or any other non-admin role", async () => {
    const { root, mine } = repoWithCommits(ORG_REMOTE);
    for (const role of ["billing_manager", "Admin", "owner", ""]) {
      const { outcome } = await authorize(
        root,
        orgState(mine, { memberships: { acme: orgMembership({ role }) } }),
      );
      expectBlocked(outcome);
      expect(statusOf(outcome, "owner_approval")).toBe("failed");
    }
  });

  it("blocks a pending membership, even with the admin role", async () => {
    const { root, mine } = repoWithCommits(ORG_REMOTE);
    const { outcome } = await authorize(
      root,
      orgState(mine, { memberships: { acme: orgMembership({ state: "pending" }) } }),
    );
    expectBlocked(outcome);
    expect(approval(outcome)).toMatchObject({
      status: "failed",
      reason:
        "me\'s membership in acme is pending, not active; an organization owner with an active membership must run the scan.",
    });
  });

  it("reports an unknown membership state as unverifiable", async () => {
    const { root, mine } = repoWithCommits(ORG_REMOTE);
    const { outcome } = await authorize(
      root,
      orgState(mine, { memberships: { acme: orgMembership({ state: "suspended" }) } }),
    );
    expectBlocked(outcome);
    expect(statusOf(outcome, "owner_approval")).toBe("unverifiable");
  });

  it("reports a membership 403 as unverifiable with the Members: Read-only permission reason", async () => {
    const { root, mine } = repoWithCommits(ORG_REMOTE);
    const { outcome } = await authorize(
      root,
      orgState(mine, {
        memberships: { acme: new GitHubAuthError("forbidden", "GitHub refused (403).", 403) },
      }),
    );
    expectBlocked(outcome);
    expect(approval(outcome)).toMatchObject({
      status: "unverifiable",
      reason:
        "GitHub refused to show me\'s membership in acme (403): the PGARD GitHub App needs the organization permission Members: Read-only, approved by an owner of acme.",
    });
  });

  it.each([
    ["404", undefined, /\(404\).*Members: Read-only/],
    [
      "5xx",
      new GitHubAuthError("http_error", "GitHub API request failed with status 502.", 502),
      /^Could not read me\'s membership in acme: GitHub API request failed with status 502\.$/,
    ],
    [
      "network error",
      new GitHubAuthError("network_error", "Could not reach the GitHub API."),
      /^Could not read me\'s membership in acme: Could not reach the GitHub API\.$/,
    ],
    [
      "malformed body",
      new GitHubAuthError(
        "unexpected_response",
        "GitHub returned a malformed organization membership.",
      ),
      /malformed organization membership/,
    ],
    [
      "rate limit",
      new GitHubAuthError("rate_limited", "GitHub API rate limit reached.", 429),
      /rate limit was reached/,
    ],
    ["non-GitHub error", new Error("boom"), /unexpected error/],
  ])("reports a membership %s as unverifiable", async (_label, error, reason) => {
    const { root, mine } = repoWithCommits(ORG_REMOTE);
    const { outcome } = await authorize(
      root,
      orgState(mine, {
        memberships: error === undefined ? {} : { acme: error },
      }),
    );
    expectBlocked(outcome);
    expect(statusOf(outcome, "owner_approval")).toBe("unverifiable");
    expect(approval(outcome)?.reason).toMatch(reason);
  });

  it("blocks when the org installation does not include the repository, whatever the membership", async () => {
    const { root, mine } = repoWithCommits(ORG_REMOTE);
    const { outcome, calls } = await authorize(
      root,
      orgState(mine, { installationRepositories: { 88: [1] } }),
    );
    expectBlocked(outcome);
    expect(approval(outcome)).toMatchObject({
      status: "failed",
      reason:
        'The PGARD GitHub App installation on the organization "acme" does not include acme/app. An owner of acme must add the repository to the installation.',
    });
    // The membership is read only to guide the user (install it yourself or ask an owner); an
    // owner membership never turns the missing repository into a pass.
    expect(calls).toContain("membership:acme");
    expect(outcome.remedy).toMatchObject({ missing: "repository", canApprove: "yes" });
  });

  it("blocks when the only installation is on a different account", async () => {
    const { root, mine } = repoWithCommits(ORG_REMOTE);
    for (const installation of [
      orgInstallation({ account: { id: 4242, login: "other-org" } }),
      // A personal installation by the org owner is not an installation on the organization.
      { ...ownerInstallation(), id: 88 },
      // Same account id, but not reported as an organization installation.
      { ...orgInstallation(), targetType: "User" },
    ]) {
      const { outcome } = await authorize(root, orgState(mine, { installations: [installation] }));
      expectBlocked(outcome);
      expect(approval(outcome)).toMatchObject({
        status: "failed",
        reason:
          'No PGARD GitHub App installation on the organization "acme" was found for acme/app. An owner of acme must install the App on the organization and include the repository.',
      });
    }
  });

  it("blocks when the remote names the organization with different case", async () => {
    const { root, mine } = repoWithCommits({ origin: "git@github.com:Acme/app.git" });
    const { outcome, calls } = await authorize(root, orgState(mine));
    expectBlocked(outcome);
    expect(approval(outcome)).toMatchObject({
      status: "unverifiable",
      reason:
        'The Git remote names the organization "Acme", but GitHub reports the owner as "acme". Update the remote to github.com/acme/app so the organization can be verified.',
    });
    expect(calls).not.toContain("membership:acme");
    expect(calls).not.toContain("membership:Acme");
  });

  it("blocks when the installation account login differs from the organization (case)", async () => {
    const { root, mine } = repoWithCommits(ORG_REMOTE);
    const { outcome } = await authorize(
      root,
      orgState(mine, {
        installations: [orgInstallation({ account: { id: ORG.id, login: "ACME" } })],
      }),
    );
    expectBlocked(outcome);
    expect(statusOf(outcome, "owner_approval")).toBe("unverifiable");
    expect(approval(outcome)?.reason).toContain('reports the account "ACME"');
  });

  it("blocks a membership that is for another organization or another user", async () => {
    const { root, mine } = repoWithCommits(ORG_REMOTE);
    for (const membership of [
      orgMembership({ organization: { id: 9, login: "acme" } }),
      orgMembership({ organization: { id: ORG.id, login: "Acme" } }),
      orgMembership({ user: { id: 2002, login: "someone" } }),
      // Same login, different id: the user must be matched by id, not by login.
      orgMembership({ user: { id: 2002, login: "me" } }),
    ]) {
      const { outcome } = await authorize(
        root,
        orgState(mine, { memberships: { acme: membership } }),
      );
      expectBlocked(outcome);
      expect(statusOf(outcome, "owner_approval")).toBe("unverifiable");
    }
  });

  it("does not use the organization path for a personal repository", async () => {
    const { root, mine } = repoWithCommits();
    const { outcome, calls } = await authorize(
      root,
      baseState({
        pulls: {
          [mine]: [
            {
              number: 4,
              userId: ME.id,
              mergedAt: "2026-10-01T00:00:00Z",
              baseRef: "main",
              baseRepositoryId: 555,
            },
          ],
        },
        compare: { [mine]: "ahead" },
      }),
    );
    expect(outcome.summary.decision).toBe("allowed");
    expect(approval(outcome)?.reason).toBe(
      'The PGARD GitHub App is installed by the owner account "me" and includes me/app.',
    );
    expect(calls.some((call) => call.startsWith("membership:"))).toBe(false);
  });
});
