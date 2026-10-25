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
  createMockGitHub,
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

  it("blocks organization repositories as unverifiable even with an installation", async () => {
    const { root, mine } = repoWithCommits();
    const { outcome } = await authorize(
      root,
      baseState({
        repository: userRepository({ owner: { id: 42, login: "org", type: "Organization" } }),
        installations: [{ id: 77, targetType: "Organization", account: { id: 42, login: "org" } }],
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
    const approval = outcome.summary.checks.find((check) => check.id === "owner_approval");
    expect(approval?.status).toBe("unverifiable");
    expect(approval?.reason).toMatch(/organization/);
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
