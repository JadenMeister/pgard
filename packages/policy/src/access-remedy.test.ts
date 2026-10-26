import { GitHubAuthError } from "@pgard/github-auth";
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
import { evaluateAccessRemedy, REPOSITORY_ACCESS_LINK_UNAVAILABLE_MESSAGE } from "./checks.js";
import {
  ME,
  ORG,
  orgInstallation,
  createMockGitHub,
  ownerInstallation,
  sessionProvider,
  userRepository,
  type MockGitHubState,
} from "./test-support/mock-github.js";

const SLUG = "pgard-jadenmeister";
const PERSONAL_URL =
  "https://github.com/apps/pgard-jadenmeister/installations/new/permissions?suggested_target_id=1001";
const ORG_URL =
  "https://github.com/apps/pgard-jadenmeister/installations/new/permissions?suggested_target_id=42";
const REASON =
  "GitHub returned no access to github.com/me/app. For a private repository this usually means the PGARD GitHub App is not installed for it, or your account has no access.";

let fixture: GitFixture | null = null;
afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

function project(remote = "git@github.com:me/app.git"): { root: string; head: string } {
  fixture?.cleanup();
  fixture = createGitFixture({ remotes: { origin: remote } });
  const head = fixture.commit({ authorName: "Me Person", authorEmail: "me@example.com" });
  return { root: fixture.root, head };
}

/** A private repository outside the installation: GitHub answers 404 for it. */
function hiddenState(head: string, overrides: Partial<MockGitHubState> = {}): MockGitHubState {
  return {
    user: ME,
    repository: null,
    installations: [],
    installationRepositories: {},
    pulls: {},
    commits: { [head]: { sha: head, authorId: ME.id, committerId: ME.id, isVerified: true } },
    compare: { [head]: "identical" },
    accounts: { me: { id: ME.id, login: "me", type: "User" } },
    ...overrides,
  };
}

function deps(state: MockGitHubState, appSlug: string | null = SLUG) {
  const { session, calls } = createMockGitHub(state);
  return { calls, deps: { getGitHubSession: sessionProvider(async () => session), appSlug } };
}

function status(outcome: Awaited<ReturnType<typeof authorizeProject>>, id: string) {
  return outcome.summary.checks.find((check) => check.id === id);
}

describe("404 from getRepository (private repository outside the installation)", () => {
  it("keeps current_access failed with the honest reason and offers the account install link", async () => {
    const { root, head } = project();
    const { deps: d } = deps(hiddenState(head));
    const outcome = await authorizeProject(root, d);
    expect(outcome.summary.decision).toBe("blocked");
    expect(status(outcome, "current_access")).toMatchObject({ status: "failed", reason: REASON });
    expect(status(outcome, "owner_approval")?.status).toBe("unverifiable");
    expect(status(outcome, "contribution")?.status).toBe("unverifiable");
    expect(isAuthorizationAllowed(outcome)).toBe(false);
    expect(outcome.remedy).toMatchObject({
      missing: "access",
      url: PERSONAL_URL,
      canApprove: "yes",
      account: { login: "me", type: "User" },
    });
    expect(outcome.remedy?.url).not.toContain("repository_ids");
    expect(guidedInstallRemedy(outcome)).toEqual(outcome.remedy);
  });

  it("has no remedy, but the same failed reason, when the owner lookup fails", async () => {
    const { root, head } = project();
    const variants: MockGitHubState["accounts"][] = [
      {},
      { me: new GitHubAuthError("network_error", "down") },
      { me: { id: ME.id, login: "someone-else", type: "User" } },
      { me: { id: ME.id, login: "me", type: "Bot" } },
    ];
    for (const accounts of variants) {
      const { deps: d } = deps(hiddenState(head, { accounts }));
      const outcome = await authorizeProject(root, d);
      expect(status(outcome, "current_access")).toMatchObject({ status: "failed", reason: REASON });
      expect(outcome.remedy ?? null).toBeNull();
      expect(guidedInstallRemedy(outcome)).toBeNull();
      expect(isAuthorizationAllowed(outcome)).toBe(false);
    }
  });

  it("is guided (unknown) for an organization and no for someone else's personal account", async () => {
    const org = project("git@github.com:acme/app.git");
    const { deps: d } = deps(
      hiddenState(org.head, { accounts: { acme: { ...ORG, type: "Organization" } } }),
    );
    const outcome = await authorizeProject(org.root, d);
    expect(outcome.remedy).toMatchObject({ canApprove: "unknown", url: ORG_URL });
    expect(guidedInstallRemedy(outcome)).not.toBeNull();

    const other = project("git@github.com:maintainer/app.git");
    const { deps: d2 } = deps(
      hiddenState(other.head, {
        accounts: { maintainer: { id: 3003, login: "maintainer", type: "User" } },
      }),
    );
    const outcome2 = await authorizeProject(other.root, d2);
    expect(outcome2.remedy).toMatchObject({ canApprove: "no" });
  });

  it("offers no link without a configured App slug", async () => {
    const { root, head } = project();
    const { deps: d } = deps(hiddenState(head), null);
    const outcome = await authorizeProject(root, d);
    expect(outcome.remedy).toMatchObject({ url: null, canApprove: "yes" });
    expect(status(outcome, "current_access")?.status).toBe("failed");
  });

  it("offers no remedy for other errors", async () => {
    const { root, head } = project();
    const { deps: d } = deps(
      hiddenState(head, { failWith: new GitHubAuthError("rate_limited", "x") }),
    );
    const outcome = await authorizeProject(root, d);
    expect(outcome.remedy ?? null).toBeNull();
    expect(isAuthorizationAllowed(outcome)).toBe(false);
  });

  it("is not guided when the outcome shape does not match", async () => {
    const { root, head } = project();
    const { deps: d } = deps(hiddenState(head));
    const outcome = await authorizeProject(root, d);
    const cases = [
      [0, "failed"],
      [1, "failed"],
      [2, "failed"],
      [3, "passed"],
      [3, "unverifiable"],
      [4, "failed"],
    ] as const;
    for (const [index, wrong] of cases) {
      const mutated = structuredClone(outcome);
      mutated.summary.checks[index]!.status = wrong;
      expect(guidedInstallRemedy(mutated)).toBeNull();
    }
  });
});

const CONFIGURE_URL = "https://github.com/settings/installations/77";
const ORG_CONFIGURE_URL = "https://github.com/organizations/acme/settings/installations/88";

describe("404 when the App is already installed on the owner account", () => {
  it("points a personal owner at the installation settings page to add the repository", async () => {
    const { root, head } = project();
    const { deps: d } = deps(hiddenState(head, { installations: [ownerInstallation()] }));
    const outcome = await authorizeProject(root, d);
    expect(status(outcome, "current_access")).toMatchObject({ status: "failed", reason: REASON });
    expect(outcome.remedy).toMatchObject({
      missing: "repository_access",
      url: CONFIGURE_URL,
      canApprove: "yes",
    });
    expect(guidedInstallRemedy(outcome)).toEqual(outcome.remedy);
    expect(isAuthorizationAllowed(outcome)).toBe(false);
  });

  it("uses the organization settings page, canApprove unknown", async () => {
    const org = project("git@github.com:acme/app.git");
    const { deps: d } = deps(
      hiddenState(org.head, {
        accounts: { acme: { ...ORG, type: "Organization" } },
        installations: [orgInstallation()],
      }),
    );
    const outcome = await authorizeProject(org.root, d);
    expect(outcome.remedy).toMatchObject({
      missing: "repository_access",
      url: ORG_CONFIGURE_URL,
      canApprove: "unknown",
    });
  });

  it("does not use an installation of another account or another account type", async () => {
    const { root, head } = project();
    for (const installations of [
      [ownerInstallation(9999, "someone")],
      [{ ...ownerInstallation(), targetType: "Organization" }],
    ]) {
      const { deps: d } = deps(hiddenState(head, { installations }));
      const outcome = await authorizeProject(root, d);
      expect(outcome.remedy).toMatchObject({ missing: "access", url: PERSONAL_URL });
    }
  });

  it("offers no remedy when the installations cannot be listed (never guesses a page)", async () => {
    const { root, head } = project();
    const { deps: d } = deps(
      hiddenState(head, { installationsError: new GitHubAuthError("network_error", "down") }),
    );
    const outcome = await authorizeProject(root, d);
    expect(status(outcome, "current_access")).toMatchObject({ status: "failed", reason: REASON });
    expect(outcome.remedy ?? null).toBeNull();
    expect(guidedInstallRemedy(outcome)).toBeNull();
  });

  it("never builds a link from an unusable installation id", async () => {
    const { root, head } = project();
    const bad = { ...ownerInstallation(), id: 0 };
    const { deps: d } = deps(hiddenState(head, { installations: [bad] }));
    const outcome = await authorizeProject(root, d);
    expect(outcome.remedy).toMatchObject({ missing: "repository_access", url: null });
  });

  it("is guided by the same exact shape as the install remedy", async () => {
    const { root, head } = project();
    const { deps: d } = deps(hiddenState(head, { installations: [ownerInstallation()] }));
    const outcome = await authorizeProject(root, d);
    const extra = structuredClone(outcome);
    extra.summary.checks.push({ id: "contribution", status: "unverifiable", reason: "x" });
    expect(guidedInstallRemedy(extra)).toBeNull();
    const short = structuredClone(outcome);
    short.summary.checks.pop();
    expect(guidedInstallRemedy(short)).toBeNull();
    const wrong = structuredClone(outcome);
    wrong.summary.checks[3]!.status = "passed";
    expect(guidedInstallRemedy(wrong)).toBeNull();
  });
});

describe("configure link safety", () => {
  it("builds no configure link for a login outside GitHub's alphabet", async () => {
    const { session } = createMockGitHub(
      hiddenState("x", {
        accounts: { a_b: { id: 5, login: "a_b", type: "User" } },
        installations: [ownerInstallation(5, "a_b")],
      }),
    );
    const remedy = await evaluateAccessRemedy(session.client, ME, "a_b", SLUG);
    expect(remedy).toMatchObject({
      missing: "repository_access",
      url: null,
      unavailableReason: REPOSITORY_ACCESS_LINK_UNAVAILABLE_MESSAGE,
    });
    expect(remedy?.unavailableReason).not.toContain("only available for repositories");
  });
});

describe("other failures and spelling", () => {
  it("offers no remedy for a non-404 getRepository failure", async () => {
    const { root, head } = project();
    for (const repositoryError of [
      new GitHubAuthError("http_error", "boom", 500),
      new GitHubAuthError("rate_limited", "slow"),
      new GitHubAuthError("forbidden", "no", 403),
      new Error("unexpected"),
    ]) {
      const { deps: d } = deps(hiddenState(head, { repositoryError }));
      const outcome = await authorizeProject(root, d);
      expect(outcome.remedy ?? null).toBeNull();
      expect(status(outcome, "current_access")?.status).toBe("unverifiable");
      const recheck = await recheckOwnerApproval(root, d);
      expect(recheck.remedy).toBeNull();
      expect(recheck.status).toBe("unverifiable");
    }
  });

  it("matches a lowercase remote owner against GitHub's canonical login", async () => {
    const { root, head } = project("git@github.com:jadenmeister/app.git");
    const { deps: d } = deps(
      hiddenState(head, {
        user: { ...ME, login: "JadenMeister" },
        accounts: { jadenmeister: { id: ME.id, login: "JadenMeister", type: "User" } },
        installations: [ownerInstallation(ME.id, "JadenMeister")],
      }),
    );
    const outcome = await authorizeProject(root, d);
    expect(outcome.remedy).toMatchObject({
      missing: "repository_access",
      account: { login: "JadenMeister" },
      canApprove: "yes",
    });
  });
});

describe("after the install", () => {
  it("passes the full authorization again once the repository is visible and all 5 checks pass", async () => {
    const { root, head } = project();
    const state = hiddenState(head);
    const { deps: d } = deps(state);
    expect(isAuthorizationAllowed(await authorizeProject(root, d))).toBe(false);

    state.repository = userRepository();
    state.installations = [ownerInstallation()];
    state.installationRepositories = { 77: [555] };
    const after = await authorizeProject(root, d);
    expect(after.summary.checks.map((check) => check.status)).toEqual([
      "passed",
      "passed",
      "passed",
      "passed",
      "passed",
    ]);
    expect(isAuthorizationAllowed(after)).toBe(true);
  });

  it("stays blocked after an install when another check does not pass", async () => {
    const { root, head } = project();
    const state = hiddenState(head);
    const { deps: d } = deps(state);
    state.repository = userRepository();
    state.installations = [ownerInstallation()];
    state.installationRepositories = { 77: [555] };
    state.compare = {};
    const after = await authorizeProject(root, d);
    expect(isAuthorizationAllowed(after)).toBe(false);
  });
});

describe("recheckOwnerApproval with a hidden repository", () => {
  it("keeps waiting (failed + remedy) while the repository is still not found", async () => {
    const { root, head } = project();
    const { deps: d } = deps(hiddenState(head));
    const result = await recheckOwnerApproval(root, d);
    expect(result).toMatchObject({ status: "failed", reason: REASON });
    expect(result.remedy).toMatchObject({ missing: "access", url: PERSONAL_URL });
  });

  it("ends the wait (no remedy) when the owner lookup fails, never passing", async () => {
    const { root, head } = project();
    const { deps: d } = deps(hiddenState(head, { accounts: {} }));
    const result = await recheckOwnerApproval(root, d);
    expect(result.status).toBe("failed");
    expect(result.remedy).toBeNull();
  });

  it("passes owner approval alone once installed (the caller must run the full gate)", async () => {
    const { root, head } = project();
    const state = hiddenState(head);
    const { deps: d } = deps(state);
    state.repository = userRepository();
    state.installations = [ownerInstallation()];
    state.installationRepositories = { 77: [555] };
    expect(await recheckOwnerApproval(root, d)).toMatchObject({ status: "passed", remedy: null });
  });
});
