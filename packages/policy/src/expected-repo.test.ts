import { afterEach, describe, expect, it, vi } from "vitest";
import { runGit } from "@pgard/git-history";
import {
  createGitFixture,
  type GitFixture,
} from "../../git-history/src/test-support/git-fixture.js";
import {
  authorizeProject,
  isAuthorizationAllowed,
  recheckOwnerApproval,
} from "./authorize-project.js";
import { inspectRepository } from "./checks.js";
import {
  collaboratorRepository,
  createMockGitHub,
  MAINTAINER,
  ME,
  ownerInstallation,
  sessionProvider,
  type MockGitHubState,
} from "./test-support/mock-github.js";
import { REPOSITORY_CHANGED_REASON } from "./types.js";

let fixture: GitFixture | null = null;
afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

function repo(remotes: Record<string, string> = { origin: "git@github.com:maintainer/app.git" }) {
  fixture = createGitFixture({ remotes });
  fixture.commit({ authorName: "Someone", authorEmail: "someone@example.com" });
  const mine = fixture.commit({ authorName: "Me Person", authorEmail: "me@example.com" });
  return { root: fixture.root, mine };
}

function state(mine: string, overrides: Partial<MockGitHubState> = {}): MockGitHubState {
  return {
    user: ME,
    repository: collaboratorRepository(),
    installations: [ownerInstallation(MAINTAINER.id, MAINTAINER.login)],
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
    commits: {},
    compare: { [mine]: "ahead" },
    ...overrides,
  };
}

describe("inspectRepository: fixed codes for the local repository check", () => {
  const cases: Array<[string, Record<string, string>, string]> = [
    ["no remote", {}, "no_remote"],
    ["another host", { origin: "https://example.com/o/r.git" }, "remote_not_github"],
    [
      "two repositories",
      { origin: "https://github.com/a/b.git", other: "https://github.com/c/d.git" },
      "remote_ambiguous",
    ],
  ];
  for (const [label, remotes, code] of cases) {
    it(`reports ${label} as ${code}`, async () => {
      const { root } = repo(remotes);
      const inspection = await inspectRepository(root, runGit);
      expect(inspection).toMatchObject({ status: "blocked", code });
    });
  }

  it("reports a repository without commits and a non-repository", async () => {
    fixture = createGitFixture({ remotes: { origin: "git@github.com:o/r.git" } });
    expect(await inspectRepository(fixture.root, runGit)).toMatchObject({
      status: "blocked",
      code: "no_commit_history",
    });
    expect(await inspectRepository(`${fixture.root}/.git`, runGit)).toMatchObject({
      status: "blocked",
      code: "not_a_git_root",
    });
  });

  it("returns owner and name for a github.com repository, the same data the gate uses", async () => {
    const { root, mine } = repo();
    expect(await inspectRepository(root, runGit)).toMatchObject({
      status: "ok",
      repo: { owner: "maintainer", name: "app" },
      revision: mine,
    });
  });
});

describe("expectedRepo: a run stops unless the folder holds the confirmed repository", () => {
  it("allows the confirmed repository, with or without the numeric id", async () => {
    const { root, mine } = repo();
    for (const expectedRepo of [
      { owner: "maintainer", name: "app" },
      { owner: "maintainer", name: "app", repositoryId: 555 },
      null,
    ]) {
      const { session } = createMockGitHub(state(mine));
      const outcome = await authorizeProject(root, {
        getGitHubSession: sessionProvider(async () => session),
        expectedRepo,
      });
      expect(outcome.summary.decision, JSON.stringify(expectedRepo)).toBe("allowed");
    }
  });

  it("blocks right after the repository check, before any sign-in, with the fixed reason", async () => {
    const { root, mine } = repo();
    const { session, calls } = createMockGitHub(state(mine));
    const getGitHubSession = vi.fn(async () => session);
    const outcome = await authorizeProject(root, {
      getGitHubSession: sessionProvider(getGitHubSession),
      expectedRepo: { owner: "someone-else", name: "app" },
    });
    expect(outcome.summary.decision).toBe("blocked");
    expect(isAuthorizationAllowed(outcome)).toBe(false);
    expect(outcome.summary.checks[0]).toMatchObject({
      id: "repository",
      status: "failed",
      reason: REPOSITORY_CHANGED_REASON,
    });
    expect(outcome.summary.checks.slice(1).every((check) => check.status === "unverifiable")).toBe(
      true,
    );
    expect(getGitHubSession).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
    expect(outcome.repo).toBeNull();
  });

  it("compares owner and name exactly (a different case is another repository)", async () => {
    const { root, mine } = repo();
    const { session } = createMockGitHub(state(mine));
    const outcome = await authorizeProject(root, {
      getGitHubSession: sessionProvider(async () => session),
      expectedRepo: { owner: "Maintainer", name: "app" },
    });
    expect(outcome.summary.decision).toBe("blocked");
  });

  it("blocks when GitHub returns another numeric repository id", async () => {
    const { root, mine } = repo();
    const { session } = createMockGitHub(state(mine));
    const outcome = await authorizeProject(root, {
      getGitHubSession: sessionProvider(async () => session),
      expectedRepo: { owner: "maintainer", name: "app", repositoryId: 999 },
    });
    expect(outcome.summary.decision).toBe("blocked");
    expect(outcome.summary.checks.find((check) => check.id === "current_access")).toMatchObject({
      status: "failed",
      reason: REPOSITORY_CHANGED_REASON,
    });
    expect(outcome.summary.checks.find((check) => check.id === "contribution")?.status).toBe(
      "unverifiable",
    );
  });

  it("stops recheckOwnerApproval too, without asking GitHub", async () => {
    const { root, mine } = repo();
    const { session, calls } = createMockGitHub(state(mine));
    const existing = vi.fn(async () => session);
    const different = await recheckOwnerApproval(root, {
      getGitHubSession: sessionProvider(async () => session, existing),
      expectedRepo: { owner: "x", name: "y" },
    });
    expect(different).toEqual({
      status: "failed",
      reason: REPOSITORY_CHANGED_REASON,
      remedy: null,
    });
    expect(existing).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
    const wrongId = await recheckOwnerApproval(root, {
      getGitHubSession: sessionProvider(
        async () => session,
        async () => session,
      ),
      expectedRepo: { owner: "maintainer", name: "app", repositoryId: 1 },
    });
    expect(wrongId).toMatchObject({ status: "failed", reason: REPOSITORY_CHANGED_REASON });
    const same = await recheckOwnerApproval(root, {
      getGitHubSession: sessionProvider(
        async () => session,
        async () => session,
      ),
      expectedRepo: { owner: "maintainer", name: "app", repositoryId: 555 },
    });
    expect(same.status).toBe("passed");
  });
});
