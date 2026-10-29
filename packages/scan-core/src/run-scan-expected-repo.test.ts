import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createGitFixture,
  type GitFixture,
} from "../../git-history/src/test-support/git-fixture.js";
import {
  collaboratorRepository,
  createMockGitHub,
  MAINTAINER,
  ME,
  ownerInstallation,
  sessionProvider,
} from "../../policy/src/test-support/mock-github.js";
import { runScan, verifyProject } from "./index.js";

let fixture: GitFixture | null = null;
afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

function setup() {
  fixture = createGitFixture({ remotes: { origin: "git@github.com:maintainer/app.git" } });
  fixture.commit({ authorName: "Someone", authorEmail: "someone@example.com" });
  const mine = fixture.commit({ authorName: "Me Person", authorEmail: "me@example.com" });
  const { session } = createMockGitHub({
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
  });
  const analyzers = {
    code: vi.fn(async () => ({ findings: [], coverage: [] })),
    history: vi.fn(async () => ({ findings: [], coverage: [] })),
  };
  return {
    root: fixture.root,
    analyzers,
    authorization: { getGitHubSession: sessionProvider(async () => session) },
  };
}

describe("ScanRequest.expectedRepo (the picker's confirmed repository)", () => {
  it("runs the scan for the confirmed repository", async () => {
    const { root, analyzers, authorization } = setup();
    const result = await runScan(
      {
        projectRoot: root,
        scopes: ["code"],
        webTarget: null,
        expectedRepo: { owner: "maintainer", name: "app" },
      },
      { authorization, analyzers, webRules: [] },
    );
    expect(result.overallStatus).not.toBe("blocked");
    expect(analyzers.code).toHaveBeenCalled();
  });

  it("blocks the scan and runs no analysis when the folder holds another repository", async () => {
    const { root, analyzers, authorization } = setup();
    const result = await runScan(
      {
        projectRoot: root,
        scopes: ["code", "history"],
        webTarget: null,
        expectedRepo: { owner: "evil", name: "app" },
      },
      { authorization, analyzers, webRules: [] },
    );
    expect(result.overallStatus).toBe("blocked");
    expect(result.authorization.decision).toBe("blocked");
    expect(result.authorization.checks[0]).toMatchObject({
      id: "repository",
      status: "failed",
      reason: "The repository changed since you confirmed it.",
    });
    expect(analyzers.code).not.toHaveBeenCalled();
    expect(analyzers.history).not.toHaveBeenCalled();
    expect(result.findings).toEqual([]);
  });

  it("stops verifyProject the same way", async () => {
    const { root, authorization } = setup();
    const outcome = await verifyProject(root, {
      ...authorization,
      expectedRepo: { owner: "evil", name: "app" },
    });
    expect(outcome.summary.decision).toBe("blocked");
    expect(outcome.summary.checks[0]?.reason).toBe(
      "The repository changed since you confirmed it.",
    );
  });
});
