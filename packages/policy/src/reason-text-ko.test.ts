import type { AuthorizationCheck } from "@pgard/findings";
import { authorizationReasonText } from "@pgard/findings";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createGitFixture,
  type GitFixture,
} from "../../git-history/src/test-support/git-fixture.js";
import { authorizeProject } from "./authorize-project.js";
import { contributionGuidance } from "./checks.js";
import {
  ME,
  collaboratorRepository,
  createMockGitHub,
  orgInstallation,
  orgMembership,
  orgRepository,
  ownerInstallation,
  sessionProvider,
  userRepository,
  MAINTAINER,
  type MockGitHubState,
} from "./test-support/mock-github.js";

/**
 * Every fixed reason the gate writes has a Korean text (#449). The reasons come from running the
 * real `authorizeProject` over stubs, so a reworded policy sentence fails here instead of
 * silently falling back to English. Reasons that embed an error message are not in these runs.
 */
let fixture: GitFixture | null = null;
afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

const merged = (sha: string) => ({
  [sha]: [
    {
      number: 4,
      userId: ME.id,
      mergedAt: "2026-10-01T00:00:00Z",
      baseRef: "main",
      baseRepositoryId: 555,
    },
  ],
});

function repo(remotes: Record<string, string>) {
  fixture = createGitFixture({ remotes });
  const other = fixture.commit({ authorName: "Someone", authorEmail: "someone@example.com" });
  const mine = fixture.commit({ authorName: "Me Person", authorEmail: "me@example.com" });
  return { root: fixture.root, other, mine };
}

function base(overrides: Partial<MockGitHubState> = {}): MockGitHubState {
  return {
    user: ME,
    repository: collaboratorRepository(),
    installations: [ownerInstallation(MAINTAINER.id, MAINTAINER.login)],
    installationRepositories: { 77: [555] },
    pulls: {},
    commits: {},
    compare: {},
    ...overrides,
  };
}

async function reasonsOf(
  root: string,
  state: MockGitHubState,
  maxCandidates?: number,
): Promise<AuthorizationCheck[]> {
  const { session } = createMockGitHub(state);
  const outcome = await authorizeProject(root, {
    getGitHubSession: sessionProvider(vi.fn(async () => session)),
    ...(maxCandidates ? { maxContributionCandidates: maxCandidates } : {}),
  });
  return outcome.summary.checks;
}

const PERSONAL = { origin: "git@github.com:maintainer/app.git" };
const OWN = { origin: "git@github.com:me/app.git" };
const ORG = { origin: "git@github.com:acme/app.git" };

const orgState = (overrides: Partial<MockGitHubState> = {}) =>
  base({
    repository: orgRepository(),
    installations: [orgInstallation()],
    installationRepositories: { 88: [555] },
    memberships: { acme: orgMembership() },
    ...overrides,
  });

describe("Korean text of every fixed reason the gate writes", () => {
  const scenarios: Array<[string, () => Promise<AuthorizationCheck[]>]> = [
    [
      "allowed by a merged pull request",
      async () => {
        const { root, mine } = repo(PERSONAL);
        return reasonsOf(root, base({ pulls: merged(mine), compare: { [mine]: "ahead" } }));
      },
    ],
    [
      "allowed by a verified signature",
      async () => {
        const { root, mine } = repo(PERSONAL);
        return reasonsOf(
          root,
          base({
            commits: {
              [mine]: { sha: mine, authorId: ME.id, committerId: ME.id, isVerified: true },
            },
            compare: { [mine]: "identical" },
          }),
        );
      },
    ],
    ["no contribution evidence", async () => reasonsOf(repo(PERSONAL).root, base())],
    [
      "contribution examined only in part",
      async () => {
        const { root, other } = repo(PERSONAL);
        return reasonsOf(root, base({ pulls: merged(other), compare: { [other]: "ahead" } }), 1);
      },
    ],
    [
      "no owner installation",
      async () => reasonsOf(repo(PERSONAL).root, base({ installations: [] })),
    ],
    [
      "owner installation without the repository",
      async () => reasonsOf(repo(PERSONAL).root, base({ installationRepositories: { 77: [1] } })),
    ],
    [
      "repository not visible (404)",
      async () => reasonsOf(repo(PERSONAL).root, base({ repository: null })),
    ],
    [
      "no pull permission",
      async () =>
        reasonsOf(
          repo(PERSONAL).root,
          base({
            repository: collaboratorRepository({
              permissions: {
                admin: false,
                maintain: false,
                push: false,
                triage: false,
                pull: false,
              },
            }),
          }),
        ),
    ],
    [
      "personal owner, linked to the default branch",
      async () => {
        const { root, mine } = repo(OWN);
        return reasonsOf(
          root,
          base({
            repository: userRepository(),
            installations: [ownerInstallation()],
            compare: { [mine]: "identical" },
          }),
        );
      },
    ],
    [
      "personal owner, not linked",
      async () =>
        reasonsOf(
          repo(OWN).root,
          base({ repository: userRepository(), installations: [ownerInstallation()] }),
        ),
    ],
    [
      "organization owner, linked",
      async () => {
        const { root, mine } = repo(ORG);
        return reasonsOf(root, orgState({ compare: { [mine]: "ahead" } }));
      },
    ],
    [
      "organization, plain member",
      async () =>
        reasonsOf(
          repo(ORG).root,
          orgState({ memberships: { acme: orgMembership({ role: "member" }) } }),
        ),
    ],
    [
      "organization, pending membership",
      async () =>
        reasonsOf(
          repo(ORG).root,
          orgState({ memberships: { acme: orgMembership({ state: "pending" }) } }),
        ),
    ],
    [
      "organization installation without the repository",
      async () => reasonsOf(repo(ORG).root, orgState({ installationRepositories: { 88: [1] } })),
    ],
    [
      "organization without an installation",
      async () => reasonsOf(repo(ORG).root, orgState({ installations: [] })),
    ],
    [
      "remote that is not on github.com",
      async () => reasonsOf(repo({ origin: "git@example.com:a/b.git" }).root, base()),
    ],
  ];

  it.each(scenarios)("%s", async (_name, run) => {
    const checks = await run();
    expect(checks.length).toBeGreaterThan(0);
    for (const check of checks) {
      const shown = authorizationReasonText(check.reason, "ko");
      expect(shown.translated, `${check.id}: ${check.reason}`).toBe(true);
      expect(shown.text).toMatch(/[가-힣]/);
    }
  });

  it("covers the guidance sentence of a non-owner for a renamed default branch", () => {
    const reason = `No local commits were found to check for a contribution. ${contributionGuidance("develop")}`;
    expect(authorizationReasonText(reason, "ko").translated).toBe(true);
  });
});
