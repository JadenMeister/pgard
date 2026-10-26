/**
 * The verified owner needs no contribution of their own, but the local code must still be tied
 * to the repository. With no local commits at all there is nothing to tie, so the check fails.
 * (The repository check already rejects a HEAD with no commits; this pins the guard anyway.)
 */
import { describe, expect, it, vi } from "vitest";
import { verifyContribution } from "./checks.js";
import { ME, createMockGitHub, userRepository } from "./test-support/mock-github.js";

vi.mock("@pgard/git-history", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@pgard/git-history")>()),
  listCommitCandidates: async () => [],
}));

describe("verifyOwnerLink", () => {
  it("fails, never passes, when there are no local commits to link", async () => {
    const repository = userRepository();
    const { session } = createMockGitHub({
      user: ME,
      repository,
      installations: [],
      installationRepositories: {},
      pulls: {},
      commits: {},
      compare: {},
    });
    const result = await verifyContribution({
      client: session.client,
      user: ME,
      repository,
      projectRoot: "/not/used",
      runner: async () => {
        throw new Error("unexpected git call");
      },
      maxCandidates: 30,
      ownerEvidence: { kind: "personal_owner", repositoryId: 555, userId: ME.id, ownerId: ME.id },
    });
    expect(result.status).toBe("failed");
    expect(result.reason).toContain("None of the last 0 local commits");
  });
});
