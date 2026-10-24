import type { AuthorizationOutcome } from "@pgard/policy";
import { afterEach, describe, expect, it, vi } from "vitest";
import { sessionProvider } from "../../policy/src/test-support/mock-github.js";
import {
  createGitFixture,
  type GitFixture,
} from "../../git-history/src/test-support/git-fixture.js";

const authorizeProject = vi.fn<(root: string) => Promise<AuthorizationOutcome>>();
vi.mock("@pgard/policy", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@pgard/policy")>();
  return { ...actual, authorizeProject: (root: string) => authorizeProject(root) };
});
const { runScan, listSupportedRules } = await import("./index.js");

const TOKEN = ["ghp", "_", "WiRiNgTeStVaLuE0123", "456789AbCdEfGhIjK"].join("");
let fixture: GitFixture | null = null;
afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

const allowed = (revision: string): AuthorizationOutcome => ({
  summary: {
    decision: "allowed",
    checks: (
      ["repository", "github_identity", "owner_approval", "current_access", "contribution"] as const
    ).map((id) => ({ id, status: "passed" as const, reason: "ok" })),
  },
  repo: "me/app",
  revision,
});

describe("default analyzers wiring", () => {
  it("runs the history scan on the authorized revision", async () => {
    fixture = createGitFixture();
    const authorized = fixture.commit({ files: { "config.ts": `export const t = "${TOKEN}";\n` } });
    fixture.commit({ files: { "config.ts": "export const t = process.env.T;\n" } });
    authorizeProject.mockResolvedValue(allowed(authorized));

    const result = await runScan(
      { projectRoot: fixture.root, scopes: ["history"], webTarget: null },
      {
        authorization: {
          getGitHubSession: sessionProvider(async () => Promise.reject(new Error("unused"))),
        },
        env: {},
      },
    );
    // The value is current at the authorized revision, so it is a tracked-file finding there.
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(["PG-SECRET-002"]);
    expect(result.coverage.find((entry) => entry.area === "history:tracked-files")?.note).toContain(
      authorized.slice(0, 12),
    );
    expect(JSON.stringify(result)).not.toContain(TOKEN);
  });

  it("lists source and history rules", () => {
    const ids = listSupportedRules().map((rule) => rule.id);
    expect(ids).toEqual(
      expect.arrayContaining(["PG-SQL-001", "PG-SECRET-001", "PG-SECRET-002", "PG-SECRET-003"]),
    );
  });
});
