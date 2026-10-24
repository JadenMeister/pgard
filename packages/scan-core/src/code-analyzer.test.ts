import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AuthorizationOutcome } from "@pgard/policy";
import { afterEach, describe, expect, it, vi } from "vitest";

const authorizeProject = vi.fn<(root: string) => Promise<AuthorizationOutcome>>();
vi.mock("@pgard/policy", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@pgard/policy")>();
  return { ...actual, authorizeProject: (root: string) => authorizeProject(root) };
});
const { runScan, listSupportedRules } = await import("./index.js");

let root: string | null = null;
afterEach(() => {
  if (root) rmSync(root, { recursive: true, force: true });
  root = null;
});

describe("code scope wiring", () => {
  it("runs source analysis through runScan with repository-relative paths", async () => {
    root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-code-")));
    writeFileSync(
      path.join(root, "db.ts"),
      'import { Pool } from "pg";\nexport const q = (req) => new Pool().query(`SELECT * FROM t WHERE id = ${req.query.id}`);\n',
    );
    authorizeProject.mockResolvedValue({
      summary: {
        decision: "allowed",
        checks: (
          [
            "repository",
            "github_identity",
            "owner_approval",
            "current_access",
            "contribution",
          ] as const
        ).map((id) => ({ id, status: "passed" as const, reason: "ok" })),
      },
      repo: "me/app",
      revision: null,
    });
    const result = await runScan(
      { projectRoot: root, scopes: ["code"], webTarget: null },
      {
        authorization: { getGitHubSession: async () => Promise.reject(new Error("unused")) },
        env: {},
      },
    );
    expect(result.findings).toEqual([
      expect.objectContaining({
        ruleId: "PG-SQL-001",
        location: expect.objectContaining({ path: "db.ts", line: 2 }),
      }),
    ]);
    expect(result.coverage.some((entry) => entry.area === "source:typescript")).toBe(true);
    expect(JSON.stringify(result)).not.toContain(root);
  });

  it("lists the source rules", () => {
    expect(listSupportedRules().map((rule) => rule.id)).toEqual(
      expect.arrayContaining(["PG-SQL-001", "PG-XSS-003", "PG-CMD-002"]),
    );
  });
});
