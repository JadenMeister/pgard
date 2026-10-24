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
      expect.arrayContaining(["PG-SQL-001", "PG-XSS-003", "PG-CMD-002", "PG-DEP-001"]),
    );
  });

  it("checks dependency advisories and reports the advisory database (#93)", async () => {
    root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-dep-")));
    writeFileSync(
      path.join(root, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "node_modules/lodash": { version: "4.17.20" } },
      }),
    );
    const dbPath = path.join(root, "..", `${path.basename(root)}-osv.json`);
    writeFileSync(
      dbPath,
      JSON.stringify({
        version: "wiring-1",
        updatedAt: "2026-10-20T00:00:00Z",
        vulnerabilities: [
          {
            id: "GHSA-wiring",
            modified: "2026-10-20T00:00:00Z",
            affected: [
              {
                package: { ecosystem: "npm", name: "lodash" },
                ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
              },
            ],
          },
        ],
      }),
    );
    try {
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
          env: { PGARD_ADVISORY_DB: dbPath },
          now: () => new Date("2026-10-24T00:00:00Z"),
        },
      );
      expect(result.findings.map((finding) => finding.ruleId)).toEqual(["PG-DEP-001"]);
      expect(result.advisoryDb).toEqual({
        version: "wiring-1",
        updatedAt: "2026-10-20T00:00:00.000Z",
      });
    } finally {
      rmSync(dbPath, { force: true });
    }
  });
});
