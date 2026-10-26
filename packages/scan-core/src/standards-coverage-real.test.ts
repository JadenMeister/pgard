import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { ScanResult } from "@pgard/findings";
import type { AuthorizationOutcome } from "@pgard/policy";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { sessionProvider } from "../../policy/src/test-support/mock-github.js";

const authorizeProject = vi.fn<(root: string) => Promise<AuthorizationOutcome>>();

vi.mock("@pgard/policy", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@pgard/policy")>();
  return { ...actual, authorizeProject: (root: string) => authorizeProject(root) };
});

const { runScan } = await import("./index.js");

const ALLOWED: AuthorizationOutcome = {
  summary: {
    decision: "allowed",
    checks: (
      ["repository", "github_identity", "owner_approval", "current_access", "contribution"] as const
    ).map((id) => ({ id, status: "passed" as const, reason: "ok" })),
  },
  repo: "octo/app",
  revision: "a".repeat(40),
};

const roots: string[] = [];
beforeEach(() => {
  authorizeProject.mockReset();
  authorizeProject.mockResolvedValue(ALLOWED);
});
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-real-")));
  roots.push(root);
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  return root;
}

async function scanCode(root: string): Promise<ScanResult> {
  return runScan(
    { projectRoot: root, scopes: ["code"], webTarget: null },
    {
      authorization: {
        getGitHubSession: sessionProvider(async () => Promise.reject(new Error("unused"))),
      },
      createScanId: () => "scan-1",
      now: () => new Date("2026-10-24T00:00:00Z"),
    },
  );
}

const SQL_VULN =
  'import { Pool } from "pg";\nconst pool = new Pool();\nexport const q = (req: any) => pool.query(`SELECT * FROM t WHERE id = ${req.query.id}`);\n';

const owasp = (result: ScanResult, id: string) =>
  result.standardsCoverage!.owasp.find((entry) => entry.id === id)!;
const cwe = (result: ScanResult, id: string) =>
  result.standardsCoverage!.cweTop25.find((entry) => entry.id === id)!;

describe("standards map on real scans of fixture projects", () => {
  it("a small TypeScript project: SQL injection rules ran", async () => {
    const result = await scanCode(project({ "src/db.ts": SQL_VULN }));
    expect(cwe(result, "CWE-89")).toMatchObject({ state: "rules_ran" });
    expect(cwe(result, "CWE-89").ruleIds).toContain("PG-SQL-001");
  });

  it("an ORM that is not analyzed makes SQL injection rules_partial (typeorm import)", async () => {
    const result = await scanCode(
      project({
        "src/db.ts": SQL_VULN,
        "package.json": JSON.stringify({ dependencies: { typeorm: "0.3.0" } }),
      }),
    );
    expect(result.coverage.find((entry) => entry.area === "source:orm:typeorm")?.status).toBe(
      "partial",
    );
    expect(cwe(result, "CWE-89").state).toBe("rules_partial");
    expect(owasp(result, "A05:2025").state).toBe("rules_partial");
    expect(owasp(result, "A05:2025").reason).toContain("source:orm:typeorm");
  });

  it("a single JavaScript file over 1 MiB makes code-mapped entries rules_partial", async () => {
    const result = await scanCode(
      project({
        "src/db.ts": SQL_VULN,
        "src/huge.js": `${"// pad\n".repeat(200_000)}module.exports = 1;\n`,
      }),
    );
    expect(result.coverage.find((entry) => entry.area === "source:large-files")?.status).toBe(
      "partial",
    );
    expect(cwe(result, "CWE-89").state).toBe("rules_partial");
    expect(cwe(result, "CWE-89").reason).toContain("source:large-files");
  });

  it("a docs-only repository: the CSRF rule has nothing to read, so CWE-352 is not rules_ran", async () => {
    const result = await scanCode(project({ "README.md": "# docs\n", "docs/guide.md": "text\n" }));
    expect(cwe(result, "CWE-352").state).not.toBe("rules_ran");
    expect(cwe(result, "CWE-352").ruleIds).toEqual([]);
    const heuristics = result.coverage.find((entry) => entry.area === "source:heuristics");
    expect(heuristics?.ruleIds).toEqual([]);
    expect(result.ruleStats?.some((stat) => stat.area === "source:heuristics")).toBe(false);
  });
});
