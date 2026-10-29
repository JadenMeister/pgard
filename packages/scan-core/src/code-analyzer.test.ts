import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AuthorizationOutcome } from "@pgard/policy";
import { afterEach, describe, expect, it, vi } from "vitest";
import { sessionProvider } from "../../policy/src/test-support/mock-github.js";
import { advisory, writeOsvFixture } from "../../dependencies/src/test-support/osv-fixture.js";

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
        authorization: {
          getGitHubSession: sessionProvider(async () => Promise.reject(new Error("unused"))),
        },
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

  it("adds a suggested fix to a fixable finding and leaves the file unchanged", async () => {
    root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-fix-")));
    const source = [
      'const express = require("express");',
      "const app = express();",
      'app.get("/login", (req, res) => {',
      '  res.cookie("session", issueToken(req.query.code));',
      "  res.sendStatus(204);",
      "});",
      "",
    ].join("\n");
    writeFileSync(path.join(root, "login.js"), source);
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
        authorization: {
          getGitHubSession: sessionProvider(async () => Promise.reject(new Error("unused"))),
        },
        env: {},
      },
    );
    const cookie = result.findings.find((finding) => finding.ruleId === "PG-COOKIE-001");
    expect(cookie?.fix).toMatchObject({ kind: "diff", confidence: "medium" });
    expect(cookie?.fix?.diff).toContain(
      '+  res.cookie("session", issueToken(req.query.code), { httpOnly: true, secure: true, sameSite: "lax" });',
    );
    expect(JSON.stringify(result)).not.toContain(root);
    // Findings of rules that are not fixable carry no fix.
    const others = result.findings.filter((finding) => finding.ruleId !== "PG-COOKIE-001");
    expect(others.every((finding) => finding.fix === undefined)).toBe(true);
    expect(readFileSync(path.join(root, "login.js"), "utf8")).toBe(source);
  });

  it("lists the source rules and the dependency advisory rule", () => {
    const ids = listSupportedRules().map((rule) => rule.id);
    expect(ids).toEqual(expect.arrayContaining(["PG-SQL-001", "PG-XSS-003", "PG-CMD-002"]));
    expect(ids.filter((id) => id.startsWith("PG-DEP-"))).toEqual(["PG-DEP-001"]);
  });

  async function scanWithLockfile(dataDir: string | null) {
    root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-dep-")));
    writeFileSync(
      path.join(root, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "node_modules/lodash": { version: "4.17.20" } },
      }),
    );
    writeFileSync(path.join(root, "app.ts"), "export const ok = 1;\n");
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
    return runScan(
      { projectRoot: root, scopes: ["code"], webTarget: null },
      {
        authorization: {
          getGitHubSession: sessionProvider(async () => Promise.reject(new Error("unused"))),
        },
        env: {},
        advisoryDataDir: dataDir,
      },
    );
  }

  it("without downloaded advisory data, the dependency area is not_tested with the hint", async () => {
    const empty = mkdtempSync(path.join(tmpdir(), "pgard-nodata-"));
    try {
      const result = await scanWithLockfile(empty);
      expect(result.findings).toEqual([]);
      const area = result.coverage.find((entry) => entry.area === "deps:npm");
      expect(area).toMatchObject({ status: "not_tested", scope: "code" });
      expect(area?.note).toContain("pgard advisories update");
      expect(result.advisoryDb).toEqual({ version: null, updatedAt: null });
      expect(result.overallStatus).toBe("partial");
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });

  it("matches a lockfile against local OSV data and reports the finding in the code scope", async () => {
    const data = mkdtempSync(path.join(tmpdir(), "pgard-osvdata-"));
    try {
      const now = new Date().toISOString();
      await writeOsvFixture(
        data,
        "npm",
        [advisory("GHSA-test-test-test", "lodash", [{ introduced: "0" }, { fixed: "4.17.21" }])],
        { fetchedAt: now, modifiedMax: now },
      );
      const result = await scanWithLockfile(data);
      expect(result.findings).toEqual([
        expect.objectContaining({
          ruleId: "PG-DEP-001",
          sources: ["code"],
          location: expect.objectContaining({ path: "package-lock.json", line: null }),
          dependency: expect.objectContaining({ name: "lodash", fixedVersions: ["4.17.21"] }),
        }),
      ]);
      expect(result.coverage.find((entry) => entry.area === "deps:npm")?.status).toBe("completed");
      expect((result.ruleStats ?? []).some((stat) => stat.area === "deps:npm")).toBe(true);
      expect(result.overallStatus).toBe("completed");
      expect(JSON.stringify(result)).not.toContain(root as string);
    } finally {
      rmSync(data, { recursive: true, force: true });
    }
  });
});
