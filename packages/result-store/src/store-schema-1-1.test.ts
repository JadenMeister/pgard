import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { compareScans, SCHEMA_VERSION, type ScanResult } from "@pgard/findings";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createResultStore, type ResultStore } from "./store.js";

const REPO_ID = 77;
const CHECKS = (
  ["repository", "github_identity", "owner_approval", "current_access", "contribution"] as const
).map((id) => ({ id, status: "passed" as const, reason: "ok" }));

function makeResult(scanId: string, extra: Partial<ScanResult> = {}): ScanResult {
  return {
    schemaVersion: SCHEMA_VERSION,
    scanBasis: { mode: "authorized", authorization: "verified", reason: null },
    scanId,
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "owner/name", revision: "abc", webOrigin: null },
    authorization: { decision: "allowed", checks: CHECKS },
    coverage: [
      {
        area: "source:typescript",
        scope: "code",
        status: "completed",
        ruleIds: ["PG-SQL-001"],
        note: null,
      },
    ],
    findings: [],
    advisoryDb: { version: null, updatedAt: null },
    ...extra,
  };
}

const NEW_FIELDS: Partial<ScanResult> = {
  ruleStats: [
    {
      ruleId: "PG-SQL-001",
      area: "source:typescript",
      scope: "code",
      status: "completed",
      targets: [{ unit: "files", examined: 2, reason: null }],
      findings: 0,
    },
  ],
  standardsCoverage: {
    owasp: [
      {
        id: "A05:2025",
        title: "Injection",
        rank: null,
        state: "rules_ran",
        breadth: { cwesWithRules: 1, cwesInCategory: 30 },
        ruleIds: ["PG-SQL-001"],
        mappedRuleIds: ["PG-SQL-001"],
        reason: "ran completely: PG-SQL-001",
      },
    ],
    cweTop25: [],
  },
};

let base: string;
let dir: string;
let store: ResultStore;

beforeEach(async () => {
  base = await mkdtemp(path.join(os.tmpdir(), "pgard-store-11-"));
  dir = path.join(base, "pgard");
  store = createResultStore({ dir, now: () => Date.UTC(2026, 9, 26) });
});
afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

describe("result store with schema 1.0 and 1.1 files", () => {
  it("saves and reads back ruleStats and standardsCoverage", async () => {
    const saved = await store.save(makeResult("new", NEW_FIELDS), { repositoryId: REPO_ID });
    expect(saved.ok).toBe(true);
    const listed = await store.list(REPO_ID);
    expect(listed.warnings).toEqual([]);
    expect(listed.scans[0]?.result.ruleStats).toEqual(NEW_FIELDS.ruleStats);
    expect(listed.scans[0]?.result.standardsCoverage).toEqual(NEW_FIELDS.standardsCoverage);
  });

  it("still reads a file written by 1.0, and compares it with a new result", async () => {
    const repoDir = path.join(dir, "repos", String(REPO_ID));
    await mkdir(repoDir, { recursive: true, mode: 0o700 });
    const old = { ...makeResult("old"), schemaVersion: "1.0" };
    await writeFile(
      path.join(repoDir, `${Date.UTC(2026, 9, 25)}-aaaaaaaaaaaaaaaa.json`),
      JSON.stringify(old),
      { mode: 0o600 },
    );
    const saved = await store.save(makeResult("new", NEW_FIELDS), { repositoryId: REPO_ID });
    expect(saved.ok).toBe(true);
    const listed = await store.list(REPO_ID);
    expect(listed.warnings).toEqual([]);
    expect(listed.scans).toHaveLength(2);
    const previous = listed.scans.find((scan) => scan.result.scanId === "old");
    const current = listed.scans.find((scan) => scan.result.scanId === "new");
    expect(previous?.sourceVersion).toBe("1.0");
    expect(previous?.result.ruleStats).toBeUndefined();
    // Compare (#217) works across the two shapes in both directions.
    expect(compareScans(previous!.result, current!.result).unchanged).toEqual([]);
    expect(compareScans(current!.result, previous!.result).new).toEqual([]);
  });
});
