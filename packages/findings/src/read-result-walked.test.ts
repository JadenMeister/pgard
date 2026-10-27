import { describe, expect, it } from "vitest";
import { readScanResult } from "./read-result.js";

const CHECKS = (
  ["repository", "github_identity", "owner_approval", "current_access", "contribution"] as const
).map((id) => ({ id, status: "passed" as const, reason: "ok" }));

function result(version: string, coverage: unknown[]): unknown {
  return {
    schemaVersion: version,
    scanId: "s",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "o/n", revision: "abc", webOrigin: null },
    authorization: { decision: "allowed", checks: CHECKS },
    coverage,
    findings: [],
    advisoryDb: { version: null, updatedAt: null },
  };
}

const entry = (extra: Record<string, unknown> = {}) => ({
  area: "source:build-output",
  scope: "code",
  status: "completed",
  ruleIds: [],
  note: "n",
  ...extra,
});

describe("schema 1.3 coverage.walkedDirectories", () => {
  it("is kept when valid", () => {
    const walked = { paths: ["build", "scripts/build"], complete: true };
    const read = readScanResult(result("1.3", [entry({ walkedDirectories: walked })]));
    expect(read.ok && read.result.coverage[0]?.walkedDirectories).toEqual(walked);
  });

  it("is absent in results of 1.2 and older, which stay readable", () => {
    const read = readScanResult(result("1.2", [entry()]));
    expect(read.ok).toBe(true);
    expect(read.ok && "walkedDirectories" in (read.result.coverage[0] ?? {})).toBe(false);
  });

  it("rejects a malformed value", () => {
    for (const bad of [
      "build",
      { paths: "build", complete: true },
      { paths: [1], complete: true },
      { paths: [], complete: "yes" },
      { paths: [] },
    ]) {
      expect(readScanResult(result("1.3", [entry({ walkedDirectories: bad })])).ok).toBe(false);
    }
  });
});
