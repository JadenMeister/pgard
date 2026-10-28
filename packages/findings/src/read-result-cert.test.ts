import { describe, expect, it } from "vitest";
import { readScanResult } from "./read-result.js";

const CHECKS = (
  ["repository", "github_identity", "owner_approval", "current_access", "contribution"] as const
).map((id) => ({ id, status: "passed" as const, reason: "ok" }));

const finding = (references: Record<string, unknown>) => ({
  id: "f1",
  ruleId: "PG-CMD-003",
  title: "t",
  category: "command_execution",
  severity: "high",
  status: "suspected",
  confidence: "medium",
  location: { kind: "file", path: "A.java", line: 1, url: null, commit: null },
  evidence: "e",
  impact: "i",
  recommendation: "r",
  references,
  sources: ["code"],
});

function result(version: string, references: Record<string, unknown>): unknown {
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
    coverage: [],
    findings: [finding(references)],
    advisoryDb: { version: null, updatedAt: null },
  };
}

describe("schema 1.4 finding references.cert", () => {
  it("is kept when valid", () => {
    const read = readScanResult(
      result("1.4", { cwe: ["CWE-78"], owasp: [], cve: [], cert: ["IDS07-J"] }),
    );
    expect(read.ok && read.result.findings[0]?.references.cert).toEqual(["IDS07-J"]);
  });

  it("is absent in results of 1.3 and older, which stay readable", () => {
    const read = readScanResult(result("1.3", { cwe: ["CWE-78"], owasp: [], cve: [] }));
    expect(read.ok).toBe(true);
    expect(read.ok && "cert" in (read.result.findings[0]?.references ?? {})).toBe(false);
  });

  it("rejects a malformed value", () => {
    for (const bad of ["IDS07-J", [1], [{}], null]) {
      const read = readScanResult(result("1.4", { cwe: [], owasp: [], cve: [], cert: bad }));
      expect(read.ok, JSON.stringify(bad)).toBe(false);
    }
  });
});
