import { describe, expect, it } from "vitest";
import { findingIdentity } from "./compare-scans.js";
import type { Finding } from "./contract.js";
import { createFindingFingerprint } from "./fingerprint.js";
import { readScanResult } from "./read-result.js";
import { buildRuleTextCatalog } from "./rule-text.js";
import { buildSarif } from "./sarif.js";

const CHECKS = (
  ["repository", "github_identity", "owner_approval", "current_access", "contribution"] as const
).map((id) => ({ id, status: "passed" as const, reason: "ok" }));

const dependency = {
  ecosystem: "npm",
  name: "lodash",
  version: "4.17.11",
  advisoryId: "GHSA-aaaa-bbbb-cccc",
  aliases: ["CVE-2021-0001"],
  affectedRange: "<4.17.21",
  fixedVersions: ["4.17.21"],
  severitySource: "cvss",
  score: 7.5,
  vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
};

const finding = (extra: Record<string, unknown>) => ({
  id: "f1",
  ruleId: "PG-DEP-001",
  title: "t",
  category: "misconfiguration",
  severity: "high",
  status: "suspected",
  confidence: "medium",
  location: { kind: "file", path: "package-lock.json", line: null, url: null, commit: null },
  evidence: "e",
  impact: "i",
  recommendation: "r",
  references: { cwe: ["CWE-1395"], owasp: ["A03:2025"], cve: ["CVE-2021-0001"] },
  sources: ["code"],
  ...extra,
});

function result(version: string, extra: Record<string, unknown>): unknown {
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
    findings: [finding(extra)],
    advisoryDb: { version: null, updatedAt: null },
  };
}

describe("schema 1.5 finding.dependency", () => {
  it("is kept when valid", () => {
    const read = readScanResult(result("1.5", { dependency }));
    expect(read.ok && read.result.findings[0]?.dependency).toEqual(dependency);
  });

  it("is absent in results of 1.4 and older, which stay readable", () => {
    const read = readScanResult(result("1.4", {}));
    expect(read.ok).toBe(true);
    expect(read.ok && "dependency" in (read.result.findings[0] ?? {})).toBe(false);
  });

  it("rejects malformed values", () => {
    const bad: Record<string, unknown>[] = [
      { ...dependency, severitySource: "guess" },
      { ...dependency, aliases: "CVE-1" },
      { ...dependency, score: 11 },
      { ...dependency, dev: "yes" },
      { ...dependency, name: undefined },
    ];
    for (const value of bad) {
      expect(readScanResult(result("1.5", { dependency: value })).ok).toBe(false);
    }
    expect(readScanResult(result("1.5", { dependency: "x" })).ok).toBe(false);
  });

  it("renders in SARIF at the lockfile without a region", () => {
    const read = readScanResult(result("1.5", { dependency }));
    if (!read.ok) throw new Error("unreadable");
    const sarif = JSON.stringify(buildSarif(read.result, buildRuleTextCatalog([])));
    expect(sarif).toContain("package-lock.json");
    expect(sarif).not.toContain("startLine");
  });
});

describe("dependency fingerprints", () => {
  const location = {
    kind: "file" as const,
    path: "package-lock.json",
    line: null,
    url: null,
    commit: null,
  };
  const id = (cause: string) => createFindingFingerprint({ ruleId: "PG-DEP-001", location, cause });

  it("is stable and differs per package version and advisory", () => {
    expect(id("npm:lodash@4.17.11:GHSA-a")).toBe(id("npm:lodash@4.17.11:GHSA-a"));
    expect(id("npm:lodash@4.17.11:GHSA-a")).not.toBe(id("npm:lodash@4.17.12:GHSA-a"));
    expect(id("npm:lodash@4.17.11:GHSA-a")).not.toBe(id("npm:lodash@4.17.11:GHSA-b"));
  });
});

describe("dependency finding identity (baseline and compare)", () => {
  const base = finding({ dependency }) as unknown as Finding;
  it("ignores evidence, range, fixed versions and severity, which follow the advisory data", () => {
    const later = {
      ...base,
      evidence: "different text after a data update",
      severity: "critical",
      dependency: {
        ...dependency,
        affectedRange: "<4.17.30",
        fixedVersions: ["4.17.30"],
        score: 9.1,
      },
    } as Finding;
    expect(findingIdentity(later)).toBe(findingIdentity(base));
  });

  it("differs for another version or another advisory", () => {
    const otherVersion = { ...base, dependency: { ...dependency, version: "4.17.12" } } as Finding;
    const otherAdvisory = {
      ...base,
      dependency: { ...dependency, advisoryId: "GHSA-x" },
    } as Finding;
    expect(findingIdentity(otherVersion)).not.toBe(findingIdentity(base));
    expect(findingIdentity(otherAdvisory)).not.toBe(findingIdentity(base));
  });
});
