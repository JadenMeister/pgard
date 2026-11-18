import { describe, expect, it } from "vitest";
import { compareScans } from "./compare-scans.js";
import { SCHEMA_VERSION, type Coverage, type Finding, type ScanResult } from "./contract.js";

const COVERAGE: Coverage[] = [
  { area: "deps:npm", scope: "code", status: "completed", ruleIds: ["PG-DEP-001"], note: null },
];

const dep = (
  advisoryId: string,
  aliases: string[],
  pkg: { name?: string; version?: string } = {},
): Finding => ({
  id: advisoryId,
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
  references: { cwe: [], owasp: [], cve: [] },
  sources: ["code"],
  dependency: {
    ecosystem: "npm",
    name: pkg.name ?? "lodash",
    version: pkg.version ?? "4.17.0",
    advisoryId,
    aliases,
    affectedRange: "<4.17.21",
    fixedVersions: ["4.17.21"],
    severitySource: "database",
  },
});

function scan(findings: Finding[]): ScanResult {
  return {
    schemaVersion: SCHEMA_VERSION,
    scanId: "s",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "o/n", revision: null, webOrigin: null },
    authorization: { decision: "allowed", checks: [] },
    coverage: COVERAGE,
    findings,
    advisoryDb: { version: null, updatedAt: null },
  };
}

const compare = (before: Finding[], after: Finding[]) => compareScans(scan(before), scan(after));
const ids = (findings: Finding[]) => findings.map((f) => f.dependency?.advisoryId).sort();

describe("dependency advisories merged by a data update", () => {
  it("is merged, not gone, when a previous advisory became an alias of a current one", () => {
    const result = compare(
      [dep("GHSA-x", ["CVE-1"]), dep("GHSA-y", [])],
      [dep("GHSA-x", ["CVE-1", "GHSA-y"])],
    );
    expect(result.noLongerReported).toEqual([]);
    expect(result.notComparable).toEqual([]);
    expect(result.new).toEqual([]);
    expect(result.unchanged).toHaveLength(1);
    expect(result.moved).toHaveLength(0);
  });

  it("keeps one-to-one pairing: the merged advisory is not paired a second time", () => {
    const result = compare([dep("GHSA-y", []), dep("GHSA-x", [])], [dep("GHSA-x", ["GHSA-y"])]);
    const pairs = [...result.unchanged, ...result.moved];
    expect(pairs).toHaveLength(1);
    expect(pairs[0]?.previous.dependency?.advisoryId).toBe("GHSA-x");
    expect(result.noLongerReported).toEqual([]);
  });

  it("still says gone when no current finding carries the previous id", () => {
    const result = compare([dep("GHSA-y", [])], [dep("GHSA-z", ["GHSA-w"])]);
    expect(ids(result.noLongerReported)).toEqual(["GHSA-y"]);
    expect(ids(result.new)).toEqual(["GHSA-z"]);
  });

  it("stays gone when the package or the version is not the same any more", () => {
    const before = [dep("GHSA-x", ["CVE-1"]), dep("GHSA-y", [])];
    const merged = ["CVE-1", "GHSA-y"];
    const otherVersion = compare(before, [dep("GHSA-x", merged, { version: "4.17.21" })]);
    expect(ids(otherVersion.noLongerReported)).toEqual(["GHSA-x", "GHSA-y"]);
    const otherPackage = compare(before, [dep("GHSA-x", merged, { name: "other" })]);
    expect(ids(otherPackage.noLongerReported)).toEqual(["GHSA-x", "GHSA-y"]);
    const single = compare([dep("GHSA-y", [])], [dep("GHSA-x", ["GHSA-y"], { version: "9.9.9" })]);
    expect(ids(single.noLongerReported)).toEqual(["GHSA-y"]);
  });

  it("does not treat a partly overlapping id set as merged", () => {
    const result = compare(
      [dep("GHSA-x", []), dep("GHSA-y", ["GHSA-q"])],
      [dep("GHSA-x", ["GHSA-y"])],
    );
    expect(ids(result.noLongerReported)).toEqual(["GHSA-y"]);
  });

  it("gives the same answer whatever order the findings arrive in", () => {
    const after = [dep("GHSA-x", ["CVE-1", "GHSA-y"])];
    for (const before of [
      [dep("GHSA-y", []), dep("GHSA-x", ["CVE-1"])],
      [dep("GHSA-x", ["CVE-1"]), dep("GHSA-y", [])],
    ]) {
      const result = compare(before, after);
      expect(result.noLongerReported).toEqual([]);
      expect(result.unchanged).toHaveLength(1);
    }
  });
});
