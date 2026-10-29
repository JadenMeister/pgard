import { describe, expect, it } from "vitest";
import { applyBaseline } from "./baseline.js";
import { compareScans, findingIdentity } from "./compare-scans.js";
import type { Finding, ScanResult } from "./contract.js";
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

describe("dependency findings in compare and baseline", () => {
  const make = (
    advisoryId: string,
    aliases: string[],
    extra: Partial<Finding["dependency"] & object> = {},
  ) =>
    ({
      ...(finding({}) as unknown as Finding),
      id: `id-${advisoryId}`,
      evidence: `evidence of ${advisoryId}`,
      dependency: { ...dependency, advisoryId, aliases, ...extra },
    }) as Finding;
  const scan = (findings: Finding[]): ScanResult =>
    ({
      ...(result("1.5", {}) as ScanResult),
      coverage: [
        {
          area: "deps:npm",
          scope: "code",
          status: "completed",
          ruleIds: ["PG-DEP-001"],
          note: null,
        },
      ],
      findings,
    }) as ScanResult;

  it("pairs a finding whose primary id changed because a GHSA alias was added to a GO record", () => {
    const comparison = compareScans(
      scan([make("GO-2026-0001", [])]),
      scan([make("GHSA-aaaa-bbbb-cccc", ["GO-2026-0001"])]),
    );
    expect(comparison.new).toEqual([]);
    expect(comparison.noLongerReported).toEqual([]);
    expect(comparison.unchanged).toHaveLength(1);
  });

  it("pairs a finding when a CVE alias is added to its GHSA record", () => {
    const comparison = compareScans(
      scan([make("GHSA-aaaa-bbbb-cccc", [])]),
      scan([make("GHSA-aaaa-bbbb-cccc", ["CVE-2021-0001"])]),
    );
    expect(comparison.new).toEqual([]);
    expect(comparison.unchanged).toHaveLength(1);
  });

  it("does not merge two unrelated advisories on the same package version", () => {
    const comparison = compareScans(
      scan([make("GHSA-1111-1111-1111", ["CVE-1"]), make("GHSA-2222-2222-2222", ["CVE-2"])]),
      scan([make("GHSA-1111-1111-1111", ["CVE-1"]), make("GHSA-3333-3333-3333", ["CVE-3"])]),
    );
    expect(comparison.unchanged).toHaveLength(1);
    expect(comparison.new.map((f) => f.dependency?.advisoryId)).toEqual(["GHSA-3333-3333-3333"]);
    expect(comparison.noLongerReported.map((f) => f.dependency?.advisoryId)).toEqual([
      "GHSA-2222-2222-2222",
    ]);
  });

  it("keeps a baselined finding in the baseline after such a change", () => {
    const baseline = scan([make("GO-2026-0001", [])]);
    const applied = applyBaseline(
      scan([make("GHSA-aaaa-bbbb-cccc", ["GO-2026-0001"])]),
      baseline,
      new Date("2026-10-24T00:00:00.000Z"),
    );
    expect(applied.result.findings[0]?.inBaseline).toBe(true);
  });

  it("does not pair the same advisory on another version or another lockfile", () => {
    const comparison = compareScans(
      scan([make("GHSA-aaaa-bbbb-cccc", [])]),
      scan([make("GHSA-aaaa-bbbb-cccc", [], { version: "4.17.12" })]),
    );
    expect(comparison.unchanged).toEqual([]);
    expect(comparison.new).toHaveLength(1);
  });
});
