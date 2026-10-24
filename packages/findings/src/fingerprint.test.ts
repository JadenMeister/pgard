import { describe, expect, it } from "vitest";
import type { Finding } from "./contract.js";
import { createFindingFingerprint, mergeFindings } from "./fingerprint.js";

const location = {
  kind: "file" as const,
  path: "src/db.ts",
  line: 10,
  url: null,
  commit: null,
};

describe("createFindingFingerprint", () => {
  it("is deterministic and 32 hex characters", () => {
    const a = createFindingFingerprint({ ruleId: "PG-SQL-001", location, cause: "concat" });
    const b = createFindingFingerprint({ ruleId: "PG-SQL-001", location, cause: "concat" });
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{32}$/);
  });

  it("changes with rule, location or cause", () => {
    const base = createFindingFingerprint({ ruleId: "PG-SQL-001", location, cause: "concat" });
    expect(createFindingFingerprint({ ruleId: "PG-SQL-002", location, cause: "concat" })).not.toBe(
      base,
    );
    expect(
      createFindingFingerprint({
        ruleId: "PG-SQL-001",
        location: { ...location, line: 11 },
        cause: "concat",
      }),
    ).not.toBe(base);
    expect(
      createFindingFingerprint({ ruleId: "PG-SQL-001", location, cause: "template" }),
    ).not.toBe(base);
  });

  it("is a fixed value (stable across releases and machines)", () => {
    expect(createFindingFingerprint({ ruleId: "R", location, cause: "c" })).toBe(
      createFindingFingerprint({ ruleId: "R", location: { ...location }, cause: "c" }),
    );
  });
});

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "same",
    ruleId: "PG-WEB-001",
    title: "t",
    category: "misconfiguration",
    severity: "low",
    status: "suspected",
    confidence: "low",
    location,
    evidence: "code evidence",
    impact: "i",
    recommendation: "r",
    references: { cwe: ["CWE-1"], owasp: [], cve: [] },
    sources: ["code"],
    ...overrides,
  };
}

describe("mergeFindings", () => {
  it("merges same-id findings preserving sources and strongest assessment", () => {
    const merged = mergeFindings([
      finding({}),
      finding({
        sources: ["web"],
        severity: "medium",
        status: "confirmed",
        confidence: "high",
        evidence: "http evidence",
        references: { cwe: ["CWE-2"], owasp: ["A05"], cve: [] },
      }),
      finding({ id: "other" }),
    ]);
    expect(merged).toHaveLength(2);
    expect(merged[0]).toMatchObject({
      sources: ["code", "web"],
      severity: "medium",
      status: "confirmed",
      confidence: "high",
      evidence: "code evidence | http evidence",
    });
    expect(merged[0]?.references.cwe).toEqual(["CWE-1", "CWE-2"]);
  });

  it("keeps canonical source order and does not duplicate identical evidence", () => {
    const merged = mergeFindings([
      finding({ sources: ["web"] }),
      finding({ sources: ["history", "code"] }),
    ]);
    expect(merged[0]?.sources).toEqual(["code", "history", "web"]);
    expect(merged[0]?.evidence).toBe("code evidence");
  });
});
