import { SCHEMA_VERSION, type Finding } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { countFindingStates, isFutureDated, isNewerSchemaMinor } from "./trend-rules.js";

const base = {
  id: "f",
  ruleId: "PG-SQL-001",
  title: "t",
  category: "injection",
  severity: "high",
  status: "suspected",
  confidence: "medium",
  location: { kind: "file", path: "a.ts", line: 1, url: null, commit: null },
  evidence: "e",
  impact: "i",
  recommendation: "r",
  references: { cwe: [], owasp: [], cve: [] },
  sources: ["code"],
} as unknown as Finding;

describe("history rules", () => {
  it("splits active, ignored and baselined findings", () => {
    const counts = countFindingStates([
      base,
      { ...base, severity: "low" },
      { ...base, suppression: { reason: "x", source: "pgard.config.json" } },
      { ...base, inBaseline: true },
    ]);
    expect(counts).toMatchObject({ total: 2, ignored: 1, baselined: 1 });
    expect(counts.severity).toEqual({ critical: 0, high: 1, medium: 0, low: 1, info: 0 });
  });

  it("recognises a newer schema minor and a future date (strictly after now)", () => {
    expect(isNewerSchemaMinor(SCHEMA_VERSION)).toBe(false);
    expect(isNewerSchemaMinor("99.0")).toBe(true);
    expect(isFutureDated(100, 100)).toBe(false);
    expect(isFutureDated(101, 100)).toBe(true);
  });
});
