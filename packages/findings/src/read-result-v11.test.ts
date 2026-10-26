import { describe, expect, it } from "vitest";
import { SCHEMA_VERSION, type ScanResult } from "./contract.js";
import { readScanResult } from "./read-result.js";

/** Schema 1.1 added `finding.suppression`, `finding.inBaseline`, `suppressions` and `baseline`. */

function sample(): ScanResult {
  return {
    schemaVersion: SCHEMA_VERSION,
    scanId: "scan-1",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:01.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "octo/app", revision: null, webOrigin: null },
    authorization: {
      decision: "allowed",
      checks: [{ id: "repository", status: "passed", reason: "ok" }],
    },
    coverage: [],
    findings: [
      {
        id: "f1",
        ruleId: "PG-SQL-001",
        title: "t",
        category: "injection",
        severity: "high",
        status: "suspected",
        confidence: "medium",
        location: { kind: "file", path: "src/db.ts", line: 3, url: null, commit: null },
        evidence: "e",
        impact: "i",
        recommendation: "r",
        references: { cwe: [], owasp: [], cve: [] },
        sources: ["code"],
      },
    ],
    advisoryDb: { version: null, updatedAt: null },
  };
}

type Loose = Record<string, any>;

const SUMMARY = {
  source: "pgard.config.json",
  suppressed: 1,
  critical: 0,
  bySeverity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
  incomplete: false,
  entries: [
    {
      ruleId: "PG-SQL-001",
      path: "src/**",
      reason: "why",
      expires: "2027-01-31",
      state: "active",
      matched: 1,
      wildcard: false,
      farExpiry: false,
    },
  ],
};
const BASELINE = {
  setAt: "2026-10-20T08:00:00.000Z",
  scanId: "base",
  revision: null,
  total: 2,
  matched: 1,
  new: 0,
  newInUncertainAreas: 0,
  toolVersionChanged: false,
};

function withFields(): Loose {
  const input = JSON.parse(JSON.stringify(sample())) as Loose;
  input.findings[0].suppression = {
    reason: "why",
    expires: "2027-01-31",
    source: "pgard.config.json",
  };
  input.findings[0].inBaseline = true;
  input.suppressions = JSON.parse(JSON.stringify(SUMMARY));
  input.baseline = JSON.parse(JSON.stringify(BASELINE));
  return input;
}

describe("suppression and baseline fields (schema 1.1)", () => {
  it("round-trips through the reader and JSON", () => {
    const input = withFields();
    const outcome = readScanResult(JSON.parse(JSON.stringify(input)));
    expect(outcome.ok && outcome.result.findings[0]?.suppression).toEqual(
      input.findings[0].suppression,
    );
    expect(outcome.ok && outcome.result.findings[0]?.inBaseline).toBe(true);
    expect(outcome.ok && outcome.result.suppressions).toEqual(SUMMARY);
    expect(outcome.ok && outcome.result.baseline).toEqual(BASELINE);
    expect(outcome.ok && outcome.sourceVersion).toBe(SCHEMA_VERSION);
  });

  it("reads an older 1.0 result without the fields, and leaves them absent", () => {
    const input = JSON.parse(JSON.stringify(sample())) as Loose;
    input.schemaVersion = "1.0";
    const outcome = readScanResult(input);
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.sourceVersion).toBe("1.0");
      expect("suppressions" in outcome.result).toBe(false);
      expect("baseline" in outcome.result).toBe(false);
      expect("suppression" in (outcome.result.findings[0] ?? {})).toBe(false);
      expect("inBaseline" in (outcome.result.findings[0] ?? {})).toBe(false);
    }
  });

  it.each<[string, (input: Loose) => void]>([
    ["an unknown suppression source", (i) => (i.findings[0].suppression.source = "elsewhere")],
    ["a suppression without a reason", (i) => delete i.findings[0].suppression.reason],
    ["inBaseline false", (i) => (i.findings[0].inBaseline = false)],
    ["a negative count", (i) => (i.suppressions.suppressed = -1)],
    ["a fractional count", (i) => (i.baseline.matched = 1.5)],
    ["an unknown entry state", (i) => (i.suppressions.entries[0].state = "gone")],
    ["a non-boolean wildcard", (i) => (i.suppressions.entries[0].wildcard = "yes")],
    ["a baseline without a date", (i) => delete i.baseline.setAt],
    ["a null suppression", (i) => (i.findings[0].suppression = null)],
  ])("refuses %s", (_name, mutate) => {
    const input = withFields();
    mutate(input);
    const outcome = readScanResult(input);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.error.code).toBe("invalid_shape");
  });

  it("drops unknown fields inside the new objects", () => {
    const input = withFields();
    input.findings[0].suppression.extra = "x";
    input.suppressions.extra = "x";
    input.baseline.extra = "x";
    const outcome = readScanResult(input);
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect("extra" in (outcome.result.findings[0]?.suppression ?? {})).toBe(false);
      expect("extra" in (outcome.result.suppressions ?? {})).toBe(false);
      expect("extra" in (outcome.result.baseline ?? {})).toBe(false);
    }
  });
});
