import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { SCHEMA_VERSION, type ScanResult } from "./contract.js";
import { readScanResult, READ_LIMITS } from "./read-result.js";

const OLD = JSON.parse(
  readFileSync(new URL("./fixtures/result-1.0.json", import.meta.url), "utf8"),
) as Record<string, any>;

const withNewFields = (): Record<string, any> => ({
  ...structuredClone(OLD),
  schemaVersion: SCHEMA_VERSION,
  ruleStats: [
    {
      ruleId: "PG-SQL-001",
      area: "source:typescript",
      scope: "code",
      status: "completed",
      targets: [{ unit: "files", examined: 2, reason: null }],
      findings: 1,
    },
    {
      ruleId: "PG-SECRET-003",
      area: "history:commits",
      scope: "history",
      status: "completed",
      targets: [
        { unit: "commits", examined: 3, reason: null },
        { unit: "blobs", examined: null, reason: "not measured" },
      ],
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
    cweTop25: [
      {
        id: "CWE-89",
        title: "SQL Injection",
        rank: 2,
        state: "rules_partial",
        breadth: null,
        ruleIds: [],
        mappedRuleIds: [],
        reason: "x",
      },
    ],
  },
});

describe("result schema 1.1: ruleStats and standardsCoverage", () => {
  it("still reads a stored 1.0 result, without inventing the new fields", () => {
    const outcome = readScanResult(structuredClone(OLD));
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.sourceVersion).toBe("1.0");
    expect(outcome.result.schemaVersion).toBe(SCHEMA_VERSION);
    expect(outcome.result.findings).toHaveLength(1);
    expect("ruleStats" in outcome.result).toBe(false);
    expect("standardsCoverage" in outcome.result).toBe(false);
  });

  it("round-trips a 1.1 result, also through JSON", () => {
    const input = withNewFields();
    const outcome = readScanResult(input);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.result).toEqual(input);
    const again = readScanResult(JSON.parse(JSON.stringify(outcome.result)));
    expect(again).toEqual({ ok: true, result: input, sourceVersion: SCHEMA_VERSION });
  });

  it("keeps the new fields when a newer minor carries unknown extras, and drops the extras", () => {
    const input = withNewFields();
    input.schemaVersion = "1.9";
    input.ruleStats[0].future = 1;
    input.standardsCoverage.future = { a: 1 };
    input.standardsCoverage.owasp[0].future = 1;
    const outcome = readScanResult(input);
    expect(outcome.ok && outcome.result.ruleStats?.[0]).not.toHaveProperty("future");
    expect(outcome.ok && outcome.result.standardsCoverage).not.toHaveProperty("future");
    expect(outcome.ok && outcome.result.standardsCoverage?.owasp[0]).not.toHaveProperty("future");
    expect(outcome.ok && outcome.result.standardsCoverage?.owasp).toHaveLength(1);
  });

  const mutations: Array<[string, (r: Record<string, any>) => void]> = [
    ["ruleStats not an array", (r) => (r.ruleStats = {})],
    ["rule stat without ruleId", (r) => delete r.ruleStats[0].ruleId],
    ["rule stat with unknown status", (r) => (r.ruleStats[0].status = "done")],
    ["rule stat with unknown scope", (r) => (r.ruleStats[0].scope = "net")],
    ["negative findings count", (r) => (r.ruleStats[0].findings = -1)],
    ["fractional findings count", (r) => (r.ruleStats[0].findings = 1.5)],
    ["string findings count", (r) => (r.ruleStats[0].findings = "1")],
    ["targets not an array", (r) => (r.ruleStats[0].targets = null)],
    ["negative examined", (r) => (r.ruleStats[0].targets[0].examined = -3)],
    ["examined as string", (r) => (r.ruleStats[0].targets[0].examined = "3")],
    [
      "unknown count without a reason",
      (r) => (r.ruleStats[1].targets[1] = { unit: "blobs", examined: null, reason: null }),
    ],
    [
      "count and reason together",
      (r) => (r.ruleStats[0].targets[0] = { unit: "files", examined: 2, reason: "because" }),
    ],
    ["old state name", (r) => (r.standardsCoverage.owasp[0].state = "checked")],
    ["breadth not an object", (r) => (r.standardsCoverage.owasp[0].breadth = 3)],
    ["negative breadth", (r) => (r.standardsCoverage.owasp[0].breadth.cwesWithRules = -1)],
    ["missing breadth", (r) => delete r.standardsCoverage.owasp[0].breadth],
    ["standardsCoverage not an object", (r) => (r.standardsCoverage = [])],
    ["missing owasp list", (r) => delete r.standardsCoverage.owasp],
    ["unknown state", (r) => (r.standardsCoverage.owasp[0].state = "checked_ok")],
    ["missing reason", (r) => delete r.standardsCoverage.owasp[0].reason],
    ["rank as string", (r) => (r.standardsCoverage.cweTop25[0].rank = "2")],
    ["ruleIds not strings", (r) => (r.standardsCoverage.owasp[0].ruleIds = [1])],
  ];
  it.each(mutations)("refuses %s", (_name, mutate) => {
    const input = withNewFields();
    mutate(input);
    const outcome = readScanResult(input);
    expect(outcome.ok).toBe(false);
    expect(!outcome.ok && outcome.error.code).toBe("invalid_shape");
  });

  it("refuses an oversized ruleStats list", () => {
    const input = withNewFields();
    input.ruleStats = Array.from({ length: READ_LIMITS.ruleStats + 1 }, () => input.ruleStats[0]);
    const outcome = readScanResult(input);
    expect(!outcome.ok && outcome.error.code).toBe("too_large");
  });

  it("typed result accepts both shapes", () => {
    const old = readScanResult(structuredClone(OLD));
    const next = readScanResult(withNewFields());
    const results: ScanResult[] = [old, next].flatMap((o) => (o.ok ? [o.result] : []));
    expect(results).toHaveLength(2);
  });
});
