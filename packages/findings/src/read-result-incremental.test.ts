import { describe, expect, it } from "vitest";
import { SCHEMA_VERSION, type IncrementalInfo, type ScanResult } from "./contract.js";
import { readIncrementalState, INCREMENTAL_STATE_FORMAT } from "./incremental-state.js";
import { readScanResult } from "./read-result.js";

const CHECKS = (
  ["repository", "github_identity", "owner_approval", "current_access", "contribution"] as const
).map((id) => ({ id, status: "passed" as const, reason: "ok" }));

const INFO: IncrementalInfo = {
  used: true,
  reason: null,
  basedOn: { scanId: "abc", revision: null },
  filesRescanned: 1,
  filesReused: 9,
  commitsScanned: 3,
  commitsReused: 40,
  code: { mode: "incremental", reason: null },
  history: { mode: "full", reason: "history_changed" },
};

function result(version: string, incremental?: unknown): unknown {
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
    findings: [],
    advisoryDb: { version: null, updatedAt: null },
    ...(incremental === undefined ? {} : { incremental }),
  };
}

describe("schema 1.2 incremental field", () => {
  it("is the current schema version", () => {
    expect(SCHEMA_VERSION).toBe("1.6");
  });

  it("reads results of 1.0 and 1.1 without it", () => {
    for (const version of ["1.0", "1.1"]) {
      const read = readScanResult(result(version));
      expect(read.ok).toBe(true);
      if (read.ok) {
        expect(read.sourceVersion).toBe(version);
        expect((read.result as ScanResult).incremental).toBeUndefined();
      }
    }
  });

  it("round-trips the field", () => {
    const read = readScanResult(JSON.parse(JSON.stringify(result("1.2", INFO))));
    expect(read.ok && read.result.incremental).toEqual(INFO);
  });

  it("refuses a field that is malformed", () => {
    for (const bad of [
      { ...INFO, used: "yes" },
      { ...INFO, reason: "because" },
      { ...INFO, filesReused: -1 },
      { ...INFO, basedOn: { scanId: 1 } },
      { ...INFO, code: { mode: "sometimes", reason: null } },
      "incremental",
    ]) {
      expect(readScanResult(result("1.2", bad)).ok).toBe(false);
    }
  });
});

describe("incremental state reader", () => {
  const state = {
    format: INCREMENTAL_STATE_FORMAT,
    analysisKey: "k",
    analyzerHash: "h",
    configHash: null,
    code: [
      {
        path: "a.ts",
        language: "typescript",
        hash: "h",
        findings: [],
        facts: null,
        goImports: [],
        hasJsx: false,
        hasParseErrors: false,
        capped: false,
      },
    ],
  };

  it("accepts a state it wrote", () => {
    expect(readIncrementalState(JSON.parse(JSON.stringify(state)))).toEqual(state);
  });

  it("rejects anything else without throwing", () => {
    for (const bad of [
      null,
      "x",
      [],
      { ...state, format: 2 },
      { ...state, analysisKey: 1 },
      { ...state, code: "no" },
      { ...state, code: [{ ...state.code[0], language: "cobol" }] },
      { ...state, code: [{ ...state.code[0], findings: [{ id: 1 }] }] },
      { ...state, code: [{ ...state.code[0], goImports: [1] }] },
      { ...state, code: [{ ...state.code[0], facts: [] }] },
    ]) {
      expect(readIncrementalState(bad)).toBeNull();
    }
  });
});
