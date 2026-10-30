import { describe, expect, it } from "vitest";
import type { ScanResult } from "./contract.js";
import { buildSarif } from "./sarif.js";

const base = (incremental?: ScanResult["incremental"]): ScanResult => ({
  schemaVersion: "1.7",
  scanId: "s",
  startedAt: "2026-10-24T00:00:00.000Z",
  finishedAt: "2026-10-24T00:00:05.000Z",
  tool: { name: "pgard", version: "0.1.0" },
  requestedScopes: ["code"],
  overallStatus: "completed",
  target: { repo: "o/n", revision: "abc", webOrigin: null },
  authorization: { decision: "allowed", checks: [] },
  coverage: [],
  findings: [],
  advisoryDb: { version: null, updatedAt: null },
  ...(incremental === undefined ? {} : { incremental }),
});

const pgard = (result: ScanResult): Record<string, unknown> => {
  const run = buildSarif(result, new Map()).runs[0] as { properties: { pgard: unknown } };
  return run.properties.pgard as Record<string, unknown>;
};

describe("SARIF incremental provenance", () => {
  it("summarizes how the scan was made under run.properties.pgard.incremental", () => {
    const properties = pgard(
      base({
        used: true,
        reason: null,
        basedOn: { scanId: "earlier", revision: "abc" },
        filesRescanned: 1,
        filesReused: 9,
        commitsScanned: 2,
        commitsReused: 5,
        code: { mode: "incremental", reason: null },
        history: { mode: "incremental", reason: null },
      }),
    );
    expect(properties.incremental).toEqual({
      used: true,
      reason: null,
      basedOnScanId: "earlier",
      filesRescanned: 1,
      filesReused: 9,
      commitsScanned: 2,
      commitsReused: 5,
    });
  });

  it("leaves it out for a result without the field", () => {
    expect(pgard(base())).not.toHaveProperty("incremental");
  });
});
