import { describe, expect, it } from "vitest";
import {
  applyBaseline,
  baselineSnapshot,
  baselineNotices,
  formatBaselineCounts,
  partitionFindings,
  stripBaselineMarks,
} from "./baseline.js";
import { compareScans } from "./compare-scans.js";
import type { Coverage, Finding, ScanResult } from "./contract.js";
import { readScanResult } from "./read-result.js";

function finding(overrides: Partial<Finding> & { line?: number; path?: string } = {}): Finding {
  const { line = 3, path = "src/db.ts", ...rest } = overrides;
  return {
    id: `${rest.ruleId ?? "PG-SQL-001"}:${path}:${line}`,
    ruleId: "PG-SQL-001",
    title: "t",
    category: "injection",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    location: { kind: "file", path, line, url: null, commit: null },
    evidence: `req.query -> concat -> query() in ${path}`,
    impact: "i",
    recommendation: "r",
    references: { cwe: [], owasp: [], cve: [] },
    sources: ["code"],
    ...rest,
  };
}

const FULL: Coverage[] = [
  {
    area: "source:typescript",
    scope: "code",
    status: "completed",
    ruleIds: ["PG-SQL-001"],
    note: null,
  },
];

function scan(findings: Finding[], overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    schemaVersion: "1.7",
    scanId: "s1",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "o/n", revision: "abc", webOrigin: null },
    authorization: { decision: "allowed", checks: [] },
    coverage: FULL,
    findings,
    advisoryDb: { version: null, updatedAt: null },
    ...overrides,
  };
}

const SET_AT = new Date("2026-10-20T08:00:00Z");

describe("applyBaseline", () => {
  it("marks findings that are in the baseline, also when they moved, and counts the new ones", () => {
    const old = finding({ line: 3 });
    const moved = finding({ line: 40, path: "src/other.ts" });
    const baseline = scan([old, moved], { scanId: "base" });
    const current = scan([
      finding({ line: 9 }),
      finding({ line: 41, path: "src/other.ts" }),
      finding({ line: 5, path: "src/new.ts" }),
    ]);
    const { result, summary } = applyBaseline(current, baseline, SET_AT);
    expect(result.findings.filter((f) => f.inBaseline === true)).toHaveLength(2);
    expect(result.findings.find((f) => f.location.path === "src/new.ts")?.inBaseline).toBe(
      undefined,
    );
    expect(summary).toEqual({
      setAt: "2026-10-20T08:00:00.000Z",
      scanId: "base",
      revision: "abc",
      total: 2,
      matched: 2,
      new: 1,
      newInUncertainAreas: 0,
      toolVersionChanged: false,
    });
    expect(result.baseline).toEqual(summary);
    expect(formatBaselineCounts(summary)).toBe("2 in baseline, 1 new");
  });

  it("uses the identity of the scan comparison: a second copy of a baseline finding is new", () => {
    const baseline = scan([finding({ line: 3 })]);
    const current = scan([finding({ line: 3 }), finding({ line: 30 })]);
    const { result } = applyBaseline(current, baseline, SET_AT);
    const flagged = result.findings.filter((f) => f.inBaseline === true);
    expect(flagged).toHaveLength(1);
    // The same pairing the comparison reports as "unchanged".
    expect(compareScans(baseline, current).unchanged).toHaveLength(1);
    expect(result.findings.filter((f) => f.inBaseline === undefined)).toHaveLength(1);
  });

  it("never removes a finding, nor touches status, coverage or authorization", () => {
    const baseline = scan([finding()]);
    const current = scan([finding(), finding({ line: 99, path: "x.ts" })], {
      overallStatus: "partial",
    });
    const { result } = applyBaseline(current, baseline, SET_AT);
    expect(result.findings).toHaveLength(2);
    expect(result.overallStatus).toBe("partial");
    expect(result.coverage).toEqual(current.coverage);
    expect(result.authorization).toEqual(current.authorization);
    expect(current.findings.every((f) => f.inBaseline === undefined)).toBe(true);
  });

  it("matches a suppressed finding like any other", () => {
    const baseline = scan([finding()]);
    const suppressed = {
      ...finding({ line: 7 }),
      suppression: { reason: "r", source: "pgard.config.json" as const },
    };
    const { result } = applyBaseline(scan([suppressed]), baseline, SET_AT);
    expect(result.findings[0]?.inBaseline).toBe(true);
    expect(result.findings[0]?.suppression).toBeDefined();
  });

  it("flags new findings in areas the baseline did not fully cover", () => {
    const baseline = scan([], {
      coverage: [{ ...(FULL[0] as Coverage), status: "partial", note: "files skipped" }],
    });
    const { summary } = applyBaseline(scan([finding()]), baseline, SET_AT);
    expect(summary.new).toBe(1);
    expect(summary.newInUncertainAreas).toBe(1);
    const kinds = baselineNotices(summary).map((n) => n.kind);
    expect(kinds).toEqual(["uncertain"]);
  });

  it("flags a tool version change", () => {
    const baseline = scan([finding()], { tool: { name: "pgard", version: "0.0.9" } });
    const { summary } = applyBaseline(scan([finding()]), baseline, SET_AT);
    expect(summary.toolVersionChanged).toBe(true);
    expect(baselineNotices(summary).map((n) => n.kind)).toContain("tool");
  });

  it("has no notices without a baseline", () => {
    expect(baselineNotices(undefined)).toEqual([]);
  });

  it("produces a result the reader accepts, with its summary and flags, after a JSON round trip", () => {
    const baseline = scan([finding()]);
    const { result } = applyBaseline(
      scan([finding(), finding({ path: "n.ts" })]),
      baseline,
      SET_AT,
    );
    const read = readScanResult(JSON.parse(JSON.stringify(result)));
    expect(read).toEqual({ ok: true, result, sourceVersion: "1.7" });
  });
});

describe("partitionFindings", () => {
  it("puts every finding in exactly one list, suppressed before baseline", () => {
    const plain = finding({ path: "a.ts" });
    const inBaseline: Finding = { ...finding({ path: "b.ts" }), inBaseline: true };
    const suppressed: Finding = {
      ...finding({ path: "c.ts" }),
      suppression: { reason: "x", source: "pgard.config.json" },
    };
    const both: Finding = { ...suppressed, id: "both", inBaseline: true };
    const {
      rest,
      baseline,
      suppressed: s,
    } = partitionFindings([plain, inBaseline, suppressed, both]);
    expect(rest).toEqual([plain]);
    expect(baseline).toEqual([inBaseline]);
    expect(s).toEqual([suppressed, both]);
  });
});

describe("stripBaselineMarks", () => {
  it("removes the baseline summary and the flags, and keeps everything else", () => {
    const baseline = scan([finding()]);
    const { result } = applyBaseline(scan([finding()]), baseline, SET_AT);
    const stripped = stripBaselineMarks(result);
    expect(stripped.baseline).toBeUndefined();
    expect(stripped.findings[0]?.inBaseline).toBeUndefined();
    expect(stripped.findings[0]?.id).toBe(result.findings[0]?.id);
    expect(Object.keys(stripped)).not.toContain("baseline");
  });
});

describe("suppressed findings and the baseline", () => {
  const suppress = (f: Finding): Finding => ({
    ...f,
    suppression: { reason: "r", source: "pgard.config.json" },
  });

  it("leaves suppressed findings out of the stored baseline", () => {
    const snapshot = baselineSnapshot(scan([finding(), suppress(finding({ path: "x.ts" }))]));
    expect(snapshot.findings).toHaveLength(1);
    expect(snapshot.findings[0]?.suppression).toBeUndefined();
  });

  it("a finding the baseline held only while suppressed comes back as new", () => {
    const baseline = scan([suppress(finding({ line: 3 }))]);
    const { result, summary } = applyBaseline(scan([finding({ line: 3 })]), baseline, SET_AT);
    expect(summary).toMatchObject({ total: 0, matched: 0, new: 1 });
    expect(result.findings[0]?.inBaseline).toBeUndefined();
  });

  it("counts a suppressed finding under the suppressions only, matched or not", () => {
    const baseline = scan([finding({ line: 3 })]);
    const current = scan([
      suppress(finding({ line: 3 })),
      suppress(finding({ line: 3, path: "other.ts" })),
      finding({ line: 3, path: "fresh.ts" }),
    ]);
    const { result, summary } = applyBaseline(current, baseline, SET_AT);
    expect(summary).toMatchObject({ matched: 0, new: 1 });
    // The suppressed one that is also in the baseline keeps both marks.
    expect(result.findings[0]).toMatchObject({ inBaseline: true });
    expect(result.findings[0]?.suppression).toBeDefined();
    const parts = partitionFindings(result.findings);
    expect(parts.suppressed).toHaveLength(2);
    expect(parts.baseline).toHaveLength(0);
    expect(parts.rest).toHaveLength(1);
  });

  it("writes the severity breakdown of the baseline group into the count line", () => {
    const summary = {
      setAt: "x",
      scanId: "s",
      revision: null,
      total: 6,
      matched: 6,
      new: 0,
      newInUncertainAreas: 0,
      toolVersionChanged: false,
    };
    const group = [
      finding({ severity: "critical" }),
      ...Array.from({ length: 5 }, () => finding({ severity: "high" })),
    ];
    expect(formatBaselineCounts(summary, group)).toBe("6 in baseline (1 critical, 5 high), 0 new");
    expect(formatBaselineCounts({ ...summary, matched: 0 })).toBe("0 in baseline, 0 new");
  });
});
