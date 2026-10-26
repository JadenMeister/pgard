import { describe, expect, it } from "vitest";
import { compareScans, findingIdentity, notComparableAreas } from "./compare-scans.js";
import type { Coverage, Finding, ScanResult } from "./contract.js";

function finding(overrides: Partial<Finding> & { line?: number | null } = {}): Finding {
  const { line, ...rest } = overrides;
  return {
    id: "x",
    ruleId: "PG-SQL-001",
    title: "t",
    category: "injection",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    location: {
      kind: "file",
      path: "src/a.ts",
      line: line === undefined ? 10 : line,
      url: null,
      commit: null,
    },
    evidence: "req.query -> concat -> query()",
    impact: "i",
    recommendation: "r",
    references: { cwe: [], owasp: [], cve: [] },
    sources: ["code"],
    ...rest,
  };
}

const webFinding = (overrides: Partial<Finding> = {}) =>
  finding({
    ruleId: "PG-WEB-005",
    location: {
      kind: "url",
      path: null,
      line: null,
      url: "http://127.0.0.1:3000/a?x=1#h",
      commit: null,
    },
    evidence: 'Server header discloses a version: "nginx/1.2".',
    sources: ["web"],
    ...overrides,
  });

const historyFinding = (overrides: Partial<Finding> = {}) =>
  finding({
    ruleId: "PG-SECRET-003",
    location: { kind: "commit", path: "config.js", line: 3, url: null, commit: "abc123" },
    evidence: "AWS access key added in commit abc123 and no longer present (value redacted)",
    sources: ["history"],
    ...overrides,
  });

const cov = (
  area: string,
  scope: Coverage["scope"],
  status: Coverage["status"] = "completed",
  ruleIds: string[] = [],
): Coverage => ({ area, scope, status, ruleIds, note: null });

const FULL = [
  cov("source:typescript", "code", "completed", ["PG-SQL-001"]),
  cov("history:commits", "history", "completed", ["PG-SECRET-003"]),
  cov("web:anonymous", "web", "completed", ["PG-WEB-005"]),
];

function scan(findings: Finding[], coverage: Coverage[] = FULL): ScanResult {
  return {
    schemaVersion: "1.0",
    scanId: "s",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "o/n", revision: null, webOrigin: null },
    authorization: { decision: "allowed", checks: [] },
    coverage,
    findings,
    advisoryDb: { version: null, updatedAt: null },
  };
}

describe("findingIdentity", () => {
  it("ignores the line, the id and the verdict fields", () => {
    expect(findingIdentity(finding({ line: 10 }))).toBe(
      findingIdentity(finding({ line: 99, id: "other", severity: "low" })),
    );
  });

  it("differs by rule, path and evidence shape", () => {
    const base = findingIdentity(finding());
    expect(findingIdentity(finding({ ruleId: "PG-SQL-002" }))).not.toBe(base);
    expect(
      findingIdentity(finding({ location: { ...finding().location, path: "src/b.ts" } })),
    ).not.toBe(base);
    expect(findingIdentity(finding({ evidence: "req.body -> template -> pool.query" }))).not.toBe(
      base,
    );
  });

  it("drops line references and whitespace from the evidence", () => {
    expect(findingIdentity(finding({ evidence: "flow at line 12  ok" }))).toBe(
      findingIdentity(finding({ evidence: "flow at line 40 ok" })),
    );
  });

  it("web: ignores query, fragment and a quoted version, keeps the header name", () => {
    const a = webFinding();
    const b = webFinding({
      location: { ...a.location, url: "http://127.0.0.1:3000/a" },
      evidence: 'Server header discloses a version: "nginx/9.9".',
    });
    expect(findingIdentity(a)).toBe(findingIdentity(b));
    expect(
      findingIdentity(
        webFinding({ evidence: 'X-Powered-By header discloses a version: "nginx/1.2".' }),
      ),
    ).not.toBe(findingIdentity(a));
    expect(
      findingIdentity(webFinding({ location: { ...a.location, url: "http://127.0.0.1:3000/b" } })),
    ).not.toBe(findingIdentity(a));
  });

  it("history: keeps the commit and path, ignores the line", () => {
    const base = historyFinding();
    expect(findingIdentity(historyFinding({ location: { ...base.location, line: 90 } }))).toBe(
      findingIdentity(base),
    );
    expect(
      findingIdentity(historyFinding({ location: { ...base.location, commit: "def" } })),
    ).not.toBe(findingIdentity(base));
  });

  it("is computed from redacted evidence only", () => {
    const a = findingIdentity(finding({ evidence: 'key = "AKIAIOSFODNN7EXAMPLE" -> query()' }));
    const b = findingIdentity(finding({ evidence: 'key = "AKIAABCDEFGHIJKLMNOP" -> query()' }));
    expect(a).toBe(b);
  });
});

describe("compareScans", () => {
  it("treats a line shift as moved, not fixed + new", () => {
    const result = compareScans(scan([finding({ line: 10 })]), scan([finding({ line: 14 })]));
    expect(result.moved).toHaveLength(1);
    expect(result.moved[0]?.delta).toBe(4);
    expect([result.new, result.fixed, result.unchanged]).toEqual([[], [], []]);
  });

  it("is unchanged on the same line, and survives edits elsewhere in the file", () => {
    const other = finding({ ruleId: "PG-XSS-001", evidence: "other", line: 50 });
    const result = compareScans(
      scan([finding({ line: 10 }), other]),
      scan([finding({ line: 10 }), { ...other, location: { ...other.location, line: 53 } }]),
    );
    expect(result.unchanged).toHaveLength(1);
    expect(result.moved).toHaveLength(1);
    expect(result.new).toEqual([]);
    expect(result.fixed).toEqual([]);
  });

  it("reports new and fixed", () => {
    const result = compareScans(
      scan([finding({ evidence: "old flow" })]),
      scan([finding({ evidence: "new flow" })]),
    );
    expect(result.new).toHaveLength(1);
    expect(result.fixed).toHaveLength(1);
  });

  it("pairs duplicates in one file by nearest line", () => {
    const result = compareScans(
      scan([finding({ line: 10 }), finding({ line: 100 })]),
      scan([finding({ line: 12 }), finding({ line: 98 })]),
    );
    expect(result.moved.map((p) => [p.previous.location.line, p.current.location.line])).toEqual(
      expect.arrayContaining([
        [10, 12],
        [100, 98],
      ]),
    );
    expect(result.moved).toHaveLength(2);
  });

  it("when a duplicate disappears, the nearest pair stays and the far one is fixed", () => {
    const result = compareScans(
      scan([finding({ line: 10 }), finding({ line: 100 })]),
      scan([finding({ line: 101 })]),
    );
    expect(result.moved).toHaveLength(1);
    expect(result.moved[0]?.previous.location.line).toBe(100);
    expect(result.fixed.map((f) => f.location.line)).toEqual([10]);
  });

  it("when a duplicate is added, the extra one is new", () => {
    const result = compareScans(
      scan([finding({ line: 10 })]),
      scan([finding({ line: 10 }), finding({ line: 200 })]),
    );
    expect(result.unchanged).toHaveLength(1);
    expect(result.new.map((f) => f.location.line)).toEqual([200]);
  });

  it("pairs null lines with each other and flags verdict changes", () => {
    const base = historyFinding();
    const result = compareScans(
      scan([historyFinding({ location: { ...base.location, line: null } })]),
      scan([
        historyFinding({
          location: { ...base.location, line: null },
          severity: "low",
          confidence: "low",
        }),
      ]),
    );
    expect(result.unchanged).toHaveLength(1);
    expect(result.unchanged[0]?.changed).toEqual(["severity", "confidence"]);
    expect(result.unchanged[0]?.delta).toBeNull();
  });

  it("compares web findings across query changes", () => {
    const a = webFinding();
    const result = compareScans(
      scan([a]),
      scan([webFinding({ location: { ...a.location, url: "http://127.0.0.1:3000/a" } })]),
    );
    expect(result.unchanged).toHaveLength(1);
  });

  describe("comparability", () => {
    it("never reports a finding as fixed when its area is partial in either scan", () => {
      const partial = [cov("source:typescript", "code", "partial", ["PG-SQL-001"])];
      for (const [before, after] of [
        [FULL, partial],
        [partial, FULL],
      ] as const) {
        const result = compareScans(scan([finding()], before), scan([], after));
        expect(result.fixed).toEqual([]);
        expect(result.notComparable.previous).toHaveLength(1);
        expect(result.areas.find((a) => a.area === "source:typescript")).toMatchObject({
          comparable: false,
          reason: "partial",
        });
      }
    });

    it("not_tested in either scan is not comparable", () => {
      const result = compareScans(
        scan([historyFinding()]),
        scan([], [cov("history:commits", "history", "not_tested", ["PG-SECRET-003"])]),
      );
      expect(result.fixed).toEqual([]);
      expect(result.notComparable.previous).toHaveLength(1);
    });

    it("an area that ran in one scan only is not comparable (and not new either)", () => {
      const onlyCode = [FULL[0] as Coverage];
      const result = compareScans(scan([], onlyCode), scan([webFinding()], FULL));
      expect(result.new).toEqual([]);
      expect(result.notComparable.current).toHaveLength(1);
      expect(result.areas.find((a) => a.area === "web:anonymous")?.reason).toBe("only_in_current");
      const reversed = compareScans(scan([webFinding()], FULL), scan([], onlyCode));
      expect(reversed.fixed).toEqual([]);
      expect(reversed.areas.find((a) => a.area === "web:anonymous")?.reason).toBe(
        "only_in_previous",
      );
    });

    it("not_selected in one scan counts as not run", () => {
      const result = compareScans(
        scan([webFinding()]),
        scan([], [...FULL.slice(0, 2), cov("web:anonymous", "web", "not_selected")]),
      );
      expect(result.fixed).toEqual([]);
    });

    it("a finding present in both scans is still paired in a partial area", () => {
      const partial = [cov("source:typescript", "code", "partial", ["PG-SQL-001"])];
      const result = compareScans(
        scan([finding()], partial),
        scan([finding({ line: 11 })], partial),
      );
      expect(result.moved).toHaveLength(1);
    });

    it("falls back to the scope when no area lists the rule, and fails closed with no area", () => {
      const byScope = [cov("source:typescript", "code", "completed")];
      expect(compareScans(scan([finding()], byScope), scan([], byScope)).fixed).toHaveLength(1);
      expect(compareScans(scan([finding()], []), scan([], [])).fixed).toEqual([]);
    });

    it("lists only areas that one scan asked for in notComparableAreas", () => {
      const result = compareScans(
        scan([], [...FULL, cov("x", "web", "not_selected")]),
        scan([], [...FULL.slice(0, 2), cov("x", "web", "not_selected")]),
      );
      expect(notComparableAreas(result).map((a) => a.area)).toEqual(["web:anonymous"]);
    });
  });

  it("is deterministic and does not mutate its inputs", () => {
    const previous = scan([finding({ line: 5 }), finding({ line: 7 })]);
    const current = scan([finding({ line: 8 }), finding({ line: 6 })]);
    const frozen = JSON.stringify([previous, current]);
    expect(compareScans(previous, current)).toEqual(compareScans(previous, current));
    expect(JSON.stringify([previous, current])).toBe(frozen);
  });

  it("handles a large duplicate group", () => {
    const many = (offset: number) =>
      Array.from({ length: 400 }, (_, index) => finding({ line: index + offset }));
    const result = compareScans(scan(many(0)), scan(many(1)));
    expect(result.moved.length + result.unchanged.length).toBe(400);
  });
});
