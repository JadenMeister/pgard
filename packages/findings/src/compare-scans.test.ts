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

function scan(
  findings: Finding[],
  coverage: Coverage[] = FULL,
  extra: Partial<ScanResult> = {},
): ScanResult {
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
    ...extra,
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
    expect([result.new, result.noLongerReported, result.unchanged]).toEqual([[], [], []]);
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
    expect(result.noLongerReported).toEqual([]);
  });

  it("reports new and fixed", () => {
    const result = compareScans(
      scan([finding({ evidence: "old flow" })]),
      scan([finding({ evidence: "new flow" })]),
    );
    expect(result.new).toHaveLength(1);
    expect(result.noLongerReported).toHaveLength(1);
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
    expect(result.noLongerReported.map((f) => f.location.line)).toEqual([10]);
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
        expect(result.noLongerReported).toEqual([]);
        expect(result.notComparable).toHaveLength(1);
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
      expect(result.noLongerReported).toEqual([]);
      expect(result.notComparable).toHaveLength(1);
    });

    it("an area that ran in one scan only is not comparable; its new findings are still listed", () => {
      const onlyCode = [FULL[0] as Coverage];
      const result = compareScans(scan([], onlyCode), scan([webFinding()], FULL));
      expect(result.new).toHaveLength(1);
      expect(result.newInUncertainAreas).toHaveLength(1);
      expect(result.areas.find((a) => a.area === "web:anonymous")?.reason).toBe("only_in_current");
      const reversed = compareScans(scan([webFinding()], FULL), scan([], onlyCode));
      expect(reversed.noLongerReported).toEqual([]);
      expect(reversed.areas.find((a) => a.area === "web:anonymous")?.reason).toBe(
        "only_in_previous",
      );
    });

    it("not_selected in one scan counts as not run", () => {
      const result = compareScans(
        scan([webFinding()]),
        scan([], [...FULL.slice(0, 2), cov("web:anonymous", "web", "not_selected")]),
      );
      expect(result.noLongerReported).toEqual([]);
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
      expect(
        compareScans(scan([finding()], byScope), scan([], byScope)).noLongerReported,
      ).toHaveLength(1);
      expect(compareScans(scan([finding()], []), scan([], [])).noLongerReported).toEqual([]);
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

  describe("positive evidence that a place was analyzed", () => {
    const JS = [cov("source:javascript", "code", "completed", ["PG-SQL-001"])];
    const gone = (previous: Coverage[], current: Coverage[]) =>
      compareScans(scan([finding()], previous), scan([], current));

    it("every owning area must be comparable, not just one (every vs some)", () => {
      const both = [
        cov("source:javascript", "code", "completed", ["PG-SQL-001"]),
        cov("source:typescript", "code", "completed", ["PG-SQL-001"]),
      ];
      const oneBad = [
        both[0] as Coverage,
        cov("source:typescript", "code", "partial", ["PG-SQL-001"]),
      ];
      expect(gone(both, oneBad).noLongerReported).toEqual([]);
      expect(gone(both, both).noLongerReported).toHaveLength(1);
    });

    it("a rule-less partial area (files over 1 MiB, unsupported ORM) blocks the scope", () => {
      for (const area of ["source:large-files", "source:orm:prisma"]) {
        const result = gone(JS, [...JS, cov(area, "code", "partial", [])]);
        expect(result.noLongerReported, area).toEqual([]);
        expect(result.notComparable, area).toHaveLength(1);
        expect(result.areas.find((a) => a.area === area)?.held).toBe(1);
      }
    });

    it("a skipped-directory or symlink area that appears or changes blocks the scope", () => {
      const note = (text: string): Coverage => ({
        ...cov("source:dependency-directories", "code", "completed", []),
        note: text,
      });
      expect(gone(JS, [...JS, note("vendor/")]).noLongerReported).toEqual([]);
      expect(gone([...JS, note("a/")], [...JS, note("a/, vendor/")]).noLongerReported).toEqual([]);
      expect(gone([...JS, note("a/")], [...JS, note("a/")]).noLongerReported).toHaveLength(1);
      expect(gone([...JS, note("a/")], JS).noLongerReported).toEqual([]);
    });

    it("a detected-but-unsupported language (not_tested, no rules) does not block", () => {
      const java = cov("source:java", "code", "not_tested", []);
      expect(gone(JS, [...JS, java]).noLongerReported).toHaveLength(1);
      expect(gone([...JS, java], [...JS, java]).noLongerReported).toHaveLength(1);
      expect(notComparableAreas(gone(JS, [...JS, java])).map((a) => a.area)).toEqual([]);
    });

    it("a skip signal in another scope does not block", () => {
      const webSkip = cov("web:crawl", "web", "partial", []);
      expect(gone(JS, [...JS, webSkip]).noLongerReported).toHaveLength(1);
    });
  });

  describe("new findings are never hidden", () => {
    it("lists a new finding in a partial area and flags it", () => {
      const partial = [cov("history:commits", "history", "partial", ["PG-SECRET-003"])];
      const result = compareScans(scan([], partial), scan([historyFinding()], partial));
      expect(result.new).toHaveLength(1);
      expect(result.newInUncertainAreas).toHaveLength(1);
    });

    it("does not flag a new finding in a fully compared area", () => {
      const result = compareScans(scan([]), scan([finding()]));
      expect(result.new).toHaveLength(1);
      expect(result.newInUncertainAreas).toEqual([]);
    });
  });

  describe("scan differences", () => {
    it("web areas are not comparable when the web origin changed", () => {
      const a = scan([webFinding()], FULL, {
        target: { repo: "o/n", revision: null, webOrigin: "http://127.0.0.1:3000" },
      });
      const b = scan([], FULL, {
        target: { repo: "o/n", revision: null, webOrigin: "http://127.0.0.1:3001" },
      });
      const result = compareScans(a, b);
      expect(result.noLongerReported).toEqual([]);
      expect(result.areas.find((area) => area.area === "web:anonymous")?.reason).toBe(
        "other_origin",
      );
      expect(compareScans(a, scan([], FULL, { target: a.target })).noLongerReported).toHaveLength(
        1,
      );
    });

    it("does not report findings as gone after a PGARD version change, but still pairs", () => {
      const updated = { tool: { name: "pgard" as const, version: "0.2.0" } };
      const gone = compareScans(scan([finding()]), scan([], FULL, updated));
      expect(gone.toolVersionChanged).toBe(true);
      expect(gone.noLongerReported).toEqual([]);
      expect(gone.notComparable).toHaveLength(1);
      const kept = compareScans(scan([finding()]), scan([finding({ line: 12 })], FULL, updated));
      expect(kept.moved).toHaveLength(1);
    });

    it("reports severity and status changes on a pair", () => {
      const result = compareScans(scan([finding()]), scan([finding({ severity: "critical" })]));
      expect(result.unchanged[0]?.changed).toEqual(["severity"]);
    });
  });

  describe("identity details", () => {
    it("PG-HYGIENE-001 ignores the revision and the counts in its evidence", () => {
      const hygiene = (text: string) =>
        historyFinding({
          ruleId: "PG-HYGIENE-001",
          location: { kind: "file", path: "node_modules/", line: null, url: null, commit: null },
          evidence: text,
        });
      expect(
        findingIdentity(
          hygiene(
            "1 dependency directory is tracked in commit aaaaaaaaaaaa: node_modules/ (5 tracked files)",
          ),
        ),
      ).toBe(
        findingIdentity(
          hygiene(
            "1 dependency directory is tracked in commit bbbbbbbbbbbb: node_modules/ (9 tracked files)",
          ),
        ),
      );
    });

    it("web: cookie names stay part of the identity, versions do not", () => {
      const cookie = (name: string) =>
        webFinding({ evidence: `Set-Cookie for "${name}" lacks HttpOnly (value not recorded).` });
      expect(findingIdentity(cookie("session"))).not.toBe(findingIdentity(cookie("tracking")));
      expect(findingIdentity(cookie("session"))).toBe(findingIdentity(cookie("session")));
    });

    it("keeps numbers that are not line references", () => {
      expect(findingIdentity(finding({ evidence: "POST /api/v1:2 route" }))).not.toBe(
        findingIdentity(finding({ evidence: "POST /api/v1 route" })),
      );
      expect(findingIdentity(finding({ evidence: "see util.ts:12 here" }))).toBe(
        findingIdentity(finding({ evidence: "see util.ts:99 here" })),
      );
    });
  });

  describe("pairing details", () => {
    it("on a tie the lower line is paired first", () => {
      const result = compareScans(
        scan([finding({ line: 10 })]),
        scan([finding({ line: 5 }), finding({ line: 15 })]),
      );
      expect(result.moved[0]?.current.location.line).toBe(5);
      expect(result.new.map((f) => f.location.line)).toEqual([15]);
    });

    it("a missing line is not as close as a real line", () => {
      const result = compareScans(
        scan([finding({ line: 7 })]),
        scan([finding({ line: null }), finding({ line: 9 })]),
      );
      expect(result.moved[0]?.current.location.line).toBe(9);
    });
  });

  describe("explanations", () => {
    const JS = [cov("source:javascript", "code", "completed", ["PG-SQL-001"])];

    it("lists a rule-less completed area whose note changed when it holds findings back", () => {
      const note = (text: string): Coverage => ({
        ...cov("source:symlinks", "code", "completed", []),
        note: text,
      });
      const result = compareScans(
        scan([finding()], [...JS, note("1 symbolic link(s) (set aaaaaaaa)")]),
        scan([], [...JS, note("1 symbolic link(s) (set bbbbbbbb)")]),
      );
      expect(result.noLongerReported).toEqual([]);
      expect(notComparableAreas(result).map((a) => a.area)).toEqual(["source:symlinks"]);
    });

    it("names the areas that made new findings uncertain", () => {
      const partial = [cov("history:commits", "history", "partial", ["PG-SECRET-003"])];
      const result = compareScans(scan([], partial), scan([historyFinding()], partial));
      expect(result.uncertainAreas).toEqual(["history:commits"]);
    });

    it("an area that did not run last time is a scope change, not a partial area", () => {
      const result = compareScans(
        scan([], []),
        scan([finding()], [cov("source:typescript", "code", "partial", ["PG-SQL-001"])]),
      );
      expect(result.areas.find((a) => a.area === "source:typescript")?.reason).toBe(
        "only_in_current",
      );
      expect(result.new).toHaveLength(1);
      expect(result.newInUncertainAreas).toHaveLength(1);
    });
  });
});

describe("project configuration exclusions", () => {
  const JS = [cov("source:typescript", "code", "completed", ["PG-SQL-001"])];
  const excluded = (note: string, status: Coverage["status"] = "completed"): Coverage => ({
    ...cov("source:config-excluded", "code", status, []),
    note,
  });

  it("a newly excluded file is not comparable, never 'no longer reported'", () => {
    const result = compareScans(
      scan([finding()], JS),
      scan([], [...JS, excluded("1 file excluded by pgard.config.json (set aaaaaaaa)")]),
    );
    expect(result.noLongerReported).toEqual([]);
    expect(result.notComparable).toHaveLength(1);
    expect(notComparableAreas(result).map((a) => a.area)).toContain("source:config-excluded");
  });

  it("a widened exclusion set (same pattern, other files) is not comparable either", () => {
    const result = compareScans(
      scan([finding()], [...JS, excluded("1 file excluded by pgard.config.json (set aaaaaaaa)")]),
      scan([], [...JS, excluded("1 file excluded by pgard.config.json (set bbbbbbbb)")]),
    );
    expect(result.noLongerReported).toEqual([]);
    expect(result.notComparable).toHaveLength(1);
  });

  it("removing the exclusions does not turn old findings into 'no longer reported'", () => {
    const result = compareScans(
      scan([finding()], [...JS, excluded("1 file excluded by pgard.config.json (set aaaaaaaa)")]),
      scan([], JS),
    );
    expect(result.noLongerReported).toEqual([]);
  });

  it("an unchanged exclusion note still lets a fixed finding be reported as gone", () => {
    const area = excluded("1 file excluded by pgard.config.json (set aaaaaaaa)");
    const result = compareScans(scan([finding()], [...JS, area]), scan([], [...JS, area]));
    expect(result.noLongerReported).toHaveLength(1);
  });

  it("a partial exclusion warning (catch-all pattern) holds findings back", () => {
    const area = excluded("WARNING", "partial");
    const result = compareScans(scan([finding()], [...JS, area]), scan([], [...JS, area]));
    expect(result.noLongerReported).toEqual([]);
  });

  it("the history note is a skip signal in the history scope only", () => {
    const note: Coverage = {
      ...cov("history:config-excluded", "history", "completed", []),
      note: "set aaaaaaaa",
    };
    const history = [cov("history:commits", "history", "completed", ["PG-SECRET-003"])];
    const result = compareScans(
      scan([finding(), historyFinding()], [...JS, ...history]),
      scan([], [...JS, ...history, note]),
    );
    expect(result.noLongerReported.map((f) => f.ruleId)).toEqual(["PG-SQL-001"]);
    expect(result.notComparable.map((f) => f.ruleId)).toEqual(["PG-SECRET-003"]);
  });
});
