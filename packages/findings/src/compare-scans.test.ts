import { describe, expect, it } from "vitest";
import { compareScans, findingIdentity, notComparableAreas } from "./compare-scans.js";
import { SKIPPED_DIRECTORIES } from "./skipped-directories.js";
import { SCHEMA_VERSION, type Coverage, type Finding, type ScanResult } from "./contract.js";

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
    schemaVersion: SCHEMA_VERSION,
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

    it("source:minified blocks only when the set of skipped bundles changes", () => {
      const min = (text: string): Coverage => ({
        ...cov("source:minified", "code", "partial", []),
        note: text,
      });
      expect(
        gone([...JS, min("a.min.js")], [...JS, min("a.min.js")]).noLongerReported,
      ).toHaveLength(1);
      expect(notComparableAreas(gone([...JS, min("a")], [...JS, min("a")]))).toEqual([]);
      const changed = gone([...JS, min("a.min.js")], [...JS, min("a.min.js, b.min.js")]);
      expect(changed.noLongerReported).toEqual([]);
      expect(changed.notComparable).toHaveLength(1);
      expect(gone(JS, [...JS, min("a.min.js")]).noLongerReported).toEqual([]);
      // Same count and same listed paths, different set fingerprint.
      const sameCount = gone(
        [...JS, min("8 skipped (set 11111111): a.min.js and 7 more.")],
        [...JS, min("8 skipped (set 22222222): a.min.js and 7 more.")],
      );
      expect(sameCount.noLongerReported).toEqual([]);
      expect(sameCount.notComparable).toHaveLength(1);
    });

    describe("skip areas block per path, not per scan", () => {
      const skip = (area: string, status: Coverage["status"], text: string): Coverage => ({
        ...cov(area, "code", status, []),
        note: text,
      });
      const at = (findingPath: string) =>
        finding({ location: { ...finding().location, path: findingPath } });
      const goneAt = (findingPath: string, previous: Coverage[], current: Coverage[]) =>
        compareScans(scan([at(findingPath)], previous), scan([], current));
      const newAt = (findingPath: string, previous: Coverage[], current: Coverage[]) =>
        compareScans(scan([], previous), scan([at(findingPath)], current));
      const states = (build: (note: string) => Coverage): [string, Coverage[], Coverage[]][] => [
        ["appears", JS, [...JS, build("1 skipped (set 11111111): a.")]],
        ["disappears", [...JS, build("1 skipped (set 11111111): a.")], JS],
        [
          "changes",
          [...JS, build("2 skipped (set 11111111): a, b.")],
          [...JS, build("3 skipped (set 22222222): a, b, c.")],
        ],
      ];

      for (const [area, status, path, other] of [
        ["source:build-output", "completed", "build/x.js", "lib/x.js"],
        ["source:xml-skipped", "completed", "app/src/main/res/a.xml", "lib/a.xml"],
        ["source:special-files", "completed", "build/x.js", "lib/x.js"],
      ] as const) {
        it(`${area} appearing, disappearing or changing does not hold back an ordinary finding`, () => {
          for (const [label, previous, current] of states((note) => skip(area, status, note))) {
            const result = goneAt(other, previous, current);
            expect(result.noLongerReported, label).toHaveLength(1);
            expect(result.notComparable, label).toEqual([]);
            const added = newAt(other, previous, current);
            expect(added.new, label).toHaveLength(1);
            expect(added.newInUncertainAreas, label).toEqual([]);
            expect(added.uncertainAreas, label).toEqual([]);
          }
        });

        it(`${area}: a finding at ${path} stays not comparable when the skip set changes`, () => {
          if (area === "source:special-files") {
            const result = goneAt(path, JS, [...JS, skip(area, status, "1 skipped (set 1): a.")]);
            expect(result.noLongerReported).toHaveLength(1);
            return;
          }
          const withArea = [...JS, skip(area, status, "1 skipped (set 11111111): a.")];
          expect(goneAt(path, JS, withArea).notComparable).toHaveLength(1);
          expect(goneAt(path, withArea, JS).notComparable).toHaveLength(1);
          expect(newAt(path, JS, withArea).newInUncertainAreas).toHaveLength(1);
          expect(goneAt(path, JS, JS).noLongerReported).toHaveLength(1);
        });
      }

      it("source:build-output: the same skip set in both scans holds nothing back", () => {
        const both = [...JS, skip("source:build-output", "completed", "1 skipped (set 1): a.")];
        expect(goneAt("build/x.js", both, both).noLongerReported).toHaveLength(1);
        expect(newAt("build/x.js", both, both).newInUncertainAreas).toEqual([]);
      });

      it("a JVM package called build is never held back by source:build-output", () => {
        const foo = "src/main/java/com/acme/build/Foo.java";
        const before = [...JS, skip("source:build-output", "completed", "1 skipped (set 1): a.")];
        const after = [...JS, skip("source:build-output", "completed", "2 skipped (set 2): a, b.")];
        for (const [previous, current] of [
          [before, before],
          [JS, before],
          [before, after],
          [before, JS],
        ]) {
          expect(
            goneAt(foo, previous as Coverage[], current as Coverage[]).noLongerReported,
          ).toHaveLength(1);
          const added = newAt(foo, previous as Coverage[], current as Coverage[]);
          expect(added.newInUncertainAreas).toEqual([]);
          expect(added.uncertainAreas).toEqual([]);
        }
      });

      it("note-only areas that stay partial leave their own area comparable", () => {
        for (const area of ["source:unreadable-files", "source:build-output"]) {
          const partial = skip(area, "partial", "1 (set 1)");
          const result = goneAt("lib/x.js", [...JS, partial], [...JS, partial]);
          const info = result.areas.find((entry) => entry.area === area);
          expect(info).toMatchObject({ comparable: true, reason: null });
          expect(notComparableAreas(result)).toEqual([]);
        }
      });

      it("source:build-output (partial, no source found) blocks everything when its note changes", () => {
        const partial = (note: string) => skip("source:build-output", "partial", note);
        const same = goneAt(
          "lib/x.js",
          [...JS, partial("n (set 1)")],
          [...JS, partial("n (set 1)")],
        );
        expect(same.noLongerReported).toHaveLength(1);
        const changed = goneAt(
          "lib/x.js",
          [...JS, partial("n (set 1)")],
          [...JS, partial("n (set 2)")],
        );
        expect(changed.notComparable).toHaveLength(1);
        expect(goneAt("lib/x.js", JS, [...JS, partial("n (set 1)")]).notComparable).toHaveLength(1);
        expect(
          newAt("lib/x.js", [...JS, partial("n (set 1)")], [...JS, partial("n (set 2)")])
            .newInUncertainAreas,
        ).toHaveLength(1);
        // One side partial is enough, even if the other side's area is informational.
        expect(
          goneAt(
            "lib/x.js",
            [...JS, skip("source:build-output", "completed", "n (set 1)")],
            [...JS, partial("n (set 1)")],
          ).noLongerReported,
        ).toHaveLength(1);
        expect(
          goneAt(
            "lib/x.js",
            [...JS, skip("source:build-output", "completed", "n (set 1)")],
            [...JS, partial("n (set 2)")],
          ).notComparable,
        ).toHaveLength(1);
      });

      it("source:unreadable-files (partial) keeps note-change blocking for the whole scope", () => {
        const unreadable = (note: string) => skip("source:unreadable-files", "partial", note);
        const same = goneAt(
          "lib/x.js",
          [...JS, unreadable("1 (set 1)")],
          [...JS, unreadable("1 (set 1)")],
        );
        expect(same.noLongerReported).toHaveLength(1);
        const changed = goneAt(
          "lib/x.js",
          [...JS, unreadable("1 (set 1)")],
          [...JS, unreadable("1 (set 2)")],
        );
        expect(changed.notComparable).toHaveLength(1);
        expect(goneAt("lib/x.js", JS, [...JS, unreadable("1 (set 1)")]).notComparable).toHaveLength(
          1,
        );
        expect(
          newAt("lib/x.js", JS, [...JS, unreadable("1 (set 1)")]).newInUncertainAreas,
        ).toHaveLength(1);
      });

      it("SKIPPED_DIRECTORIES has the build directories the walk skips", () => {
        for (const name of ["dist", "build", "out", "coverage", ".next", ".git"]) {
          expect(SKIPPED_DIRECTORIES.has(name), name).toBe(true);
        }
      });
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
