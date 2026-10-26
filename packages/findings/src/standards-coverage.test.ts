import { describe, expect, it } from "vitest";
import type { Coverage, CoverageStatus, RuleStat, ScanScope } from "./contract.js";
import {
  computeStandardsCoverage,
  countStandardStates,
  presentLanguages,
  type StandardsRule,
} from "./standards-coverage.js";

const rule = (id: string, scope: ScanScope, owasp: string[], cwe: string[]): StandardsRule => ({
  id,
  scope,
  metadata: { standards: { owasp, cwe } },
});

// A small catalog: injection in code (JS/TS and Go rules), secrets in history, headers on the web,
// and one code rule that shares a category with a history rule.
const SQL_JS = rule("R-SQL-JS", "code", ["A05:2025"], ["CWE-89"]);
const SQL_GO = rule("R-SQL-GO", "code", ["A05:2025"], ["CWE-89"]);
const SECRET = rule("R-SECRET", "history", ["A07:2025"], ["CWE-200"]);
const AUTH = rule("R-AUTH", "code", ["A07:2025"], ["CWE-306"]);
const HEADER = rule("R-HEADER", "web", ["A02:2025"], ["CWE-693"]);
const COOKIE = rule("R-COOKIE", "code", ["A02:2025"], ["CWE-1004"]);
const CATALOG = [SQL_JS, SQL_GO, SECRET, AUTH, HEADER, COOKIE];

const cov = (
  area: string,
  scope: ScanScope,
  status: CoverageStatus,
  ruleIds: string[] = [],
  note: string | null = null,
): Coverage => ({ area, scope, status, ruleIds, note });

const stat = (
  ruleId: string,
  area: string,
  status: CoverageStatus,
  scope: ScanScope,
  examined: number | null = 1,
): RuleStat => ({
  ruleId,
  area,
  scope,
  status,
  targets: [
    examined === null
      ? { unit: "files", examined: null, reason: "not measured" }
      : { unit: "files", examined, reason: null },
  ],
  findings: 0,
});

type Map = ReturnType<typeof computeStandardsCoverage>;
const owasp = (map: Map, id: string) => map.owasp.find((entry) => entry.id === id)!;
const cwe = (map: Map, id: string) => map.cweTop25.find((entry) => entry.id === id)!;

const jsCompleted = {
  coverage: [cov("source:javascript", "code", "completed", ["R-SQL-JS"])],
  ruleStats: [stat("R-SQL-JS", "source:javascript", "completed", "code")],
};

describe("computeStandardsCoverage", () => {
  it("always lists the ten OWASP categories and the 25 CWE Top 25 entries, in order", () => {
    const map = computeStandardsCoverage({ rules: [], coverage: [], ruleStats: [] });
    expect(map.owasp.map((entry) => entry.id)).toEqual(
      Array.from({ length: 10 }, (_, i) => `A${String(i + 1).padStart(2, "0")}:2025`),
    );
    expect(map.cweTop25).toHaveLength(25);
    expect(map.cweTop25[0]).toMatchObject({ id: "CWE-79", rank: 1, breadth: null });
    expect(map.owasp[0]?.rank).toBeNull();
  });

  it("says `no_rules` for an entry that no rule maps to, and `not_run` when rules exist but none ran", () => {
    const map = computeStandardsCoverage({ rules: CATALOG, ...jsCompleted });
    expect(owasp(map, "A03:2025")).toMatchObject({
      state: "no_rules",
      reason: "no rules",
      ruleIds: [],
      mappedRuleIds: [],
    });
    expect(cwe(map, "CWE-787")).toMatchObject({ state: "no_rules", reason: "no rules" });
    expect(owasp(map, "A07:2025").state).toBe("not_run");
  });

  it("reports how many of a category's mapped CWEs have any rule", () => {
    const map = computeStandardsCoverage({ rules: CATALOG, ...jsCompleted });
    const a05 = owasp(map, "A05:2025");
    expect(a05.breadth).toEqual({ cwesWithRules: 1, cwesInCategory: expect.any(Number) });
    expect(a05.breadth!.cwesInCategory).toBeGreaterThan(1);
    expect(owasp(map, "A03:2025").breadth!.cwesWithRules).toBe(0);
    // Breadth follows the category's own CWE list: CWE-200 is listed under A01, not A05, even
    // though the rule that lists it is mapped to A07.
    expect(owasp(map, "A01:2025").breadth!.cwesWithRules).toBe(1);
    expect(owasp(map, "A08:2025").breadth!.cwesWithRules).toBe(0);
  });

  it("is rules_ran when the mapped rule ran in a completed area for the only language present", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [...jsCompleted.coverage, cov("source:go", "code", "completed")],
      ruleStats: jsCompleted.ruleStats,
    });
    expect(owasp(map, "A05:2025")).toMatchObject({
      state: "rules_ran",
      ruleIds: ["R-SQL-JS"],
      mappedRuleIds: ["R-SQL-GO", "R-SQL-JS"],
      reason: "mapped rules ran to completion",
    });
    expect(cwe(map, "CWE-89").state).toBe("rules_ran");
  });

  it("is rules_partial when the mapped rule ran in a partial area", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [cov("source:javascript", "code", "partial", ["R-SQL-JS"])],
      ruleStats: [stat("R-SQL-JS", "source:javascript", "partial", "code")],
    });
    expect(owasp(map, "A05:2025").state).toBe("rules_partial");
    expect(owasp(map, "A05:2025").reason).toContain("partial areas: source:javascript");
    expect(cwe(map, "CWE-89").state).toBe("rules_partial");
  });

  it("is rules_partial when one of several areas was partial, even if another completed", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [
        cov("source:javascript", "code", "completed", ["R-SQL-JS"]),
        cov("source:typescript", "code", "partial", ["R-SQL-JS"]),
      ],
      ruleStats: [
        stat("R-SQL-JS", "source:javascript", "completed", "code"),
        stat("R-SQL-JS", "source:typescript", "partial", "code"),
      ],
    });
    expect(owasp(map, "A05:2025").state).toBe("rules_partial");
  });

  describe("a partial code area without rules (large files, unreadable directories, ORMs)", () => {
    it.each(["source:large-files", "source:unreadable", "source:config", "source:orm:typeorm"])(
      "caps code-mapped entries at rules_partial: %s",
      (area) => {
        const map = computeStandardsCoverage({
          rules: CATALOG,
          coverage: [...jsCompleted.coverage, cov(area, "code", "partial", [], "x")],
          ruleStats: jsCompleted.ruleStats,
        });
        expect(owasp(map, "A05:2025").state).toBe("rules_partial");
        expect(owasp(map, "A05:2025").reason).toContain(area);
        expect(cwe(map, "CWE-89").state).toBe("rules_partial");
      },
    );

    it("does not touch entries that no code rule maps to", () => {
      const map = computeStandardsCoverage({
        rules: CATALOG,
        coverage: [
          cov("source:large-files", "code", "partial", [], "x"),
          cov("history:commits", "history", "completed", ["R-SECRET"]),
        ],
        ruleStats: [stat("R-SECRET", "history:commits", "completed", "history")],
      });
      expect(cwe(map, "CWE-200").state).toBe("rules_ran");
    });
  });

  describe("a scope that has a mapped rule but did not run", () => {
    it("history-only scan: an entry with code and history rules is rules_partial (A07)", () => {
      const map = computeStandardsCoverage({
        rules: CATALOG,
        coverage: [
          cov("code", "code", "not_selected"),
          cov("history:commits", "history", "completed", ["R-SECRET"]),
        ],
        ruleStats: [stat("R-SECRET", "history:commits", "completed", "history")],
      });
      expect(owasp(map, "A07:2025")).toMatchObject({
        state: "rules_partial",
        ruleIds: ["R-SECRET"],
      });
      expect(owasp(map, "A07:2025").reason).toContain("code rules not run: scope not selected");
      // CWE-200 is mapped by the history rule alone, so it is not affected.
      expect(cwe(map, "CWE-200").state).toBe("rules_ran");
    });

    it("code-only scan: an entry with code and web rules is rules_partial (A02 with R-COOKIE)", () => {
      const map = computeStandardsCoverage({
        rules: CATALOG,
        coverage: [
          cov("source:javascript", "code", "completed", ["R-COOKIE"]),
          cov("web", "web", "not_selected"),
        ],
        ruleStats: [stat("R-COOKIE", "source:javascript", "completed", "code")],
      });
      expect(owasp(map, "A02:2025").state).toBe("rules_partial");
      expect(owasp(map, "A02:2025").reason).toContain("web rules not run: scope not selected");
    });

    it("says the areas could not run when the scope was selected", () => {
      const map = computeStandardsCoverage({
        rules: CATALOG,
        coverage: [
          cov("source:javascript", "code", "completed", ["R-COOKIE"]),
          cov("web", "web", "not_tested"),
        ],
        ruleStats: [stat("R-COOKIE", "source:javascript", "completed", "code")],
      });
      expect(owasp(map, "A02:2025").reason).toContain("web rules not run: areas could not run");
    });
  });

  it("is rules_partial when a language is present that no completed mapped rule covers", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [
        ...jsCompleted.coverage,
        cov("source:java", "code", "not_tested", [], "Java detected, no rules yet (3 file(s))."),
      ],
      ruleStats: jsCompleted.ruleStats,
    });
    const a05 = owasp(map, "A05:2025");
    expect(a05.state).toBe("rules_partial");
    expect(a05.reason).toContain("no completed mapped rule covers java (3 files)");
    expect(a05.reason).toContain('"exclude" in pgard.config.json');
  });

  it("is rules_partial when Go files are present that only the Go rule would cover", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [...jsCompleted.coverage, cov("source:go", "code", "not_tested", [])],
      ruleStats: jsCompleted.ruleStats,
    });
    expect(owasp(map, "A05:2025").state).toBe("rules_partial");
  });

  it("is rules_ran when every present language is covered by a completed mapped rule", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [
        cov("source:javascript", "code", "completed", ["R-SQL-JS"]),
        cov("source:go", "code", "completed", ["R-SQL-GO"]),
      ],
      ruleStats: [
        stat("R-SQL-JS", "source:javascript", "completed", "code"),
        stat("R-SQL-GO", "source:go", "completed", "code"),
      ],
    });
    expect(owasp(map, "A05:2025").state).toBe("rules_ran");
  });

  it("does not apply the language check to history and web rules", () => {
    const map = computeStandardsCoverage({
      rules: [SECRET, HEADER],
      coverage: [
        cov("source:java", "code", "not_tested"),
        cov("history:commits", "history", "completed", ["R-SECRET"]),
        cov("web:anonymous", "web", "completed", ["R-HEADER"]),
      ],
      ruleStats: [
        stat("R-SECRET", "history:commits", "completed", "history"),
        stat("R-HEADER", "web:anonymous", "completed", "web"),
      ],
    });
    expect(owasp(map, "A07:2025").state).toBe("rules_ran");
    expect(owasp(map, "A02:2025").state).toBe("rules_ran");
  });

  it("is not_run when the mapped rules did not run: not tested, and says so", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [cov("web", "web", "not_tested")],
      ruleStats: [],
    });
    expect(owasp(map, "A02:2025")).toMatchObject({ state: "not_run", ruleIds: [] });
    expect(owasp(map, "A02:2025").reason).toContain("no mapped rule ran (R-COOKIE, R-HEADER");
  });

  it("is not_run when the scope was not selected, and says so", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [cov("web", "web", "not_selected")],
      ruleStats: [],
    });
    expect(owasp(map, "A02:2025").reason).toContain("web scope not selected");
  });

  it("ignores rule stats of areas that did not run", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [],
      ruleStats: [stat("R-HEADER", "web:anonymous", "not_tested", "web")],
    });
    expect(owasp(map, "A02:2025").state).toBe("not_run");
  });

  describe("a rule that looked at nothing", () => {
    it("cannot make an entry rules_ran (docs-only repository, CWE-352)", () => {
      const csrf = rule("R-CSRF", "code", ["A01:2025"], ["CWE-352"]);
      const map = computeStandardsCoverage({
        rules: [csrf],
        coverage: [cov("source:heuristics", "code", "completed", ["R-CSRF"])],
        ruleStats: [stat("R-CSRF", "source:heuristics", "completed", "code", 0)],
      });
      expect(cwe(map, "CWE-352").state).toBe("rules_partial");
      expect(cwe(map, "CWE-352").reason).toContain("examined 0 targets: R-CSRF");
    });

    it("an unknown count (null) is not zero", () => {
      const map = computeStandardsCoverage({
        rules: [SQL_JS],
        coverage: jsCompleted.coverage,
        ruleStats: [stat("R-SQL-JS", "source:javascript", "completed", "code", null)],
      });
      expect(owasp(map, "A05:2025").state).toBe("rules_ran");
    });
  });

  describe("a rule that ran but is not in the catalog", () => {
    it("fails closed: entries that would be rules_ran become rules_partial", () => {
      const map = computeStandardsCoverage({
        rules: CATALOG,
        coverage: [...jsCompleted.coverage, cov("web:anonymous", "web", "completed", ["R-GHOST"])],
        ruleStats: [...jsCompleted.ruleStats, stat("R-GHOST", "web:anonymous", "completed", "web")],
      });
      expect(owasp(map, "A05:2025").state).toBe("rules_partial");
      expect(owasp(map, "A05:2025").reason).toContain("R-GHOST");
      // Entries that claim nothing keep their state.
      expect(owasp(map, "A03:2025").state).toBe("no_rules");
    });
  });

  it("never reports rules_ran unless a completed row backs it and nothing contributing is partial", () => {
    const statuses: CoverageStatus[] = ["completed", "partial", "not_tested", "not_selected"];
    for (const a of statuses) {
      for (const b of statuses) {
        const ran = (status: CoverageStatus) => status === "completed" || status === "partial";
        const rows = [
          ...(ran(a) ? [stat("R-SQL-JS", "source:javascript", a, "code")] : []),
          ...(ran(b) ? [stat("R-SQL-JS", "source:typescript", b, "code")] : []),
        ];
        const map = computeStandardsCoverage({
          rules: [SQL_JS],
          coverage: [
            cov("source:javascript", "code", a, ran(a) ? ["R-SQL-JS"] : []),
            cov("source:typescript", "code", b, ran(b) ? ["R-SQL-JS"] : []),
          ],
          ruleStats: rows,
        });
        const state = owasp(map, "A05:2025").state;
        const hasPartial = a === "partial" || b === "partial";
        const hasCompleted = a === "completed" || b === "completed";
        if (!hasCompleted && !hasPartial) expect(state).toBe("not_run");
        else if (hasPartial) expect(state).toBe("rules_partial");
        // An area that was detected but could not run leaves its language uncovered.
        else if (a === "not_tested" || b === "not_tested") expect(state).toBe("rules_partial");
        else expect(state).toBe("rules_ran");
      }
    }
  });

  it("a blocked scan (no coverage, no stats) ran nothing", () => {
    const map = computeStandardsCoverage({ rules: CATALOG, coverage: [], ruleStats: [] });
    expect(
      map.owasp.every((entry) => entry.state === "not_run" || entry.state === "no_rules"),
    ).toBe(true);
    expect(map.cweTop25.every((entry) => entry.state !== "rules_ran")).toBe(true);
  });

  it("maps a CWE only by its exact id", () => {
    const map = computeStandardsCoverage({
      rules: [rule("R-X", "history", ["A07:2025"], ["CWE-200"])],
      coverage: [cov("history:commits", "history", "completed", ["R-X"])],
      ruleStats: [stat("R-X", "history:commits", "completed", "history")],
    });
    expect(cwe(map, "CWE-79").state).toBe("no_rules");
    expect(cwe(map, "CWE-20").mappedRuleIds).toEqual([]);
  });

  it("counts states", () => {
    const map = computeStandardsCoverage({ rules: CATALOG, ...jsCompleted });
    expect(countStandardStates(map.owasp)).toEqual({
      rules_ran: 1,
      rules_partial: 0,
      not_run: 2,
      no_rules: 7,
    });
  });
});

describe("presentLanguages", () => {
  it("counts analyzed and detected-only languages, not empty ones or other areas", () => {
    expect(
      presentLanguages([
        cov("source:javascript", "code", "completed", ["R"]),
        cov("source:typescript", "code", "completed"), // no files
        cov("source:python", "code", "not_tested"),
        cov("source:react", "code", "completed", ["R"]),
        cov("source:config-excluded", "code", "completed"),
        cov("history:commits", "history", "completed", ["R"]),
      ]),
    ).toEqual(["javascript", "python"]);
  });
});
