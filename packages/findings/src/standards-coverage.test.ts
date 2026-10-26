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

// A small catalog: injection in code (JS/TS and Go rules), secrets in history, headers on the web.
const SQL_JS = rule("R-SQL-JS", "code", ["A05:2025"], ["CWE-89"]);
const SQL_GO = rule("R-SQL-GO", "code", ["A05:2025"], ["CWE-89"]);
const SECRET = rule("R-SECRET", "history", ["A07:2025"], ["CWE-798"]);
const HEADER = rule("R-HEADER", "web", ["A02:2025"], ["CWE-693"]);
const CATALOG = [SQL_JS, SQL_GO, SECRET, HEADER];

const cov = (
  area: string,
  scope: ScanScope,
  status: CoverageStatus,
  ruleIds: string[] = [],
): Coverage => ({ area, scope, status, ruleIds, note: null });

const stat = (
  ruleId: string,
  area: string,
  status: CoverageStatus,
  scope: ScanScope,
): RuleStat => ({
  ruleId,
  area,
  scope,
  status,
  targets: [{ unit: "files", examined: 1, reason: null }],
  findings: 0,
});

const owasp = (map: ReturnType<typeof computeStandardsCoverage>, id: string) =>
  map.owasp.find((entry) => entry.id === id)!;
const cwe = (map: ReturnType<typeof computeStandardsCoverage>, id: string) =>
  map.cweTop25.find((entry) => entry.id === id)!;

describe("computeStandardsCoverage", () => {
  it("always lists the ten OWASP categories and the 25 CWE Top 25 entries, in order", () => {
    const map = computeStandardsCoverage({ rules: [], coverage: [], ruleStats: [] });
    expect(map.owasp.map((entry) => entry.id)).toEqual(
      Array.from({ length: 10 }, (_, i) => `A${String(i + 1).padStart(2, "0")}:2025`),
    );
    expect(map.cweTop25).toHaveLength(25);
    expect(map.cweTop25[0]).toMatchObject({ id: "CWE-79", rank: 1 });
    expect(map.owasp[0]?.rank).toBeNull();
  });

  it("says `no rules` for an entry that no rule maps to", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [cov("source:javascript", "code", "completed", ["R-SQL-JS"])],
      ruleStats: [stat("R-SQL-JS", "source:javascript", "completed", "code")],
    });
    expect(owasp(map, "A03:2025")).toMatchObject({
      state: "not_checked",
      reason: "no rules",
      ruleIds: [],
      mappedRuleIds: [],
    });
    expect(cwe(map, "CWE-787")).toMatchObject({ state: "not_checked", reason: "no rules" });
  });

  it("is checked when the mapped rule ran in a completed area for the only language present", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [
        cov("source:javascript", "code", "completed", ["R-SQL-JS"]),
        cov("source:go", "code", "completed"), // "No Go files found."
      ],
      ruleStats: [stat("R-SQL-JS", "source:javascript", "completed", "code")],
    });
    expect(owasp(map, "A05:2025")).toMatchObject({
      state: "checked",
      ruleIds: ["R-SQL-JS"],
      mappedRuleIds: ["R-SQL-GO", "R-SQL-JS"],
    });
    expect(cwe(map, "CWE-89").state).toBe("checked");
    expect(owasp(map, "A05:2025").reason).toBe("mapped rules ran to completion");
  });

  it("is only partial when the mapped rule ran in a partial area", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [cov("source:javascript", "code", "partial", ["R-SQL-JS"])],
      ruleStats: [stat("R-SQL-JS", "source:javascript", "partial", "code")],
    });
    expect(owasp(map, "A05:2025").state).toBe("partial");
    expect(owasp(map, "A05:2025").reason).toContain("partial areas: source:javascript");
    expect(cwe(map, "CWE-89").state).toBe("partial");
  });

  it("is partial when one of several areas was partial, even if another completed", () => {
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
    expect(owasp(map, "A05:2025").state).toBe("partial");
  });

  it("is partial when a language is present that no completed mapped rule covers", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [
        cov("source:javascript", "code", "completed", ["R-SQL-JS"]),
        // Java was detected and has no rules yet.
        cov("source:java", "code", "not_tested"),
      ],
      ruleStats: [stat("R-SQL-JS", "source:javascript", "completed", "code")],
    });
    expect(owasp(map, "A05:2025")).toMatchObject({ state: "partial" });
    expect(owasp(map, "A05:2025").reason).toContain("no completed mapped rule covers java");
  });

  it("is partial when the project also has Go files that only the other rule would cover", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [
        cov("source:javascript", "code", "completed", ["R-SQL-JS"]),
        cov("source:go", "code", "not_tested", []),
      ],
      ruleStats: [stat("R-SQL-JS", "source:javascript", "completed", "code")],
    });
    expect(owasp(map, "A05:2025").state).toBe("partial");
  });

  it("is checked when every present language is covered by a completed mapped rule", () => {
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
    expect(owasp(map, "A05:2025").state).toBe("checked");
  });

  it("does not apply the language check to history and web rules", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
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
    expect(owasp(map, "A07:2025").state).toBe("checked");
    expect(owasp(map, "A02:2025").state).toBe("checked");
  });

  it("is not checked when the mapped rules did not run: not tested", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [cov("web", "web", "not_tested")],
      ruleStats: [],
    });
    expect(owasp(map, "A02:2025")).toMatchObject({
      state: "not_checked",
      ruleIds: [],
      mappedRuleIds: ["R-HEADER"],
    });
    expect(owasp(map, "A02:2025").reason).toBe(
      "no mapped rule ran (R-HEADER: their areas were not selected or could not run)",
    );
  });

  it("is not checked when the scope was not selected, and says so", () => {
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
    expect(owasp(map, "A02:2025").state).toBe("not_checked");
  });

  it("never reports checked unless a completed row backs it and no contributing area is partial", () => {
    // Every combination of statuses for two areas of one rule.
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
        if (!hasCompleted && !hasPartial) expect(state).toBe("not_checked");
        else if (hasPartial) expect(state).toBe("partial");
        // An area that was detected but could not run leaves its language uncovered.
        else if (a === "not_tested" || b === "not_tested") expect(state).toBe("partial");
        else expect(state).toBe("checked");
      }
    }
  });

  it("a blocked scan (no coverage, no stats) checks nothing", () => {
    const map = computeStandardsCoverage({ rules: CATALOG, coverage: [], ruleStats: [] });
    expect(map.owasp.every((entry) => entry.state === "not_checked")).toBe(true);
    expect(map.cweTop25.every((entry) => entry.state === "not_checked")).toBe(true);
  });

  it("maps a CWE only by its exact id", () => {
    const map = computeStandardsCoverage({
      rules: [rule("R-X", "history", ["A07:2025"], ["CWE-798"])],
      coverage: [cov("history:commits", "history", "completed", ["R-X"])],
      ruleStats: [stat("R-X", "history:commits", "completed", "history")],
    });
    expect(cwe(map, "CWE-79").state).toBe("not_checked"); // CWE-79 is a prefix of nothing here
    expect(cwe(map, "CWE-20").mappedRuleIds).toEqual([]);
  });

  it("counts states", () => {
    const map = computeStandardsCoverage({
      rules: CATALOG,
      coverage: [cov("source:javascript", "code", "completed", ["R-SQL-JS"])],
      ruleStats: [stat("R-SQL-JS", "source:javascript", "completed", "code")],
    });
    expect(countStandardStates(map.owasp)).toEqual({ checked: 1, partial: 0, not_checked: 9 });
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
