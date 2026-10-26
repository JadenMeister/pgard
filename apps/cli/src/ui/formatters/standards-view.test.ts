import { computeStandardsCoverage, type Coverage, type RuleStat } from "@pgard/findings";
import { listSupportedRules } from "@pgard/scan-core";
import { describe, expect, it } from "vitest";
import { testResult } from "../../test-support.js";
import { STANDARDS_NOTE, formatScanResult, formatStandardsCoverage } from "./result-view.js";
import { createStyle } from "./style.js";

const plain = createStyle(false);

const coverage: Coverage[] = [
  {
    area: "source:typescript",
    scope: "code",
    status: "completed",
    ruleIds: ["PG-SQL-001", "PG-XSS-001"],
    note: null,
  },
  { area: "source:java", scope: "code", status: "not_tested", ruleIds: [], note: null },
  {
    area: "history:commits",
    scope: "history",
    status: "partial",
    ruleIds: ["PG-SECRET-003"],
    note: null,
  },
];
const ruleStats: RuleStat[] = coverage.flatMap((entry) =>
  entry.status === "not_tested"
    ? []
    : entry.ruleIds.map((ruleId) => ({
        ruleId,
        area: entry.area,
        scope: entry.scope,
        status: entry.status,
        targets: [{ unit: "files", examined: 3, reason: null }],
        findings: 0,
      })),
);
const standardsCoverage = computeStandardsCoverage({
  rules: listSupportedRules(),
  coverage,
  ruleStats,
});

describe("formatStandardsCoverage", () => {
  const text = formatStandardsCoverage(standardsCoverage, plain);
  const lines = text.split("\n");

  it("has one line per OWASP category and one CWE Top 25 summary line", () => {
    expect(lines).toHaveLength(11);
    expect(lines[0]).toContain("A01 Broken Access Control");
    expect(lines.at(-1)).toMatch(
      /^ {2}CWE Top 25 2025: \d+ rules ran, \d+ rules partial, \d+ not run, \d+ no rules$/,
    );
  });

  it("never prints `rules ran` for a partial category, and shows the reason", () => {
    const a05 = lines.find((line) => line.includes("A05 Injection"));
    // Java is present with no rules, so the injection rules only partly ran.
    expect(a05).toContain("[rules partial]");
    expect(a05).not.toContain("[rules ran]");
    expect(a05).toContain("no completed mapped rule covers java");
    const a07 = lines.find((line) => line.includes("A07 "));
    expect(a07).toContain("[rules partial]");
  });

  it("shows how many of the category's CWEs have rules, next to the state", () => {
    const a03 = lines.find((line) => line.includes("A03 "));
    expect(a03).toMatch(/- 1 of \d+ mapped CWEs have rules/);
    expect(a03).toContain("PG-HYGIENE-001");
  });

  it("says `no rules` for a category with no mapped rule", () => {
    const rules = listSupportedRules().filter(
      (rule) => !rule.metadata.standards.owasp.includes("A09:2025"),
    );
    const map = computeStandardsCoverage({ rules, coverage, ruleStats });
    const line = formatStandardsCoverage(map, plain)
      .split("\n")
      .find((entry) => entry.includes("A09 "));
    expect(line).toContain("[no rules]");
  });

  it("prints `not run` for a category whose rules did not run", () => {
    const map = computeStandardsCoverage({
      rules: listSupportedRules(),
      coverage: [],
      ruleStats: [],
    });
    const line = formatStandardsCoverage(map, plain)
      .split("\n")
      .find((entry) => entry.includes("A05 "));
    expect(line).toContain("[not run]");
  });

  it("never colours `rules ran` green", () => {
    const colored = createStyle(true);
    const rows = standardsCoverage.owasp.map((entry) => ({
      ...entry,
      state: "rules_ran" as const,
    }));
    const out = formatStandardsCoverage({ ...standardsCoverage, owasp: rows }, colored);
    // ANSI green is 32; no line may carry it.
    expect(out).not.toMatch(/\u001b\[32m/);
  });

  it("matches the counts of the structured data", () => {
    const count = (state: string) =>
      standardsCoverage.cweTop25.filter((entry) => entry.state === state).length;
    expect(lines.at(-1)).toBe(
      `  CWE Top 25 2025: ${count("rules_ran")} rules ran, ${count("rules_partial")} rules partial, ${count("not_run")} not run, ${count("no_rules")} no rules`,
    );
  });
});

describe("formatScanResult standards section", () => {
  it("is shown after Coverage when the result carries it", () => {
    const text = formatScanResult({ ...testResult(), standardsCoverage }, plain);
    expect(text.indexOf("Standards coverage (OWASP Top 10 2025)")).toBeGreaterThan(
      text.indexOf("\nCoverage"),
    );
    expect(text).toContain(STANDARDS_NOTE);
  });

  it("is left out for a result without it (stored by 1.0)", () => {
    const text = formatScanResult(testResult(), plain);
    expect(text).not.toContain("Standards coverage");
  });

  it("is not shown for a blocked scan", () => {
    const text = formatScanResult(
      { ...testResult(), overallStatus: "blocked", standardsCoverage },
      plain,
    );
    expect(text).not.toContain("Standards coverage");
  });
});
