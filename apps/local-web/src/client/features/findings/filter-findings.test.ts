import type { Finding } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import {
  countBySeverity,
  EMPTY_FILTERS,
  filterFindings,
  formatLocation,
  formatContextCounts,
  formatOutsideContexts,
  splitByContext,
} from "./filter-findings";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "f",
    ruleId: "PG-SQL-001",
    title: "SQL",
    category: "injection",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    location: { kind: "file", path: "src/a.ts", line: 3, url: null, commit: null },
    evidence: "",
    impact: "",
    recommendation: "",
    references: { cwe: [], owasp: [], cve: [] },
    sources: ["code"],
    ...overrides,
  };
}

const FINDINGS = [
  finding({
    id: "a",
    severity: "low",
    status: "informational",
    sources: ["web"],
    ruleId: "PG-WEB-001",
    location: { kind: "url", path: null, line: null, url: "http://127.0.0.1:3000/", commit: null },
  }),
  finding({
    id: "b",
    severity: "critical",
    status: "confirmed",
    ruleId: "PG-SECRET-001",
    sources: ["history"],
  }),
  finding({ id: "c" }),
];

describe("filterFindings", () => {
  it("sorts by severity and filters by severity, status, source and text", () => {
    expect(filterFindings(FINDINGS, EMPTY_FILTERS).map((entry) => entry.id)).toEqual([
      "b",
      "c",
      "a",
    ]);
    expect(
      filterFindings(FINDINGS, { ...EMPTY_FILTERS, severity: "low" }).map((entry) => entry.id),
    ).toEqual(["a"]);
    expect(
      filterFindings(FINDINGS, { ...EMPTY_FILTERS, source: "history" }).map((entry) => entry.id),
    ).toEqual(["b"]);
    expect(
      filterFindings(FINDINGS, { ...EMPTY_FILTERS, status: "suspected" }).map((entry) => entry.id),
    ).toEqual(["c"]);
    expect(
      filterFindings(FINDINGS, { ...EMPTY_FILTERS, text: "127.0.0.1" }).map((entry) => entry.id),
    ).toEqual(["a"]);
  });

  it("counts per severity and formats locations", () => {
    expect(countBySeverity(FINDINGS)).toEqual({ critical: 1, high: 1, medium: 0, low: 1, info: 0 });
    expect(formatLocation(FINDINGS[2]!.location)).toBe("src/a.ts:3");
    expect(formatLocation(FINDINGS[0]!.location)).toBe("http://127.0.0.1:3000/");
  });

  it("splits test or fixture findings from regular ones without dropping any", () => {
    const test = finding({ id: "t", context: "test", confidence: "low" });
    const { primary, test: tests } = splitByContext([...FINDINGS, test]);
    expect(primary.map((entry) => entry.id)).toEqual(FINDINGS.map((entry) => entry.id));
    expect(tests).toEqual([test]);
  });

  it("splits vendored suggestions from test and regular findings without dropping any", () => {
    const test = finding({ id: "t", context: "test", confidence: "low" });
    const vendored = finding({
      id: "v",
      context: "vendored",
      confidence: "low",
      location: {
        kind: "file",
        path: "node_modules/pkg/index.js",
        line: 1,
        url: null,
        commit: null,
      },
    });
    const groups = splitByContext([vendored, ...FINDINGS, test]);
    expect(groups.primary.map((entry) => entry.id)).toEqual(FINDINGS.map((entry) => entry.id));
    expect(groups.test).toEqual([test]);
    expect(groups.vendored).toEqual([vendored]);
    // Headline counts use regular code only.
    expect(countBySeverity(groups.primary)).toEqual(countBySeverity(FINDINGS));
  });

  it("words the headline addition like the CLI and reports", () => {
    expect(formatContextCounts({ test: 0, vendored: 0 })).toBe("");
    expect(formatContextCounts({ test: 2, vendored: 0 })).toBe("plus 2 in test or fixture code");
    expect(formatContextCounts({ test: 0, vendored: 1 })).toBe(
      "plus 1 suggestion in vendored code",
    );
    expect(formatContextCounts({ test: 1, vendored: 3 })).toBe(
      "plus 1 in test or fixture code, 3 suggestions in vendored code",
    );
    expect(formatOutsideContexts({ test: 0, vendored: 0 })).toBe("");
    expect(formatOutsideContexts({ test: 1, vendored: 0 })).toBe(" outside test or fixture code");
    expect(formatOutsideContexts({ test: 0, vendored: 1 })).toBe(" outside vendored code");
    expect(formatOutsideContexts({ test: 1, vendored: 1 })).toBe(
      " outside test, fixture or vendored code",
    );
  });
});
