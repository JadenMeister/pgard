import { applySuppressions, type Finding, type ScanResult } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { testFinding, testResult } from "../../test-support.js";
import { formatScanResult } from "./result-view.js";
import { createStyle } from "./style.js";

const style = createStyle(false);
const NOW = new Date("2026-10-27T00:00:00Z");

const at = (path: string, overrides: Partial<Finding> = {}): Finding =>
  testFinding({
    id: `${overrides.ruleId ?? "PG-SQL-001"}-${path}`,
    location: { kind: "file", path, line: 4, url: null, commit: null },
    ...overrides,
  });

function suppressedResult(
  findings: Finding[],
  entries: Array<{ ruleId?: string; path: string; reason?: string; expires?: string }>,
  overrides: Partial<ScanResult> = {},
): ScanResult {
  const applied = applySuppressions(
    findings,
    entries.map((entry) => ({ ruleId: "PG-SQL-001", reason: "Admin-only script", ...entry })),
    NOW,
  );
  return testResult({
    findings: applied.findings,
    ...(applied.summary === null ? {} : { suppressions: applied.summary }),
    ...overrides,
  });
}

const render = (result: ScanResult, allFindings = false) =>
  formatScanResult(result, style, { allFindings });

describe("suppressed findings in the terminal result", () => {
  it("shows the count always, lists them in their own group, and keeps them out of the severity groups", () => {
    const text = render(
      suppressedResult(
        [at("src/a.ts"), at("scripts/b.ts"), at("scripts/c.ts")],
        [{ path: "scripts/**" }],
      ),
    );
    expect(text).toContain("Suppressed by pgard.config.json: 2");
    expect(text).toContain("Findings by severity (1 total) - plus 2 suppressed");
    expect(text).toContain("Suppressed (2)");
    expect(text).toContain("Findings (1):");
    // Not listed by default, but the summary names them and tells how to see all of them.
    expect(text).toContain("2 not listed here");
    expect(text).toContain("By rule: PG-SQL-001 x2");
    expect(text).toContain("--all-findings");
    expect(text).not.toContain("scripts/b.ts");
  });

  it("lists every suppressed finding with the reason from the config under --all-findings", () => {
    const text = render(
      suppressedResult(
        [at("scripts/b.ts"), at("scripts/c.ts")],
        [{ path: "scripts/**", reason: "Admin-only script", expires: "2027-01-31" }],
      ),
      true,
    );
    expect(text).toContain(
      'Reason from pgard.config.json: "Admin-only script" (expires 2027-01-31)',
    );
    expect(text).toContain("scripts/b.ts");
    expect(text).toContain("scripts/c.ts");
  });

  it("groups suppressed findings by the reason the config gave", () => {
    const text = render(
      suppressedResult(
        [at("scripts/b.ts"), at("tools/c.ts")],
        [
          { path: "scripts/**", reason: "first reason" },
          { path: "tools/**", reason: "second reason" },
        ],
      ),
      true,
    );
    expect(text).toContain('"first reason"');
    expect(text).toContain('"second reason"');
  });

  it("names the severities, warns with a ! line and always lists a critical finding in full", () => {
    const text = render(
      suppressedResult(
        [at("scripts/a.ts", { severity: "critical", title: "Hard-coded key" }), at("scripts/b.ts")],
        [{ path: "scripts/**" }],
      ),
    );
    expect(text).toContain("Suppressed by pgard.config.json: 2 (1 critical, 1 high)");
    expect(text).toContain("plus 2 suppressed (1 critical, 1 high)");
    expect(text).toMatch(/^! 2 suppressed findings are high or critical \(1 high, 1 critical\)\./m);
    // The critical one is listed in full even without --all-findings; the other is summarized.
    expect(text).toContain("Hard-coded key");
    expect(text).toContain("scripts/a.ts");
    expect(text).toContain("1 not listed here (the critical ones are above)");
    expect(text).not.toContain("scripts/b.ts");
  });

  it("flags a wildcard path and a broad match with ! lines", () => {
    const many = Array.from({ length: 12 }, (_, index) => at(`scripts/f${index}.ts`));
    const text = render(
      suppressedResult(
        [...many, at("src/a.ts", { ruleId: "PG-XSS-001" })],
        [{ path: "scripts/**" }, { ruleId: "PG-XSS-001", path: "**" }],
      ),
    );
    expect(text).toMatch(
      /^! The suppression of PG-SQL-001 for "scripts\/\*\*" matches 12 findings\./m,
    );
    expect(text).toMatch(/^! The suppression of PG-XSS-001 uses "\*\*", which matches every file/m);
  });

  it("reports an expired entry as a warning and does not suppress its findings", () => {
    const text = render(
      suppressedResult([at("scripts/a.ts")], [{ path: "scripts/**", expires: "2026-10-26" }]),
    );
    expect(text).toMatch(
      /^! The suppression of PG-SQL-001 for "scripts\/\*\*" expired on 2026-10-26 and is not applied\./m,
    );
    expect(text).toContain("Suppressed by pgard.config.json: 0");
    expect(text).toContain("Findings by severity (1 total)");
    expect(text).not.toContain("Suppressed (");
  });

  it("a config that suppresses everything stays visible: count, warning, group and listing", () => {
    const findings = [
      at("src/a.ts", { severity: "critical" }),
      at("src/b.ts"),
      at("lib/c.ts", { ruleId: "PG-XSS-001" }),
    ];
    const result = suppressedResult(findings, [
      { path: "**", reason: "all good" },
      { ruleId: "PG-XSS-001", path: "**", reason: "all good" },
    ]);
    const text = render(result);
    expect(result.findings).toHaveLength(3);
    expect(text).toContain("Suppressed by pgard.config.json: 3 (1 critical, 2 high)");
    expect(text).toMatch(
      /^! Every finding of this scan \(3\) is suppressed by pgard\.config\.json/m,
    );
    expect(text).toMatch(/^! 3 suppressed findings are high or critical \(2 high, 1 critical\)/m);
    expect(text).toContain("Suppressed (3)");
    expect(text).toContain(
      "No unsuppressed findings in the areas that ran (3 suppressed: 1 critical, 2 high)",
    );
    expect(text).toContain("src/a.ts"); // the critical one, in full
    expect(render(result, true)).toContain("lib/c.ts");
  });

  it("does not change the overall status line", () => {
    const status = (result: ScanResult) => render(result).split("\n")[0];
    const plain = testResult({ findings: [at("scripts/a.ts")] });
    const suppressed = suppressedResult([at("scripts/a.ts")], [{ path: "scripts/**" }]);
    expect(status(suppressed)).toBe(status(plain));
    const partial = suppressedResult([at("scripts/a.ts")], [{ path: "scripts/**" }], {
      overallStatus: "partial",
    });
    expect(status(partial)).toContain("Partial");
  });

  it("strips terminal control sequences from a reason", () => {
    const result = suppressedResult([at("scripts/a.ts")], [{ path: "scripts/**" }]);
    const hostile = {
      ...result,
      findings: result.findings.map((finding) => ({
        ...finding,
        suppression: {
          reason: "ok\u001b[2J\u001b]0;pwned\u0007",
          source: "pgard.config.json" as const,
        },
      })),
    };
    const text = render(hostile, true);
    expect(text).not.toContain("\u001b");
    expect(text).not.toContain("\u0007");
  });

  it("prints nothing about suppressions when the config has none", () => {
    const text = render(testResult());
    expect(text).not.toContain("Suppressed");
    expect(text).not.toContain("Baseline");
  });
});

describe("many narrow suppressions hiding high findings", () => {
  const modules = Array.from({ length: 12 }, (_, index) => `src/mod${index}`);
  const findings = [
    ...modules.map((dir) => at(`${dir}/db.ts`, { status: "confirmed" })),
    at("tests/a.test.ts", { context: "test", severity: "low", ruleId: "PG-XSS-001" }),
  ];
  const entries = modules.map((dir) => ({
    path: `${dir}/**`,
    expires: "2027-01-31",
    reason: "Reviewed, internal only",
  }));

  it("shows the severity everywhere on the terminal, with a ! notice and no bare 'No findings'", () => {
    const result = suppressedResult(findings, entries);
    const text = render(result);
    expect(text).toMatch(
      /^! 12 suppressed findings are high or critical \(12 high, 0 critical\)\./m,
    );
    expect(text).toMatch(/^! 12 findings are suppressed in total/m);
    expect(text).toContain("Suppressed by pgard.config.json: 12 (12 high)");
    expect(text).toContain("plus 1 in test or fixture code, 12 suppressed (12 high)");
    expect(result.suppressions?.bySeverity.high).toBe(12);
    // The only unsuppressed finding is in test code: the sentence says what was suppressed.
    expect(text).toContain(
      "No unsuppressed findings outside test or fixture code in the areas that ran (12 suppressed: 12 high)",
    );
  });

  it("does not warn for medium findings below the threshold", () => {
    const text = render(
      suppressedResult(
        [at("scripts/a.ts", { severity: "medium" }), at("src/a.ts")],
        [{ path: "scripts/**", expires: "2027-01-31" }],
      ),
    );
    expect(text.split("\n").filter((l) => l.startsWith("!"))).toEqual([]);
    expect(text).toContain("Suppressed by pgard.config.json: 1 (1 medium)");
  });

  it("flags a far expiry as a warning and a missing one as a quiet line", () => {
    const text = render(
      suppressedResult(
        [at("scripts/a.ts", { severity: "low" }), at("tools/a.ts", { severity: "low" })],
        [{ path: "scripts/**", expires: "9999-12-31" }, { path: "tools/**" }],
      ),
    );
    expect(text).toMatch(
      /^! The suppression of PG-SQL-001 for "scripts\/\*\*" runs until 9999-12-31, more than a year ahead/m,
    );
    expect(text).toMatch(/^ {2}1 suppression has no expiry date/m);
  });

  it("quotes the reason so it cannot fake an expiry suffix", () => {
    const text = render(
      suppressedResult(
        [at("scripts/a.ts", { severity: "low" })],
        [{ path: "scripts/**", reason: 'fine" (expires 9999-12-31', expires: "2027-01-31" }],
      ),
      true,
    );
    expect(text).toContain(String.raw`"fine\" (expires 9999-12-31" (expires 2027-01-31)`);
  });
});
