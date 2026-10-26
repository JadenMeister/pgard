import type { Coverage, Finding } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { testFinding, testResult } from "../../test-support.js";
import { COLLAPSE_THRESHOLD, groupFindings, sortBySeverity } from "./result-groups.js";
import { formatScanResult } from "./result-view.js";
import { createStyle } from "./style.js";

const plain = createStyle(false);

function at(path: string, line: number, overrides: Partial<Finding> = {}): Finding {
  return testFinding({
    id: `${path}:${line}:${overrides.ruleId ?? "r"}`,
    location: { kind: "file", path, line, url: null, commit: null },
    ...overrides,
  });
}

function testCode(count: number, ruleId = "PG-SQL-001"): Finding[] {
  return Array.from({ length: count }, (_, index) =>
    at(`test/case${index}.test.ts`, 1, {
      ruleId,
      context: "test",
      confidence: "low",
      severity: "low",
    }),
  );
}

describe("sorting", () => {
  it("orders by severity, then status, then location", () => {
    const sorted = sortBySeverity([
      at("b.ts", 1, { severity: "low", status: "confirmed" }),
      at("z.ts", 1, { severity: "critical", status: "informational" }),
      at("a.ts", 10, { severity: "high", status: "suspected" }),
      at("a.ts", 2, { severity: "high", status: "suspected" }),
      at("c.ts", 1, { severity: "high", status: "confirmed" }),
      at("m.ts", 1, { severity: "info", status: "informational" }),
      at("a.ts", 1, { severity: "medium", status: "confirmed" }),
    ]);
    expect(sorted.map((f) => `${f.location.path}:${f.location.line}`)).toEqual([
      "z.ts:1",
      "c.ts:1",
      "a.ts:2",
      "a.ts:10",
      "a.ts:1",
      "b.ts:1",
      "m.ts:1",
    ]);
  });
});

describe("grouping", () => {
  it("groups the same rule and cause across lines and files, not different causes", () => {
    const groups = groupFindings([
      at("a.ts", 1),
      at("b.ts", 5),
      at("a.ts", 9),
      at("a.ts", 3, { title: "Other cause" }),
      at("a.ts", 4, { ruleId: "PG-OTHER" }),
    ]);
    expect(groups.map((g) => g.findings.length).sort()).toEqual([1, 1, 3]);
    const big = groups.find((g) => g.findings.length === 3);
    expect(big?.findings.map((f) => `${f.location.path}:${f.location.line}`)).toEqual([
      "a.ts:1",
      "a.ts:9",
      "b.ts:5",
    ]);
  });

  it("shows the count and at most 3 locations, and every location with allFindings", () => {
    const findings = [1, 2, 3, 4, 5].map((n) => at("src/a.ts", n));
    const text = formatScanResult(testResult({ findings }), plain);
    expect(text).toContain("5 locations");
    expect(text).toContain("src/a.ts:1, src/a.ts:2, src/a.ts:3 and 2 more");
    expect(text).not.toContain("src/a.ts:4");
    expect(text).toContain("--all-findings");
    const all = formatScanResult(testResult({ findings }), plain, { allFindings: true });
    for (const n of [1, 2, 3, 4, 5]) expect(all).toContain(`src/a.ts:${n}`);
  });
});

describe("collapsing test, fixture and vendored code", () => {
  it("lists exactly 5 but collapses 6", () => {
    expect(COLLAPSE_THRESHOLD).toBe(5);
    const five = formatScanResult(testResult({ findings: testCode(5) }), plain);
    expect(five).toContain("In test or fixture code (5)");
    expect(five).not.toContain("not listed");
    const six = formatScanResult(testResult({ findings: testCode(6) }), plain);
    expect(six).toContain("6 lower-severity findings not listed");
    expect(six).not.toContain("test/case0.test.ts");
    expect(six).toContain("By context: test 6");
    expect(six).toContain("By rule: PG-SQL-001 x6");
    expect(six).toContain("--all-findings");
    expect(six).toContain("--report html");
  });

  it("counts test and vendored together, per context and per rule", () => {
    const vendored = [1, 2, 3].map((n) =>
      at(`node_modules/x/${n}.js`, 1, {
        ruleId: "PG-XSS-001",
        context: "vendored",
        severity: "low",
      }),
    );
    const text = formatScanResult(testResult({ findings: [...testCode(3), ...vendored] }), plain);
    expect(text).toContain("By context: test 3, vendored 3");
    expect(text).toContain("PG-SQL-001 x3");
    expect(text).toContain("PG-XSS-001 x3");
  });

  it("never collapses real code, however many findings", () => {
    const real = Array.from({ length: 12 }, (_, n) => at(`src/f${n}.ts`, 1, { ruleId: `R${n}` }));
    const text = formatScanResult(testResult({ findings: [...real, ...testCode(9)] }), plain);
    for (let n = 0; n < 12; n += 1) expect(text).toContain(`src/f${n}.ts:1`);
    expect(text).toContain("9 lower-severity findings not listed");
  });

  it("--all-findings shows everything", () => {
    const text = formatScanResult(testResult({ findings: testCode(9) }), plain, {
      allFindings: true,
    });
    expect(text).not.toContain("not listed");
    for (let n = 0; n < 9; n += 1) expect(text).toContain(`test/case${n}.test.ts:1`);
  });
});

describe("plain output", () => {
  it("has no escape codes without color and keeps a readable layout", () => {
    const text = formatScanResult(
      testResult({
        findings: [
          at("src/a.ts", 3, { severity: "critical", status: "confirmed", title: "Leaked key" }),
          at("src/b.ts", 4),
          ...testCode(6),
        ],
      }),
      plain,
    );
    expect(text).not.toContain("\u001b");
    expect(text.indexOf("Leaked key")).toBeLessThan(text.indexOf("User input concatenated"));
    expect(text).toMatchInlineSnapshot(`
      "PGARD scan result - Completed
      Repository owner/name @ abcdef123456 - scopes: code, history

      Summary
        Areas    2 scanned: 2 completed
        Elapsed  5.0 s

      Findings by severity (2 total) - plus 6 in test or fixture code
        Critical ############################## 1
        High     ############################## 1
        Medium   0
        Low      0
        Info     0

      By OWASP Top 10 2025 category
        No OWASP mapping ############################## 2

      By area
        code    ############################## 2
        history 0

      Findings (2): 1 confirmed, 1 suspected (needs review)
        [CRITICAL] Leaked key (confirmed)
            src/a.ts:3  PG-SQL-001 - confidence medium
            Evidence: req.query -> concat -> query()
            Fix: Use parameters

        [HIGH] User input concatenated into SQL (suspected)
            src/b.ts:4  PG-SQL-001 - confidence medium
            Evidence: req.query -> concat -> query()
            Fix: Use parameters

      Test, fixture and vendored code (6 lower-severity findings not listed)
        Collapsed because there are more than 5 in this code. Findings in your own code, and critical or high findings anywhere, are always listed. Review these too: a real value committed in a test is still exposed.
        By context: test 6
        By rule: PG-SQL-001 x6
        By severity: Low 6
        Run again with --all-findings to list everything, or save a report (--report html --output-dir <dir>).

      Coverage
        [ok] source:typescript (Completed)
        [ok] history:secrets (Completed)

      PGARD does not ship or query a vulnerability database. Findings come from the code itself (query statements, server code, configuration), Git history and, if selected, local HTTP checks. Dependency versions are not checked against known vulnerabilities."
    `);
  });
});

describe("severe findings in test code", () => {
  it("lists a critical finding in a test file with its location while 5 lows collapse", () => {
    const text = formatScanResult(
      testResult({
        findings: [
          at("src/auth.test.ts", 12, {
            ruleId: "PG-SECRET-001",
            title: "Hardcoded API key",
            severity: "critical",
            status: "confirmed",
            context: "test",
            confidence: "low",
          }),
          ...testCode(5),
        ],
      }),
      plain,
    );
    expect(text).toContain("src/auth.test.ts:12");
    expect(text).toContain("Hardcoded API key");
    expect(text).toContain("5 lower-severity findings not listed");
    expect(text).not.toContain("test/case0.test.ts");
    expect(text).toContain("plus 6 in test or fixture code (1 critical)");
    expect(text).toContain("a real value committed in a test is still exposed");
  });

  it("lists high findings in vendored code even when the rest collapses", () => {
    const text = formatScanResult(
      testResult({
        findings: [
          at("node_modules/x/a.js", 3, {
            context: "vendored",
            severity: "high",
            confidence: "low",
          }),
          ...testCode(5),
        ],
      }),
      plain,
    );
    expect(text).toContain("node_modules/x/a.js:3");
    expect(text).toContain("5 lower-severity findings not listed");
  });
});

describe("evidence in groups", () => {
  const varied = [
    at("a.ts", 1, { evidence: "first evidence" }),
    at("b.ts", 2, { evidence: "second evidence" }),
  ];

  it("says the evidence varies instead of showing only the first", () => {
    const text = formatScanResult(testResult({ findings: varied }), plain);
    expect(text).toContain("Evidence: varies by location");
    expect(text).not.toContain("first evidence");
  });

  it("shows the shared evidence when every member agrees", () => {
    const text = formatScanResult(testResult({ findings: [at("a.ts", 1), at("b.ts", 2)] }), plain);
    expect(text).toContain("Evidence: req.query -> concat -> query()");
  });

  it("prints each location with its own evidence under allFindings", () => {
    const text = formatScanResult(testResult({ findings: varied }), plain, {
      allFindings: true,
    });
    expect(text).toContain("- a.ts:1\n          Evidence: first evidence");
    expect(text).toContain("- b.ts:2\n          Evidence: second evidence");
  });
});

describe("headline status counts", () => {
  it("names the number of confirmed and suspected findings", () => {
    const text = formatScanResult(
      testResult({
        findings: [
          at("a.ts", 1, { status: "confirmed", severity: "critical", title: "K" }),
          at("b.ts", 1),
          at("c.ts", 1),
        ],
      }),
      plain,
    );
    expect(text).toContain("Findings (3): 1 confirmed, 2 suspected (needs review)");
  });
});

describe("project configuration notices", () => {
  const withCoverage = (...entries: Coverage[]) =>
    testResult({ overallStatus: "partial", coverage: entries });
  const area = (name: string, status: Coverage["status"], note: string): Coverage => ({
    area: name,
    scope: "code",
    status,
    ruleIds: [],
    note,
  });

  it("shows a prominent line above the findings when files were excluded", () => {
    const text = formatScanResult(
      withCoverage(
        area(
          "source:config-excluded",
          "completed",
          "3 files excluded by pgard.config.json (of 9).",
        ),
      ),
      plain,
    );
    const line = text
      .split("\n")
      .findIndex((l) => l.startsWith("! 3 files excluded by pgard.config.json"));
    expect(line).toBeGreaterThan(0);
    expect(line).toBeLessThan(
      text.split("\n").findIndex((l) => l.startsWith("Findings by severity")),
    );
  });

  it("shows warnings and an ignored invalid config prominently", () => {
    const text = formatScanResult(
      withCoverage(
        area(
          "source:config-excluded",
          "partial",
          "9 files excluded by pgard.config.json. WARNING: x",
        ),
        area("source:config", "partial", "pgard.config.json is invalid and was ignored; reason."),
      ),
      plain,
    );
    expect(text).toContain("! 9 files excluded by pgard.config.json. WARNING: x");
    expect(text).toContain("! pgard.config.json is invalid and was ignored; reason.");
  });

  it("is quiet when nothing was excluded and the config is fine", () => {
    const text = formatScanResult(
      withCoverage(
        area("source:config-excluded", "completed", "0 files excluded by pgard.config.json."),
        area("source:config", "completed", "pgard.config.json read."),
      ),
      plain,
    );
    expect(text).not.toContain("! ");
  });

  it("strips terminal control characters from hostile patterns in the note", () => {
    const text = formatScanResult(
      withCoverage(
        area(
          "source:config-excluded",
          "completed",
          "1 file excluded by pgard.config.json: \u001b[2J\u001b]0;pwned\u0007",
        ),
      ),
      plain,
    );
    expect(text).not.toContain("\u001b");
    expect(text).not.toContain("\u0007");
  });
});

describe("testDirectories notices", () => {
  const coverage: Coverage[] = [
    {
      area: "source:config",
      scope: "code",
      status: "completed",
      ruleIds: [],
      note: "pgard.config.json read (version 1): 0 exclude patterns, 1 test directory pattern (3 findings classified as test code by it), 0 suppressions parsed, not yet applied.",
    },
  ];

  it("says so with a ! line whenever the config reclassified findings, even when completed", () => {
    const findings = testCode(3);
    const text = formatScanResult(testResult({ coverage, findings }), plain);
    expect(text).toContain(
      "! 3 findings were classified as test code by the testDirectories setting of pgard.config.json",
    );
    expect(text).toContain("3 of them were classified by the testDirectories setting");
  });

  it("keeps the notice when the test findings are collapsed into a count", () => {
    const text = formatScanResult(testResult({ coverage, findings: testCode(8) }), plain);
    expect(text).toContain("lower-severity findings not listed");
    expect(text).toContain("! 3 findings were classified as test code");
  });

  it("no notice when the config reclassified nothing", () => {
    const quiet = coverage.map((entry) => ({
      ...entry,
      note: (entry.note ?? "").replace("3 findings", "0 findings"),
    }));
    expect(
      formatScanResult(testResult({ coverage: quiet, findings: testCode(2) }), plain),
    ).not.toContain("! ");
  });
});
