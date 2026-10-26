import {
  compareScans,
  computeStandardsCoverage,
  type Coverage,
  type Finding,
  type RuleStat,
  type ScanResult,
} from "@pgard/findings";
import { listSupportedRules } from "@pgard/scan-core";
import { describe, expect, it } from "vitest";
import { getRuleTextCatalog } from "../../rule-texts.js";
import { testFinding, testResult } from "../../test-support.js";
import { displayWidth } from "../i18n/display-width.js";
import { formatScanResult, type ScanResultOptions } from "./result-view.js";
import { createStyle } from "./style.js";

const plain = createStyle(false);
const colored = createStyle(true);
const ESC = String.fromCharCode(27);
const GREEN = `${ESC}[32m`;

const coverage: Coverage[] = [
  {
    area: "source:typescript",
    scope: "code",
    status: "completed",
    ruleIds: ["PG-SQL-001", "PG-XSS-001"],
    note: null,
  },
  {
    area: "history:commits",
    scope: "history",
    status: "partial",
    ruleIds: ["PG-SECRET-003"],
    note: null,
  },
  { area: "web:anonymous", scope: "web", status: "not_selected", ruleIds: [], note: null },
];
const ruleStats: RuleStat[] = [
  {
    ruleId: "PG-SQL-001",
    area: "source:typescript",
    scope: "code",
    status: "completed",
    targets: [{ unit: "files", examined: 152, reason: null }],
    findings: 1,
  },
  {
    ruleId: "PG-XSS-001",
    area: "source:typescript",
    scope: "code",
    status: "completed",
    targets: [{ unit: "files", examined: 120, reason: null }],
    findings: 0,
  },
  {
    ruleId: "PG-SECRET-003",
    area: "history:commits",
    scope: "history",
    status: "partial",
    targets: [
      { unit: "commits", examined: 340, reason: null },
      { unit: "files", examined: 90, reason: null },
    ],
    findings: 1,
  },
];

function at(path: string, overrides: Partial<Finding> = {}): Finding {
  return testFinding({
    id: `${path}:${overrides.ruleId ?? "r"}`,
    location: { kind: "file", path, line: 3, url: null, commit: null },
    ...overrides,
  });
}

const real: Finding[] = [
  at("src/api/users.ts", {
    ruleId: "PG-SQL-001",
    severity: "critical",
    status: "confirmed",
    references: { cwe: ["CWE-89"], owasp: ["A05:2025"], cve: [] },
  }),
  at("src/view.ts", {
    ruleId: "PG-XSS-001",
    title: "User input rendered as HTML",
    severity: "medium",
    references: { cwe: ["CWE-79"], owasp: ["A05:2025"], cve: [] },
  }),
  at("config.js", {
    ruleId: "PG-SECRET-003",
    title: "Secret in history",
    severity: "high",
    sources: ["history"],
    location: { kind: "commit", path: "config.js", line: 3, url: null, commit: "abcdef0123456" },
    references: { cwe: [], owasp: [], cve: [] },
  }),
];

function testCode(count: number): Finding[] {
  return Array.from({ length: count }, (_, index) =>
    at(`test/case${index}.test.ts`, {
      ruleId: "PG-SQL-001",
      context: "test",
      confidence: "low",
      severity: "low",
    }),
  );
}

function fixture(overrides: Partial<ScanResult> = {}): ScanResult {
  const standardsCoverage = computeStandardsCoverage({
    rules: listSupportedRules(),
    coverage,
    ruleStats,
  });
  return testResult({
    coverage,
    ruleStats,
    standardsCoverage,
    findings: real,
    ...overrides,
  });
}

const previous = testResult({
  scanId: "scan-0",
  coverage,
  findings: [real[0] as Finding, at("src/old.ts", { ruleId: "PG-SQL-001" })],
});

function options(extra: ScanResultOptions = {}): ScanResultOptions {
  return { ruleTexts: getRuleTextCatalog(), width: 80, ...extra };
}

function withDiff(result: ScanResult): ScanResultOptions["diff"] {
  return {
    comparison: compareScans(previous, result),
    previousSavedAt: new Date(2026, 9, 25, 14, 2),
  };
}

/** Local times differ by timezone. */
const stable = (text: string): string => text.replace(/\d{4}-\d\d-\d\d \d\d:\d\d/g, "<time>");

describe("result screen, English", () => {
  const result = fixture();
  const text = stable(formatScanResult(result, plain, options({ diff: withDiff(result) })));

  it("matches the reviewed layout", () => {
    expect(text).toMatchSnapshot();
  });

  it("opens with a summary of areas, rules, target size, time and the last scan", () => {
    expect(text).toContain("Summary");
    expect(text).toMatch(/Areas +2 scanned: 1 completed, 1 partial \(1 not selected\)/);
    expect(text).toMatch(/Rules +3 rules ran \(1 in partially scanned areas\)/);
    expect(text).toMatch(/Target size +152 files, 340 commits/);
    expect(text).toMatch(/Elapsed +5\.0 s/);
    expect(text).toMatch(/Since last scan +\+2 new \/ -1 no longer reported/);
  });

  it("charts severity, OWASP category and area", () => {
    expect(text).toContain("Findings by severity (3 total)");
    expect(text).toContain("By OWASP Top 10 2025 category");
    expect(text).toMatch(/A05 Injection +#+ 2/);
    expect(text).toContain("No OWASP mapping");
    expect(text).toContain("By area");
    expect(text).toMatch(/code +#+ 2/);
    expect(text).toMatch(/history +#+ 1/);
  });

  it("lists findings worst first with evidence, fix and standards links", () => {
    expect(text.indexOf("[CRITICAL]")).toBeLessThan(text.indexOf("[HIGH]"));
    expect(text.indexOf("[HIGH]")).toBeLessThan(text.indexOf("[MEDIUM]"));
    expect(text).toContain("Evidence: req.query -> concat -> query()");
    expect(text).toContain("Fix: Use parameters");
    expect(text).toMatch(/Standards:\n\s+A05:2025 Injection https:\/\/top10\.owasp\.org\//);
    expect(text).toMatch(/CWE-89 .*https:\/\/cwe\.mitre\.org\//);
  });

  it("describes the standards map with the four states and no claim of safety", () => {
    const section = text.slice(text.indexOf("Standards coverage"));
    const lines = section.split("\n").filter((line) => /^ {2}\[/.test(line));
    expect(lines.length).toBeGreaterThan(5);
    for (const line of lines) {
      expect(line).toMatch(/^ {2}\[(rules ran|rules partial|not run|no rules)\]/);
      expect(line).not.toMatch(/covered|checked|safe/i);
    }
  });
});

describe("result screen, Korean", () => {
  const result = fixture();
  const text = stable(
    formatScanResult(result, plain, options({ locale: "ko", diff: withDiff(result) })),
  );

  it("matches the reviewed layout", () => {
    expect(text).toMatchSnapshot();
  });

  it("translates the fixed text of the screen", () => {
    for (const phrase of [
      "PGARD 검사 결과 - 완료",
      "저장소 owner/name",
      "요약",
      "소요 시간",
      "+2 신규 / -1 더 이상 보고되지 않음",
      "OWASP Top 10 2025 분류별",
      "영역별",
      "근거: ",
      "조치: ",
      "검사 범위",
      "표준 매핑 현황",
      "[규칙 실행됨]",
    ]) {
      expect(text, phrase).toContain(phrase);
    }
  });

  it("keeps English where the text is not PGARD's wording", () => {
    // Paths, evidence and the standards' own titles and links are shown as they are.
    expect(text).toContain("src/api/users.ts:3");
    expect(text).toContain("https://top10.owasp.org/");
    expect(text).not.toContain("Findings by severity");
    expect(text).not.toContain("Evidence:");
  });

  it("aligns the summary values in one column even with two-column characters", () => {
    const rows = text
      .split("\n")
      .slice(text.split("\n").indexOf("요약") + 1)
      .filter((line) => /^ {2}\S/.test(line))
      .slice(0, 5);
    expect(rows.length).toBe(5);
    const valueColumns = rows.map((line) => {
      const match = /^( {2}.+?)( {2,})\S/.exec(line);
      return displayWidth(`${match?.[1] ?? ""}${match?.[2] ?? ""}`);
    });
    expect(new Set(valueColumns).size).toBe(1);
  });

  it("does not claim safety or coverage in the standards map", () => {
    const section = text.slice(text.indexOf("표준 매핑 현황"));
    const lines = section.split("\n").filter((line) => /^ {2}\[/.test(line));
    expect(lines.length).toBeGreaterThan(5);
    for (const line of lines) {
      expect(line).toMatch(/^ {2}\[(규칙 실행됨|규칙 일부 실행|실행 안 됨|규칙 없음)\]/);
      expect(line).not.toMatch(/안전|검사 완료/);
    }
  });
});

describe("colour, NO_COLOR and narrow terminals", () => {
  const result = fixture();

  it("has no escape codes and # bars without colour (NO_COLOR, pipes)", () => {
    const text = formatScanResult(result, plain, options());
    expect(text).not.toContain(ESC);
    expect(text).toMatch(/Critical #+ 1/);
  });

  it("uses block bars with colour, and never green in the standards map", () => {
    const text = formatScanResult(result, colored, options());
    expect(text).toContain(ESC);
    expect(text).toContain("\u2588");
    const section = text.slice(text.indexOf("Standards coverage"));
    expect(section).not.toContain(GREEN);
  });

  it("shows plain count lines under 60 columns, in both languages", () => {
    for (const locale of ["en", "ko"] as const) {
      const text = formatScanResult(result, colored, options({ width: 50, locale }));
      const chart = text.split("\n").filter((line) => /^ {2}\S.* \d+$/.test(line));
      expect(chart.length).toBeGreaterThan(5);
      expect(text).not.toContain("\u2588");
      expect(text).not.toMatch(/#{3,}/);
    }
  });

  it("keeps every chart row inside a 60 column terminal", () => {
    const text = formatScanResult(result, plain, options({ width: 60, locale: "ko" }));
    const rows = text.split("\n").filter((line) => /#/.test(line) && /\d$/.test(line));
    expect(rows.length).toBeGreaterThan(3);
    for (const row of rows) expect(displayWidth(row)).toBeLessThanOrEqual(60);
  });
});

describe("grouped test findings", () => {
  const withTests = (count: number, extra: Partial<ScanResult> = {}) =>
    fixture({ findings: [...real, ...testCode(count)], ...extra });

  it("collapses more than 5 and says how many, in English", () => {
    const text = formatScanResult(withTests(8), plain, options());
    expect(text).toContain(
      "Test, fixture and vendored code (8 lower-severity findings not listed)",
    );
    expect(text).toContain("Collapsed because there are more than 5");
    expect(text).toContain("By context: test 8");
    expect(text).toContain("--all-findings");
    expect(text).not.toContain("test/case0.test.ts");
  });

  it("collapses more than 5 and says how many, in Korean", () => {
    const text = formatScanResult(withTests(8), plain, options({ locale: "ko" }));
    expect(text).toContain(
      "테스트·fixture·vendored 코드 (심각도가 낮은 발견 항목 8건은 나열하지 않음)",
    );
    expect(text).toContain("이 코드의 항목이 5건을 넘어 접었습니다");
    expect(text).toContain("분류별: 테스트 8");
    expect(text).toContain("--all-findings");
    expect(text).not.toContain("test/case0.test.ts");
  });

  it("lists exactly 5 in full", () => {
    const text = formatScanResult(withTests(5), plain, options());
    expect(text).toContain("In test or fixture code (5)");
    expect(text).not.toContain("lower-severity findings not listed");
  });

  it("includes the testDirectories note in Korean as well as English", () => {
    const config: Coverage = {
      area: "source:config",
      scope: "code",
      status: "completed",
      ruleIds: [],
      note: "pgard.config.json read (3 findings classified as test code by it)",
    };
    const result = withTests(2, { coverage: [...coverage, config] });
    const en = formatScanResult(result, plain, options());
    const ko = formatScanResult(result, plain, options({ locale: "ko" }));
    expect(en).toContain(
      "3 of them were classified by the testDirectories setting of pgard.config.json",
    );
    expect(ko).toContain(
      "그중 3건은 기본 규칙이 아니라 pgard.config.json의 testDirectories 설정으로 분류되었습니다",
    );
    expect(ko).toContain(
      "! 발견 항목 3건이 pgard.config.json의 testDirectories 설정으로 테스트 코드로 분류되었습니다",
    );
  });
});

describe("last scan", () => {
  it("shows +N new / -N no longer reported next to the summary", () => {
    const result = fixture();
    const text = stable(formatScanResult(result, plain, options({ diff: withDiff(result) })));
    expect(text).toContain("+2 new / -1 no longer reported");
    expect(text).toContain("<time>");
  });

  it("omits the row without an earlier scan", () => {
    const text = formatScanResult(fixture(), plain, options({ diff: null }));
    expect(text).not.toContain("Since last scan");
  });

  it("says when some areas could not be compared", () => {
    const result = fixture();
    const partialPrevious = testResult({
      scanId: "scan-0",
      coverage: coverage.map((entry) => ({ ...entry, status: "partial" as const })),
      findings: [],
    });
    const diff = {
      comparison: compareScans(partialPrevious, result),
      previousSavedAt: new Date(2026, 9, 25, 14, 2),
    };
    expect(formatScanResult(result, plain, options({ diff }))).toContain("not fully compared");
    expect(formatScanResult(result, plain, options({ diff, locale: "ko" }))).toContain(
      "완전히 비교하지 못함",
    );
  });
});

describe("older results", () => {
  it("leaves out the rows it has no data for", () => {
    const old = testResult({ ruleStats: undefined, standardsCoverage: undefined });
    const text = formatScanResult(old, plain, options());
    expect(text).toContain("Areas");
    expect(text).not.toContain("Rules ");
    expect(text).not.toContain("Target size");
    expect(text).not.toContain("Standards coverage");
  });
});
