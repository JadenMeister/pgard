/// <reference types="node" />
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  computeStandardsCoverage,
  type Finding,
  type RuleStat,
  type ScanResult,
} from "@pgard/findings";
import type { RuleTextsResponse } from "../../../shared/api-types";
import { I18nProvider } from "../../i18n/I18nProvider";
import { FindingsDashboard } from "../findings/FindingsDashboard";
import { ExternalLink, isOfficialStandardsUrl } from "./ExternalLink";
import { RuleStatsPanel } from "./RuleStatsPanel";
import { StandardsCoveragePanel } from "./StandardsCoveragePanel";

const VULNERABLE = `q(\`SELECT * FROM t WHERE a = '\${a}'\`); // <img src=x onerror=alert(1)>`;
const SAFE = `q('SELECT * FROM t WHERE a = $1', [a]); // "quoted" & <b>`;

const TEXTS: RuleTextsResponse = {
  "PG-SQL-001": {
    title: { en: "SQL from dynamic strings", ko: "동적 문자열로 만든 SQL" },
    impact: { en: "Query may change", ko: "쿼리가 바뀔 수 있습니다" },
    recommendation: { en: "Use parameters", ko: "매개변수를 사용하세요" },
    details: {
      rationale: { en: "Query may change", ko: "쿼리가 바뀔 수 있습니다" },
      remediation: { en: "Use parameters", ko: "매개변수를 사용하세요" },
      standards: [
        {
          kind: "owasp",
          id: "A05:2025",
          title: "Injection",
          url: "https://top10.owasp.org/2025/A05_2025-Injection/",
        },
        {
          kind: "cwe",
          id: "CWE-89",
          title: null,
          url: "https://cwe.mitre.org/data/definitions/89.html",
        },
        {
          kind: "cert",
          id: "IDS00-J",
          title: "Prevent SQL injection",
          url: "https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/x/ids00-j",
          viaCwe: "CWE-89",
        },
      ],
      examples: [
        {
          language: "javascript",
          vulnerable: VULNERABLE,
          safe: SAFE,
          note: { en: "A quote changes the query.", ko: "따옴표가 쿼리를 바꿉니다." },
        },
      ],
    },
  },
};

const FINDING: Finding = {
  id: "f1",
  ruleId: "PG-SQL-001",
  title: "SQL from dynamic strings",
  category: "injection",
  severity: "high",
  status: "suspected",
  confidence: "medium",
  location: { kind: "file", path: "src/a.ts", line: 3, url: null, commit: null },
  evidence: "concat (value redacted)",
  impact: "Query may change",
  recommendation: "Use parameters",
  references: { cwe: [], owasp: [], cve: [] },
  sources: ["code"],
};

const STATS: RuleStat[] = [
  {
    ruleId: "PG-SQL-001",
    area: "source:typescript",
    scope: "code",
    status: "completed",
    targets: [{ unit: "files", examined: 12, reason: null }],
    findings: 1,
  },
  {
    ruleId: "PG-XSS-001",
    area: "source:typescript",
    scope: "code",
    status: "partial",
    targets: [{ unit: "files", examined: null, reason: "not counted" }],
    findings: 0,
  },
];

const COVERAGE: ScanResult["coverage"] = [
  {
    area: "source:typescript",
    scope: "code",
    status: "completed",
    ruleIds: ["PG-SQL-001", "PG-XSS-001"],
    note: null,
  },
];

const RULES = [
  {
    id: "PG-SQL-001",
    scope: "code",
    metadata: { standards: { owasp: ["A05:2025"], cwe: ["CWE-89"] } },
  },
  {
    id: "PG-XSS-001",
    scope: "code",
    metadata: { standards: { owasp: ["A05:2025"], cwe: ["CWE-79"] } },
  },
] as const;

function mapFor(coverage: ScanResult["coverage"], ruleStats: RuleStat[]) {
  return computeStandardsCoverage({ rules: RULES, coverage, ruleStats });
}

function resultV11(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    schemaVersion: "1.4",
    scanId: "s1",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "o/n", revision: "abc", webOrigin: null },
    authorization: { decision: "allowed", checks: [] },
    coverage: COVERAGE,
    advisoryDb: { version: null, updatedAt: null },
    findings: [FINDING],
    ruleStats: STATS,
    standardsCoverage: mapFor(COVERAGE, STATS),
    ...overrides,
  } as ScanResult;
}

function resultV10(): ScanResult {
  const { ruleStats: _ruleStats, standardsCoverage: _standards, ...rest } = resultV11();
  return { ...rest, schemaVersion: "1.0" } as unknown as ScanResult;
}

function withLanguage(language: "en" | "ko", node: React.ReactElement): string {
  vi.stubGlobal("navigator", { languages: [language === "ko" ? "ko-KR" : "en-US"] });
  return renderToStaticMarkup(<I18nProvider>{node}</I18nProvider>);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("finding details in the dashboard", () => {
  for (const language of ["en", "ko"] as const) {
    it(`shows standards links, examples as text and attribution-free details (${language})`, () => {
      const html = withLanguage(
        language,
        <FindingsDashboard result={resultV11()} ruleTexts={TEXTS} />,
      );
      expect(html).toContain('href="https://top10.owasp.org/2025/A05_2025-Injection/"');
      expect(html).toContain('href="https://cwe.mitre.org/data/definitions/89.html"');
      expect(html).toContain("cmu-sei.github.io/secure-coding-standards/");
      for (const anchor of html.match(/<a [^>]*>/g) ?? []) {
        expect(anchor).toContain('rel="noopener noreferrer"');
        expect(anchor).toContain('target="_blank"');
      }
      // Code is React text: escaped, never markup.
      expect(html).not.toContain("<img src=x");
      expect(html).not.toContain("<b>");
      expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
      expect(html).toContain("&quot;quoted&quot; &amp; &lt;b&gt;");
      expect(html).toContain(language === "en" ? "Examples (1)" : "예시 (1)");
      expect(html).toContain(language === "en" ? "(indirect, via CWE-89)" : "(간접, CWE-89 경유)");
      expect(html).toContain(language === "en" ? "Vulnerable" : "취약한 코드");
      // The examples sit in a collapsed details element.
      expect(html).toMatch(/<details class="rule-examples">/);
    });
  }

  it("adds the rule's general text only when the finding carries its own different text", () => {
    const own = { ...resultV11(), findings: [{ ...FINDING, recommendation: "Do X here" }] };
    const html = withLanguage("ko", <FindingsDashboard result={own} ruleTexts={TEXTS} />);
    expect(html).toContain("Do X here");
    expect(html).toContain("일반적인 조치");
    expect(
      withLanguage("ko", <FindingsDashboard result={resultV11()} ruleTexts={TEXTS} />),
    ).not.toContain("일반적인 조치");
  });

  it("renders without rule details (texts not loaded, or a 1.0 result)", () => {
    const loading = withLanguage("en", <FindingsDashboard result={resultV11()} ruleTexts={null} />);
    expect(loading).not.toContain("Examples");
    const old = withLanguage("en", <FindingsDashboard result={resultV10()} ruleTexts={TEXTS} />);
    expect(old).toContain("SQL from dynamic strings");
  });
});

describe("standards coverage panel", () => {
  for (const language of ["en", "ko"] as const) {
    it(`renders states, breadth, links and attribution (${language})`, () => {
      const html = withLanguage(language, <StandardsCoveragePanel result={resultV11()} />);
      const ran = language === "en" ? "Rules ran" : "규칙 실행됨";
      const none = language === "en" ? "No rules" : "규칙 없음";
      expect(html).toContain(
        language === "en" ? "Standards coverage (OWASP Top 10 2025)" : "표준 매핑 현황",
      );
      expect(html).toMatch(new RegExp(`A05[^]*Injection[^]*state-rules_ran">${ran}`));
      expect(html).toContain(`state-no_rules">${none}`);
      expect(html).toMatch(
        language === "en"
          ? /\d+ of \d+ mapped CWEs have rules/
          : /매핑된 CWE \d+개 중 \d+개에 규칙이 있음/,
      );
      expect(html).toContain(
        language === "en" ? "does not mean the project is safe" : "안전하다거나",
      );
      expect(html).toContain('href="https://top10.owasp.org/2025/A05_2025-Injection/"');
      expect(html).toContain('href="https://cwe.mitre.org/data/definitions/79.html"');
      expect(html).toContain("CC BY-SA 4.0");
      expect(html).toContain("The MITRE Corporation");
      // Neutral: no green anywhere in the panel's markup.
      expect(html).not.toMatch(/green/i);
    });
  }

  it("links only well-formed CWE ids in the Top 25 table", () => {
    const result = resultV11();
    const map = result.standardsCoverage!;
    const entry = map.cweTop25[0]!;
    const forged = {
      ...result,
      standardsCoverage: {
        ...map,
        cweTop25: [{ ...entry, id: "CWE-79/../../x" }, { ...entry, id: "CWE-0" }, entry],
      },
    } as ScanResult;
    const html = withLanguage("en", <StandardsCoveragePanel result={forged} />);
    expect(html).not.toContain("CWE-79/../../x.html");
    expect(html).not.toContain("definitions/0.html");
    expect(html).toContain(`definitions/${entry.id.slice(4)}.html`);
  });

  it("shows each of the four states with its own badge", () => {
    const partialCoverage = [{ ...COVERAGE[0]!, status: "partial" as const }];
    const partialStats = STATS.map((stat) => ({ ...stat, status: "partial" as const }));
    const partial = resultV11({ standardsCoverage: mapFor(partialCoverage, partialStats) });
    const html = withLanguage("en", <StandardsCoveragePanel result={partial} />);
    expect(html).toContain("state-rules_partial");
    expect(html).toContain("Rules partial");
    const none = withLanguage(
      "en",
      <StandardsCoveragePanel result={resultV11({ standardsCoverage: mapFor([], []) })} />,
    );
    expect(none).toContain("state-not_run");
    expect(none).toContain("Not run");
  });

  it("says that a 1.0 result has no standards data", () => {
    expect(withLanguage("en", <StandardsCoveragePanel result={resultV10()} />)).toContain(
      "were not recorded",
    );
    expect(withLanguage("ko", <StandardsCoveragePanel result={resultV10()} />)).toContain(
      "기록되어 있지 않습니다",
    );
  });
});

describe("rule statistics panel", () => {
  it("renders targets, findings and status per rule and area (en)", () => {
    const html = withLanguage("en", <RuleStatsPanel result={resultV11()} ruleTexts={TEXTS} />);
    expect(html).toContain("Rule statistics (2)");
    expect(html).toContain("<th>Targets examined</th>");
    expect(html).toContain("12 files");
    expect(html).toContain("unknown (not counted)");
    expect(html).toContain("SQL from dynamic strings");
    expect(html).toContain("source:typescript");
  });

  it("renders in Korean", () => {
    const html = withLanguage("ko", <RuleStatsPanel result={resultV11()} ruleTexts={TEXTS} />);
    expect(html).toContain("규칙 통계 (2)");
    expect(html).toContain("<th>살펴본 대상</th>");
    expect(html).toContain("files 12개");
    expect(html).toContain("알 수 없음 (not counted)");
    expect(html).toContain("동적 문자열로 만든 SQL");
  });

  it("renders nothing for a 1.0 result", () => {
    expect(withLanguage("en", <RuleStatsPanel result={resultV10()} ruleTexts={null} />)).toBe("");
  });
});

describe("external links", () => {
  it("only links official standards pages over https", () => {
    expect(isOfficialStandardsUrl("https://cwe.mitre.org/data/definitions/79.html")).toBe(true);
    expect(isOfficialStandardsUrl("http://cwe.mitre.org/data/definitions/79.html")).toBe(false);
    expect(isOfficialStandardsUrl("javascript:alert(1)")).toBe(false);
    expect(isOfficialStandardsUrl("https://evil.example/cwe.mitre.org")).toBe(false);
    expect(isOfficialStandardsUrl("https://user:pw@cwe.mitre.org/x")).toBe(false);
    expect(isOfficialStandardsUrl("https://cwe.mitre.org:8443/x")).toBe(false);
    expect(isOfficialStandardsUrl("https://cwe.mitre.org:443/data/definitions/79.html")).toBe(true);
    expect(isOfficialStandardsUrl("")).toBe(false);
    const html = renderToStaticMarkup(<ExternalLink url="javascript:alert(1)">x</ExternalLink>);
    expect(html).toBe("<span>x</span>");
  });
});

describe("rendering safety", () => {
  function sources(directory: string): string[] {
    return readdirSync(directory).flatMap((name) => {
      const full = path.join(directory, name);
      if (statSync(full).isDirectory()) return sources(full);
      return /\.(ts|tsx)$/.test(name) && !name.endsWith(".test.tsx") && !name.endsWith(".test.ts")
        ? [full]
        : [];
    });
  }

  it("never uses dangerouslySetInnerHTML in the client", () => {
    const root = fileURLToPath(new URL("../../", import.meta.url));
    for (const file of sources(root)) {
      expect(readFileSync(file, "utf8"), file).not.toContain("dangerouslySetInnerHTML");
    }
  });
});
