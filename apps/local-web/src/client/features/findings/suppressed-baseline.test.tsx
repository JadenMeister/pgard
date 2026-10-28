import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { applyBaseline, applySuppressions, type Finding, type ScanResult } from "@pgard/findings";
import { I18nProvider } from "../../i18n/I18nProvider";
import { SuppressionNotices } from "../scan/SuppressionNotices";
import { FindingsDashboard } from "./FindingsDashboard";
import { EMPTY_FILTERS, buildFindingsView, partitionFindings } from "./filter-findings";

const NOW = new Date("2026-10-27T00:00:00Z");

const at = (id: string, path: string, overrides: Partial<Finding> = {}): Finding => ({
  id,
  ruleId: "PG-SQL-001",
  title: `Title ${id}`,
  category: "injection",
  severity: "high",
  status: "suspected",
  confidence: "medium",
  location: { kind: "file", path, line: 3, url: null, commit: null },
  evidence: "concat (value redacted)",
  impact: "Query may change",
  recommendation: "Use parameters",
  references: { cwe: [], owasp: [], cve: [] },
  sources: ["code"],
  ...overrides,
});

function resultOf(findings: Finding[], extra: Partial<ScanResult> = {}): ScanResult {
  return {
    schemaVersion: "1.3",
    scanId: "s1",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "o/n", revision: "abc", webOrigin: null },
    authorization: { decision: "allowed", checks: [] },
    coverage: [],
    advisoryDb: { version: null, updatedAt: null },
    findings,
    ...extra,
  } as ScanResult;
}

function suppressed(
  findings: Finding[],
  entries: Array<{ ruleId?: string; path: string; reason?: string; expires?: string }>,
): ScanResult {
  const applied = applySuppressions(
    findings,
    entries.map((entry) => ({ ruleId: "PG-SQL-001", reason: "Admin-only script", ...entry })),
    NOW,
  );
  return resultOf(
    applied.findings,
    applied.summary === null ? {} : { suppressions: applied.summary },
  );
}

function render(language: "en" | "ko", result: ScanResult): string {
  vi.stubGlobal("navigator", { languages: [language === "ko" ? "ko-KR" : "en-US"] });
  return renderToStaticMarkup(
    <I18nProvider>
      <SuppressionNotices result={result} />
      <FindingsDashboard result={result} />
    </I18nProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("dashboard view model", () => {
  it("partitions suppressed before baseline and keeps the rest", () => {
    const plain = at("p", "src/p.ts");
    const inBaseline: Finding = { ...at("b", "src/b.ts"), inBaseline: true };
    const both: Finding = {
      ...at("s", "src/s.ts"),
      inBaseline: true,
      suppression: { reason: "r", source: "pgard.config.json" },
    };
    const parts = partitionFindings([plain, inBaseline, both]);
    expect(parts.rest).toEqual([plain]);
    expect(parts.baseline).toEqual([inBaseline]);
    expect(parts.suppressed).toEqual([both]);
  });

  it("counts regular findings in the headline and adds the suppressed and baseline counts", () => {
    const result = suppressed(
      [at("a", "scripts/a.ts", { severity: "critical" }), at("b", "src/b.ts"), at("c", "src/c.ts")],
      [{ path: "scripts/**" }],
    );
    const view = buildFindingsView(result.findings, EMPTY_FILTERS);
    expect(view.total).toBe(2);
    expect(view.contextNote).toBe("plus 1 suppressed (1 critical)");
    expect(view.sections.map((section) => section.kind)).toEqual(["suppressed"]);
    expect(view.counts.critical).toBe(0);
  });
});

describe("dashboard suppressed and baseline sections", () => {
  it("shows a collapsed Suppressed section with the count, the reason and a critical warning", () => {
    const html = render(
      "en",
      suppressed(
        [at("a", "scripts/a.ts"), at("b", "src/b.ts")],
        [{ path: "scripts/**", reason: "Admin <i>only</i>", expires: "2027-01-31" }],
      ),
    );
    expect(html).toContain("<details");
    expect(html).not.toContain('<details class="finding-group collapsible-findings" open');
    expect(html).toContain("Suppressed (1)");
    expect(html).toContain("1 suppressed");
    expect(html).toContain(
      "Suppressed by pgard.config.json: &quot;Admin &lt;i&gt;only&lt;/i&gt;&quot; (expires 2027-01-31)",
    );
    expect(html).not.toContain("<i>only</i>");
  });

  it("opens the section when a critical finding is suppressed, and says so in a notice", () => {
    const html = render(
      "en",
      suppressed([at("a", "scripts/a.ts", { severity: "critical" })], [{ path: "scripts/**" }]),
    );
    expect(html).toContain('<details class="finding-group collapsible-findings" open=""');
    expect(html).toContain("1 suppressed finding is high or critical (0 high, 1 critical)");
    expect(html).toContain("plus 1 suppressed (1 critical)");
    expect(html).toContain(
      "No unsuppressed findings in the areas that ran (1 suppressed: 1 critical)",
    );
  });

  it("warns in Korean for a wildcard and an expired entry, and for everything suppressed", () => {
    const html = render(
      "ko",
      suppressed(
        [at("a", "src/a.ts")],
        [{ path: "**" }, { path: "old/**", expires: "2026-01-01" }],
      ),
    );
    expect(html).toContain("모든 파일, 그 규칙의 모든 발견 항목");
    expect(html).toContain("2026-01-01에 만료되어 적용되지 않았습니다");
    expect(html).toContain("발견 항목 1건이 모두 pgard.config.json으로 억제되었습니다");
    expect(html).toContain("억제됨 (1)");
  });

  it("shows the baseline count line, the NEW badge and an In baseline section", () => {
    const base = resultOf([at("b", "src/b.ts")]);
    const { result } = applyBaseline(
      resultOf([at("b2", "src/b.ts"), at("n", "src/n.ts", { ruleId: "PG-XSS-001" })]),
      base,
      NOW,
    );
    const html = render("en", result);
    expect(html).toContain("baseline: 1 in baseline (1 high), 1 new");
    expect(html).toContain("In baseline (1)");
    expect(html).toContain(">NEW<");
    expect(html.split(">NEW<")).toHaveLength(2);
    expect(render("ko", result)).toContain("기준선에 있음 (1)");
  });

  it("renders a result without either feature as before", () => {
    const html = render("en", resultOf([at("a", "src/a.ts")]));
    expect(html).not.toContain("Suppressed");
    expect(html).not.toContain("baseline");
    expect(html).not.toContain(">NEW<");
  });
});
