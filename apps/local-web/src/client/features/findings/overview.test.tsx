import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding, ScanResult } from "@pgard/findings";
import { SeverityBar } from "../../components/charts/SeverityBar";
import { I18nProvider } from "../../i18n/I18nProvider";
import { countByCategory, EMPTY_FILTERS, filterFindings } from "./filter-findings";
import { FindingsDashboard } from "./FindingsDashboard";
import { INITIAL_LIST_STATE } from "./pagination";
import { ResultOverview } from "./ResultOverview";

afterEach(() => {
  vi.unstubAllGlobals();
});

const finding = (id: string, overrides: Partial<Finding> = {}): Finding => ({
  id,
  ruleId: "PG-SQL-001",
  title: `Title ${id}`,
  category: "injection",
  severity: "high",
  status: "suspected",
  confidence: "medium",
  location: { kind: "file", path: `src/${id}.ts`, line: 3, url: null, commit: null },
  evidence: "concat",
  impact: "Query may change",
  recommendation: "Use parameters",
  references: { cwe: [], owasp: [], cve: [] },
  sources: ["code"],
  ...overrides,
});

const result = (findings: Finding[], extra: Partial<ScanResult> = {}): ScanResult =>
  ({
    schemaVersion: "1.4",
    scanId: "s1",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "partial",
    target: { repo: "o/n", revision: "abc", webOrigin: null },
    authorization: { decision: "allowed", checks: [] },
    coverage: [
      { area: "source:typescript", scope: "code", status: "completed", ruleIds: [], note: null },
      {
        area: "source:java",
        scope: "code",
        status: "partial",
        ruleIds: [],
        note: "2 files were larger than the size limit",
      },
    ],
    advisoryDb: { version: null, updatedAt: null },
    findings,
    ...extra,
  }) as ScanResult;

const FINDINGS = [
  finding("a", { severity: "critical", category: "xss" }),
  finding("b", { category: "xss" }),
  finding("c"),
  finding("d", { severity: "low", category: "secret_exposure" }),
];

function overview(language: "en" | "ko", value: ScanResult | null): string {
  vi.stubGlobal("navigator", { languages: [language === "ko" ? "ko-KR" : "en-US"] });
  return renderToStaticMarkup(
    <I18nProvider>
      <ResultOverview
        result={value}
        aside={<p>aside</p>}
        emptyText="No scan yet"
        onFilter={() => undefined}
        onCoverage={() => undefined}
      />
    </I18nProvider>,
  );
}

describe("severity bar", () => {
  it("draws one segment per severity present, with a text alternative and legend toggles", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const html = renderToStaticMarkup(
      <I18nProvider>
        <SeverityBar
          counts={{ critical: 1, high: 3, medium: 0, low: 0, info: 0 }}
          selected="high"
          onSelect={() => undefined}
        />
      </I18nProvider>,
    );
    expect(html).toContain(
      'role="img" aria-label="Findings by severity: 1 critical, 3 high, 0 medium, 0 low, 0 info"',
    );
    expect(html.split('class="sev-seg').length - 1).toBe(2);
    expect(html).toContain('x="0" y="0" width="25"');
    expect(html).toContain('x="25" y="0" width="75"');
    expect(html.split("<button").length - 1).toBe(5);
    expect(html).toMatch(/aria-pressed="true"><span class="num">3<\/span> high/);
  });
});

describe("categories", () => {
  it("counts findings per category, largest first, and filters by one", () => {
    expect(countByCategory(FINDINGS)).toEqual([
      { category: "xss", count: 2 },
      { category: "injection", count: 1 },
      { category: "secret_exposure", count: 1 },
    ]);
    const xss = filterFindings(FINDINGS, { ...EMPTY_FILTERS, category: "xss" });
    expect(xss.map((entry) => entry.id)).toEqual(["a", "b"]);
  });

  it("starts the Findings view filtered by a category from the overview", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const html = renderToStaticMarkup(
      <I18nProvider>
        <FindingsDashboard
          result={result(FINDINGS)}
          initialState={{
            ...INITIAL_LIST_STATE,
            filters: { ...EMPTY_FILTERS, category: "xss" },
          }}
        />
      </I18nProvider>,
    );
    expect(html).toContain("Showing 1–2 of 2");
    expect(html).toContain('<option value="xss" selected="">Cross-site scripting (XSS)</option>');
  });
});

describe("overview panels", () => {
  it("shows the summary, per-area coverage, top findings and categories as separate panels", () => {
    const html = overview("en", result(FINDINGS));
    expect(html).toContain('<div class="overview-grid">');
    expect(html.split('class="section panel').length - 1).toBe(4);
    expect(html).toContain("Partial · 1 area did not finish");
    expect(html).toContain("Confirmed: the evidence shows the problem directly.");
    expect(html).toContain('<code class="area-name">source:java</code>');
    expect(html).toContain("2 files were larger than the size limit");
    expect(html).toContain("Partial means only part of an area ran");
    expect(html).toContain(">Cross-site scripting (XSS)</a>");
    expect(html).toContain('<div class="overview-stack"><p>aside</p></div>');
  });

  it("puts the summary across the full width before a scan, in Korean too", () => {
    const html = overview("ko", null);
    expect(html).toContain('class="overview-grid is-empty is-flat"');
    expect(html).toContain('class="section panel span-full"');
    expect(html).toContain("요약");
    expect(html).not.toContain("분류별");
    expect(overview("ko", result(FINDINGS))).toContain("부분 완료 · 1개 영역이 끝나지 않음");
  });
});
