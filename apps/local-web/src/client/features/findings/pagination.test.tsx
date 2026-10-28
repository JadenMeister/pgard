import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding, ScanResult, Severity } from "@pgard/findings";
import { I18nProvider } from "../../i18n/I18nProvider";
import { FindingsDashboard } from "./FindingsDashboard";
import { EMPTY_FILTERS } from "./filter-findings";
import {
  findingsListReducer,
  INITIAL_LIST_STATE,
  pageRequest,
  pageWindow,
  paginate,
  type FindingsListState,
} from "./pagination";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function finding(index: number, overrides: Partial<Finding> = {}): Finding {
  return {
    id: `f${index}`,
    ruleId: "PG-SQL-001",
    title: `Finding number ${index}`,
    category: "injection",
    severity: SEVERITIES[index % SEVERITIES.length] as Severity,
    status: "suspected",
    confidence: "medium",
    location: { kind: "file", path: `src/file-${index}.ts`, line: 1, url: null, commit: null },
    evidence: "concat (value redacted)",
    impact: "impact",
    recommendation: "fix",
    references: { cwe: [], owasp: [], cve: [] },
    sources: ["code"],
    ...overrides,
  };
}

function resultWith(findings: Finding[]): ScanResult {
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
  } as ScanResult;
}

const many = (count: number): Finding[] =>
  Array.from({ length: count }, (_, index) => finding(index + 1));

function render(findings: Finding[], state?: FindingsListState): string {
  return renderToStaticMarkup(
    <I18nProvider>
      <FindingsDashboard result={resultWith(findings)} initialState={state} />
    </I18nProvider>,
  );
}

const rowCount = (html: string): number => html.split('<details class="finding sev-').length - 1;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("paginate", () => {
  it("returns one page with its 1-based range and the page count", () => {
    const items = Array.from({ length: 213 }, (_, index) => index);
    const first = paginate(items, 1, 25);
    expect(first).toMatchObject({ page: 1, pageCount: 9, start: 1, end: 25, total: 213 });
    expect(first.items).toHaveLength(25);
    const last = paginate(items, 9, 25);
    expect(last).toMatchObject({ start: 201, end: 213 });
    expect(last.items).toEqual(items.slice(200));
  });

  it("clamps a page past the end, so a shrinking list never shows an empty page", () => {
    expect(paginate([1, 2, 3], 7, 25)).toMatchObject({ page: 1, start: 1, end: 3 });
    expect(paginate([], 3, 25)).toMatchObject({ page: 1, pageCount: 1, start: 0, end: 0 });
  });

  it("offers the first, last and neighbouring pages with gaps", () => {
    expect(pageWindow(1, 1)).toEqual([1]);
    expect(pageWindow(1, 12)).toEqual([1, 2, null, 12]);
    expect(pageWindow(6, 12)).toEqual([1, null, 5, 6, 7, null, 12]);
    expect(pageWindow(3, 12)).toEqual([1, 2, 3, 4, null, 12]);
    expect(pageWindow(12, 12)).toEqual([1, null, 11, 12]);
  });
});

describe("findingsListReducer", () => {
  it("changes the page of one list only", () => {
    const state = findingsListReducer(INITIAL_LIST_STATE, {
      type: "page",
      list: "primary",
      page: 3,
    });
    expect(state.pages).toEqual({ primary: 3 });
    expect(findingsListReducer(state, { type: "page", list: "test", page: 2 }).pages).toEqual({
      primary: 3,
      test: 2,
    });
  });

  it("sends every list back to page 1 when a filter or the page size changes", () => {
    const paged: FindingsListState = { ...INITIAL_LIST_STATE, pages: { primary: 4, test: 2 } };
    const filtered = findingsListReducer(paged, { type: "filter", patch: { severity: "high" } });
    expect(filtered.pages).toEqual({});
    expect(filtered.filters).toEqual({ ...EMPTY_FILTERS, severity: "high" });
    const resized = findingsListReducer(paged, { type: "pageSize", pageSize: 50 });
    expect(resized).toEqual({ filters: EMPTY_FILTERS, pageSize: 50, pages: {} });
    expect(Object.keys(resized.pages)).toHaveLength(0);
  });
});

describe("paged results panel", () => {
  it("renders one page of a large result but counts every finding", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const html = render(many(250));
    expect(rowCount(html)).toBe(25);
    expect(html).toContain("Showing 1–25 of 250");
    // Headline and charts count all 250, not the page.
    expect(html).toContain("250 finding(s)");
    expect(html).toContain("250 findings in total");
    expect(html).toContain('aria-label="Pages: Findings"');
    expect(html).toContain('aria-current="page"');
  });

  it("shows the requested page", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const html = render(many(250), { ...INITIAL_LIST_STATE, pages: { primary: 3 } });
    expect(html).toContain("Showing 51–75 of 250");
    expect(rowCount(html)).toBe(25);
    expect(html).toMatch(/aria-label="Page 3" aria-current="page"/);
  });

  it("counts the filter result, not the page, and keeps the headline total", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const filtered = findingsListReducer(
      { ...INITIAL_LIST_STATE, pages: { primary: 5 } },
      { type: "filter", patch: { severity: "critical" } },
    );
    const html = render(many(250), filtered);
    expect(html).toContain("Showing 1–25 of 50");
    expect(html).toContain("250 finding(s)");
  });

  it("has no page controls for a short list, and Korean range text", () => {
    vi.stubGlobal("navigator", { languages: ["ko-KR"] });
    const html = render(many(10));
    expect(rowCount(html)).toBe(10);
    expect(html).toContain("전체 10건 중 1–10건");
    expect(html).not.toContain("<nav");
  });

  it("pages the separate groups on their own", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const tests = Array.from({ length: 30 }, (_, index) =>
      finding(1000 + index, { context: "test", confidence: "low" }),
    );
    const html = render([...many(3), ...tests], {
      ...INITIAL_LIST_STATE,
      pages: { test: 2 },
    });
    expect(html).toContain("Showing 1–3 of 3");
    expect(html).toContain("Showing 26–30 of 30");
  });

  it("pages the vendored, suppressed and baseline groups each on their own", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const group = (offset: number, extra: Partial<Finding>) =>
      Array.from({ length: 30 }, (_, index) => finding(offset + index, extra));
    const findings = [
      ...many(3),
      ...group(2000, { context: "vendored", confidence: "low" }),
      ...group(3000, {
        suppression: { reason: "accepted", expires: "2027-01-31" },
      } as Partial<Finding>),
      ...group(4000, { inBaseline: true }),
    ];
    const html = render(findings, {
      ...INITIAL_LIST_STATE,
      pages: { vendored: 2, baseline: 2 },
    });
    expect(html).toContain('aria-label="Pages: Suggestions in third-party or vendored code"');
    expect(html).toContain('aria-label="Pages: Suppressed findings"');
    expect(html).toContain('aria-label="Pages: Findings in the baseline"');
    // Vendored and baseline on page 2, suppressed still on page 1.
    expect(html.split("Showing 26–30 of 30").length - 1).toBe(2);
    expect(html.split("Showing 1–25 of 30").length - 1).toBe(1);
  });

  it("has no pager for exactly one page of 25", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const html = render(many(25));
    expect(rowCount(html)).toBe(25);
    expect(html).toContain("Showing 1–25 of 25");
    expect(html).not.toContain("<nav");
    expect(html).not.toContain("Per page");
    const next = render(many(26));
    expect(html).not.toContain('aria-label="Pages: Findings"');
    expect(next).toContain('aria-label="Pages: Findings"');
  });

  it("shows the page size chosen in the select", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const html = render(many(250), { ...INITIAL_LIST_STATE, pageSize: 50 });
    expect(rowCount(html)).toBe(50);
    expect(html).toContain("Showing 1–50 of 250");
    expect(html).toMatch(/Per page<select>[^]*<option value="50" selected="">50<\/option>/);
    expect(html).toContain('<option value="25">25</option>');
    expect(html).toContain('<option value="100">100</option>');
  });

  it("clamps to the last page after a filter shrinks the list, and marks that page current", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    // 50 critical findings: page 9 no longer exists, page 2 is the last.
    const state = {
      ...INITIAL_LIST_STATE,
      filters: { ...EMPTY_FILTERS, severity: "critical" as const },
      pages: { primary: 9 },
    };
    const html = render(many(250), state);
    expect(html).toContain("Showing 26–50 of 50");
    expect(html).toContain('aria-label="Page 2" aria-current="page"');
    expect(html).not.toContain('aria-label="Page 1" aria-current="page"');
    expect(html).not.toContain('aria-label="Page 9"');
  });

  it("keeps the status and a suppression visible in the collapsed row", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const html = render([
      finding(1, { status: "confirmed" }),
      finding(2, {
        suppression: { reason: "accepted", expires: "2027-01-31" },
      } as Partial<Finding>),
    ]);
    const summaries = html.match(/<summary>[^]*?<\/summary>/g) ?? [];
    expect(summaries.some((summary) => summary.includes("badge-confirmed"))).toBe(true);
    expect(summaries.some((summary) => summary.includes("Suppressed until 2027-01-31"))).toBe(true);
    vi.stubGlobal("navigator", { languages: ["ko-KR"] });
    expect(
      render([
        finding(2, { suppression: { reason: "x", expires: "2027-01-31" } } as Partial<Finding>),
      ]),
    ).toContain("2027-01-31까지 억제됨");
  });

  it("uses h3 titles in the main list and h4 inside a group", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const html = render([finding(1), finding(2, { context: "test", confidence: "low" })]);
    expect(html).toContain('<h3 class="finding-title">Finding number 1</h3>');
    expect(html).toContain('<h4 class="finding-title">Finding number 2</h4>');
  });
});

describe("pageRequest", () => {
  it("asks for a page change only when the page actually changes", () => {
    // Only a real change moves focus; clicking the current page must not leave a pending focus.
    expect(pageRequest(3, 3, 9)).toBeNull();
    expect(pageRequest(1, 0, 9)).toBeNull();
    expect(pageRequest(9, 10, 9)).toBeNull();
    expect(pageRequest(3, 4, 9)).toBe(4);
    expect(pageRequest(3, 1, 9)).toBe(1);
  });
});
