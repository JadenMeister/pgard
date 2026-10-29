import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding, ScanResult } from "@pgard/findings";
import { viewFromHash } from "../../app/views";
import { I18nProvider } from "../../i18n/I18nProvider";
import {
  buildAreaRules,
  EMPTY_FILTERS,
  filterFindings,
  toggleFilter,
  type FindingFilters,
} from "./filter-findings";
import {
  buildHash,
  canonicalHash,
  hasActiveFilters,
  parseHash,
  serializeFilters,
} from "./filter-url";
import { FindingsDashboard } from "./FindingsDashboard";
import { buildLinkedCounts } from "./linked-panels";
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

const FINDINGS = [
  finding("a", { severity: "critical", category: "xss", ruleId: "PG-XSS-001" }),
  finding("b", { category: "xss", ruleId: "PG-XSS-001" }),
  finding("c"),
  finding("d", { severity: "low", category: "secret_exposure", ruleId: "PG-SECRET-001" }),
  finding("e", {
    severity: "high",
    category: "secret_exposure",
    ruleId: "PG-SECRET-001",
    sources: ["history"],
    location: { kind: "commit", path: "src/c.ts", line: null, url: null, commit: "abc" },
  }),
];

const COVERAGE = [
  { area: "source:typescript", scope: "code", status: "completed", ruleIds: [], note: null },
  { area: "history:secrets", scope: "history", status: "completed", ruleIds: [], note: null },
  { area: "web", scope: "web", status: "not_selected", ruleIds: [], note: null },
] as ScanResult["coverage"];

const RULE_STATS = [
  {
    ruleId: "PG-SQL-001",
    area: "source:typescript",
    targets: [],
    findings: 1,
    status: "completed",
  },
  {
    ruleId: "PG-XSS-001",
    area: "source:typescript",
    targets: [],
    findings: 2,
    status: "completed",
  },
  {
    ruleId: "PG-SECRET-001",
    area: "history:secrets",
    targets: [],
    findings: 2,
    status: "completed",
  },
] as unknown as NonNullable<ScanResult["ruleStats"]>;

const AREAS = buildAreaRules(COVERAGE, RULE_STATS);

const withFilters = (patch: Partial<FindingFilters>): FindingFilters => ({
  ...EMPTY_FILTERS,
  ...patch,
});

const ids = (list: readonly Finding[]): string[] => list.map((entry) => entry.id).sort();

describe("filter combination", () => {
  it("combines severity, category, rule, file and area with AND", () => {
    expect(ids(filterFindings(FINDINGS, withFilters({ category: "xss" }), AREAS))).toEqual([
      "a",
      "b",
    ]);
    expect(
      ids(filterFindings(FINDINGS, withFilters({ category: "xss", severity: "critical" }), AREAS)),
    ).toEqual(["a"]);
    expect(ids(filterFindings(FINDINGS, withFilters({ rule: "PG-SECRET-001" }), AREAS))).toEqual([
      "d",
      "e",
    ]);
    expect(ids(filterFindings(FINDINGS, withFilters({ path: "src/c.ts" }), AREAS))).toEqual([
      "c",
      "e",
    ]);
    expect(ids(filterFindings(FINDINGS, withFilters({ area: "history:secrets" }), AREAS))).toEqual([
      "d",
      "e",
    ]);
    expect(
      ids(
        filterFindings(FINDINGS, withFilters({ area: "history:secrets", severity: "low" }), AREAS),
      ),
    ).toEqual(["d"]);
    expect(
      filterFindings(FINDINGS, withFilters({ category: "xss", rule: "PG-SECRET-001" }), AREAS),
    ).toEqual([]);
  });

  it("matches nothing for an area that has no rules, and ignores an area without the map", () => {
    expect(filterFindings(FINDINGS, withFilters({ area: "web" }), AREAS)).toEqual([]);
    expect(filterFindings(FINDINGS, withFilters({ area: "unknown" }), AREAS)).toEqual([]);
  });

  it("toggles a value off when it is already the active one", () => {
    const active = withFilters({ category: "xss", text: "sql" });
    expect(toggleFilter(active, { category: "xss" })).toEqual({ category: null });
    expect(toggleFilter(active, { category: "injection" })).toEqual({ category: "injection" });
    expect(toggleFilter(EMPTY_FILTERS, { rule: "PG-SQL-001" })).toEqual({ rule: "PG-SQL-001" });
  });

  it("counts every panel without its own filter so the other values stay selectable", () => {
    const counts = buildLinkedCounts(
      FINDINGS,
      withFilters({ severity: "high", category: "xss" }),
      AREAS,
    );
    expect(ids(counts.matched)).toEqual(["b"]);
    // Severity bar: the category filter applies, the severity filter does not.
    expect(counts.severity).toMatchObject({ critical: 1, high: 1, low: 0 });
    // Category list: the severity filter applies, the category filter does not.
    expect(counts.categories).toEqual([
      { category: "injection", count: 1 },
      { category: "secret_exposure", count: 1 },
      { category: "xss", count: 1 },
    ]);
    expect(counts.areas.get("source:typescript")).toBe(1);
    expect(counts.areas.get("history:secrets")).toBe(0);
    expect(counts.areas.get("web")).toBe(0);
    expect(counts.total).toBe(5);
  });
});

describe("filter state in the address", () => {
  it("round-trips every filter", () => {
    const filters = withFilters({
      severity: "high",
      status: "suspected",
      source: "history",
      category: "secret_exposure",
      rule: "PG-SECRET-001",
      area: "history:secrets",
      path: "src/a b/c.ts",
      text: "sql & more=1",
    });
    const hash = buildHash("findings", filters);
    expect(hash.startsWith("#findings?")).toBe(true);
    expect(parseHash(hash)).toEqual({ view: "findings", filters });
  });

  it("keeps the view readable next to the filters", () => {
    expect(viewFromHash("#findings?severity=high")).toBe("findings");
    expect(viewFromHash("#overview?category=xss")).toBe("overview");
    expect(viewFromHash("#?severity=high")).toBe("overview");
  });

  it("writes only a view when nothing is filtered", () => {
    expect(buildHash("overview", EMPTY_FILTERS)).toBe("#overview");
    expect(parseHash("#coverage")).toEqual({ view: "coverage", filters: EMPTY_FILTERS });
    expect(parseHash("")).toEqual({ view: "overview", filters: EMPTY_FILTERS });
    expect(hasActiveFilters(EMPTY_FILTERS)).toBe(false);
    expect(hasActiveFilters(withFilters({ text: "  " }))).toBe(false);
  });

  it("drops invalid values and unknown keys", () => {
    const parsed = parseHash("#findings?severity=urgent&status=x&source=ftp&category=A%20B&rule=");
    expect(parsed.filters).toEqual(EMPTY_FILTERS);
    expect(serializeFilters(parsed.filters)).toBe("");
    const long = parseHash(`#overview?q=${"x".repeat(500)}`).filters.text;
    expect(long).toHaveLength(200);
  });

  it("never reads or writes a session token", () => {
    const token = "abcdefghijklmnopqrstuvwxyz012345";
    for (const hash of [
      `#token=${token}`,
      `#findings?severity=high&token=${token}`,
      `#token=${token}&findings?severity=high`,
      `#overview?token=${token}`,
    ]) {
      const parsed = parseHash(hash);
      expect(buildHash(parsed.view, parsed.filters)).not.toContain(token);
      expect(canonicalHash(hash)).not.toContain(token);
      expect(canonicalHash(hash)).not.toContain("token");
    }
    // The view and filters next to the token survive; a token alone leaves nothing.
    expect(canonicalHash(`#findings?severity=high&token=${token}`)).toBe("#findings?severity=high");
    expect(canonicalHash(`#token=${token}`)).toBe("");
    expect(canonicalHash("#unknown")).toBe("");
  });
});

function result(findings: Finding[]): ScanResult {
  return {
    schemaVersion: "1.5",
    scanId: "s1",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code", "history"],
    overallStatus: "completed",
    target: { repo: "o/n", revision: "abc", webOrigin: null },
    authorization: { decision: "allowed", checks: [] },
    coverage: COVERAGE,
    ruleStats: RULE_STATS,
    advisoryDb: { version: null, updatedAt: null },
    findings,
  } as ScanResult;
}

function overview(language: "en" | "ko", filters: FindingFilters): string {
  vi.stubGlobal("navigator", { languages: [language === "ko" ? "ko-KR" : "en-US"] });
  return renderToStaticMarkup(
    <I18nProvider>
      <ResultOverview
        result={result(FINDINGS)}
        aside={<p>aside</p>}
        emptyText={null}
        filters={filters}
        onFilter={() => undefined}
        onClearFilters={() => undefined}
        onOpenFindings={() => undefined}
        onCoverage={() => undefined}
      />
    </I18nProvider>,
  );
}

/** Opening tags of every `<button ...>` in the markup. */
const buttons = (html: string): string[] => html.match(/<button\b[^>]*>/g) ?? [];

describe("linked panels: roles and state", () => {
  it("offers every panel value as a real button that exposes its pressed state", () => {
    const html = overview("en", EMPTY_FILTERS);
    const all = buttons(html);
    const pressed = (cls: string): string[] =>
      all.filter((tag) => tag.includes(cls) && tag.includes("aria-pressed"));
    expect(pressed("sev-chip")).toHaveLength(5);
    expect(pressed("category-pick")).toHaveLength(3);
    expect(pressed("area-pick")).toHaveLength(3);
    expect(pressed("cell-pick").length).toBeGreaterThanOrEqual(2);
    expect(all.every((tag) => tag.includes('type="button"'))).toBe(true);
    // Nothing is selected yet.
    expect(all.filter((tag) => tag.includes('aria-pressed="true"'))).toHaveLength(0);
    // No fake links for filters.
    expect(html).not.toMatch(/<a[^>]*role="button"/);
  });

  it("marks the selected values pressed and lists them as removable chips", () => {
    const html = overview("en", withFilters({ severity: "high", category: "xss" }));
    const all = buttons(html);
    expect(all.filter((tag) => tag.includes('aria-pressed="true"'))).toHaveLength(2);
    expect(html).toContain('aria-label="Remove filter Severity: high"');
    expect(html).toContain('aria-label="Remove filter Category: ');
    expect(html).toContain('aria-label="Clear all filters"');
    expect(html).toContain('role="group" aria-label="Active filters"');
    expect(html).toContain('role="status"');
    expect(html).toContain("1 of 5 findings match the filters");
  });

  it("disables an area that has no findings and says why in its name", () => {
    const html = overview("en", EMPTY_FILTERS);
    const web = buttons(html).find((tag) => tag.includes("area-pick") && tag.includes("web:"));
    expect(web).toContain("disabled");
    expect(web).toContain("no findings are linked to this area");
  });

  it("shows an empty table message instead of hiding the panel when filters match nothing", () => {
    const html = overview("en", withFilters({ category: "xss", rule: "PG-SECRET-001" }));
    expect(html).toContain("No findings match these filters");
    expect(html).toContain("0 of 5 findings match the filters");
  });

  it("is available in Korean", () => {
    const html = overview("ko", withFilters({ severity: "high" }));
    expect(html).toContain("필터 해제");
    expect(html).toContain("모두 해제");
    expect(html).toContain("건이 필터에 맞습니다");
  });

  it("renders the Findings view from shared filters, with the same bar", () => {
    vi.stubGlobal("navigator", { languages: ["en-US"] });
    const html = renderToStaticMarkup(
      <I18nProvider>
        <FindingsDashboard
          result={result(FINDINGS)}
          linkedFilters={{
            filters: withFilters({ rule: "PG-XSS-001" }),
            onChange: () => undefined,
            onClear: () => undefined,
          }}
        />
      </I18nProvider>,
    );
    expect(html).toContain('aria-label="Remove filter Rule: PG-XSS-001"');
    expect(html).toContain("2 of 5 findings match the filters");
    expect(html).toContain("Title a");
    expect(html).not.toContain("Title c");
  });
});
