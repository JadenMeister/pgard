import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding, ScanResult } from "@pgard/findings";
import { viewFromHash } from "../../app/views";
import { I18nProvider } from "../../i18n/I18nProvider";
import {
  areaMatcher,
  buildAreaRules,
  EMPTY_FILTERS,
  filterFindings,
  isAreaFilterable,
  toggleFilter,
  type FindingFilters,
} from "./filter-findings";
import {
  buildHash,
  canonicalHash,
  escapeInvisible,
  hasActiveFilters,
  limitLength,
  parseHash,
  serializeFilters,
} from "./filter-url";
import { FindingsDashboard } from "./FindingsDashboard";
import { buildLinkedCounts } from "./linked-panels";
import { ResultOverview } from "./ResultOverview";

const RLO = String.fromCodePoint(0x202e);
const ZWSP = String.fromCodePoint(0x200b);
const BOM = String.fromCodePoint(0xfeff);

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
  // A secret in a tracked file (history scope, no commit).
  finding("d", {
    severity: "low",
    category: "secret_exposure",
    ruleId: "PG-SECRET-001",
    sources: ["history"],
    location: { kind: "file", path: "config/.env", line: 1, url: null, commit: null },
  }),
  // The same rule found in a past commit.
  finding("e", {
    severity: "high",
    category: "secret_exposure",
    ruleId: "PG-SECRET-001",
    sources: ["history"],
    location: { kind: "commit", path: "src/c.ts", line: null, url: null, commit: "abc" },
  }),
  // A JavaScript file: same rules as TypeScript, another area.
  finding("f", { severity: "medium", location: pathLocation("src/f.js") }),
  // The history rule's id on a code-scope finding: no history area may claim it.
  finding("h", {
    severity: "low",
    category: "secret_exposure",
    ruleId: "PG-SECRET-001",
    sources: ["code"],
  }),
];

function pathLocation(path: string): Finding["location"] {
  return { kind: "file", path, line: 3, url: null, commit: null };
}

const COVERAGE = [
  { area: "source:typescript", scope: "code", status: "completed", ruleIds: [], note: null },
  { area: "source:javascript", scope: "code", status: "completed", ruleIds: [], note: null },
  { area: "history:tracked-files", scope: "history", status: "completed", ruleIds: [], note: null },
  { area: "history:commits", scope: "history", status: "completed", ruleIds: [], note: null },
  { area: "source:heuristics", scope: "code", status: "completed", ruleIds: [], note: null },
  { area: "web", scope: "web", status: "not_selected", ruleIds: [], note: null },
] as ScanResult["coverage"];

const stat = (ruleId: string, area: string, scope: string) => ({
  ruleId,
  area,
  scope,
  targets: [],
  findings: 1,
  status: "completed",
});

// Rule ids are shared across areas, as in a real scan.
const RULE_STATS = [
  stat("PG-SQL-001", "source:typescript", "code"),
  stat("PG-XSS-001", "source:typescript", "code"),
  stat("PG-SQL-001", "source:javascript", "code"),
  stat("PG-XSS-001", "source:javascript", "code"),
  stat("PG-SECRET-001", "history:tracked-files", "history"),
  stat("PG-SECRET-001", "history:commits", "history"),
  stat("PG-SQL-001", "source:heuristics", "code"),
] as unknown as NonNullable<ScanResult["ruleStats"]>;

const AREAS = buildAreaRules(COVERAGE, RULE_STATS);

const withFilters = (patch: Partial<FindingFilters>): FindingFilters => ({
  ...EMPTY_FILTERS,
  ...patch,
});

const ids = (list: readonly Finding[]): string[] => list.map((entry) => entry.id).sort();
const inArea = (area: string): string[] =>
  ids(filterFindings(FINDINGS, withFilters({ area }), AREAS));

describe("filter combination", () => {
  it("combines severity, category, rule and file with AND", () => {
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
      "h",
    ]);
    expect(ids(filterFindings(FINDINGS, withFilters({ path: "src/c.ts" }), AREAS))).toEqual([
      "c",
      "e",
    ]);
    expect(
      filterFindings(FINDINGS, withFilters({ category: "xss", rule: "PG-SECRET-001" }), AREAS),
    ).toEqual([]);
  });

  it("attributes a finding to one area when several areas run the same rules", () => {
    // TypeScript and JavaScript carry the same rule ids: the file's language decides.
    expect(inArea("source:typescript")).toEqual(["a", "b", "c"]);
    expect(inArea("source:javascript")).toEqual(["f"]);
    // Tracked files and commits both run PG-SECRET-001: a commit decides; scope must be history.
    expect(inArea("history:tracked-files")).toEqual(["d"]);
    expect(inArea("history:commits")).toEqual(["e"]);
    // The code-scope finding with a history rule id belongs to none of them.
    expect(inArea("history:tracked-files")).not.toContain("h");
    expect(inArea("history:commits")).not.toContain("h");
  });

  it("combines an area with the other filters", () => {
    expect(
      ids(
        filterFindings(
          FINDINGS,
          withFilters({ area: "source:typescript", severity: "high" }),
          AREAS,
        ),
      ),
    ).toEqual(["b", "c"]);
    expect(
      ids(
        filterFindings(
          FINDINGS,
          withFilters({ area: "source:javascript", category: "xss" }),
          AREAS,
        ),
      ),
    ).toEqual([]);
  });

  it("never over-includes: areas that cannot be told apart match nothing and are not filters", () => {
    for (const area of ["source:heuristics", "web", "web:anonymous", "source:react", "nope"]) {
      expect(inArea(area)).toEqual([]);
      expect(isAreaFilterable(area, AREAS)).toBe(false);
    }
    expect(areaMatcher("source:heuristics", AREAS)).toBeNull();
    expect(isAreaFilterable("source:typescript", AREAS)).toBe(true);
    expect(isAreaFilterable("history:commits", AREAS)).toBe(true);
  });

  it("reads the language from the extension, case-insensitively, and ignores extensionless paths", () => {
    const only = buildAreaRules(
      [{ area: "source:typescript", ruleIds: ["PG-SQL-001"] }],
      undefined,
    );
    const match = areaMatcher("source:typescript", only);
    const at = (path: string | null) =>
      match?.(finding("x", { location: { ...pathLocation("x"), path } })) ?? false;
    expect(at("a/b/File.TSX")).toBe(true);
    expect(at("a.ts/readme")).toBe(false);
    expect(at("Makefile")).toBe(false);
    expect(at(null)).toBe(false);
    expect(at("a.js")).toBe(false);
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
    expect(counts.areas.get("source:javascript")).toBe(0);
    expect(counts.areas.get("history:commits")).toBe(0);
    expect(counts.areas.get("web")).toBe(0);
    expect(counts.total).toBe(7);
  });

  it("counts areas by the same attribution as the filter", () => {
    const counts = buildLinkedCounts(FINDINGS, EMPTY_FILTERS, AREAS);
    expect(counts.areas.get("source:typescript")).toBe(3);
    expect(counts.areas.get("source:javascript")).toBe(1);
    expect(counts.areas.get("history:tracked-files")).toBe(1);
    expect(counts.areas.get("history:commits")).toBe(1);
    expect(counts.areas.get("source:heuristics")).toBe(0);
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
      area: "history:commits",
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

  it("truncates by code point and strips invisible or direction-changing characters", () => {
    const pairs = "😀".repeat(300);
    const text = parseHash(`#overview?q=${encodeURIComponent(pairs)}`).filters.text;
    expect([...text]).toHaveLength(200);
    expect(text).toBe("😀".repeat(200));
    expect(limitLength(pairs)).toBe("😀".repeat(200));
    const sneaky = "a" + RLO + "b" + ZWSP + "c" + BOM + "";
    expect(parseHash(`#overview?rule=${encodeURIComponent(sneaky)}`).filters.rule).toBe("abc");
    expect(escapeInvisible(sneaky)).toBe("a\\u{202e}b\\u{200b}c\\u{feff}");
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
    schemaVersion: "1.8",
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

function overview(
  language: "en" | "ko",
  filters: FindingFilters,
  findings: Finding[] = FINDINGS,
): string {
  vi.stubGlobal("navigator", { languages: [language === "ko" ? "ko-KR" : "en-US"] });
  return renderToStaticMarkup(
    <I18nProvider>
      <ResultOverview
        result={result(findings)}
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
    expect(pressed("area-pick")).toHaveLength(6);
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
    expect(html).toContain("1 of 7 findings match the filters");
  });

  it("disables an area that has no findings and says why in its name and tooltip", () => {
    const html = overview("en", EMPTY_FILTERS);
    const heuristics = buttons(html).find(
      (tag) => tag.includes("area-pick") && tag.includes("source:heuristics"),
    );
    expect(heuristics).toContain("disabled");
    expect(heuristics).toContain("cannot be reliably attributed to this area");
    expect(heuristics).toContain('title="source:heuristics: findings cannot be reliably');
    const web = buttons(html).find((tag) => tag.includes("area-pick") && tag.includes("web:"));
    expect(web).toContain("disabled");
    // A usable area is enabled and names its count.
    const typescript = buttons(html).find(
      (tag) => tag.includes("area-pick") && tag.includes("source:typescript"),
    );
    expect(typescript).not.toContain("disabled");
    expect(typescript).toContain("Filter by area source:typescript, 3 findings");
  });

  it("marks the filtered numbers in the summary, and only when a filter is active", () => {
    const filtered = overview("en", withFilters({ category: "xss" }));
    expect(filtered).toContain("/ 7");
    expect(filtered).toContain("of 7 (filtered)");
    const plain = overview("en", EMPTY_FILTERS);
    expect(plain).not.toContain("stat-of");
    expect(plain).not.toContain("(filtered)");
  });

  it("shows an empty table message instead of hiding the panel when filters match nothing", () => {
    const html = overview("en", withFilters({ category: "xss", rule: "PG-SECRET-001" }));
    expect(html).toContain("No findings match these filters");
    expect(html).toContain("0 of 7 findings match the filters");
  });

  it("keeps the filter bar to clear a stale filter on a scan without regular findings", () => {
    const html = overview("en", withFilters({ severity: "high", area: "source:typescript" }), []);
    expect(html).toContain('aria-label="Remove filter Severity: high"');
    expect(html).toContain('aria-label="Clear all filters"');
    expect(html).toContain("0 of 0 findings match the filters");
    // The ordinary empty state, not the "filters match nothing" one.
    expect(html).toContain("No findings in any category.");
    expect(html).not.toContain("No findings match these filters");
    expect(html).not.toContain("Remove a filter to see more");
  });

  it("is available in Korean", () => {
    const html = overview("ko", withFilters({ severity: "high" }));
    expect(html).toContain("필터 해제");
    expect(html).toContain("모두 해제");
    expect(html).toContain("건이 필터에 맞습니다");
    expect(html).toContain("필터 적용");
  });

  it("shows invisible characters in a chip label as escapes", () => {
    const html = overview("en", withFilters({ text: "a" + RLO + "b" }));
    expect(html).toContain("a\\u{202e}b");
    expect(html).not.toContain("" + RLO + "");
  });

  it("renders the Findings view from shared filters, with the same bar and a bounded search box", () => {
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
    expect(html).toContain("2 of 7 findings match the filters");
    expect(html).toContain("Title a");
    expect(html).not.toContain("Title c");
    expect(html).toContain('maxLength="200"');
  });
});
