import { applyBaseline, applySuppressions, type Finding, type ScanResult } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { formatFindingSummary, groupReportFindings } from "./format.js";
import { renderHtmlReport } from "./render-html.js";
import { renderPdfReport } from "./render-pdf.js";
import { finding, scanResult } from "./test-fixtures.js";
import { extractEmbeddedFontText } from "./test-pdf-text.js";

const NOW = new Date("2026-10-27T00:00:00Z");

const at = (id: string, path: string, overrides: Partial<Finding> = {}): Finding =>
  finding({
    id,
    location: { kind: "file", path, line: 4, url: null, commit: null },
    ...overrides,
  });

function withSuppressions(
  findings: Finding[],
  entries: Array<{ ruleId?: string; path: string; reason?: string; expires?: string }>,
): ScanResult {
  const applied = applySuppressions(
    findings,
    entries.map((entry) => ({ ruleId: "PG-SQL-001", reason: "Admin-only script", ...entry })),
    NOW,
  );
  return scanResult({
    findings: applied.findings,
    ...(applied.summary === null ? {} : { suppressions: applied.summary }),
  });
}

describe("grouping for reports", () => {
  it("puts every finding in exactly one list: suppressed, baseline, then regular, test, vendored", () => {
    const base = scanResult({ findings: [at("b", "src/b.ts")] });
    const current = scanResult({
      findings: [
        at("a", "src/a.ts", { ruleId: "PG-XSS-001" }),
        at("b2", "src/b.ts"),
        at("t", "src/a.test.ts", { context: "test" }),
        at("s", "scripts/s.ts"),
      ],
    });
    const suppressedInput = withSuppressions(current.findings, [{ path: "scripts/**" }]);
    const { result } = applyBaseline(suppressedInput, base, NOW);
    const groups = groupReportFindings(result.findings);
    expect(groups.suppressed.map((f) => f.id)).toEqual(["s"]);
    expect(groups.baseline.map((f) => f.id)).toEqual(["b2"]);
    expect(groups.primary.map((f) => f.id)).toEqual(["a"]);
    expect(groups.test.map((f) => f.id)).toEqual(["t"]);
    const total = Object.values(groups).reduce((sum, list) => sum + list.length, 0);
    expect(total).toBe(result.findings.length);
  });

  it("states the suppressed count with critical, and the baseline counts, in the summary", () => {
    const result = withSuppressions(
      [at("a", "scripts/a.ts", { severity: "critical" }), at("b", "src/b.ts")],
      [{ path: "scripts/**" }],
    );
    expect(formatFindingSummary(result.findings, result)).toContain(
      "1 suppressed by pgard.config.json (1 critical), listed separately.",
    );
    const none = withSuppressions([at("b", "src/b.ts")], [{ path: "scripts/**" }]);
    expect(formatFindingSummary(none.findings, none)).toContain(
      "0 suppressed by pgard.config.json, listed separately.",
    );
    expect(formatFindingSummary(scanResult().findings)).not.toContain("suppressed");
  });
});

describe("HTML report", () => {
  it("shows a collapsed Suppressed section with the reason, the count and the notices", () => {
    const html = renderHtmlReport(
      withSuppressions(
        [at("a", "scripts/a.ts"), at("b", "src/b.ts")],
        [{ path: "scripts/**", reason: "Admin-only <b>script</b>", expires: "2027-01-31" }],
      ),
    );
    expect(html).toContain("1 suppressed by pgard.config.json");
    expect(html).toContain('<details class="group">');
    expect(html).toContain("<summary>Suppressed (1)</summary>");
    expect(html).toContain(
      "Suppressed by pgard.config.json: &quot;Admin-only &lt;b&gt;script&lt;/b&gt;&quot; (expires 2027-01-31)",
    );
    expect(html).not.toContain("<b>script</b>");
    // The suppressed finding is in the section, not in the main list.
    const [main, rest] = html.split("<summary>Suppressed (1)</summary>");
    expect(main).not.toContain("scripts/a.ts");
    expect(rest).toContain("scripts/a.ts");
  });

  it("opens the section and warns when a critical finding is suppressed", () => {
    const html = renderHtmlReport(
      withSuppressions(
        [at("a", "scripts/a.ts", { severity: "critical" })],
        [{ path: "scripts/**" }],
      ),
    );
    expect(html).toContain('<details class="group" open>');
    expect(html).toContain("1 suppressed finding is high or critical (0 high, 1 critical)");
    expect(html).toContain("1 suppressed by pgard.config.json (1 critical)");
  });

  it("warns about a wildcard, an expired entry and a total suppression", () => {
    const html = renderHtmlReport(
      withSuppressions(
        [at("a", "src/a.ts")],
        [{ path: "**" }, { path: "old/**", expires: "2026-01-01" }],
      ),
    );
    expect(html).toContain("matches every file and every finding of that rule");
    expect(html).toContain("expired on 2026-01-01 and is not applied");
    expect(html).toContain("Every finding of this scan (1) is suppressed");
    expect(html).toContain(
      "No unsuppressed findings in the areas that ran (1 suppressed: 1 high).",
    );
  });

  it("lists baseline findings in their own section and marks new ones", () => {
    const base = scanResult({ findings: [at("b", "src/b.ts")] });
    const { result } = applyBaseline(
      scanResult({
        findings: [at("b2", "src/b.ts"), at("n", "src/n.ts", { ruleId: "PG-XSS-001" })],
      }),
      base,
      NOW,
    );
    const html = renderHtmlReport(result);
    expect(html).toContain("Baseline: 1 in baseline (1 high), 1 new.");
    expect(html).toContain("<summary>In baseline (1)</summary>");
    expect(html).toContain("<h2>New findings (since the baseline)</h2>");
    expect(html).toContain('<span class="new-badge">NEW</span>');
    expect(html.split('class="new-badge"')).toHaveLength(2);
  });

  it("renders a report without either feature exactly as before", () => {
    const html = renderHtmlReport(scanResult());
    expect(html).not.toContain("Suppressed");
    expect(html).not.toContain("baseline");
    expect(html).toContain("<h2>Findings</h2>");
  });
});

describe("PDF report", () => {
  it("lists suppressed and baseline findings in full, with notices", async () => {
    const base = scanResult({ findings: [at("b", "src/b.ts")] });
    const suppressed = withSuppressions(
      [at("s", "scripts/s.ts", { severity: "critical" }), at("b2", "src/b.ts")],
      [{ path: "scripts/**" }],
    );
    const { result } = applyBaseline(suppressed, base, NOW);
    const lines = extractEmbeddedFontText(await renderPdfReport(result, { compress: false }));
    const text = lines.join(" ");
    expect(text).toContain("1 suppressed finding is high or critical (0 high, 1 critical)");
    expect(text).toContain("Baseline: 1 in baseline (1 high), 0 new.");
    expect(text).toContain(
      "No new unsuppressed findings in the areas that ran (1 suppressed: 1 critical).",
    );
    expect(lines).toContain("Suppressed (1)");
    expect(lines).toContain("In baseline (1)");
    expect(lines).toContain("Location: scripts/s.ts:4");
    expect(text).toContain('Suppressed by pgard.config.json: "Admin-only script"');
    expect(lines.indexOf("Suppressed (1)")).toBeGreaterThan(lines.indexOf("Findings") - 1);
    expect(lines.indexOf("In baseline (1)")).toBeGreaterThan(lines.indexOf("Suppressed (1)"));
  });
});

describe("reason quoting", () => {
  it("quotes the reason as JSON so it cannot fake an expiry suffix", () => {
    const result = withSuppressions(
      [at("a", "scripts/a.ts")],
      [{ path: "scripts/**", reason: 'fine" (expires 9999-12-31', expires: "2027-01-31" }],
    );
    const html = renderHtmlReport(result);
    expect(html).toContain("&quot;fine\\&quot; (expires 9999-12-31&quot; (expires 2027-01-31)");
  });
});
