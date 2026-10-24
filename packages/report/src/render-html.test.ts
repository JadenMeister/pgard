import { describe, expect, it } from "vitest";
import { escapeHtml } from "./escape-html.js";
import {
  formatLocation,
  labelSeverity,
  prepareReportResult,
  sortFindings,
  truncateField,
} from "./format.js";
import { renderHtmlReport, renderSeverityBarChartSvg } from "./render-html.js";
import { finding, scanResult, XSS } from "./test-fixtures.js";

describe("formatLocation", () => {
  it("formats file:line, URL and commit locations", () => {
    expect(formatLocation(finding({}).location)).toBe("src/api/users.ts:42");
    expect(
      formatLocation({
        kind: "url",
        path: null,
        line: null,
        url: "http://127.0.0.1:3000/a",
        commit: null,
      }),
    ).toBe("http://127.0.0.1:3000/a");
    expect(
      formatLocation({
        kind: "commit",
        path: ".env",
        line: 1,
        url: null,
        commit: "0123456789abcdef0123",
      }),
    ).toBe(".env:1 (commit 0123456789ab)");
  });

  it("sorts critical first and confirmed before suspected", () => {
    expect(sortFindings(scanResult().findings).map((entry) => entry.id)).toEqual([
      "f3",
      "f1",
      "f2",
    ]);
  });
});

describe("renderHtmlReport", () => {
  const html = renderHtmlReport(scanResult());

  it("escapes every dynamic value and contains no script", () => {
    expect(html).not.toContain("<script");
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;");
    expect(html).toContain("default-src 'none'");
  });

  it("includes chart, coverage incl. not_tested/not_selected, locations, advisory DB and disclaimer", () => {
    expect(html).toContain("<svg");
    expect(html).toContain("Not tested");
    expect(html).toContain("Not selected");
    expect(html).toContain("authenticated browsing is not available in this MVP");
    expect(html).toContain("src/api/users.ts:42");
    expect(html).toContain("http://127.0.0.1:3000/");
    expect(html).toContain("bundle-2026-10-01");
    expect(html).toContain("No findings does not mean the project is secure");
    expect(html).toContain("1 confirmed, 1 suspected, 1 informational");
  });

  it("does not load any external resource", () => {
    expect(html).not.toMatch(/(src|href)=["']https?:/);
  });

  it("states that a blocked scan ran no analysis", () => {
    const blocked = renderHtmlReport(scanResult({ overallStatus: "blocked", findings: [] }));
    expect(blocked).toContain("Blocked by the authorization gate");
  });

  it("lists test or fixture findings in their own section, outside the headline counts", () => {
    const testFinding = finding({
      id: "t1",
      severity: "medium",
      confidence: "low",
      context: "test",
      title: "Secret in a test",
      location: { kind: "file", path: "src/a.test.ts", line: 3, url: null, commit: null },
    });
    const withTest = renderHtmlReport(
      scanResult({ findings: [testFinding, ...scanResult().findings] }),
    );
    expect(withTest).toContain(
      "3 finding(s): 1 confirmed, 1 suspected, 1 informational. 1 more in test or fixture code, listed separately.",
    );
    expect(withTest).toContain("Medium 0");
    const section = withTest.indexOf("<h2>In test or fixture code (1)</h2>");
    expect(section).toBeGreaterThan(withTest.indexOf("src/api/users.ts:42"));
    expect(withTest.indexOf("src/a.test.ts:3")).toBeGreaterThan(section);
    expect(withTest.indexOf("<h2>Authorization</h2>")).toBeGreaterThan(section);

    const onlyTest = renderHtmlReport(scanResult({ findings: [testFinding] }));
    expect(onlyTest).toContain("No findings outside test or fixture code");
    expect(onlyTest).toContain("src/a.test.ts:3");
    expect(html).not.toContain("In test or fixture code");
  });

  it("draws one bar per severity", () => {
    const svg = renderSeverityBarChartSvg({ critical: 1, high: 2, medium: 0, low: 0, info: 5 });
    expect(svg.match(/<rect/g)).toHaveLength(5);
    expect(svg).toContain("Info 5");
  });
});

describe("escapeHtml", () => {
  it("replaces bidi and invisible characters with a visible marker", () => {
    expect(escapeHtml("src/\u202Etxt.exe")).toBe("src/[U+202E]txt.exe");
    expect(escapeHtml("a\u200Bb\u2066c\u0000d")).toBe("a[U+200B]b[U+2066]c[U+0000]d");
    expect(escapeHtml("line1\nline2\tx")).toBe("line1\nline2\tx");
  });
});

describe("runtime guards", () => {
  it("renders unknown enum values with an Unknown label instead of NaN/undefined", () => {
    const odd = scanResult({
      overallStatus: "weird" as never,
      findings: [finding({ severity: "urgent" as never, status: "maybe" as never })],
      coverage: [{ area: "x", scope: "code", status: "odd" as never, ruleIds: [], note: null }],
    });
    const html = renderHtmlReport(odd);
    expect(html).not.toContain("undefined");
    expect(html).not.toContain("NaN");
    expect(html).toContain("Unknown");
    expect(labelSeverity("urgent")).toBe("Unknown");
    expect(labelSeverity("__proto__")).toBe("Unknown");
  });
});

describe("field length caps", () => {
  it("truncates long fields with a marker", () => {
    const long = "A".repeat(200_000);
    const prepared = prepareReportResult(
      scanResult({ findings: [finding({ evidence: long, title: long })] }),
    );
    expect(prepared.findings[0]?.evidence).toHaveLength(2000 + " (truncated)".length);
    expect(prepared.findings[0]?.title.endsWith("(truncated)")).toBe(true);
    expect(renderHtmlReport(scanResult({ findings: [finding({ evidence: long })] }))).toContain(
      "(truncated)",
    );
  });
});

describe("prepareReportResult caps every string", () => {
  it("caps target, references, ids and advisory fields", () => {
    const long = "R".repeat(100_000);
    const prepared = prepareReportResult(
      scanResult({
        scanId: long,
        target: { repo: long, revision: long, webOrigin: long },
        advisoryDb: { version: long, updatedAt: long },
        findings: [finding({ ruleId: long, references: { cwe: [long], owasp: [], cve: [long] } })],
      }),
    );
    const limit = 500 + " (truncated)".length;
    expect(prepared.scanId.length).toBe(limit);
    expect(prepared.target.repo?.length).toBe(limit);
    expect(prepared.target.webOrigin?.length).toBe(limit);
    expect(prepared.advisoryDb.version?.length).toBe(limit);
    expect(prepared.findings[0]?.ruleId.length).toBe(limit);
    expect(prepared.findings[0]?.references.cve[0]?.length).toBe(limit);
    expect(prepared.findings[0]?.references.cwe[0]?.length).toBe(limit);
  });

  it("does not split a surrogate pair at the cut", () => {
    const value = "a".repeat(499) + "\uD83D\uDE00" + "b";
    const truncated = truncateField(value, 500);
    expect(truncated).toBe("a".repeat(499) + " (truncated)");
  });
});
