import { describe, expect, it } from "vitest";
import { hasUnsupportedPdfCharacters, renderPdfReport, toPdfText } from "./render-pdf.js";
import {
  countFindingsBySeverity,
  TEST_FINDINGS_TITLE,
  VENDORED_FINDINGS_DETAIL,
  VENDORED_FINDINGS_NOTE,
  VENDORED_FINDINGS_TITLE,
} from "./format.js";
import { finding, scanResult } from "./test-fixtures.js";
import { extractEmbeddedFontText } from "./test-pdf-text.js";

const pdfTextLines = extractEmbeddedFontText;

describe("renderPdfReport", () => {
  it("produces a PDF document", async () => {
    const pdf = await renderPdfReport(scanResult());
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    expect(pdf.length).toBeGreaterThan(1000);
  });

  it("renders a result with test or fixture findings", async () => {
    const pdf = await renderPdfReport(
      scanResult({
        findings: [
          finding({ id: "t1", context: "test", confidence: "low" }),
          ...scanResult().findings,
        ],
      }),
    );
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
  });

  it("charts regular code only and lists test findings, then vendored suggestions", async () => {
    const result = scanResult({
      findings: [
        finding({
          id: "v1",
          ruleId: "PG-SECRET-002",
          severity: "critical",
          context: "vendored",
          confidence: "low",
          location: {
            kind: "file",
            path: "node_modules/pkg/index.js",
            line: 7,
            url: null,
            commit: null,
          },
        }),
        finding({
          id: "t1",
          severity: "critical",
          context: "test",
          confidence: "low",
          location: { kind: "file", path: "src/a.test.ts", line: 3, url: null, commit: null },
        }),
        ...scanResult().findings,
      ],
    });
    const lines = pdfTextLines(await renderPdfReport(result, { compress: false }));
    // Severity chart: label then count, for regular code only.
    const regular = countFindingsBySeverity(scanResult().findings);
    const chart = lines.indexOf("Critical");
    expect(lines.slice(chart, chart + 10)).toEqual([
      "Critical",
      String(regular.critical),
      "High",
      String(regular.high),
      "Medium",
      String(regular.medium),
      "Low",
      String(regular.low),
      "Info",
      String(regular.info),
    ]);
    // The vendored and test findings are critical; the chart must not count either.
    expect(lines[chart + 1]).not.toBe(String(regular.critical + 1));
    expect(lines.join(" ")).toContain(
      "3 finding(s): 1 confirmed, 1 suspected, 1 informational. 1 more in test or fixture code, listed separately. 1 suggestion in vendored code (1 critical), listed last.",
    );
    const testSection = lines.indexOf(`${TEST_FINDINGS_TITLE} (1)`);
    const suggestions = lines.indexOf(`${VENDORED_FINDINGS_TITLE} (1)`);
    expect(testSection).toBeGreaterThan(lines.indexOf("Location: src/api/users.ts:42"));
    expect(lines.indexOf("Location: src/a.test.ts:3")).toBeGreaterThan(testSection);
    expect(suggestions).toBeGreaterThan(lines.indexOf("Location: src/a.test.ts:3"));
    expect(lines.indexOf("Location: node_modules/pkg/index.js:7")).toBeGreaterThan(suggestions);
    expect(lines.indexOf("Authorization")).toBeGreaterThan(suggestions);
  });

  it("does not call a PDF with only vendored findings empty", async () => {
    const lines = pdfTextLines(
      await renderPdfReport(
        scanResult({
          findings: [
            finding({
              id: "v1",
              context: "vendored",
              confidence: "low",
              location: { kind: "file", path: "vendor/a.php", line: 1, url: null, commit: null },
            }),
          ],
        }),
        { compress: false },
      ),
    );
    expect(lines.some((text) => text.startsWith("No findings outside vendored code"))).toBe(true);
    expect(lines).toContain(`${VENDORED_FINDINGS_TITLE} (1)`);
    expect(lines).toContain("Location: vendor/a.php:1");
  });

  it("renders a result with vendored suggestions using only text the PDF fonts can show", async () => {
    const result = scanResult({
      findings: [
        finding({
          id: "v1",
          context: "vendored",
          confidence: "low",
          location: {
            kind: "file",
            path: "node_modules/pkg/index.js",
            line: 1,
            url: null,
            commit: null,
          },
        }),
        ...scanResult().findings,
      ],
    });
    const pdf = await renderPdfReport(result);
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    for (const text of [
      VENDORED_FINDINGS_TITLE,
      VENDORED_FINDINGS_NOTE,
      VENDORED_FINDINGS_DETAIL,
    ]) {
      expect(text).toMatch(/^[\x20-\x7e]+$/);
    }
  });

  it("replaces characters the built-in fonts cannot encode", () => {
    expect(toPdfText("ok \u001b[31m \u4e2d")).toBe("ok ?[31m ?");
  });
});

describe("PDF character notice", () => {
  it("detects text the built-in fonts cannot show", () => {
    expect(hasUnsupportedPdfCharacters(scanResult())).toBe(false);
    expect(
      hasUnsupportedPdfCharacters(
        scanResult({ findings: [finding({ title: "\uD55C\uAE00 title" })] }),
      ),
    ).toBe(true);
    expect(
      hasUnsupportedPdfCharacters(scanResult({ findings: [finding({ evidence: "multi\nline" })] })),
    ).toBe(false);
  });
});

describe("PDF performance", () => {
  it("renders a 200k-character unbroken field quickly (fields are capped)", async () => {
    const startedAt = Date.now();
    const pdf = await renderPdfReport(
      scanResult({
        findings: [finding({ evidence: "A".repeat(200_000), title: "B".repeat(200_000) })],
      }),
    );
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    expect(Date.now() - startedAt).toBeLessThan(3000);
  });
});

describe("PDF performance on long metadata", () => {
  it("renders a 100k-character repository and reference quickly", async () => {
    const long = "R".repeat(100_000);
    const startedAt = Date.now();
    await renderPdfReport(
      scanResult({
        target: { repo: long, revision: long, webOrigin: null },
        findings: [finding({ references: { cwe: [long], owasp: [], cve: [] } })],
      }),
    );
    expect(Date.now() - startedAt).toBeLessThan(3000);
  });
});

describe("project configuration notices in the PDF report", () => {
  it("lists the notices before the summary", async () => {
    const result = scanResult({
      coverage: [
        {
          area: "source:config",
          scope: "code",
          status: "partial",
          ruleIds: [],
          note: "pgard.config.json is invalid and was ignored; the scan ran with no exclusions: x.",
        },
      ],
    });
    const text = pdfTextLines(await renderPdfReport(result, { compress: false })).join(" ");
    expect(text).toContain("Note:");
    expect(text.indexOf("invalid and was ignored")).toBeLessThan(text.indexOf("Summary"));
  });
});
