import { describe, expect, it } from "vitest";
import { hasUnsupportedPdfCharacters, renderPdfReport, toPdfText } from "./render-pdf.js";
import {
  VENDORED_FINDINGS_DETAIL,
  VENDORED_FINDINGS_NOTE,
  VENDORED_FINDINGS_TITLE,
} from "./format.js";
import { finding, scanResult } from "./test-fixtures.js";

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
