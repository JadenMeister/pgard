import { describe, expect, it } from "vitest";
import { hasUnsupportedPdfCharacters, renderPdfReport, toPdfText } from "./render-pdf.js";
import { finding, scanResult } from "./test-fixtures.js";

describe("renderPdfReport", () => {
  it("produces a PDF document", async () => {
    const pdf = await renderPdfReport(scanResult());
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    expect(pdf.length).toBeGreaterThan(1000);
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
