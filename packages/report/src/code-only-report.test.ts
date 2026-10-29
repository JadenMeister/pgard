import { describe, expect, it } from "vitest";
import { codeOnlyLabel } from "./code-only-text.js";
import { renderHtmlReport } from "./render-html.js";
import { renderPdfReport } from "./render-pdf.js";
import { finding, scanResult } from "./test-fixtures.js";
import { extractEmbeddedFontText } from "./test-pdf-text.js";

/** D5 (decided 2026-10-29): a code-only result is exported with a banner on every page. */

const codeOnly = scanResult({
  scanBasis: { mode: "code_only", authorization: "not_verified", reason: "not_a_git_repository" },
});

describe("code-only report label", () => {
  it("is absent for an authorized or older result", () => {
    expect(codeOnlyLabel(scanResult(), "en")).toBeNull();
    expect(
      codeOnlyLabel(
        scanResult({ scanBasis: { mode: "authorized", authorization: "verified", reason: null } }),
        "en",
      ),
    ).toBeNull();
    expect(renderHtmlReport(scanResult())).not.toContain('class="code-only-banner"');
  });

  it("puts the banner and the cover block in the HTML report, never verified wording", () => {
    const html = renderHtmlReport(codeOnly);
    expect(html).toContain('<div class="code-only-banner" role="note">Not authorized: code-only');
    expect(html).toContain("This folder is not a Git repository");
    // In print a table header row repeats the banner on every page, above the content (never
    // a fixed element over it).
    expect(html).toMatch(
      /<table class="code-only-frame"[^>]*><thead[^>]*><tr><td><div class="code-only-banner"/,
    );
    expect(html).toMatch(/<\/main>\n<\/td><\/tr><\/tbody><\/table>/);
    expect(html).toContain(".code-only-frame > thead { display: table-header-group; }");
    expect(html).not.toMatch(/code-only-banner \{[^}]*position: fixed/);
    expect(html).not.toMatch(/PGARD-verified|verified audit/i);
    const ko = renderHtmlReport(codeOnly, { lang: "ko" });
    expect(ko).toContain("권한 미확인: 코드 전용 검사");
  });

  it("draws the banner on every PDF page", async () => {
    const many = scanResult({
      scanBasis: codeOnly.scanBasis!,
      findings: Array.from({ length: 40 }, (_, index) =>
        finding({ id: `f${index}`, location: { ...finding({}).location, line: index + 1 } }),
      ),
    });
    const pdf = await renderPdfReport(many, { compress: false });
    const pageCount = (pdf.toString("latin1").match(/\/Type \/Page\b/g) ?? []).length;
    expect(pageCount).toBeGreaterThan(1);
    const lines = extractEmbeddedFontText(pdf);
    const banners = lines.filter((line) => line.includes("Not authorized: code-only scan.")).length;
    expect(banners).toBe(pageCount);
    expect(lines.join(" ")).toContain("not an authorized audit");
  });

  it("leaves the font of the text after a page break as it was", async () => {
    const findings = Array.from({ length: 40 }, (_, index) =>
      finding({ id: `f${index}`, location: { ...finding({}).location, line: index + 1 } }),
    );
    const fontOps = (pdf: Buffer): string[] =>
      (pdf.toString("latin1").match(/\/F\d+ [\d.]+ Tf|[\d.]+ [\d.]+ [\d.]+ rg/g) ?? []).sort();
    const plain = await renderPdfReport(scanResult({ findings }), { compress: false });
    const labelled = await renderPdfReport(
      scanResult({ scanBasis: codeOnly.scanBasis!, findings }),
      { compress: false },
    );
    const pageCount = (labelled.toString("latin1").match(/\/Type \/Page\b/g) ?? []).length;
    expect(pageCount).toBeGreaterThan(1);
    // Every font, size and colour change of the body is the same; the banners only add their own.
    const extra = [...fontOps(labelled)];
    for (const op of fontOps(plain)) {
      const at = extra.indexOf(op);
      expect(at).toBeGreaterThanOrEqual(0);
      extra.splice(at, 1);
    }
    // The only 8 pt text added is one banner per page...
    expect(extra.filter((op) => / 8 Tf$/.test(op))).toHaveLength(pageCount);
    // ...drawn last on its page, so no body text after it can inherit its font.
    const streams = labelled.toString("latin1").match(/stream\n[\s\S]*?endstream/g) ?? [];
    const pages = streams.filter((stream) => / Tf\b/.test(stream));
    expect(pages).toHaveLength(pageCount);
    for (const page of pages) expect(page.match(/[\d.]+ Tf/g)?.at(-1)).toBe("8 Tf");
  });
});
