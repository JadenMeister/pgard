import type { IncrementalInfo } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { renderHtmlReport } from "./render-html.js";
import { scanResult } from "./test-fixtures.js";

const INFO: IncrementalInfo = {
  used: true,
  reason: null,
  basedOn: { scanId: "1a2b3c4d5e6f", revision: null },
  filesRescanned: 3,
  filesReused: 1997,
  commitsScanned: 2,
  commitsReused: 40,
  code: { mode: "incremental", reason: null },
  history: { mode: "incremental", reason: null },
};

describe("incremental line in the HTML report", () => {
  it("says what was re-scanned and reused", () => {
    const html = renderHtmlReport(scanResult({ incremental: INFO }));
    expect(html).toContain("<strong>Incremental:</strong> re-scanned 3 files, reused 1997");
    expect(html).toContain("(based on scan 1a2b3c4d)");
  });

  it("is translated for the Korean report", () => {
    const html = renderHtmlReport(scanResult({ incremental: INFO }), { lang: "ko" });
    expect(html).toContain("<strong>증분 검사:</strong> 파일 3개 다시 검사, 1997개 재사용");
  });

  it("names the reason of a full scan", () => {
    const html = renderHtmlReport(
      scanResult({
        incremental: {
          ...INFO,
          used: false,
          reason: "head_not_ancestor",
          basedOn: null,
          code: { mode: "full", reason: "head_not_ancestor" },
          history: { mode: "full", reason: "head_not_ancestor" },
        },
      }),
    );
    expect(html).toContain("<strong>Full scan:</strong> the stored commit is not in this branch");
  });

  it("adds nothing for a result without the field", () => {
    const html = renderHtmlReport(scanResult());
    expect(html).not.toContain("Incremental:");
    expect(html).not.toContain("Full scan:");
  });
});
