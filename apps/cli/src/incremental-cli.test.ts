import { INCREMENTAL_FULL_REASONS, type IncrementalInfo, type ScanResult } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { UsageError, parseCommandLine } from "./options.js";
import { testResult } from "./test-support.js";
import { CLI_TEXT } from "./ui/i18n/cli-text.js";
import { formatSummaryBlock } from "./ui/formatters/result-summary.js";
import { createStyle } from "./ui/formatters/style.js";

const plain = createStyle(false);

const INCREMENTAL: IncrementalInfo = {
  used: true,
  reason: null,
  basedOn: { scanId: "1a2b3c4d5e6f", revision: "abc" },
  filesRescanned: 3,
  filesReused: 1997,
  commitsScanned: 2,
  commitsReused: 40,
  code: { mode: "incremental", reason: null },
  history: { mode: "incremental", reason: null },
};

function summary(result: ScanResult, locale: "en" | "ko"): string {
  const lines = formatSummaryBlock(result, null, {
    t: CLI_TEXT[locale],
    style: plain,
    width: 100,
    allFindings: false,
  });
  // Rows are padded and wrapped to the width: compare the words, not the layout.
  return lines.join(" ").replace(/\s+/g, " ");
}

describe("pgard scan --full", () => {
  it("is accepted for scan only, once", () => {
    expect(parseCommandLine(["scan", "--full"])).toMatchObject({ kind: "scan", full: true });
    expect(parseCommandLine(["scan", "code", "--full", "--no-store"])).toMatchObject({
      full: true,
      noStore: true,
    });
    expect(parseCommandLine(["scan"])).not.toHaveProperty("full");
    for (const argv of [
      ["doctor", "--full"],
      ["baseline", "show", "--full"],
      ["scan", "--full", "--full"],
    ]) {
      expect(() => parseCommandLine(argv), argv.join(" ")).toThrow(UsageError);
    }
  });
});

describe("incremental line of the summary", () => {
  it("says what was re-scanned and reused, and which scan it builds on (English)", () => {
    const text = summary(testResult({ incremental: INCREMENTAL }), "en");
    expect(text).toContain(
      "Incremental re-scanned 3 files, reused 1997; 2 new commits scanned, 40 reused (based on scan 1a2b3c4d)",
    );
    expect(text).not.toContain("Full scan");
  });

  it("says the same in Korean", () => {
    const text = summary(testResult({ incremental: INCREMENTAL }), "ko");
    expect(text).toContain("증분 검사");
    expect(text).toContain("파일 3개 다시 검사, 1997개 재사용");
    expect(text).toContain("새 커밋 2개 검사, 40개 재사용");
    expect(text).toContain("검사 1a2b3c4d 기준");
  });

  it("names the reason when the scan was a full one", () => {
    const full: IncrementalInfo = {
      used: false,
      reason: "config_changed",
      basedOn: null,
      filesRescanned: 12,
      filesReused: 0,
      commitsScanned: 5,
      commitsReused: 0,
      code: { mode: "full", reason: "config_changed" },
      history: { mode: "full", reason: "config_changed" },
    };
    expect(summary(testResult({ incremental: full }), "en")).toContain(
      "Full scan pgard.config.json changed since the stored scan",
    );
    expect(summary(testResult({ incremental: full }), "ko")).toContain(
      "전체 검사 저장된 검사 이후 pgard.config.json이 바뀜",
    );
  });

  it("flags an area that was scanned in full next to an incremental one", () => {
    const mixed: IncrementalInfo = {
      ...INCREMENTAL,
      reason: "history_changed",
      commitsScanned: 40,
      commitsReused: 0,
      history: { mode: "full", reason: "history_changed" },
    };
    const text = summary(testResult({ incremental: mixed }), "en");
    expect(text).toContain("history in full: the new commits change what the earlier history");
  });

  it("is left out of results without the field (older results, web only)", () => {
    expect(summary(testResult(), "en")).not.toMatch(/Incremental|Full scan/);
  });

  it("has a translation for every reason, in both languages", () => {
    for (const locale of ["en", "ko"] as const) {
      for (const reason of INCREMENTAL_FULL_REASONS) {
        expect(
          CLI_TEXT[locale].fullScanReason[reason].length,
          `${locale} ${reason}`,
        ).toBeGreaterThan(5);
      }
    }
  });
});
