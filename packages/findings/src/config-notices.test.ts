import { describe, expect, it } from "vitest";
import type { Coverage } from "./contract.js";
import {
  configTestFindingCount,
  configTestGroupNote,
  projectConfigNotices,
} from "./config-notices.js";

const area = (name: string, status: Coverage["status"], note: string | null): Coverage => ({
  area: name,
  scope: "code",
  status,
  ruleIds: [],
  note,
});

describe("projectConfigNotices", () => {
  it("a catch-all testDirectories with zero findings still warns", () => {
    const coverage = [
      area(
        "source:config",
        "partial",
        'pgard.config.json read (version 1): 0 exclude patterns, 1 test directory pattern (0 findings classified as test code by it), 0 suppressions parsed, not yet applied. WARNING: testDirectories "**" matches every file.',
      ),
      area(
        "source:config-test",
        "partial",
        "2 of 2 source files are classified ... WARNING: most or all",
      ),
    ];
    const notices = projectConfigNotices(coverage);
    expect(notices.map((n) => n.kind)).toEqual(["config", "test"]);
    expect(notices.every((n) => n.tone === "warning")).toBe(true);
    expect(configTestFindingCount(coverage)).toBe(0);
    expect(configTestGroupNote(coverage)).toBe("");
  });

  it("classifies each notice and counts demoted findings", () => {
    const coverage = [
      area("source:config-excluded", "completed", "3 files excluded by pgard.config.json."),
      area("source:config", "completed", "x (2 findings classified as test code by it)"),
    ];
    const notices = projectConfigNotices(coverage);
    expect(notices.map((n) => n.kind)).toEqual(["excluded", "demoted"]);
    expect(notices[1]?.count).toBe(2);
    expect(configTestGroupNote(coverage)).toContain("2 of them were classified");
  });

  it("zero excluded files is only information, null notes are skipped, singular wording", () => {
    const coverage = [
      area("source:config-excluded", "completed", "0 files excluded by pgard.config.json."),
      area("source:config-excluded", "completed", null),
      area("source:config", "completed", "x (1 finding classified as test code by it)"),
    ];
    const notices = projectConfigNotices(coverage);
    expect(notices[0]).toMatchObject({ kind: "excluded", tone: "info" });
    expect(notices[1]?.text).toContain("1 finding was classified");
    expect(configTestGroupNote(coverage)).toContain("1 of them was classified");
  });
});
