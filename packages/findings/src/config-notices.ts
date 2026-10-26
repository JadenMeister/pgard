import type { Coverage } from "./contract.js";

/**
 * Notices about `pgard.config.json` that every front end (terminal, HTML and PDF report,
 * dashboard) shows above the findings, so the effect of the file is never visible only as a row
 * of the coverage table. They are derived from the coverage areas the scan wrote:
 * - `source:config-excluded`: "N files excluded by pgard.config.json ...";
 * - `source:config` (partial: invalid file, or `testDirectories` matching everything);
 * - `source:config-test` (partial: `testDirectories` demote most of the production code);
 * - `source:config` also carries how many findings `testDirectories` moved into the test group.
 */
export interface ConfigNotice {
  text: string;
  /** `warning` is shown prominently; `info` only records that a config was read. */
  tone: "warning" | "info";
}

const TEST_FINDINGS = /\((\d+) findings? classified as test code by it\)/;

/** How many findings `testDirectories` classified as test code (0 without a config). */
export function configTestFindingCount(coverage: readonly Coverage[]): number {
  const note = coverage.find((entry) => entry.area === "source:config")?.note ?? "";
  return Number(TEST_FINDINGS.exec(note)?.[1] ?? 0);
}

/** Sentence for the test-code group when the config, not the built-in rules, classified some. */
export function configTestGroupNote(coverage: readonly Coverage[]): string {
  const count = configTestFindingCount(coverage);
  return count === 0
    ? ""
    : ` ${count} of them ${count === 1 ? "was" : "were"} classified by the testDirectories setting of pgard.config.json, not by the built-in rules.`;
}

export function projectConfigNotices(coverage: readonly Coverage[]): ConfigNotice[] {
  const notices: ConfigNotice[] = [];
  for (const entry of coverage) {
    if (entry.note === null) continue;
    if (entry.area === "source:config-excluded") {
      const isNone = /^0 files /.test(entry.note);
      notices.push({
        text: entry.note,
        tone: entry.status === "partial" || !isNone ? "warning" : "info",
      });
    } else if (
      (entry.area === "source:config" || entry.area === "source:config-test") &&
      entry.status === "partial"
    ) {
      notices.push({ text: entry.note, tone: "warning" });
    }
  }
  const count = configTestFindingCount(coverage);
  if (count > 0) {
    notices.push({
      text: `${count} finding${count === 1 ? " was" : "s were"} classified as test code by the testDirectories setting of pgard.config.json (listed apart, confidence capped at low). Review ${count === 1 ? "it" : "them"}.`,
      tone: "warning",
    });
  }
  return notices;
}
