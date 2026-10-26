import {
  compareScans,
  notComparableAreas,
  SCHEMA_VERSION,
  type NotComparableReason,
  type ScanComparison,
  type ScanResult,
} from "@pgard/findings";
import type { ResultStore, StoredScan } from "@pgard/result-store";
import { safeText } from "../ui/formatters/style.js";

/** How many skipped-file warnings are shown before the rest are only counted. */
const MAX_WARNINGS = 3;

const REASON_TEXT: Record<NotComparableReason, string> = {
  partial: "partial",
  not_tested: "not tested",
  only_in_previous: "ran in one scan only",
  only_in_current: "ran in one scan only",
  not_run: "not run",
};

function pad(value: number): string {
  return String(value).padStart(2, "0");
}

/** Local time, `YYYY-MM-DD HH:mm`. */
export function formatScanTime(date: Date): string {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function isNewerMinor(sourceVersion: string): boolean {
  const [major = 0, minor = 0] = sourceVersion.split(".").map(Number);
  const [currentMajor = 0, currentMinor = 0] = SCHEMA_VERSION.split(".").map(Number);
  return major > currentMajor || (major === currentMajor && minor > currentMinor);
}

export interface PreviousScan {
  scan: StoredScan | null;
  /** Why some stored files were not used (corrupt, too large, written by a newer PGARD). */
  warnings: string[];
}

/**
 * Newest stored scan of this repository to compare against. Everything goes through the store's
 * `list`, which reads each file with a size cap and `readScanResult`. A file written by a newer
 * minor schema is skipped with a warning (this version might misread it). The result is only ever
 * compared, never used to authorize anything.
 */
export async function findPreviousScan(
  store: ResultStore,
  repositoryId: number,
  currentScanId: string,
): Promise<PreviousScan> {
  const listed = await store.list(repositoryId);
  const warnings = [...listed.warnings];
  for (const scan of listed.scans) {
    if (scan.result.scanId === currentScanId) continue;
    if (isNewerMinor(scan.sourceVersion)) {
      warnings.push(
        `Skipped stored result ${safeText(scan.file, 40)}: it uses schema version ${safeText(scan.sourceVersion, 12)}, newer than this PGARD understands.`,
      );
      continue;
    }
    return { scan, warnings };
  }
  return { scan: null, warnings };
}

export function formatWarnings(warnings: readonly string[]): string[] {
  if (warnings.length === 0) return [];
  const shown = warnings.slice(0, MAX_WARNINGS).map((line) => safeText(line, 200));
  const rest = warnings.length - shown.length;
  return [
    ...shown,
    ...(rest > 0 ? [`${rest} more stored result(s) were skipped and not compared.`] : []),
  ];
}

/** One line: `Since the last scan (2026-10-25 14:02): 2 new, 1 fixed, 9 unchanged (3 moved)`. */
export function formatComparisonLine(comparison: ScanComparison, previousSavedAt: Date): string {
  const unchanged = comparison.unchanged.length + comparison.moved.length;
  const moved = comparison.moved.length > 0 ? ` (${comparison.moved.length} moved)` : "";
  let line = `Since the last scan (${formatScanTime(previousSavedAt)}): ${comparison.new.length} new, ${comparison.fixed.length} fixed, ${unchanged} unchanged${moved}`;
  const skipped = notComparableAreas(comparison);
  if (skipped.length > 0) {
    const names = skipped
      .slice(0, 3)
      .map((area) => `${safeText(area.area, 40)}: ${REASON_TEXT[area.reason ?? "not_run"]}`);
    const more = skipped.length > 3 ? `, +${skipped.length - 3} more` : "";
    const held = comparison.notComparable.previous.length + comparison.notComparable.current.length;
    line += `. Not compared (${names.join(", ")}${more})${held > 0 ? `; ${held} finding(s) there are neither new nor fixed` : ""}`;
  }
  return line;
}

export function summarizeSinceLastScan(current: ScanResult, previous: StoredScan): string {
  return formatComparisonLine(compareScans(previous.result, current), previous.savedAt);
}
