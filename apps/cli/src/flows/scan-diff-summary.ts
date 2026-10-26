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
  const found = await store.findNewest(repositoryId, (scan) => {
    if (scan.result.scanId === currentScanId) return "it is the scan being compared.";
    if (isNewerMinor(scan.sourceVersion)) {
      return `it uses schema version ${safeText(scan.sourceVersion, 12)}, newer than this PGARD understands.`;
    }
    return null;
  });
  // The scan being compared is skipped silently: it is not a problem with the store.
  const warnings = found.warnings.filter(
    (line) => !line.endsWith("it is the scan being compared."),
  );
  return { scan: found.scan, warnings };
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

const BECAUSE_TEXT: Record<NotComparableReason, string> = {
  partial: "was only partially scanned",
  not_tested: "was not tested",
  only_in_previous: "ran in only one of the two scans",
  only_in_current: "ran in only one of the two scans",
  not_run: "was not run",
  other_origin: "used a different web address",
};

export interface RevisionInfo {
  previous: string | null;
  current: string | null;
}

function shortRevision(value: string | null): string | null {
  return value !== null && /^[0-9a-f]{7,64}$/i.test(value) ? value.slice(0, 7) : null;
}

/**
 * One line: `Since the last scan (2026-10-25 14:02, local time): 2 new (1 in partially scanned
 * areas), 1 no longer reported, 9 unchanged (3 moved)`. "No longer reported" is not "fixed": the
 * code may also have been skipped, renamed or removed.
 */
export function formatComparisonLine(
  comparison: ScanComparison,
  previousSavedAt: Date,
  revisions: RevisionInfo = { previous: null, current: null },
): string {
  const pairs = [...comparison.unchanged, ...comparison.moved];
  const rated = pairs.filter(
    (pair) => pair.changed.includes("severity") || pair.changed.includes("status"),
  ).length;
  const uncertain = comparison.newInUncertainAreas.length;
  const newText = `${comparison.new.length} new${uncertain > 0 ? ` (${uncertain} in partially scanned areas)` : ""}`;
  const details = [
    ...(comparison.moved.length > 0 ? [`${comparison.moved.length} moved`] : []),
    ...(rated > 0 ? [`${rated} changed severity or status`] : []),
  ];
  const previousRevision = shortRevision(revisions.previous);
  const differs =
    previousRevision !== null && previousRevision !== shortRevision(revisions.current);
  const when = `${formatScanTime(previousSavedAt)}${differs ? `, at ${previousRevision}` : ""}`;
  let line = `Since the last scan (${when}): ${newText}, ${comparison.noLongerReported.length} no longer reported, ${pairs.length} unchanged${details.length > 0 ? ` (${details.join(", ")})` : ""}`;
  if (comparison.toolVersionChanged && comparison.notComparable.length > 0) {
    line += `. PGARD was updated since the last scan, so ${comparison.notComparable.length} earlier finding(s) that are not reported now could not be checked`;
  }
  const areas = notComparableAreas(comparison);
  if (areas.length > 0) {
    const shown = areas
      .slice(0, 3)
      .map((area) => `${safeText(area.area, 40)} ${BECAUSE_TEXT[area.reason ?? "not_run"]}`);
    const more = areas.length > 3 ? `, and ${areas.length - 3} more area(s)` : "";
    const held = areas.reduce((sum, area) => sum + area.held, 0);
    line +=
      held > 0
        ? `. Some findings could not be compared because ${shown.join("; ")}${more}`
        : `. Not fully compared: ${shown.join("; ")}${more}`;
  }
  return line;
}

export function summarizeSinceLastScan(current: ScanResult, previous: StoredScan): string {
  return formatComparisonLine(compareScans(previous.result, current), previous.savedAt, {
    previous: previous.result.target.revision,
    current: current.target.revision,
  });
}
