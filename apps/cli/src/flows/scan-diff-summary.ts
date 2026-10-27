import {
  compareScans,
  type AreaComparability,
  notComparableAreas,
  SCHEMA_VERSION,
  type ScanComparison,
  type ScanResult,
} from "@pgard/findings";
import type { ResultStore, StoredScan } from "@pgard/result-store";
import { CLI_TEXT, type CliText } from "../ui/i18n/cli-text.js";
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

export function isNewerMinor(sourceVersion: string): boolean {
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

export function formatWarnings(warnings: readonly string[], t: CliText = CLI_TEXT.en): string[] {
  if (warnings.length === 0) return [];
  const shown = warnings.slice(0, MAX_WARNINGS).map((line) => safeText(line, 200));
  const rest = warnings.length - shown.length;
  return [...shown, ...(rest > 0 ? [t.diff.skippedStored(rest)] : [])];
}

/** Rule-less areas are skip signals: they appear or change, they are not "out of scope". */
function describeReason(area: AreaComparability, t: CliText): string {
  const because = t.diff.because;
  if (area.reason === null) return because.changed;
  if (!area.ownsRules && area.reason === "only_in_current") return because.appeared;
  if (!area.ownsRules && area.reason === "only_in_previous") return because.lastOnly;
  return because[area.reason];
}

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
  t: CliText = CLI_TEXT.en,
): string {
  const text = t.diff;
  const pairs = [...comparison.unchanged, ...comparison.moved];
  const rated = pairs.filter(
    (pair) => pair.changed.includes("severity") || pair.changed.includes("status"),
  ).length;
  const uncertain = comparison.newInUncertainAreas.length;
  const named = comparison.uncertainAreas.slice(0, 2).map((area) => safeText(area, 40));
  const newText = text.newCount(comparison.new.length, uncertain, named.join(", "));
  const details = [
    ...(comparison.moved.length > 0 ? [text.moved(comparison.moved.length)] : []),
    ...(rated > 0 ? [text.changedRating(rated)] : []),
  ];
  const previousRevision = shortRevision(revisions.previous);
  const differs =
    previousRevision !== null && previousRevision !== shortRevision(revisions.current);
  const when = `${formatScanTime(previousSavedAt)}${differs ? text.atRevision(previousRevision) : ""}`;
  let line = `${text.sinceLast(when)}: ${newText}, ${text.noLongerReported(comparison.noLongerReported.length)}, ${text.unchanged(pairs.length)}${details.length > 0 ? ` (${details.join(", ")})` : ""}`;
  if (comparison.toolVersionChanged && comparison.notComparable.length > 0) {
    line += `. ${text.toolUpdated(comparison.notComparable.length)}`;
  }
  const areas = notComparableAreas(comparison);
  if (areas.length > 0) {
    const shown = areas
      .slice(0, 3)
      .map((area) => `${safeText(area.area, 40)} ${describeReason(area, t)}`);
    const more = Math.max(0, areas.length - 3);
    const held = areas.reduce((sum, area) => sum + area.held, 0);
    line +=
      held > 0
        ? `. ${text.notComparedBecause(shown.join("; "), more)}`
        : `. ${text.notFullyCompared(shown.join("; "), more)}`;
  }
  const explained = areas.reduce((sum, area) => sum + area.held, 0);
  if (!comparison.toolVersionChanged && comparison.notComparable.length > 0 && explained === 0) {
    line += `. ${text.couldNotCheck(comparison.notComparable.length)}`;
  }
  return line;
}

export function summarizeSinceLastScan(
  current: ScanResult,
  previous: StoredScan,
  t: CliText = CLI_TEXT.en,
): string {
  return formatComparisonLine(
    compareScans(previous.result, current),
    previous.savedAt,
    { previous: previous.result.target.revision, current: current.target.revision },
    t,
  );
}
