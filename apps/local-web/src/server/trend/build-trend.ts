import { compareScans, type Coverage } from "@pgard/findings";
import {
  countFindingStates,
  isFutureDated,
  isNewerSchemaMinor,
  RETENTION_MAX_SCANS_PER_REPO,
  type ResultStore,
  type StoredScan,
} from "@pgard/result-store";
import {
  TREND_MAX_POINTS,
  type TrendChangeDto,
  type TrendCoverage,
  type TrendPointDto,
  type TrendResponse,
} from "../../shared/api-types.js";

/**
 * How completely the scan covered what it was asked to check. A scan is "completed" only when
 * every selected area completed; one partial or untested area makes it "partial"; "not_tested"
 * means nothing that was selected ran at all. A blocked or failed overall status is never stored,
 * but counts as partial here if a hand-edited file says so.
 */
export function coverageOf(
  coverage: readonly Coverage[],
  overallStatus: string,
): { coverage: TrendCoverage; incompleteAreas: number } {
  const selected = coverage.filter((entry) => entry.status !== "not_selected");
  const incompleteAreas = selected.filter((entry) => entry.status !== "completed").length;
  if (selected.length > 0 && selected.every((entry) => entry.status === "not_tested")) {
    return { coverage: "not_tested", incompleteAreas };
  }
  const isPartial = incompleteAreas > 0 || overallStatus !== "completed";
  return { coverage: isPartial ? "partial" : "completed", incompleteAreas };
}

function changeOf(previous: StoredScan, current: StoredScan): TrendChangeDto | null {
  try {
    const comparison = compareScans(previous.result, current.result);
    return {
      new: comparison.new.length,
      noLongerReported: comparison.noLongerReported.length,
      unchanged: comparison.unchanged.length + comparison.moved.length,
      notComparable: comparison.notComparable.length,
    };
  } catch {
    return null;
  }
}

/**
 * The trend of one repository: its saved scans (at most 20, the store's own limit), oldest first,
 * as counts only. Reads the local store only; nothing is rescanned. Scans from a newer schema are
 * counted and left out, and scans dated in the future are left out too, so a tampered or
 * clock-skewed file can neither reverse the order nor become the "latest" scan. The store is
 * keyed by repository id, so another repository's scans are never read. Throws only when the
 * store itself cannot be read; the caller turns that into an "unreadable" answer.
 */
export async function buildTrend(
  store: ResultStore,
  repositoryId: number,
  now: number,
): Promise<TrendResponse> {
  // Future-dated and newer-schema files are turned down inside `isUsable`, before the limit
  // applies, so they can never use up the 20 slots and push real scans out.
  let future = 0;
  const listed = await store.list(repositoryId, {
    limit: Math.min(TREND_MAX_POINTS, RETENTION_MAX_SCANS_PER_REPO),
    isUsable: (scan) => {
      if (isNewerSchemaMinor(scan.sourceVersion)) return false;
      if (isFutureDated(scan.savedAt.getTime(), now)) {
        future += 1;
        return false;
      }
      return true;
    },
  });
  if (listed.scans.length === 0 && listed.warnings.length > 0) {
    return { kind: "unavailable", why: "unreadable" };
  }
  const futureSkipped = future;
  // `list` is newest first; the chart reads oldest first.
  const scans = [...listed.scans].sort((a, b) => a.savedAt.getTime() - b.savedAt.getTime());
  const points: TrendPointDto[] = scans.map((scan, index) => {
    const previous = scans[index - 1];
    return {
      savedAt: scan.savedAt.getTime(),
      ...coverageOf(scan.result.coverage, scan.result.overallStatus),
      ...countFindingStates(scan.result.findings),
      change: previous === undefined ? null : changeOf(previous, scan),
    };
  });
  return {
    kind: "ready",
    points,
    skipped: listed.warnings.length,
    newerSkipped: listed.rejected - futureSkipped,
    futureSkipped,
    unread: listed.unread,
  };
}
