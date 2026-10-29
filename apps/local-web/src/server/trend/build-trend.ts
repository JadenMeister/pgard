import { compareScans, SCHEMA_VERSION, type Coverage, type Finding } from "@pgard/findings";
import {
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
  type TrendSeverityCounts,
} from "../../shared/api-types.js";

/** A stored scan dated further ahead than this (clock drift) counts as future-dated. */
export const FUTURE_TOLERANCE_MS = 5 * 60 * 1000;

/** A newer minor of the result schema than this build understands (same rule as the CLI panel). */
function isNewerMinor(sourceVersion: string): boolean {
  const [major = 0, minor = 0] = sourceVersion.split(".").map(Number);
  const [currentMajor = 0, currentMinor = 0] = SCHEMA_VERSION.split(".").map(Number);
  return major > currentMajor || (major === currentMajor && minor > currentMinor);
}

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

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

function countFindings(findings: readonly Finding[]) {
  const severity: TrendSeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let ignored = 0;
  let baselined = 0;
  for (const finding of findings) {
    if (finding.suppression !== undefined) ignored += 1;
    else if (finding.inBaseline === true) baselined += 1;
    else if ((SEVERITIES as readonly string[]).includes(finding.severity)) {
      severity[finding.severity] += 1;
    }
  }
  const total = SEVERITIES.reduce((sum, name) => sum + severity[name], 0);
  return { severity, total, ignored, baselined };
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
  const listed = await store.list(repositoryId, {
    limit: Math.min(TREND_MAX_POINTS, RETENTION_MAX_SCANS_PER_REPO),
    isUsable: (scan) => !isNewerMinor(scan.sourceVersion),
  });
  if (listed.scans.length === 0 && listed.warnings.length > 0) {
    return { kind: "unavailable", why: "unreadable" };
  }
  const inOrder = listed.scans.filter(
    (scan) => scan.savedAt.getTime() <= now + FUTURE_TOLERANCE_MS,
  );
  const futureSkipped = listed.scans.length - inOrder.length;
  // `list` is newest first; the chart reads oldest first.
  const scans = [...inOrder].sort((a, b) => a.savedAt.getTime() - b.savedAt.getTime());
  const points: TrendPointDto[] = scans.map((scan, index) => {
    const previous = scans[index - 1];
    return {
      savedAt: scan.savedAt.getTime(),
      ...coverageOf(scan.result.coverage, scan.result.overallStatus),
      ...countFindings(scan.result.findings),
      change: previous === undefined ? null : changeOf(previous, scan),
    };
  });
  return {
    kind: "ready",
    points,
    skipped: listed.warnings.length,
    newerSkipped: listed.rejected,
    futureSkipped,
    unread: listed.unread,
  };
}
