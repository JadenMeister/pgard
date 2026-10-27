import { compareScans, type Severity } from "@pgard/findings";
import type { AuthorizationOutcome } from "@pgard/scan-core";
import { RETENTION_MAX_SCANS_PER_REPO, type StoredScan } from "@pgard/result-store";
import type { CommandContext } from "../context.js";
import { safeText } from "../ui/formatters/style.js";
import { type TrendData, type TrendDiff, type TrendScan } from "../ui/panels/types.js";
import { isNewerMinor } from "./scan-diff-summary.js";
import { NO_STORE_ENV } from "./store-result.js";

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

function toTrendScan(scan: StoredScan): TrendScan {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of scan.result.findings) {
    if (SEVERITIES.includes(finding.severity)) counts[finding.severity] += 1;
  }
  return {
    savedAt: scan.savedAt.getTime(),
    counts,
    total: SEVERITIES.reduce((sum, severity) => sum + counts[severity], 0),
  };
}

function diffOf(previous: StoredScan, latest: StoredScan): TrendDiff | null {
  try {
    const comparison = compareScans(previous.result, latest.result);
    return {
      newCount: comparison.new.length,
      fixedCount: comparison.noLongerReported.length,
      unchangedCount: comparison.unchanged.length + comparison.moved.length,
    };
  } catch {
    return null;
  }
}

/**
 * The trend panel's data: this repository's stored scans (at most 20, the store's own limit),
 * read from the local store only. Nothing is rescanned and no source file or secret is read; the
 * stored results are already redacted and only counted here. Never throws: a store that cannot be
 * read becomes an "unavailable" state with a short reason, and the scan or its exit code is not
 * affected.
 */
export async function loadTrend(
  context: CommandContext,
  outcome: AuthorizationOutcome | null,
  noStoreFlag: boolean,
  /** The scan the view opened for: the panel says so when it is not among the stored ones. */
  currentScanId: string | null = null,
  now: () => number = Date.now,
): Promise<TrendData> {
  try {
    if (noStoreFlag || context.io.env[NO_STORE_ENV] === "1") return { kind: "disabled" };
    const store = context.deps.openResultStore(context.io.env);
    if (store === null) return { kind: "unavailable", why: "no-store-dir", reason: "" };
    const repositoryId = outcome?.repositoryId;
    if (typeof repositoryId !== "number") {
      return { kind: "unavailable", why: "no-repository", reason: "" };
    }
    const listed = await store.list(repositoryId);
    if (listed.scans.length === 0 && listed.warnings.length > 0) {
      return {
        kind: "unavailable",
        why: "unreadable",
        reason: safeText(listed.warnings[0] ?? "", 100),
      };
    }
    // `list` is newest first; the panel wants the newest 20, oldest first.
    const usable = listed.scans.filter((scan) => !isNewerMinor(scan.sourceVersion));
    const newest = usable.slice(0, RETENTION_MAX_SCANS_PER_REPO);
    const [latest, previous] = newest;
    return {
      kind: "ready",
      scans: newest.map(toTrendScan).reverse(),
      diff: latest !== undefined && previous !== undefined ? diffOf(previous, latest) : null,
      skipped: listed.warnings.length,
      newerSkipped: listed.scans.length - usable.length,
      isCurrentStored:
        currentScanId === null || listed.scans.some((scan) => scan.result.scanId === currentScanId),
      now: now(),
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    return { kind: "unavailable", why: "unreadable", reason: safeText(message, 100) };
  }
}
