import { compareScans } from "./compare-scans.js";
import type { BaselineSummary, Finding, ScanResult } from "./contract.js";

/**
 * Baseline: a stored scan of the same repository that the user accepted as the reference
 * (`pgard baseline set`). Findings of a later scan that match it are flagged `inBaseline` and
 * listed in their own group; the others are new. Nothing is removed, and the status and exit code
 * never depend on the baseline.
 *
 * Matching uses exactly the identity and one-to-one pairing of the scan comparison
 * (`compareScans`): the same issue on another line is still "in baseline", a second copy of it
 * is new. Suppressed findings are matched like any other.
 */

export interface AppliedBaseline {
  result: ScanResult;
  summary: BaselineSummary;
}

/** Marks findings of `current` that are in `baseline`, and adds the `baseline` summary. */
export function applyBaseline(
  current: ScanResult,
  baseline: ScanResult,
  setAt: Date,
): AppliedBaseline {
  const comparison = compareScans(baseline, current);
  const known = new Set<Finding>(
    [...comparison.unchanged, ...comparison.moved].map((pair) => pair.current),
  );
  const findings = current.findings.map((finding): Finding => {
    if (!known.has(finding)) return finding;
    return { ...finding, inBaseline: true };
  });
  const summary: BaselineSummary = {
    setAt: setAt.toISOString(),
    scanId: baseline.scanId,
    revision: baseline.target.revision,
    total: baseline.findings.length,
    matched: known.size,
    new: current.findings.length - known.size,
    newInUncertainAreas: comparison.newInUncertainAreas.length,
    toolVersionChanged: comparison.toolVersionChanged,
  };
  return { result: { ...current, findings, baseline: summary }, summary };
}

/** The result without the marks of an earlier baseline: what a new baseline is stored from. */
export function stripBaselineMarks(result: ScanResult): ScanResult {
  const { baseline: _baseline, ...rest } = result;
  return {
    ...rest,
    findings: result.findings.map((finding) => {
      const { inBaseline: _inBaseline, ...plain } = finding;
      return plain;
    }),
  };
}

export interface BaselineNotice {
  kind: "new" | "uncertain" | "tool";
  text: string;
  count?: number;
  tone: "warning" | "info";
}

/** Short lines every front end shows when a baseline was applied. */
export function baselineNotices(summary: BaselineSummary | undefined): BaselineNotice[] {
  if (summary === undefined) return [];
  const notices: BaselineNotice[] = [];
  if (summary.newInUncertainAreas > 0) {
    notices.push({
      kind: "uncertain",
      count: summary.newInUncertainAreas,
      tone: "warning",
      text: `${summary.newInUncertainAreas} new finding${summary.newInUncertainAreas === 1 ? "" : "s"} sit in areas the baseline did not fully cover, so ${summary.newInUncertainAreas === 1 ? "it" : "they"} may be old.`,
    });
  }
  if (summary.toolVersionChanged) {
    notices.push({
      kind: "tool",
      tone: "warning",
      text: "PGARD was updated since the baseline was set; rules may have changed, so read the new and in-baseline counts with care.",
    });
  }
  return notices;
}

/** "12 in baseline, 3 new (baseline set 2026-10-20)". */
export function formatBaselineCounts(summary: BaselineSummary): string {
  return `${summary.matched} in baseline, ${summary.new} new`;
}

export interface FindingPartition {
  /** Matched an active suppression. Takes precedence over the baseline. */
  suppressed: Finding[];
  /** In the baseline and not suppressed. */
  baseline: Finding[];
  /** Everything else: the findings the severity groups and counts are about. */
  rest: Finding[];
}

/**
 * The one place that decides where a finding is listed, for every front end: suppressed first,
 * then in the baseline, then the rest. Every finding lands in exactly one list.
 */
export function partitionFindings(findings: readonly Finding[]): FindingPartition {
  const partition: FindingPartition = { suppressed: [], baseline: [], rest: [] };
  for (const finding of findings) {
    if (finding.suppression !== undefined) partition.suppressed.push(finding);
    else if (finding.inBaseline === true) partition.baseline.push(finding);
    else partition.rest.push(finding);
  }
  return partition;
}
