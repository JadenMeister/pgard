import { compareScans } from "./compare-scans.js";
import type { BaselineSummary, Finding, ScanResult } from "./contract.js";
import { countBySeverity, formatSeverityBreakdown } from "./suppressions.js";

/**
 * Baseline: a stored scan of the same repository that the user accepted as the reference
 * (`pgard baseline set`). Findings of a later scan that match it are flagged `inBaseline` and
 * listed in their own group; the others are new. Nothing is removed, and the status and exit code
 * never depend on the baseline.
 *
 * Matching uses exactly the identity and one-to-one pairing of the scan comparison
 * (`compareScans`): the same issue on another line is still "in baseline", a second copy of it
 * is new.
 *
 * Suppressed findings are left out of a baseline (`baselineSnapshot`): a suppression is a
 * temporary, expiring statement, and a finding the baseline swallowed together with it would stay
 * hidden after the suppression is removed or expires. Left out, it comes back as new then. A
 * suppressed finding of the current scan is still matched (it keeps `suppression` and gets
 * `inBaseline`), but it is counted under the suppressions only, never as "in baseline" or "new".
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
  // An older baseline may still hold suppressed findings: they do not count as accepted.
  const accepted = baselineSnapshot(baseline);
  const comparison = compareScans(accepted, current);
  const known = new Set<Finding>(
    [...comparison.unchanged, ...comparison.moved].map((pair) => pair.current),
  );
  const findings = current.findings.map((finding): Finding => {
    if (!known.has(finding)) return finding;
    return { ...finding, inBaseline: true };
  });
  const isOpen = (finding: Finding) => finding.suppression === undefined;
  const matched = [...known].filter(isOpen).length;
  const summary: BaselineSummary = {
    setAt: setAt.toISOString(),
    scanId: baseline.scanId,
    revision: baseline.target.revision,
    total: accepted.findings.length,
    matched,
    new: current.findings.filter((finding) => isOpen(finding) && !known.has(finding)).length,
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

/**
 * What a baseline is stored as: the result without the marks of an earlier baseline and without
 * suppressed findings.
 */
export function baselineSnapshot(result: ScanResult): ScanResult {
  const stripped = stripBaselineMarks(result);
  return {
    ...stripped,
    findings: stripped.findings.filter((finding) => finding.suppression === undefined),
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

/** "6 in baseline (1 critical, 5 high), 0 new"; the breakdown comes from the baseline group. */
export function formatBaselineCounts(
  summary: BaselineSummary,
  inBaseline: readonly Pick<Finding, "severity">[] = [],
): string {
  const breakdown = formatSeverityBreakdown(countBySeverity(inBaseline));
  return `${summary.matched} in baseline${breakdown === "" ? "" : ` (${breakdown})`}, ${summary.new} new`;
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
