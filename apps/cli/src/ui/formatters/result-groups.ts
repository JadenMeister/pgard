import { SEVERITIES, type Finding, type FindingStatus } from "@pgard/findings";

/**
 * Findings from test, fixture or vendored code are collapsed into a summary when there are MORE
 * than this many of them (5 are listed, 6 are collapsed). Findings in real code are never
 * collapsed, whatever their number.
 */
export const COLLAPSE_THRESHOLD = 5;

/** Locations named per group when not every location is requested. */
export const MAX_REPRESENTATIVE_LOCATIONS = 3;

const STATUS_RANK: Record<FindingStatus, number> = {
  confirmed: 0,
  suspected: 1,
  informational: 2,
};

function severityRank(severity: unknown): number {
  const index = (SEVERITIES as readonly unknown[]).indexOf(severity);
  return index === -1 ? SEVERITIES.length : index;
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Location order: file or URL, then line (numeric), then commit. */
function compareLocations(a: Finding, b: Finding): number {
  const left = a.location;
  const right = b.location;
  return (
    compareText(left.path ?? left.url ?? "", right.path ?? right.url ?? "") ||
    (left.line ?? 0) - (right.line ?? 0) ||
    compareText(left.commit ?? "", right.commit ?? "")
  );
}

/**
 * Severity (critical first), then confirmed before suspected before informational, then
 * location, then rule id and finding id so the order is fully deterministic.
 */
export function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank(a.severity) - severityRank(b.severity) ||
    (STATUS_RANK[a.status] ?? 3) - (STATUS_RANK[b.status] ?? 3) ||
    compareLocations(a, b) ||
    compareText(a.ruleId, b.ruleId) ||
    compareText(a.id, b.id)
  );
}

export function sortBySeverity(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(compareFindings);
}

export interface FindingGroup {
  /** First finding in sort order; its evidence and fix text stand for the whole group. */
  representative: Finding;
  /** Every finding of the group, in location order. */
  findings: Finding[];
}

/**
 * What "the same cause" means: the result carries no cause string (it is a fingerprint input
 * and only its hash is kept in `id`, which also contains the line), so a group is the findings
 * that agree on everything the result does expose about the cause: rule, title (which names the
 * kind of problem), severity, status, confidence, location kind and context. Only the place
 * (file, line, URL, commit) may differ.
 */
export function groupKey(finding: Finding): string {
  return [
    finding.ruleId,
    finding.title,
    finding.severity,
    finding.status,
    finding.confidence,
    finding.location.kind,
    finding.context ?? "",
  ].join("\u001f");
}

/** Groups findings (same rule and cause) and orders the groups by their first finding. */
export function groupFindings(findings: readonly Finding[]): FindingGroup[] {
  const groups = new Map<string, Finding[]>();
  for (const finding of sortBySeverity(findings)) {
    const key = groupKey(finding);
    const members = groups.get(key);
    if (members === undefined) groups.set(key, [finding]);
    else members.push(finding);
  }
  return [...groups.values()].map((members) => ({
    representative: members[0] as Finding,
    findings: members,
  }));
}

export interface CollapseSummary {
  count: number;
  byContext: Array<{ context: string; count: number }>;
  byRule: Array<{ ruleId: string; count: number }>;
  bySeverity: Array<{ severity: string; count: number }>;
}

function tally(keys: readonly string[]): Array<{ key: string; count: number }> {
  const counts = new Map<string, number>();
  for (const key of keys) counts.set(key, (counts.get(key) ?? 0) + 1);
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || compareText(a.key, b.key));
}

/** Whether test, fixture and vendored findings are summarized instead of listed. */
export function shouldCollapse(nonRealCount: number, allFindings: boolean): boolean {
  return !allFindings && nonRealCount > COLLAPSE_THRESHOLD;
}

export function summarizeCollapsed(findings: readonly Finding[]): CollapseSummary {
  return {
    count: findings.length,
    byContext: tally(findings.map((finding) => finding.context ?? "other")).map(
      ({ key, count }) => ({ context: key, count }),
    ),
    byRule: tally(findings.map((finding) => finding.ruleId)).map(({ key, count }) => ({
      ruleId: key,
      count,
    })),
    bySeverity: SEVERITIES.map((severity) => ({
      severity: severity as string,
      count: findings.filter((finding) => finding.severity === severity).length,
    })).filter((entry) => entry.count > 0),
  };
}
