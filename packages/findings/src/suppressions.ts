import type {
  Finding,
  ScanResult,
  SuppressionEntryResult,
  SuppressionSummary,
} from "./contract.js";
import {
  MAX_GLOB_WORK,
  compileGlob,
  compilePathMatcher,
  matchesEverything,
  type PathMatcher,
} from "./glob.js";
import type { ProjectSuppression } from "./project-config.js";

/**
 * Applying `suppressions` of `pgard.config.json`. The file is part of the scanned repository, so
 * it is untrusted: a suppression can only change where a finding is listed, never remove it.
 *
 * Policy (also in the README):
 * - An entry matches a finding when the rule id is equal and the path glob matches the finding's
 *   repository-relative path. A finding without a file path (a web finding, location kind `url`)
 *   is matched only by an entry whose pattern matches every file (`**`, `*`), which is always
 *   flagged as a wildcard.
 * - The first active entry (in file order) is the one recorded on the finding; every active entry
 *   still counts the findings it matches, so an entry that matches a lot is visible even when an
 *   earlier entry took the findings.
 * - An entry expires at the end of its `expires` day (UTC). An expired entry is not applied: its
 *   findings stay in the regular groups, and the entry is reported.
 * - Critical findings may be suppressed. They are never silent: the count says "including K
 *   critical", the notices carry a warning, and the terminal lists critical suppressed findings in
 *   full even without `--all-findings`.
 * - Status and exit code never depend on suppressions.
 * - Pattern matching shares one work budget. When it runs out, the remaining findings are NOT
 *   suppressed (the failure direction is "more is shown") and `incomplete` is set.
 */

/** An active entry that matches more findings than this is flagged in the notices. */
export const BROAD_SUPPRESSION_THRESHOLD = 10;

const DAY = /^(\d{4})-(\d{2})-(\d{2})$/;

/** True when `expires` (`YYYY-MM-DD`) is before today in UTC. Unparseable counts as expired. */
export function isSuppressionExpired(expires: string | undefined, now: Date): boolean {
  if (expires === undefined) return false;
  if (!DAY.test(expires)) return true;
  return now.toISOString().slice(0, 10) > expires;
}

export interface AppliedSuppressions {
  findings: Finding[];
  /** `null` when the config has no suppressions. */
  summary: SuppressionSummary | null;
}

interface Compiled {
  source: ProjectSuppression;
  expired: boolean;
  wildcard: boolean;
  matcher: PathMatcher | null;
  matched: number;
}

export function applySuppressions(
  findings: readonly Finding[],
  suppressions: readonly ProjectSuppression[],
  now: Date,
  maxWork: number = MAX_GLOB_WORK,
): AppliedSuppressions {
  if (suppressions.length === 0) return { findings: [...findings], summary: null };
  let spent = 0;
  const compiled: Compiled[] = suppressions.map((source) => {
    const expired = isSuppressionExpired(source.expires, now);
    const wildcard = matchesEverything(compileGlob(source.path));
    return {
      source,
      expired,
      wildcard,
      matcher: expired || wildcard ? null : compilePathMatcher([source.path], maxWork),
      matched: 0,
    };
  });
  const active = compiled.filter((entry) => !entry.expired);
  let incomplete = false;
  const matches = (entry: Compiled, finding: Finding): boolean => {
    if (entry.source.ruleId !== finding.ruleId) return false;
    if (entry.wildcard) return true;
    const filePath = finding.location.kind === "url" ? null : finding.location.path;
    if (filePath === null || entry.matcher === null) return false;
    // One budget for all entries: the work of every matcher adds up.
    const before = entry.matcher.work;
    const matched = entry.matcher.matches(filePath);
    spent += entry.matcher.work - before;
    if (entry.matcher.exhausted || spent > maxWork) incomplete = true;
    return matched && !entry.matcher.exhausted;
  };
  let critical = 0;
  let suppressed = 0;
  const result = findings.map((finding): Finding => {
    let applied: ProjectSuppression | null = null;
    for (const entry of active) {
      if (incomplete) break;
      if (!matches(entry, finding)) continue;
      entry.matched += 1;
      applied ??= entry.source;
    }
    if (applied === null || incomplete) return finding;
    suppressed += 1;
    if (finding.severity === "critical") critical += 1;
    return {
      ...finding,
      suppression: {
        reason: applied.reason,
        ...(applied.expires === undefined ? {} : { expires: applied.expires }),
        source: "pgard.config.json",
      },
    };
  });
  const entries: SuppressionEntryResult[] = compiled.map((entry) => ({
    ruleId: entry.source.ruleId,
    path: entry.source.path,
    reason: entry.source.reason,
    ...(entry.source.expires === undefined ? {} : { expires: entry.source.expires }),
    state: entry.expired ? "expired" : "active",
    matched: entry.matched,
    wildcard: entry.wildcard,
  }));
  return {
    findings: result,
    summary: { source: "pgard.config.json", suppressed, critical, entries, incomplete },
  };
}

export type SuppressionNoticeKind =
  "critical" | "wildcard" | "broad" | "expired" | "incomplete" | "everything";

export interface SuppressionNotice {
  kind: SuppressionNoticeKind;
  text: string;
  /** Entry the notice is about (not for `critical`, `incomplete` or `everything`). */
  ruleId?: string;
  path?: string;
  expires?: string;
  count?: number;
  /** Always `warning`: a suppression notice is never merely informational. */
  tone: "warning";
}

/**
 * Warnings every front end shows above the findings. Derived from the result alone (the summary
 * and the findings), so the terminal, HTML and PDF reports and the dashboard agree.
 */
export function suppressionNotices(
  result: Pick<ScanResult, "suppressions" | "findings">,
): SuppressionNotice[] {
  const summary = result.suppressions;
  if (summary === undefined) return [];
  const notices: SuppressionNotice[] = [];
  const total = result.findings.length;
  if (summary.suppressed > 0 && summary.suppressed === total) {
    notices.push({
      kind: "everything",
      count: total,
      tone: "warning",
      text: `Every finding of this scan (${total}) is suppressed by pgard.config.json. They are all listed under "Suppressed"; review the reasons before relying on this result.`,
    });
  }
  if (summary.critical > 0) {
    notices.push({
      kind: "critical",
      count: summary.critical,
      tone: "warning",
      text: `${summary.critical} suppressed finding${summary.critical === 1 ? " is" : "s are"} critical. ${summary.critical === 1 ? "It is" : "They are"} still listed in full under "Suppressed"; check the reason in pgard.config.json.`,
    });
  }
  for (const entry of summary.entries) {
    const where = `${entry.ruleId} for ${JSON.stringify(entry.path)}`;
    if (entry.state === "expired") {
      notices.push({
        kind: "expired",
        ruleId: entry.ruleId,
        path: entry.path,
        ...(entry.expires === undefined ? {} : { expires: entry.expires }),
        tone: "warning",
        text: `The suppression of ${where} expired on ${entry.expires ?? "an unknown date"} and is not applied.`,
      });
    } else if (entry.wildcard) {
      notices.push({
        kind: "wildcard",
        ruleId: entry.ruleId,
        path: entry.path,
        count: entry.matched,
        tone: "warning",
        text: `The suppression of ${entry.ruleId} uses ${JSON.stringify(entry.path)}, which matches every file and every finding of that rule (${entry.matched} suppressed).`,
      });
    } else if (entry.matched > BROAD_SUPPRESSION_THRESHOLD) {
      notices.push({
        kind: "broad",
        ruleId: entry.ruleId,
        path: entry.path,
        count: entry.matched,
        tone: "warning",
        text: `The suppression of ${where} matches ${entry.matched} findings.`,
      });
    }
  }
  if (summary.incomplete) {
    notices.push({
      kind: "incomplete",
      tone: "warning",
      text: "Suppression matching stopped early (pattern work limit). Findings checked after that are NOT suppressed and are listed normally.",
    });
  }
  return notices;
}

/** "3 suppressed (including 1 critical)"; the critical part is always present when it applies. */
export function formatSuppressedCount(
  summary: Pick<SuppressionSummary, "suppressed" | "critical">,
): string {
  return `${summary.suppressed} suppressed${summary.critical > 0 ? ` (including ${summary.critical} critical)` : ""}`;
}
