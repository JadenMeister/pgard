import {
  SEVERITIES,
  baselineNotices,
  countBySeverity,
  countStandardStates,
  getOwaspCategory,
  cweUrl,
  formatSeverityBreakdown,
  localizedRuleTitle,
  isJvmSourcePath,
  standardsForPath,
  pickText,
  suppressionNotices,
  type Finding,
  type RuleDetails,
  type RuleLocale,
  type RuleStat,
  type RuleTextCatalog,
  type ScanResult,
  type Severity,
  type StandardCoverageEntry,
  type StandardLink,
  type SuppressionNotice,
} from "@pgard/findings";
import {
  formatFindingSummary,
  formatNoFindings,
  groupReportFindings,
  summarizeStatusSplit,
  truncateField,
  MAX_EVIDENCE_CHARS,
  type ReportLanguageOptions,
} from "./format.js";
import { REPORT_TEXT, type ReportText } from "./report-text.js";

/** What a renderer needs besides the result: the language, its fixed words and the rule catalog. */
export interface ReportContext {
  lang: RuleLocale;
  /** Language of the fixed words in `t` (differs from `lang` only in a Latin-1 PDF fallback). */
  chrome: RuleLocale;
  t: ReportText;
  ruleTexts: RuleTextCatalog | undefined;
}

export function reportContext(
  options: ReportLanguageOptions,
  /** `en` forces English chrome (a PDF that could not load the Korean-capable font). */
  forceChrome?: RuleLocale,
): ReportContext {
  const lang = options.lang ?? "en";
  const chrome = forceChrome ?? lang;
  return { lang, chrome, t: REPORT_TEXT[chrome], ruleTexts: options.ruleTexts };
}

const isHttpsUrl = (url: string): boolean => url.startsWith("https://");

/** Standards links of a finding's rule; empty when the catalog does not know the rule. */
export function findingDetails(finding: Finding, ctx: ReportContext): RuleDetails | undefined {
  const details = ctx.ruleTexts?.get(finding.ruleId)?.details;
  if (details === undefined) return undefined;
  const { noDirectCert, ...rest } = details;
  return {
    ...rest,
    // The "no direct CERT rule" marker belongs to Java and Kotlin findings only.
    ...(noDirectCert !== undefined && isJvmSourcePath(finding.location.path)
      ? { noDirectCert }
      : {}),
    // Only official https links are ever rendered as links.
    // A direct CERT Java link is only valid for a finding in a Java or Kotlin file.
    standards: standardsForPath(
      details.standards.filter((link) => isHttpsUrl(link.url)),
      finding.location.path,
    ),
    examples: details.examples.map((example) => ({
      ...example,
      vulnerable: truncateField(example.vulnerable, MAX_EVIDENCE_CHARS),
      safe: truncateField(example.safe, MAX_EVIDENCE_CHARS),
    })),
  };
}

/**
 * The rule-level rationale and remediation, only when the finding carries its own different
 * text (so the general text adds something). Otherwise the finding's Impact and Recommendation
 * already are the rule's rationale and remediation in the report language.
 */
export function ruleGuidance(
  finding: Finding,
  details: RuleDetails | undefined,
  lang: RuleLocale,
): { rationale: string | null; remediation: string | null } {
  if (details === undefined) return { rationale: null, remediation: null };
  const rationale = pickText(details.rationale, lang);
  const remediation = pickText(details.remediation, lang);
  return {
    rationale: rationale === finding.impact ? null : rationale,
    remediation: remediation === finding.recommendation ? null : remediation,
  };
}

/** " (direct, Java/Kotlin)" or " (indirect, via CWE-78)" for a CERT link; empty for the rest. */
export function standardMark(
  link: StandardLink,
  t: Pick<ReportText, "viaCwe" | "certDirect">,
): string {
  if (link.viaCwe !== undefined) return ` (${t.viaCwe(link.viaCwe)})`;
  if (link.direct === true) return ` (${t.certDirect})`;
  return "";
}

/** "CWE-89 (Improper ...)"; OWASP and CERT entries name their title. */
export function standardLabel(link: StandardLink, t: ReportText): string {
  const title = link.title === null ? "" : ` ${link.title}`;
  return `${link.id}${title}${standardMark(link, t)}`;
}

function breakdownText(counts: Readonly<Record<Severity, number>>, ctx: ReportContext): string {
  if (ctx.chrome === "en") return formatSeverityBreakdown(counts);
  return SEVERITIES.filter((severity) => counts[severity] > 0)
    .map((severity) => `${ctx.t.severity[severity]} ${counts[severity]}건`)
    .join(", ");
}

function severeText(findings: readonly Pick<Finding, "severity">[], ctx: ReportContext): string {
  return (["critical", "high"] as const)
    .map((severity) => ({
      severity,
      count: findings.filter((finding) => finding.severity === severity).length,
    }))
    .filter((entry) => entry.count > 0)
    .map((entry) =>
      ctx.chrome === "en"
        ? `${entry.count} ${entry.severity}`
        : `${ctx.t.severity[entry.severity]} ${entry.count}건`,
    )
    .join(", ");
}

/** The one-line summary under "Summary", in the report language. English equals the CLI's text. */
export function summaryLine(result: ScanResult, ctx: ReportContext): string {
  if (ctx.chrome === "en") return formatFindingSummary(result.findings, result);
  const t = ctx.t;
  const { primary, test, vendored, suppressed, baseline } = groupReportFindings(result.findings);
  const split = summarizeStatusSplit(primary);
  const showSuppressed = suppressed.length > 0 || result.suppressions !== undefined;
  return (
    (result.baseline === undefined
      ? ""
      : t.summaryBaseline(
          result.baseline.matched,
          result.baseline.new,
          breakdownText(countBySeverity(baseline), ctx),
        )) +
    t.summaryFindings(primary.length, split.confirmed, split.suspected, split.informational) +
    (test.length === 0 ? "" : t.summaryTest(test.length)) +
    (vendored.length === 0 ? "" : t.summaryVendored(vendored.length, severeText(vendored, ctx))) +
    (showSuppressed
      ? t.summarySuppressed(suppressed.length, breakdownText(countBySeverity(suppressed), ctx))
      : "") +
    (baseline.length === 0 ? "" : t.summaryBaselineGroup(baseline.length))
  );
}

/** "No findings ... in the areas that ran", in the report language. */
export function noFindingsLine(
  groups: { test: number; vendored: number; suppressed: readonly Pick<Finding, "severity">[] },
  isNew: boolean,
  ctx: ReportContext,
): string {
  if (ctx.chrome === "en") return formatNoFindings(groups, isNew);
  const t = ctx.t;
  const outside =
    groups.test > 0 && groups.vendored > 0
      ? t.outsideTestAndVendored
      : groups.test > 0
        ? t.outsideTest
        : groups.vendored > 0
          ? t.outsideVendored
          : "";
  return t.noFindings(
    outside,
    groups.suppressed.length,
    breakdownText(countBySeverity(groups.suppressed), ctx),
    isNew,
  );
}

function suppressionNoticeText(notice: SuppressionNotice, ctx: ReportContext): string {
  const texts = ctx.t.notices;
  if (texts === null) return notice.text;
  const rule = notice.ruleId ?? "";
  const path = notice.path ?? "";
  const count = notice.count ?? 0;
  switch (notice.kind) {
    case "severe":
      return texts.severe(count, notice.high ?? 0, notice.critical ?? 0);
    case "everything":
      return texts.everything(count);
    case "incomplete":
      return texts.incomplete;
    case "expired":
      return texts.expired(rule, path, notice.expires ?? "?");
    case "far":
      return texts.far(rule, path, notice.expires ?? "?");
    case "wildcard":
      return texts.wildcard(rule, path, count);
    case "total":
      return texts.total(count);
    case "broad":
      return texts.broad(rule, path, count);
    case "noexpiry":
      return notice.text;
  }
}

/** Warnings about suppressions and the baseline, in the report language. */
export function localizedSuppressionNotices(result: ScanResult, ctx: ReportContext): string[] {
  const texts = ctx.t.notices;
  return [
    ...suppressionNotices(result)
      .filter((notice) => notice.tone === "warning")
      .map((notice) => suppressionNoticeText(notice, ctx)),
    ...baselineNotices(result.baseline)
      .filter((notice) => notice.tone === "warning")
      .map((notice) =>
        texts === null
          ? notice.text
          : notice.kind === "uncertain"
            ? texts.baselineUncertain(notice.count ?? 0)
            : texts.baselineTool,
      ),
  ];
}

/** Reason line of a suppressed finding. The reason itself is the config's own words. */
export function suppressionReasonLine(finding: Finding, ctx: ReportContext): string {
  const suppression = finding.suppression;
  if (suppression === undefined) return "";
  // The reason is quoted as JSON, so a quote inside it cannot fake the "(expires ...)" suffix.
  return ctx.t.suppressedByConfig(
    suppression.source,
    JSON.stringify(suppression.reason),
    suppression.expires ?? "",
  );
}

export interface StandardsRow {
  id: string;
  title: string;
  /** Official page of the entry (OWASP category or CWE definition). */
  url: string;
  state: StandardCoverageEntry["state"];
  stateLabel: string;
  /** OWASP only: "3 of 38 mapped CWEs have rules". */
  breadth: string;
  rules: string;
  reason: string;
}

const MAX_LISTED_RULES = 4;

function rowOf(entry: StandardCoverageEntry, url: string, ctx: ReportContext): StandardsRow {
  const rest = entry.ruleIds.length - MAX_LISTED_RULES;
  return {
    id: entry.id.replace(":2025", ""),
    title: entry.title,
    url,
    state: entry.state,
    stateLabel: ctx.t.standardState[entry.state],
    breadth:
      entry.breadth === null
        ? ""
        : ctx.t.breadth(entry.breadth.cwesWithRules, entry.breadth.cwesInCategory),
    rules: `${entry.ruleIds.slice(0, MAX_LISTED_RULES).join(", ")}${rest > 0 ? ` +${rest}` : ""}`,
    reason: entry.reason,
  };
}

/** OWASP Top 10 2025 rows of the coverage map, with their official category links. */
export function owaspRows(result: ScanResult, ctx: ReportContext): StandardsRow[] {
  return (result.standardsCoverage?.owasp ?? []).map((entry) =>
    rowOf(entry, owaspUrl(entry.id), ctx),
  );
}

/** CWE Top 25 2025 rows (rank order as stored), with their MITRE definition links. */
export function cweTop25Rows(
  result: ScanResult,
  ctx: ReportContext,
): Array<StandardsRow & { rank: number | null }> {
  return (result.standardsCoverage?.cweTop25 ?? []).map((entry) => ({
    ...rowOf(entry, cweDefinitionUrl(entry.id), ctx),
    id: entry.id,
    rank: entry.rank,
  }));
}

export function cweTop25CountsText(result: ScanResult, ctx: ReportContext): string {
  const counts = countStandardStates(result.standardsCoverage?.cweTop25 ?? []);
  return ctx.t.cweTop25Counts(counts);
}

function owaspUrl(id: string): string {
  return getOwaspCategory(id)?.url ?? "";
}

function cweDefinitionUrl(id: string): string {
  return /^CWE-[1-9]\d*$/.test(id) ? cweUrl(id) : "";
}

export interface RuleStatRow {
  ruleId: string;
  title: string;
  area: string;
  targets: string;
  findings: number;
  status: string;
}

function targetsText(stat: RuleStat, ctx: ReportContext): string {
  if (stat.targets.length === 0) return ctx.t.targetUnknown(ctx.t.unknown);
  return stat.targets
    .map((target) =>
      target.examined === null
        ? ctx.t.targetUnknown(target.reason ?? ctx.t.unknown)
        : ctx.t.targetCount(target.examined, target.unit),
    )
    .join(", ");
}

/** Rule statistics sorted by rule id and area, with the rule's title in the report language. */
export function ruleStatRows(result: ScanResult, ctx: ReportContext): RuleStatRow[] {
  return [...(result.ruleStats ?? [])]
    .sort((a, b) => a.ruleId.localeCompare(b.ruleId) || a.area.localeCompare(b.area))
    .map((stat) => ({
      ruleId: stat.ruleId,
      title:
        ctx.ruleTexts === undefined
          ? ""
          : localizedRuleTitle(ctx.ruleTexts, stat.ruleId, ctx.chrome, ""),
      area: stat.area,
      targets: targetsText(stat, ctx),
      findings: stat.findings,
      status: Object.hasOwn(ctx.t.coverageStatus, stat.status)
        ? ctx.t.coverageStatus[stat.status]
        : ctx.t.unknown,
    }));
}

/** Distinct rules that have findings in the result, with their details, in rule id order. */
export function rulesWithExamples(
  findings: readonly Finding[],
  ctx: ReportContext,
): Array<{ ruleId: string; title: string; details: RuleDetails }> {
  const seen = new Set<string>();
  const out: Array<{ ruleId: string; title: string; details: RuleDetails }> = [];
  for (const finding of findings) {
    if (seen.has(finding.ruleId)) continue;
    seen.add(finding.ruleId);
    const details = findingDetails(finding, ctx);
    if (details === undefined || details.examples.length === 0) continue;
    out.push({
      ruleId: finding.ruleId,
      title:
        ctx.ruleTexts === undefined
          ? finding.title
          : localizedRuleTitle(ctx.ruleTexts, finding.ruleId, ctx.chrome, finding.title),
      details,
    });
  }
  return out.sort((a, b) => a.ruleId.localeCompare(b.ruleId));
}

/** Unique standards links of the rules that have findings, for the PDF's link appendix. */
export function standardsLinksOf(findings: readonly Finding[], ctx: ReportContext): StandardLink[] {
  const byId = new Map<string, StandardLink>();
  for (const finding of findings) {
    for (const link of findingDetails(finding, ctx)?.standards ?? []) {
      const key = `${link.id}:${link.direct === true ? "direct" : (link.viaCwe ?? "")}`;
      if (!byId.has(key)) byId.set(key, link);
    }
  }
  const order = { owasp: 0, cwe: 1, cert: 2 } as const;
  return [...byId.values()].sort(
    (a, b) => order[a.kind] - order[b.kind] || a.id.localeCompare(b.id, "en", { numeric: true }),
  );
}
