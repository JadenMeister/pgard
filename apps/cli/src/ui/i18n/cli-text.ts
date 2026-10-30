import type { IncrementalFullReason, IncrementalInfo, RuleLocale, Severity } from "@pgard/findings";
import { INCREMENTAL_TEXT, REPORT_TEXT, type ReportText } from "@pgard/report";
import { COMMAND_TEXT_EN, COMMAND_TEXT_KO, type CommandText } from "./command-text.js";

/**
 * Every fixed word of the terminal screens (headings, labels, status words, notices, progress
 * lines), per language. English is the default; Korean follows `--lang ko` / `PGARD_LANG=ko`.
 *
 * Not in here, on purpose: rule texts (the rule catalog translates them), the words of the
 * scanned repository (paths, evidence, reasons quoted from pgard.config.json), analyzer coverage
 * notes (counts and quoted patterns written by the scan) and `--format json`, which stays English.
 * Words the HTML/PDF report already has (severity, coverage status, standards states, suppression
 * and baseline notices) come from `@pgard/report` so both front ends say the same thing.
 */
export interface CliText {
  locale: RuleLocale;
  /** The report wording, reused for severity, coverage status, standards states and notices. */
  report: ReportText;
  /** Fixed text of sign-in, App install, report export, `doctor` and `rules list`. */
  commands: CommandText;

  // --- Header and summary block ---------------------------------------------------------
  scanResult: string;
  repository: string;
  web: string;
  scopes: string;
  unknown: string;
  summaryTitle: string;
  summaryLabels: {
    areas: string;
    rules: string;
    target: string;
    elapsed: string;
    sinceLast: string;
    incremental: string;
    fullScan: string;
  };
  /** `warn` colours the partial and not-tested counts, as the coverage list does. */
  areasValue: (
    counts: {
      requested: number;
      completed: number;
      partial: number;
      notTested: number;
      notSelected: number;
    },
    warn: (text: string) => string,
  ) => string;
  rulesValue: (ran: number, partial: number) => string;
  targetValue: (sizes: {
    files: number | null;
    commits: number | null;
    pages: number | null;
  }) => string;
  elapsedValue: (milliseconds: number) => string;
  /** "re-scanned 3 files, reused 1997 (based on scan 1a2b3c4d)" */
  incrementalValue: (info: IncrementalInfo) => string;
  /** Why a scan (or one of its areas) was a full scan. */
  fullScanReason: Record<IncrementalFullReason, string>;
  /** "+2 new / -1 no longer reported" */
  diffCompact: (added: number, gone: number, unclear: boolean) => string;
  /** A reason or note written by the scan (English) next to this language's text. */
  scanText: (text: string) => string;

  // --- Charts ----------------------------------------------------------------------------
  chartBySeverity: (isNew: boolean, total: number) => string;
  chartByOwasp: string;
  chartByArea: string;
  chartUnmapped: string;
  chartNoFindings: string;
  scopeName: Record<"code" | "history" | "web", string>;

  // --- Findings ---------------------------------------------------------------------------
  plus: (parts: string[]) => string;
  testCount: (count: number, severe: string) => string;
  vendoredCount: (count: number, severe: string) => string;
  suppressedCount: (count: number, breakdown: string) => string;
  baselineCount: (count: number) => string;
  /** "1 critical, 5 high" in this language, "" when nothing. */
  breakdown: (counts: Readonly<Record<Severity, number>>) => string;
  statusCounts: (confirmed: number, suspected: number, informational: number) => string;
  findingsHeading: (isNew: boolean, total: number, statuses: string) => string;
  noFindings: (parts: {
    isNew: boolean;
    hasUnsuppressed: boolean;
    outside: "none" | "test" | "vendored" | "both";
    suppressed: number;
    suppressedBreakdown: string;
  }) => string;
  locationsDetail: (status: string, count: number) => string;
  confidence: string;
  evidence: string;
  fix: string;
  /** Heading of a suggested-fix diff (`--fixes`). */
  suggestedFix: string;
  standards: string;
  variesByLocation: string;
  andMore: (count: number) => string;
  showAllHint: string;
  shortenedGroupsHint: (max: number) => string;

  /** Terminal result: findings first, compact by default, summary and charts last. */
  compact: {
    /** "+43 more findings (medium 17, low 2) - ..." (`breakdown` is "medium 17, low 2"). */
    more: (count: number, breakdown: string) => string;
    /** Always shown under the compact list: where evidence, fixes and standards are. */
    details: string;
    /** One line for test/fixture or vendored code: its title, count and counts by severity. */
    context: (title: string, count: number, bySeverity: string) => string;
    /** Status line at the top of the closing summary. */
    result: (overall: string, total: number, breakdown: string) => string;
    /** Shown whenever the scan was not complete or an area was partial or not tested. */
    notSafe: string;
    /** "Coverage: 3 ok, 1 partial, 1 not tested" */
    coverageCount: (counts: {
      ok: number;
      partial: number;
      notTested: number;
      notSelected: number;
    }) => string;
    /** One line for the OWASP Top 10 map (the table is in --all-findings). */
    owaspLine: (
      counts: Record<"rules_ran" | "rules_partial" | "not_run" | "no_rules", number>,
    ) => string;
    /** "Next" line; `hasHidden` is true when the list above left findings out. */
    next: (hasHidden: boolean) => string;
  };

  // --- Test, vendored and collapsed groups --------------------------------------------
  testGroupTitle: string;
  testGroupNote: string;
  /** Sentence about findings that the `testDirectories` setting (not the built-in rules) classified. */
  configTestNote: (count: number) => string;
  severeAlwaysListed: string;
  collapsedTitle: (count: number) => string;
  collapsedNote: (threshold: number) => string;
  byContext: string;
  byRule: string;
  bySeverity: string;
  contextName: Record<string, string>;
  moreRules: (count: number) => string;
  notListedHere: (count: number, hasCritical: boolean) => string;
  suppressedReason: (reasonJson: string, expires: string) => string;
  suppressedCountLine: (count: number, breakdown: string) => string;
  baselineCountLine: (matched: number, fresh: number, breakdown: string, setOn: string) => string;
  newFindingsSinceBaseline: string;

  // --- Coverage, standards, authorization -------------------------------------------
  coverageTitle: string;
  coverageMark: Record<"completed" | "partial" | "not_tested" | "not_selected", string>;
  noCoverage: string;
  standardsTitle: string;
  /** Words in the standards coverage map; "rules ran" is not "safe" or "covered". */
  standardMark: Record<"rules_ran" | "rules_partial" | "not_run" | "no_rules", string>;
  standardsNote: string;
  standardsBreadth: (withRules: number, inCategory: number) => string;
  cweTop25Line: (
    counts: Record<"rules_ran" | "rules_partial" | "not_run" | "no_rules", number>,
  ) => string;
  authorizationAllowed: string;
  authorizationBlocked: string;
  checkStatus: Record<"passed" | "failed" | "unverifiable", string>;
  checkName: Record<string, string>;

  // --- Config notices -----------------------------------------------------------------
  configExcluded: (count: number, rest: string) => string;
  configNoticePrefix: string;
  configDemoted: (count: number) => string;

  // --- Since the last scan --------------------------------------------------------------
  diff: {
    sinceLast: (when: string) => string;
    newCount: (count: number, uncertain: number, areas: string) => string;
    noLongerReported: (count: number) => string;
    unchanged: (count: number) => string;
    moved: (count: number) => string;
    changedRating: (count: number) => string;
    toolUpdated: (count: number) => string;
    notComparedBecause: (parts: string, more: number) => string;
    notFullyCompared: (parts: string, more: number) => string;
    couldNotCheck: (count: number) => string;
    atRevision: (revision: string) => string;
    because: Record<
      | "partial"
      | "not_tested"
      | "only_in_previous"
      | "only_in_current"
      | "not_run"
      | "other_origin"
      | "changed"
      | "appeared"
      | "lastOnly",
      string
    >;
    skippedStored: (count: number) => string;
    notCompared: string;
  };

  // --- Offer of a detected local web service (interactive `pgard scan`) ---------------
  webOffer: {
    /** Where the question is followed by `[y/N]`; `label` is "URL (title)" or just the URL. */
    askOne: (label: string) => string;
    pickTitle: string;
    none: string;
    help: string;
  };

  // --- Progress, status lines and notices ---------------------------------------------
  progress: {
    scanning: (scopes: string) => string;
    pagesChecked: (count: number) => string;
    stage: Record<string, string>;
    status: Record<string, string>;
    message: Record<string, string>;
    /** Messages that carry the scope ("Running code analysis."); undefined when not one. */
    scoped: (message: string, stageNames: Record<string, string>) => string | undefined;
  };
  notices: {
    /** Info notice about suppressions without an expiry date. */
    noExpiry: (count: number) => string;
    webNotConfirmed: string;
    noReportBlocked: string;
    baselineNotSet: string;
    notStored: (reason: string) => string;
    notStoredShort: string;
    notComparable: string;
    firstRun: (dir: string, isWindows: boolean) => string;
  };
  /** `pgard scan code` without approval (#414, D1, D2, D4). */
  codeOnly: {
    /** The first line of a code-only result. */
    line: string;
    /** The label at the start of the panel view's title line. */
    short: string;
    /** The interactive menu entry for `pgard scan code`. */
    menuLabel: string;
    /** How to get an authorized scan, after a code-only result. */
    upgrade: string;
    /** After a blocked `scan history`, `scan web` or `scan all`. */
    blockedHint: string;
    /** The question after authorization failed for `scan` or `scan code` (a terminal only). */
    prompt: string;
    /** `?` at that question. */
    promptHelp: string;
    /** Without a terminal, after authorization failed for `scan` or `scan code`. */
    addFlagHint: string;
    /** `pgard scan code` outside a Git repository, in the home folder, above it, or a top-level folder. */
    tooBroad: string;
    /** `pgard scan code` in a Git repository whose top folder is the home folder or above it. */
    tooBroadRepository: string;
    /** `pgard scan code` in a `.git` folder or a bare repository. */
    gitDirectory: string;
    /** `pgard scan code` when no home folder is known (HOME empty, no account home). */
    noHome: string;
    /** A folder on a virtual file system (`/proc`, `/sys`, `/dev`). */
    virtualFolder: string;
    /** The folder, or one above it, belongs to another user or is writable by group or others. */
    unsafeFolder: (problem: "not_owned_by_you" | "group_or_world_writable", at: string) => string;
    /** Git puts the work tree of this repository elsewhere (`core.worktree`). */
    worktreeRedirected: string;
  };
  /** Chrome of the full-screen panel view (`pgard scan --panels`). Scan data is not in here. */
  panels: PanelsText;
}

export interface TrendPanelText {
  title: (count: number) => string;
  /** "No history yet" states; each says why and what to do. */
  noHistory: {
    empty: string;
    single: (date: string) => string;
    disabled: string;
    noStoreDir: string;
    noRepository: string;
    unreadable: (reason: string) => string;
  };
  skipped: (count: number) => string;
  latestVsPrevious: string;
  /** The heading when the current scan is not stored: the two newest stored scans. */
  newestStored: string;
  /** A note: the scan this view opened for is not among the stored ones. */
  notStored: string;
  /** Stored scans written by a newer PGARD version are left out. */
  newerSkipped: (count: number) => string;
  chartTitle: string;
  /** Legend of the bar characters: `symbols` in the severity order, then the severity names. */
  legend: (pairs: string) => string;
  tableTitle: string;
  columns: { date: string; age: string; total: string };
  /** One letter (or syllable) per severity, for the narrow table and the legend. */
  letters: Record<Severity, string>;
  /** Relative age from a millisecond difference; `short` for the narrow table. */
  age: (ms: number, short: boolean) => string;
}

export interface PanelsText {
  title: string;
  /** Tab labels, in tab order. */
  tabs: Record<"overview" | "charts" | "coverage" | "trend" | "findings", string>;
  /** The trend panel: stored scans of this repository over time. */
  trend: TrendPanelText;
  /** Footer key hints for each state of the view; cut at the terminal width. */
  hints: Record<"default" | "findings" | "filter" | "detail" | "help" | "noMatch", string>;
  /** Footer hint for the export key; shown only when exporting is possible. */
  exportHint: string;
  /** Printed on the normal screen after an export, before the view comes back. */
  exportReturn: string;
  /** Filter line above the findings list. */
  filter: {
    label: string;
    /** "3 of 12": how many of all findings the list shows. */
    count: (shown: number, total: number) => string;
    none: string;
    names: Record<"severity" | "area" | "rule" | "search", string>;
    searchPrompt: string;
    /** The list is empty because of the filters, not because there are no findings. */
    noMatch: (total: number) => string;
  };
  /** Labels in the opened finding. */
  detail: { where: string; rule: string; references: string };
  helpTitle: string;
  helpLines: string[];
  confirmCancel: string;
  tooSmall: (columns: number, rows: number, minColumns: number, minRows: number) => string;
  noFindings: string;
  position: (from: number, to: number, total: number) => string;
  suppressed: string;
  inBaseline: string;
  /** Printed (stderr) when `--panels` is given but the output is not a terminal. */
  notTerminal: string;
  /** stderr notes: the view crashed; `--panels` on a blocked scan. */
  failed: string;
  notOpenedBlocked: string;
  /** stderr hint for an unknown `PGARD_PANELS` value. */
  badEnv: string;
  /** stderr note: `--panels` with TERM=dumb, which cannot draw a full-screen view. */
  dumbTerminal: string;
}

const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

function plural(count: number, one: string, many: string): string {
  return count === 1 ? one : many;
}

const EN_REPORT = REPORT_TEXT.en;
const KO_REPORT = REPORT_TEXT.ko;

const EN: CliText = {
  locale: "en",
  report: EN_REPORT,
  commands: COMMAND_TEXT_EN,
  scanResult: "PGARD scan result",
  repository: "Repository",
  web: "web",
  scopes: "scopes",
  unknown: "unknown",
  summaryTitle: "Summary",
  summaryLabels: {
    areas: "Areas",
    rules: "Rules",
    target: "Max per rule",
    elapsed: "Elapsed",
    sinceLast: "Since last scan",
    incremental: INCREMENTAL_TEXT.en.label,
    fullScan: INCREMENTAL_TEXT.en.fullScanLabel,
  },
  areasValue: (c, warn) =>
    `${c.requested} requested \u2014 ${[
      c.completed > 0 ? `${c.completed} completed` : null,
      c.partial > 0 ? warn(`${c.partial} partial`) : null,
      c.notTested > 0 ? warn(`${c.notTested} not tested`) : null,
    ]
      .filter((part) => part !== null)
      .join(", ")}${c.notSelected > 0 ? ` (${c.notSelected} not selected)` : ""}`,
  rulesValue: (ran, partial) =>
    `${ran} ${plural(ran, "rule", "rules")} ran${partial > 0 ? ` (${partial} in partially scanned areas)` : ""}`,
  targetValue: (s) =>
    [
      s.files === null ? null : `${s.files} ${plural(s.files, "file", "files")}`,
      s.commits === null ? null : `${s.commits} ${plural(s.commits, "commit", "commits")}`,
      s.pages === null ? null : `${s.pages} ${plural(s.pages, "page", "pages")}`,
    ]
      .filter((part) => part !== null)
      .join(", "),
  elapsedValue: (ms) => formatElapsed(ms, "m", "s"),
  incrementalValue: INCREMENTAL_TEXT.en.value,
  fullScanReason: INCREMENTAL_TEXT.en.reason,
  diffCompact: (added, gone, unclear) =>
    `+${added} new / -${gone} no longer reported${unclear ? " (some areas not fully compared)" : ""}`,
  scanText: (text) => text,
  chartBySeverity: (isNew, total) =>
    `${isNew ? "New findings" : "Findings"} by severity (${total} total)`,
  chartByOwasp: "By OWASP Top 10 2025 category",
  chartByArea: "By area",
  chartUnmapped: "No OWASP mapping",
  chartNoFindings: "(no findings)",
  scopeName: { code: "code", history: "history", web: "web" },
  plus: (parts) => ` - plus ${parts.join(", ")}`,
  testCount: (count, severe) =>
    `${count} in test or fixture code${severe === "" ? "" : ` (${severe})`}`,
  vendoredCount: (count, severe) =>
    `${count} ${plural(count, "suggestion", "suggestions")} in vendored code${severe === "" ? "" : ` (${severe})`}`,
  suppressedCount: (count, breakdown) =>
    `${count} suppressed${breakdown === "" ? "" : ` (${breakdown})`}`,
  baselineCount: (count) => `${count} in baseline`,
  breakdown: (counts) =>
    SEVERITY_ORDER.filter((severity) => counts[severity] > 0)
      .map((severity) => `${counts[severity]} ${severity}`)
      .join(", "),
  statusCounts: (confirmed, suspected, informational) =>
    [
      confirmed > 0 ? `${confirmed} confirmed` : null,
      suspected > 0 ? `${suspected} suspected (needs review)` : null,
      informational > 0 ? `${informational} informational` : null,
    ]
      .filter((part) => part !== null)
      .join(", "),
  findingsHeading: (isNew, total, statuses) =>
    `${isNew ? "New findings since the baseline" : "Findings"} (${total}): ${statuses}`,
  noFindings: ({ isNew, hasUnsuppressed, outside, suppressed, suppressedBreakdown }) =>
    `No ${isNew ? "new " : ""}${hasUnsuppressed ? "unsuppressed " : ""}findings${
      outside === "both"
        ? " outside test, fixture or vendored code"
        : outside === "test"
          ? " outside test or fixture code"
          : outside === "vendored"
            ? " outside vendored code"
            : ""
    } in the areas that ran${suppressed > 0 ? ` (${suppressed} suppressed: ${suppressedBreakdown})` : ""}. This does not mean the project is secure; see coverage.`,
  locationsDetail: (status, count) => `${status}${count > 1 ? `, ${count} locations` : ""}`,
  confidence: "confidence",
  evidence: "Evidence",
  fix: "Fix",
  suggestedFix: "Suggested fix",
  standards: "Standards",
  variesByLocation: "varies by location (run with --all-findings to see each)",
  andMore: (count) => ` and ${count} more`,
  showAllHint:
    "Run again with --all-findings to list everything, or save a report (--report html --output-dir <dir>).",
  shortenedGroupsHint: (max) =>
    `Groups show up to ${max} locations. Run again with --all-findings to list every location.`,
  compact: {
    more: (count, breakdown) =>
      `+${count} more ${count === 1 ? "finding" : "findings"} (${breakdown}) - run with --all-findings`,
    details:
      "Evidence, fix and standards for each finding: --all-findings, the panel view, the dashboard or a report.",
    context: (title, count, bySeverity) => `${title} (${count}): ${bySeverity}`,
    result: (overall, total, breakdown) =>
      `Result: ${overall} - ${total} ${total === 1 ? "finding" : "findings"}${breakdown === "" ? "" : ` (${breakdown})`}`,
    notSafe:
      "! Not a safe result: an area that is partial or not tested was not fully checked, so no finding there does not mean no problem.",
    coverageCount: (c) =>
      `${c.ok} ok, ${c.partial} partial, ${c.notTested} not tested${c.notSelected > 0 ? `, ${c.notSelected} not selected` : ""}`,
    owaspLine: (c) =>
      `OWASP Top 10 2025: ${c.rules_ran} rules ran, ${c.rules_partial} rules partial, ${c.not_run} not run, ${c.no_rules} no rules (table: --all-findings)`,
    next: (hasHidden) =>
      `Next: ${hasHidden ? "pgard scan --all-findings lists everything; " : ""}save a report with --report html --output-dir <dir>, or open pgard dashboard.`,
  },
  testGroupTitle: "In test or fixture code",
  testGroupNote:
    "Matches in files classified as test or fixture code by their path only (confidence capped at low). Review them: a real value committed in a test is still exposed.",
  configTestNote: (count) =>
    ` ${count} of them ${count === 1 ? "was" : "were"} classified by the testDirectories setting of pgard.config.json, not by the built-in rules.`,
  severeAlwaysListed: " Critical and high findings are always listed.",
  collapsedTitle: (count) =>
    `Test, fixture and vendored code (${count} lower-severity findings not listed)`,
  collapsedNote: (threshold) =>
    `  Collapsed because there are more than ${threshold} in this code. Findings in your own code, and critical or high findings anywhere, are always listed. Review these too: a real value committed in a test is still exposed.`,
  byContext: "By context",
  byRule: "By rule",
  bySeverity: "By severity",
  contextName: { test: "test", vendored: "vendored", other: "other" },
  moreRules: (count) => ` and ${count} more rules`,
  notListedHere: (count, hasCritical) =>
    `${count} not listed here${hasCritical ? " (the critical ones are above)" : ""}.`,
  suppressedReason: (reasonJson, expires) =>
    `Reason from pgard.config.json: ${reasonJson}${expires === "" ? "" : ` (expires ${expires})`}`,
  suppressedCountLine: (count, breakdown) =>
    `Suppressed by pgard.config.json: ${count}${breakdown === "" ? "" : ` (${breakdown})`}`,
  baselineCountLine: (matched, fresh, breakdown, setOn) =>
    `Baseline (set ${setOn}): ${matched} in baseline${breakdown === "" ? "" : ` (${breakdown})`}, ${fresh} new`,
  newFindingsSinceBaseline: "New findings",
  coverageTitle: "Coverage",
  coverageMark: {
    completed: "ok",
    partial: "partial",
    not_tested: "not tested",
    not_selected: "not selected",
  },
  noCoverage: "(no coverage recorded)",
  standardsTitle: "Standards coverage (OWASP Top 10 2025)",
  standardMark: {
    rules_ran: "rules ran",
    rules_partial: "rules partial",
    not_run: "not run",
    no_rules: "no rules",
  },
  standardsNote:
    "Rules ran means the mapped rules ran to completion in this scan. It does not mean the project is safe or that the category is covered: see how many of its CWEs have rules. Full detail per entry: --format json (standardsCoverage, ruleStats).",
  standardsBreadth: (withRules, inCategory) =>
    `${withRules} of ${inCategory} mapped CWEs have rules`,
  cweTop25Line: (c) =>
    `CWE Top 25 2025: ${c.rules_ran} rules ran, ${c.rules_partial} rules partial, ${c.not_run} not run, ${c.no_rules} no rules`,
  authorizationAllowed: "Authorization: allowed",
  authorizationBlocked: "Authorization: blocked - no analysis ran",
  checkStatus: { passed: "passed", failed: "failed", unverifiable: "unverifiable" },
  checkName: {
    repository: "repository",
    github_identity: "github identity",
    owner_approval: "owner approval",
    current_access: "current access",
    contribution: "contribution",
  },
  configExcluded: (count, rest) => `${count} files excluded by pgard.config.json${rest}`,
  configNoticePrefix: "",
  configDemoted: (count) =>
    `${count} finding${count === 1 ? " was" : "s were"} classified as test code by the testDirectories setting of pgard.config.json (listed apart, confidence capped at low). Review ${count === 1 ? "it" : "them"}.`,
  diff: {
    sinceLast: (when) => `Since the last scan (${when})`,
    newCount: (count, uncertain, areas) =>
      `${count} new${uncertain > 0 ? ` (${uncertain} in areas not fully compared${areas === "" ? "" : `: ${areas}`})` : ""}`,
    noLongerReported: (count) => `${count} no longer reported`,
    unchanged: (count) => `${count} unchanged`,
    moved: (count) => `${count} moved`,
    changedRating: (count) => `${count} changed severity or status`,
    toolUpdated: (count) =>
      `PGARD was updated since the last scan, so ${count} earlier finding(s) that are not reported now could not be checked`,
    notComparedBecause: (parts, more) =>
      `Some findings could not be compared because ${parts}${more > 0 ? `, and ${more} more area(s)` : ""}`,
    notFullyCompared: (parts, more) =>
      `Not fully compared: ${parts}${more > 0 ? `, and ${more} more area(s)` : ""}`,
    couldNotCheck: (count) => `${count} earlier finding(s) could not be checked`,
    atRevision: (revision) => `, at ${revision}`,
    because: {
      partial: "was only partially scanned",
      not_tested: "was not tested",
      only_in_previous: "was not in this scan's scope",
      only_in_current: "was not in the last scan's scope",
      not_run: "was not run",
      other_origin: "used a different web address",
      changed: "changed between the two scans",
      appeared: "appeared since the last scan",
      lastOnly: "was only in the last scan",
    },
    skippedStored: (count) => `${count} more stored result(s) were skipped and not compared.`,
    notCompared: "The previous scan could not be compared.",
  },
  webOffer: {
    askOne: (label) => `Also scan ${label} (web checks)?`,
    pickTitle: "Local web services found. Also scan one of them?",
    none: "No, do not scan a web service",
    help: `PGARD found local web servers on 127.0.0.1. Web checks are optional.
- Choosing one still asks you to confirm it is this project's service.
- PGARD sends one GET / to each listening local port to read its title; scan requests are sent only after you confirm.
- Enter on "No" (or Esc) skips web checks.`,
  },
  progress: {
    scanning: (scopes) => `Scanning (${scopes})... Press Ctrl+C twice to cancel.`,
    pagesChecked: (count) => `  web: ${count} page(s) checked`,
    stage: {},
    status: {},
    message: {},
    scoped: (_message, _names) => undefined,
  },
  notices: {
    noExpiry: (count) =>
      `${count} suppression${count === 1 ? " has" : "s have"} no expiry date, so ${count === 1 ? "it" : "they"} will never be reviewed again unless someone remembers.`,
    webNotConfirmed:
      "The web target cannot be confirmed without an interactive terminal; web checks are recorded as not tested.",
    noReportBlocked: "No report was written because the scan was blocked.",
    baselineNotSet: "The baseline was not set: this scan cannot be stored.",
    notStored: (reason) => `The scan result was not stored: ${reason}`,
    notStoredShort: "The scan result was not stored.",
    notComparable: "The previous scan could not be compared.",
    firstRun: (dir, isWindows) =>
      [
        "PGARD now keeps your scan results on this computer, so later scans can be compared.",
        `  Where: ${dir} (${
          isWindows
            ? "nothing is uploaded; access follows your Windows profile folder"
            : "readable only by you; nothing is uploaded"
        })`,
        "  What: the redacted result only, last 20 scans per repository for 90 days.",
        "  Stop storing: pass --no-store, or set PGARD_NO_STORE=1.",
        "  Delete everything: pgard history clear --all",
      ].join("\n"),
  },
  codeOnly: {
    line: "! Code-only scan: authorization not verified (current files only; no Git history, no web checks, not saved).",
    short: "! Code-only, not verified",
    menuLabel: "Scan the current files (code only)",
    upgrade:
      "For an authorized scan with Git history, run `pgard scan` (GitHub sign-in and owner approval).",
    blockedHint: "`pgard scan code --code-only` checks the current files without approval.",
    prompt: "Skip Git history and scan only the current code? (marked as not authorized)",
    promptHelp:
      "y: scan the current files only, with no Git history and no authorization; the result says so and is not saved. N: stop here.",
    addFlagHint: "For a code-only scan, add --code-only.",
    tooBroad:
      "This is your home folder, a folder above it, or a top-level folder (such as / or /Users), not a project. Run pgard scan --code-only inside the project's own folder.",
    tooBroadRepository:
      "This folder is inside a Git repository at your home folder (or a folder above it), so a code-only scan would read all of it, including folders such as .ssh. Run pgard scan --code-only inside a project folder that has its own Git repository (run `git init` there if it has none).",
    gitDirectory:
      "This is a Git directory (.git or a bare repository), not a project's files; its config can hold credentials. Run pgard scan --code-only in the project's working folder.",
    noHome:
      "PGARD could not find your home folder (HOME is empty and the account has none), so it cannot check that this folder is not your home folder. Set HOME and run pgard scan --code-only again.",
    virtualFolder:
      "This is a folder on a virtual file system (/proc, /sys or /dev), not a project's files. Run pgard scan --code-only inside the project's own folder.",
    unsafeFolder: (problem, at) =>
      problem === "not_owned_by_you"
        ? `${at} belongs to another user. Files another user can change are not scanned. Run it in a project folder you own.`
        : `${at} is writable by its group or by other users. Files another user can change are not scanned. Remove the write permission (for example chmod go-w).`,
    worktreeRedirected:
      "Git reports a different work-tree root than the folder that holds .git (usually the core.worktree setting in .git/config), so the files that would be read are not the repository that was checked. It is not scanned. If core.worktree is set, remove it from .git/config",
  },
  panels: {
    title: "PGARD panels",
    tabs: {
      overview: "Overview",
      charts: "Charts",
      coverage: "Coverage",
      trend: "Trend",
      findings: "Findings",
    },
    trend: {
      title: (count) =>
        `Trend: ${count} stored ${count === 1 ? "scan" : "scans"} of this repository`,
      noHistory: {
        empty:
          "No history yet: no earlier scan of this repository is stored. Scan again later to see a trend.",
        single: (date) =>
          `No history yet: only one stored scan (${date}). Scan again later to see a trend.`,
        disabled:
          "No history yet: storing is off (--no-store or PGARD_NO_STORE=1), so there is nothing to compare.",
        noStoreDir:
          "No history yet: no app-data directory could be determined, so nothing is stored.",
        noRepository:
          "No history yet: this scan is not tied to a GitHub repository, so no history is kept for it.",
        unreadable: (reason) =>
          `History could not be read${reason === "" ? "" : ` (reason: ${reason})`}. The scan itself is unaffected.`,
      },
      skipped: (count) =>
        `${count} stored ${count === 1 ? "file was" : "files were"} unreadable and left out.`,
      latestVsPrevious: "Latest scan vs the previous one",
      newestStored: "The two newest stored scans",
      notStored: "This scan was not stored.",
      newerSkipped: (count) =>
        `${count} ${count === 1 ? "scan" : "scans"} from a newer PGARD version ${count === 1 ? "was" : "were"} skipped.`,
      chartTitle: "Active findings per scan (newest first)",
      legend: (pairs) => `Legend: ${pairs}`,
      tableTitle: "Active findings per scan by severity (newest first)",
      columns: { date: "Date", age: "Age", total: "Active" },
      letters: { critical: "C", high: "H", medium: "M", low: "L", info: "I" },
      age: (ms, short) => {
        const minutes = Math.floor(ms / 60000);
        if (minutes < 1) return short ? "now" : "just now";
        if (minutes < 60) return short ? `${minutes}m` : `${minutes} min ago`;
        const hours = Math.floor(minutes / 60);
        if (hours < 24) return short ? `${hours}h` : `${hours} h ago`;
        const days = Math.floor(hours / 24);
        if (days === 1 && !short) return "yesterday";
        return short ? `${days}d` : `${days} days ago`;
      },
    },
    hints: {
      default: "Esc: back  ?: help  Tab: panel  Up/Down: scroll",
      findings: "Esc: back  ?: help  Enter: open  /: search  1-5: severity",
      filter: "Esc: clear  Enter: keep  Type to search",
      detail: "Esc/Enter: close  Up/Down: scroll",
      help: "?/Esc: close  Up/Down: scroll",
      noMatch: "Esc: back  ?: help  c: clear filters  /: search",
    },
    exportHint: "e: export",
    exportReturn: "Press any key to return to the panel view.",
    filter: {
      label: "Filters",
      count: (shown, total) => `${shown} of ${total}`,
      none: "none",
      names: { severity: "severity", area: "area", rule: "rule", search: "search" },
      searchPrompt: "Search",
      noMatch: (total) =>
        `No finding matches these filters, but ${total} ${total === 1 ? "finding exists" : "findings exist"}. Press c to clear the filters.`,
    },
    detail: { where: "Where", rule: "Rule", references: "References" },
    helpTitle: "Panel view help",
    helpLines: [
      "Tab, Shift+Tab, Left, Right: next or previous panel",
      "Up, Down, j, k: scroll (in the findings list: move the selection)",
      "PageUp, PageDown: scroll one page",
      "Home, End: first or last line",
      "Findings list:",
      "  Enter: open the selected finding (evidence, fix, standards); Enter or Esc closes it",
      "  1-5: show one severity (1 critical ... 5 info; again to clear), 0 or s: next severity",
      "  a: next area (code, history, web), r: next rule, c: clear all filters",
      "  /: search title, rule id and path; Enter keeps it, Esc clears it, then Esc leaves",
      "Trend panel: stored scans of this repository (local store only), newest first; Up/Down scrolls",
      "e: save a report (HTML, PDF or both): the view closes while you answer and comes back as it was",
      "?: show or hide this help",
      "Esc: close help or a finding, clear the search, or leave the panel view (q leaves at once)",
      "Ctrl+C: ask to cancel (y exits with status 130)",
      "",
      "Read-only: nothing is changed or uploaded. Evidence is shown redacted, as in the result.",
    ],
    confirmCancel: "Cancel and exit? [y/N]",
    tooSmall: (columns, rows, minColumns, minRows) =>
      `Terminal too small (${columns}x${rows}). Need at least ${minColumns}x${minRows}. Resize, or press Esc.`,
    noFindings: "(no findings)",
    position: (from, to, total) => `${from}-${to}/${total}`,
    suppressed: "suppressed",
    inBaseline: "baseline",
    notTerminal: "--panels needs a terminal; the plain text result above is all there is.",
    failed: "The panel view failed and was closed. The scan result above is unaffected.",
    notOpenedBlocked: "--panels: the panel view was not opened because the scan was blocked.",
    badEnv: "PGARD_PANELS is not off, 0, false or no; the panel view stays on.",
    dumbTerminal:
      "--panels: the panel view was not opened because TERM=dumb cannot draw a full-screen view.",
  },
};

const KO: CliText = {
  locale: "ko",
  report: KO_REPORT,
  commands: COMMAND_TEXT_KO,
  scanResult: "PGARD 검사 결과",
  repository: "저장소",
  web: "웹",
  scopes: "범위",
  unknown: "알 수 없음",
  summaryTitle: "요약",
  summaryLabels: {
    areas: "영역",
    rules: "규칙",
    target: "규칙별 최대 검사 대상",
    elapsed: "소요 시간",
    sinceLast: "지난 검사 대비",
    incremental: INCREMENTAL_TEXT.ko.label,
    fullScan: INCREMENTAL_TEXT.ko.fullScanLabel,
  },
  areasValue: (c, warn) =>
    `요청 ${c.requested} \u2014 ${[
      c.completed > 0 ? `완료 ${c.completed}` : null,
      c.partial > 0 ? warn(`부분 완료 ${c.partial}`) : null,
      c.notTested > 0 ? warn(`미검사 ${c.notTested}`) : null,
    ]
      .filter((part) => part !== null)
      .join(", ")}${c.notSelected > 0 ? ` (선택 안 함 ${c.notSelected})` : ""}`,
  rulesValue: (ran, partial) =>
    `규칙 ${ran}개 실행됨${partial > 0 ? ` (부분 완료 영역에서 ${partial}개)` : ""}`,
  targetValue: (s) =>
    [
      s.files === null ? null : `파일 ${s.files}개`,
      s.commits === null ? null : `커밋 ${s.commits}개`,
      s.pages === null ? null : `페이지 ${s.pages}개`,
    ]
      .filter((part) => part !== null)
      .join(", "),
  elapsedValue: (ms) => formatElapsed(ms, "분", "초"),
  incrementalValue: INCREMENTAL_TEXT.ko.value,
  fullScanReason: INCREMENTAL_TEXT.ko.reason,
  diffCompact: (added, gone, unclear) =>
    `신규 ${added}건 / 더 이상 보고되지 않음 ${gone}건${unclear ? " (일부 영역은 완전히 비교하지 못함)" : ""}`,
  scanText: (text) => `(${text})`,
  chartBySeverity: (isNew, total) =>
    `${isNew ? KO_REPORT.newSinceBaseline : "발견 항목"} 심각도별 (총 ${total}건)`,
  chartByOwasp: "OWASP Top 10 2025 분류별",
  chartByArea: "영역별",
  chartUnmapped: "OWASP 매핑 없음",
  chartNoFindings: "(발견 항목 없음)",
  scopeName: { code: "코드", history: "이력", web: "웹" },
  plus: (parts) => ` - 별도: ${parts.join(", ")}`,
  testCount: (count, severe) =>
    `테스트·fixture 코드 ${count}건${severe === "" ? "" : ` (${severe})`}`,
  vendoredCount: (count, severe) =>
    `vendored 코드의 제안 ${count}건${severe === "" ? "" : ` (${severe})`}`,
  suppressedCount: (count, breakdown) =>
    `억제됨 ${count}건${breakdown === "" ? "" : ` (${breakdown})`}`,
  baselineCount: (count) => `기준선에 있음 ${count}건`,
  breakdown: (counts) =>
    SEVERITY_ORDER.filter((severity) => counts[severity] > 0)
      .map((severity) => `${KO_REPORT.severity[severity]} ${counts[severity]}건`)
      .join(", "),
  statusCounts: (confirmed, suspected, informational) =>
    [
      confirmed > 0 ? `확인됨 ${confirmed}` : null,
      suspected > 0 ? `의심 ${suspected} (검토 필요)` : null,
      informational > 0 ? `참고 ${informational}` : null,
    ]
      .filter((part) => part !== null)
      .join(", "),
  findingsHeading: (isNew, total, statuses) =>
    `${isNew ? `${KO_REPORT.newSinceBaseline} 발견 항목` : "발견 항목"} (${total}건): ${statuses}`,
  noFindings: ({ isNew, hasUnsuppressed, outside, suppressed, suppressedBreakdown }) =>
    `실행된 영역에서${
      outside === "both"
        ? " 테스트·fixture·vendored 코드를 제외하고"
        : outside === "test"
          ? " 테스트·fixture 코드를 제외하고"
          : outside === "vendored"
            ? " vendored 코드를 제외하고"
            : ""
    } ${isNew ? "새 " : ""}${hasUnsuppressed ? "억제되지 않은 " : ""}발견 항목이 없습니다${suppressed > 0 ? ` (억제됨 ${suppressed}건: ${suppressedBreakdown})` : ""}. 프로젝트가 안전하다는 뜻은 아니므로 검사 범위를 확인하세요.`,
  locationsDetail: (status, count) => `${status}${count > 1 ? `, 위치 ${count}곳` : ""}`,
  confidence: "신뢰도",
  evidence: "근거",
  fix: "조치",
  suggestedFix: "제안된 수정",
  standards: "표준",
  variesByLocation: "위치마다 다름 (--all-findings로 각각 확인)",
  andMore: (count) => ` 외 ${count}곳`,
  showAllHint:
    "모두 보려면 --all-findings로 다시 실행하거나 보고서를 저장하세요 (--report html --output-dir <dir>).",
  shortenedGroupsHint: (max) =>
    `묶음마다 위치를 최대 ${max}곳까지 보여 줍니다. 모든 위치를 보려면 --all-findings로 다시 실행하세요.`,
  compact: {
    more: (count, breakdown) => `+${count}건 더 있음 (${breakdown}) - --all-findings로 실행`,
    details:
      "각 발견 항목의 근거, 수정 방법, 표준: --all-findings, 패널 화면, 대시보드 또는 보고서.",
    context: (title, count, bySeverity) => `${title} (${count}): ${bySeverity}`,
    result: (overall, total, breakdown) =>
      `결과: ${overall} - 발견 ${total}건${breakdown === "" ? "" : ` (${breakdown})`}`,
    notSafe:
      "! 안전하다는 결과가 아닙니다: 일부 또는 검사하지 못한 영역은 끝까지 확인하지 않았으므로, 그곳에 발견 항목이 없다고 문제가 없다는 뜻은 아닙니다.",
    coverageCount: (c) =>
      `정상 ${c.ok}, 일부 ${c.partial}, 검사 안 됨 ${c.notTested}${c.notSelected > 0 ? `, 선택 안 함 ${c.notSelected}` : ""}`,
    owaspLine: (c) =>
      `OWASP Top 10 2025: 규칙 실행 ${c.rules_ran}, 규칙 일부 ${c.rules_partial}, 미실행 ${c.not_run}, 규칙 없음 ${c.no_rules} (표: --all-findings)`,
    next: (hasHidden) =>
      `다음: ${hasHidden ? "pgard scan --all-findings로 전체를 나열하거나 " : ""}--report html --output-dir <dir>로 보고서를 저장하거나 pgard dashboard를 여세요.`,
  },
  testGroupTitle: "테스트·fixture 코드",
  testGroupNote:
    "경로만으로 테스트·fixture 코드로 분류된 파일의 항목입니다(신뢰도는 최대 낮음). 검토하세요. 테스트에 커밋된 실제 값도 노출된 것입니다.",
  configTestNote: (count) =>
    ` 그중 ${count}건은 기본 규칙이 아니라 pgard.config.json의 testDirectories 설정으로 분류되었습니다.`,
  severeAlwaysListed: " 치명적·높음 항목은 항상 나열됩니다.",
  collapsedTitle: (count) =>
    `테스트·fixture·vendored 코드 (심각도가 낮은 발견 항목 ${count}건은 나열하지 않음)`,
  collapsedNote: (threshold) =>
    `  이 코드의 항목이 ${threshold}건을 넘어 접었습니다. 사용자 코드의 항목과, 어디에 있든 치명적·높음 항목은 항상 나열합니다. 이 항목도 검토하세요. 테스트에 커밋된 실제 값도 노출된 것입니다.`,
  byContext: "분류별",
  byRule: "규칙별",
  bySeverity: "심각도별",
  contextName: { test: "테스트", vendored: "vendored", other: "기타" },
  moreRules: (count) => ` 외 규칙 ${count}개`,
  notListedHere: (count, hasCritical) =>
    `${count}건은 여기에 나열하지 않습니다${hasCritical ? " (치명적 항목은 위에 있음)" : ""}.`,
  suppressedReason: (reasonJson, expires) =>
    `pgard.config.json의 사유: ${reasonJson}${expires === "" ? "" : ` (만료 ${expires})`}`,
  suppressedCountLine: (count, breakdown) =>
    `pgard.config.json으로 억제됨: ${count}건${breakdown === "" ? "" : ` (${breakdown})`}`,
  baselineCountLine: (matched, fresh, breakdown, setOn) =>
    `기준선 (${setOn} 설정): 기준선에 있음 ${matched}건${breakdown === "" ? "" : ` (${breakdown})`}, 새 항목 ${fresh}건`,
  newFindingsSinceBaseline: KO_REPORT.newSinceBaseline,
  coverageTitle: "검사 범위",
  coverageMark: {
    completed: "완료",
    partial: "부분 완료",
    not_tested: "미검사",
    not_selected: "선택 안 함",
  },
  noCoverage: "(기록된 검사 범위 없음)",
  standardsTitle: "표준 매핑 현황 (OWASP Top 10 2025)",
  standardMark: KO_REPORT.standardState,
  standardsNote:
    "규칙 실행됨은 매핑된 규칙이 이번 검사에서 끝까지 실행되었다는 뜻입니다. 프로젝트가 안전하다거나 그 분류를 모두 다뤘다는 뜻이 아닙니다. 분류에 속한 CWE 중 규칙이 있는 개수를 확인하세요. 항목별 전체 내용: --format json (standardsCoverage, ruleStats).",
  standardsBreadth: (withRules, inCategory) =>
    `매핑된 CWE ${inCategory}개 중 ${withRules}개에 규칙이 있음`,
  cweTop25Line: (c) => `CWE Top 25 2025: ${KO_REPORT.cweTop25Counts(c)}`,
  authorizationAllowed: "권한 확인: 허용됨",
  authorizationBlocked: "권한 확인: 차단됨 - 분석이 실행되지 않았습니다",
  checkStatus: { passed: "통과", failed: "실패", unverifiable: "확인 불가" },
  checkName: {
    repository: "저장소",
    github_identity: "GitHub 계정",
    owner_approval: "소유자 승인",
    current_access: "현재 접근 권한",
    contribution: "기여 이력",
  },
  configExcluded: (count, rest) => `pgard.config.json으로 제외된 파일 ${count}개${rest}`,
  configNoticePrefix: "pgard.config.json: ",
  configDemoted: (count) =>
    `발견 항목 ${count}건이 pgard.config.json의 testDirectories 설정으로 테스트 코드로 분류되었습니다(따로 나열, 신뢰도 최대 낮음). 검토하세요.`,
  diff: {
    sinceLast: (when) => `지난 검사 이후 (${when})`,
    newCount: (count, uncertain, areas) =>
      `신규 ${count}건${uncertain > 0 ? ` (완전히 비교하지 못한 영역에서 ${uncertain}건${areas === "" ? "" : `: ${areas}`})` : ""}`,
    noLongerReported: (count) => `더 이상 보고되지 않음 ${count}건`,
    unchanged: (count) => `변화 없음 ${count}건`,
    moved: (count) => `위치 이동 ${count}건`,
    changedRating: (count) => `심각도 또는 상태 변경 ${count}건`,
    toolUpdated: (count) =>
      `지난 검사 이후 PGARD가 업데이트되어, 지금 보고되지 않는 이전 발견 항목 ${count}건은 확인할 수 없었습니다`,
    notComparedBecause: (parts, more) =>
      `일부 발견 항목은 비교할 수 없었습니다: ${parts}${more > 0 ? ` 외 영역 ${more}개` : ""}`,
    notFullyCompared: (parts, more) =>
      `완전히 비교하지 못함: ${parts}${more > 0 ? ` 외 영역 ${more}개` : ""}`,
    couldNotCheck: (count) => `이전 발견 항목 ${count}건은 확인할 수 없었습니다`,
    atRevision: (revision) => `, ${revision} 시점`,
    because: {
      partial: "부분적으로만 검사됨",
      not_tested: "검사되지 않음",
      only_in_previous: "이번 검사 범위에 없었음",
      only_in_current: "지난 검사 범위에 없었음",
      not_run: "실행되지 않음",
      other_origin: "다른 웹 주소를 사용함",
      changed: "두 검사 사이에 달라짐",
      appeared: "지난 검사 이후 새로 나타남",
      lastOnly: "지난 검사에만 있었음",
    },
    skippedStored: (count) => `저장된 결과 ${count}개는 건너뛰어 비교하지 않았습니다.`,
    notCompared: "지난 검사와 비교할 수 없었습니다.",
  },
  webOffer: {
    askOne: (label) => `${label}도 함께 검사할까요(웹 검사)?`,
    pickTitle: "로컬 웹 서비스를 찾았습니다. 하나를 함께 검사할까요?",
    none: "아니요, 웹 서비스는 검사하지 않음",
    help: `127.0.0.1에서 로컬 웹 서버를 찾았습니다. 웹 검사는 선택 사항입니다.
- 하나를 고르면 이 프로젝트의 서비스가 맞는지 다시 확인합니다.
- 제목을 읽기 위해 대기 중인 각 로컬 포트에 GET / 요청을 한 번씩 보냅니다. 검사 요청은 확인한 뒤에만 보냅니다.
- "아니요"에서 Enter(또는 Esc)를 누르면 웹 검사를 건너뜁니다.`,
  },
  progress: {
    scanning: (scopes) => `검사 중 (${scopes})... 취소하려면 Ctrl+C를 두 번 누르세요.`,
    pagesChecked: (count) => `  웹: 페이지 ${count}개 확인함`,
    stage: {
      authorization: "권한 확인",
      code: "코드",
      history: "이력",
      web: "웹",
    },
    status: {
      started: "시작",
      completed: "완료",
      failed: "실패",
      skipped: "건너뜀",
    },
    message: {
      "Verifying repository authorization.": "저장소 권한을 확인하는 중입니다.",
      "Authorization check failed.": "권한 확인에 실패했습니다.",
      "Scan blocked by authorization gate.": "권한 확인에서 검사가 차단되었습니다.",
      "Authorization verified.": "권한이 확인되었습니다.",
      "No confirmed local web target.": "확인된 로컬 웹 대상이 없습니다.",
      "Web scanner unavailable.": "웹 검사기를 사용할 수 없습니다.",
      "Checking local web pages.": "로컬 웹 페이지를 확인하는 중입니다.",
    },
    scoped: (message, names) => {
      const name = (scope: string): string => names[scope] ?? scope;
      const running = /^Running (\w+) analysis\.$/.exec(message);
      if (running !== null) return `${name(running[1] ?? "")} 분석을 실행하는 중입니다.`;
      const finished = /^Finished (\w+) analysis\.$/.exec(message);
      if (finished !== null) return `${name(finished[1] ?? "")} 분석을 마쳤습니다.`;
      const failed = /^The (\w+) analysis failed\.$/.exec(message);
      if (failed !== null) return `${name(failed[1] ?? "")} 분석이 실패했습니다.`;
      return undefined;
    },
  },
  notices: {
    noExpiry: (count) =>
      `만료일이 없는 억제 항목이 ${count}개 있어, 누군가 기억하지 않는 한 다시 검토되지 않습니다.`,
    webNotConfirmed:
      "대화형 터미널이 아니면 웹 대상을 확인할 수 없어 웹 검사는 미검사로 기록됩니다.",
    noReportBlocked: "검사가 차단되어 보고서를 작성하지 않았습니다.",
    baselineNotSet: "기준선을 설정하지 못했습니다. 이 검사는 저장할 수 없습니다.",
    notStored: (reason) => `검사 결과를 저장하지 못했습니다: ${reason}`,
    notStoredShort: "검사 결과를 저장하지 못했습니다.",
    notComparable: "지난 검사와 비교할 수 없었습니다.",
    firstRun: (dir, isWindows) =>
      [
        "PGARD가 이제 이 컴퓨터에 검사 결과를 보관해, 이후 검사와 비교할 수 있습니다.",
        `  위치: ${dir} (${
          isWindows
            ? "업로드되지 않으며, 접근은 Windows 사용자 폴더 권한을 따릅니다"
            : "본인만 읽을 수 있으며 업로드되지 않습니다"
        })`,
        "  내용: 민감 정보를 가린 결과만, 저장소마다 최근 20건을 90일 동안 보관합니다.",
        "  저장 끄기: --no-store를 붙이거나 PGARD_NO_STORE=1을 설정하세요.",
        "  모두 삭제: pgard history clear --all",
      ].join("\n"),
  },
  codeOnly: {
    line: "! 코드 전용 검사: 권한 미확인(현재 파일만 검사, Git 기록·웹 검사 없음, 저장하지 않음).",
    short: "! 코드 전용, 권한 미확인",
    menuLabel: "현재 파일 검사(코드 전용)",
    upgrade:
      "Git 기록까지 포함한 권한 있는 검사는 `pgard scan`(GitHub 로그인과 소유자 승인 필요)으로 실행하세요.",
    blockedHint: "`pgard scan code --code-only`는 승인 없이 현재 파일을 검사합니다.",
    prompt: "Git 기록은 빼고 현재 코드만 검사할까요? (권한 미확인으로 표시됩니다)",
    promptHelp:
      "y: Git 기록과 권한 확인 없이 현재 파일만 검사합니다. 결과에 그렇게 표시되고 저장하지 않습니다. N: 여기서 멈춥니다.",
    addFlagHint: "코드만 검사하려면 --code-only를 붙이세요.",
    tooBroad:
      "홈 폴더, 그 위의 폴더, 또는 최상위 폴더(/나 /Users 등)이며 프로젝트 폴더가 아닙니다. 프로젝트 자체의 폴더에서 pgard scan --code-only를 실행하세요.",
    tooBroadRepository:
      "이 폴더는 홈 폴더(또는 그 위의 폴더)에 있는 Git 저장소 안에 있어서, 코드 전용 검사가 .ssh 같은 폴더까지 전부 읽게 됩니다. 자체 Git 저장소가 있는 프로젝트 폴더에서 pgard scan --code-only를 실행하세요(없다면 그 폴더에서 `git init`을 실행하세요).",
    gitDirectory:
      "Git 디렉터리(.git 또는 bare 저장소)이며 프로젝트 파일이 아닙니다. 그 config에는 자격 증명이 들어 있을 수 있습니다. 프로젝트의 작업 폴더에서 pgard scan --code-only를 실행하세요.",
    noHome:
      "홈 폴더를 찾지 못해(HOME이 비어 있고 계정에도 홈 폴더가 없음) 이 폴더가 홈 폴더가 아닌지 확인할 수 없습니다. HOME을 설정한 뒤 pgard scan --code-only를 다시 실행하세요.",
    virtualFolder:
      "가상 파일 시스템(/proc, /sys, /dev)의 폴더이며 프로젝트 파일이 아닙니다. 프로젝트 자체의 폴더에서 pgard scan --code-only를 실행하세요.",
    unsafeFolder: (problem, at) =>
      problem === "not_owned_by_you"
        ? `${at} 폴더가 다른 사용자 소유입니다. 다른 사용자가 바꿀 수 있는 파일은 검사하지 않습니다. 본인 소유의 프로젝트 폴더에서 실행하세요.`
        : `${at} 폴더에 그룹 또는 다른 사용자의 쓰기 권한이 있습니다. 다른 사용자가 바꿀 수 있는 파일은 검사하지 않습니다. 쓰기 권한을 제거하세요(예: chmod go-w).`,
    worktreeRedirected:
      "Git이 알려 준 작업 트리 최상위 폴더가 .git이 있는 폴더와 다릅니다(보통 .git/config의 core.worktree 설정 때문입니다). 확인한 저장소와 읽게 될 파일이 달라지므로 검사하지 않습니다. core.worktree가 설정되어 있다면 .git/config에서 지우세요.",
  },
  panels: {
    title: "PGARD 패널",
    tabs: {
      overview: "개요",
      charts: "차트",
      coverage: "검사 범위",
      trend: "추이",
      findings: "발견 항목",
    },
    trend: {
      title: (count) => `추이: 이 저장소의 저장된 검사 ${count}건`,
      noHistory: {
        empty:
          "아직 이력이 없습니다: 이 저장소의 이전 검사가 저장되어 있지 않습니다. 나중에 다시 검사하면 추이를 볼 수 있습니다.",
        single: (date) =>
          `아직 이력이 없습니다: 저장된 검사가 1건뿐입니다 (${date}). 나중에 다시 검사하면 추이를 볼 수 있습니다.`,
        disabled:
          "아직 이력이 없습니다: 저장이 꺼져 있어(--no-store 또는 PGARD_NO_STORE=1) 비교할 대상이 없습니다.",
        noStoreDir:
          "아직 이력이 없습니다: 앱 데이터 폴더를 찾을 수 없어 아무것도 저장되지 않습니다.",
        noRepository:
          "아직 이력이 없습니다: 이 검사는 GitHub 저장소와 연결되지 않아 이력을 보관하지 않습니다.",
        unreadable: (reason) =>
          `이력을 읽을 수 없습니다${reason === "" ? "" : ` (원인: ${reason})`}. 검사 결과 자체에는 영향이 없습니다.`,
      },
      skipped: (count) => `저장된 파일 ${count}개를 읽을 수 없어 제외했습니다.`,
      latestVsPrevious: "최근 검사와 직전 검사 비교",
      newestStored: "저장된 최근 두 검사 비교",
      notStored: "이 검사는 저장되지 않았습니다.",
      newerSkipped: (count) => `더 새로운 PGARD 버전에서 만든 검사 ${count}건을 건너뛰었습니다.`,
      chartTitle: "검사별 활성 발견 항목 (최신순)",
      legend: (pairs) => `범례: ${pairs}`,
      tableTitle: "검사별 활성 발견 항목의 심각도 (최신순)",
      columns: { date: "날짜", age: "경과", total: "활성" },
      letters: { critical: "치", high: "높", medium: "중", low: "낮", info: "정" },
      age: (ms, short) => {
        const minutes = Math.floor(ms / 60000);
        if (minutes < 1) return short ? "방금" : "방금 전";
        if (minutes < 60) return short ? `${minutes}분` : `${minutes}분 전`;
        const hours = Math.floor(minutes / 60);
        if (hours < 24) return short ? `${hours}시간` : `${hours}시간 전`;
        const days = Math.floor(hours / 24);
        if (days === 1 && !short) return "어제";
        return short ? `${days}일` : `${days}일 전`;
      },
    },
    hints: {
      default: "Esc: 뒤로  ?: 도움말  Tab: 패널  위/아래: 스크롤",
      findings: "Esc: 뒤로  ?: 도움말  Enter: 열기  /: 검색  1-5: 심각도",
      filter: "Esc: 지우기  Enter: 유지  입력해서 검색",
      detail: "Esc/Enter: 닫기  위/아래: 스크롤",
      help: "?/Esc: 닫기  위/아래: 스크롤",
      noMatch: "Esc: 뒤로  ?: 도움말  c: 필터 해제  /: 검색",
    },
    exportHint: "e: 내보내기",
    exportReturn: "아무 키나 누르면 패널 화면으로 돌아갑니다.",
    filter: {
      label: "필터",
      count: (shown, total) => `${total}개 중 ${shown}개`,
      none: "없음",
      names: { severity: "심각도", area: "영역", rule: "규칙", search: "검색" },
      searchPrompt: "검색",
      noMatch: (total) =>
        `이 필터에 맞는 항목이 없지만 발견 항목은 ${total}개 있습니다. c를 누르면 필터를 지웁니다.`,
    },
    detail: { where: "위치", rule: "규칙", references: "참조" },
    helpTitle: "패널 화면 도움말",
    helpLines: [
      "Tab, Shift+Tab, 왼쪽, 오른쪽: 다음·이전 패널",
      "위, 아래, j, k: 스크롤 (발견 항목에서는 선택 이동)",
      "PageUp, PageDown: 한 페이지 스크롤",
      "Home, End: 처음 또는 마지막 줄",
      "발견 항목 목록:",
      "  Enter: 선택한 항목 열기(증거, 수정 방법, 표준). Enter나 Esc로 닫기",
      "  1-5: 한 심각도만 보기(1 치명 ... 5 정보, 다시 누르면 해제), 0 또는 s: 다음 심각도",
      "  a: 다음 영역(코드, 이력, 웹), r: 다음 규칙, c: 모든 필터 해제",
      "  /: 제목·규칙 ID·경로 검색. Enter로 유지, Esc로 지우기, 한 번 더 Esc로 나가기",
      "추이 패널: 이 저장소의 저장된 검사(로컬 저장소만), 최신순. 위/아래로 스크롤",
      "e: 보고서 저장(HTML, PDF 또는 둘 다). 답하는 동안 화면이 닫히고, 끝나면 그대로 돌아옵니다",
      "?: 이 도움말 열기·닫기",
      "Esc: 도움말·상세 닫기, 검색 지우기, 또는 패널 화면 나가기 (q는 바로 나가기)",
      "Ctrl+C: 취소 확인 (y를 누르면 종료 코드 130)",
      "",
      "읽기 전용입니다. 아무것도 바꾸거나 업로드하지 않으며, 증거는 결과 화면처럼 가려진 상태로 표시합니다.",
    ],
    confirmCancel: "취소하고 종료할까요? [y/N]",
    tooSmall: (columns, rows, minColumns, minRows) =>
      `터미널이 너무 작습니다 (${columns}x${rows}). 최소 ${minColumns}x${minRows}가 필요합니다. 크기를 키우거나 Esc를 누르세요.`,
    noFindings: "(발견 항목 없음)",
    position: (from, to, total) => `${from}-${to}/${total}`,
    suppressed: "억제됨",
    inBaseline: "기준선",
    notTerminal: "--panels는 터미널이 필요합니다. 위의 일반 텍스트 결과만 출력됩니다.",
    failed: "패널 화면에 문제가 생겨 닫았습니다. 위의 검사 결과에는 영향이 없습니다.",
    notOpenedBlocked: "--panels: 검사가 차단되어 패널 화면을 열지 않았습니다.",
    badEnv: "PGARD_PANELS 값이 off, 0, false, no가 아니어서 패널 화면을 그대로 사용합니다.",
    dumbTerminal: "--panels: TERM=dumb에서는 전체 화면을 그릴 수 없어 패널 화면을 열지 않았습니다.",
  },
};

/** The catalogs, keyed by language. A test fails when a Korean key is missing. */
export const CLI_TEXT: Record<RuleLocale, CliText> = { en: EN, ko: KO };

export function cliText(locale: RuleLocale | undefined): CliText {
  return CLI_TEXT[locale ?? "en"];
}

/** "5 s", "1 m 5 s" (English) or "5초", "1분 5초" (Korean). */
function formatElapsed(milliseconds: number, minuteWord: string, secondWord: string): string {
  const total = Math.max(0, milliseconds) / 1000;
  const isKorean = secondWord === "\ucd08";
  const join = (value: string, unit: string): string =>
    isKorean ? `${value}${unit}` : `${value} ${unit}`;
  // Round to tenths first: 9.96 s is "10 s", never "10.0 s".
  if (Math.round(total * 10) < 100)
    return join((Math.round(total * 10) / 10).toFixed(1), secondWord);
  // Round once, before splitting, so 119.6 s is "2 m 0 s" and never "1 m 60 s".
  const whole = Math.round(total);
  if (whole < 60) return join(String(whole), secondWord);
  const minutes = Math.floor(whole / 60);
  return `${join(String(minutes), minuteWord)} ${join(String(whole % 60), secondWord)}`;
}
