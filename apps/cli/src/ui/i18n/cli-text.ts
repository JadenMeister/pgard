import type { IncrementalFullReason, IncrementalInfo, RuleLocale, Severity } from "@pgard/findings";
import { INCREMENTAL_TEXT, REPORT_TEXT, type ReportText } from "@pgard/report";

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
  standards: string;
  variesByLocation: string;
  andMore: (count: number) => string;
  showAllHint: string;
  shortenedGroupsHint: (max: number) => string;

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
  standards: "Standards",
  variesByLocation: "varies by location (run with --all-findings to see each)",
  andMore: (count) => ` and ${count} more`,
  showAllHint:
    "Run again with --all-findings to list everything, or save a report (--report html --output-dir <dir>).",
  shortenedGroupsHint: (max) =>
    `Groups show up to ${max} locations. Run again with --all-findings to list every location.`,
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
};

const KO: CliText = {
  locale: "ko",
  report: KO_REPORT,
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
  standards: "표준",
  variesByLocation: "위치마다 다름 (--all-findings로 각각 확인)",
  andMore: (count) => ` 외 ${count}곳`,
  showAllHint:
    "모두 보려면 --all-findings로 다시 실행하거나 보고서를 저장하세요 (--report html --output-dir <dir>).",
  shortenedGroupsHint: (max) =>
    `묶음마다 위치를 최대 ${max}곳까지 보여 줍니다. 모든 위치를 보려면 --all-findings로 다시 실행하세요.`,
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
  if (total < 10) return join(total.toFixed(1), secondWord);
  // Round once, before splitting, so 119.6 s is "2 m 0 s" and never "1 m 60 s".
  const whole = Math.round(total);
  if (whole < 60) return join(String(whole), secondWord);
  const minutes = Math.floor(whole / 60);
  return `${join(String(minutes), minuteWord)} ${join(String(whole % 60), secondWord)}`;
}
