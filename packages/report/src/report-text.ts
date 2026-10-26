import type { CoverageStatus, OverallStatus, RuleLocale, Severity } from "@pgard/findings";
import type { StandardCheckState } from "@pgard/findings";
import {
  ANALYSIS_BASIS_NOTE,
  BASELINE_FINDINGS_NOTE,
  BASELINE_FINDINGS_TITLE,
  REPORT_DISCLAIMER,
  SUPPRESSED_FINDINGS_NOTE,
  SUPPRESSED_FINDINGS_TITLE,
  TEST_FINDINGS_NOTE,
  TEST_FINDINGS_TITLE,
  VENDORED_FINDINGS_DETAIL,
  VENDORED_FINDINGS_NOTE,
  VENDORED_FINDINGS_TITLE,
} from "./format.js";

/** Notices about suppressions and the baseline, by kind (mirrors the dashboard catalogs). */
export interface NoticeTexts {
  severe: (count: number, high: number, critical: number) => string;
  everything: (count: number) => string;
  incomplete: string;
  expired: (ruleId: string, path: string, expires: string) => string;
  far: (ruleId: string, path: string, expires: string) => string;
  wildcard: (ruleId: string, path: string, count: number) => string;
  total: (count: number) => string;
  broad: (ruleId: string, path: string, count: number) => string;
  baselineUncertain: (count: number) => string;
  baselineTool: string;
}

/** Every fixed word of a report, so the whole page (not only rule texts) follows `--report-lang`. */
export interface ReportText {
  htmlTitle: string;
  title: string;
  repository: string;
  revision: string;
  webTarget: string;
  scan: string;
  schema: string;
  to: string;
  requestedScopes: string;
  none: string;
  unknown: string;
  unknownLabel: string;
  overallStatus: string;
  overall: Record<OverallStatus, string>;
  coverageStatus: Record<CoverageStatus, string>;
  severity: Record<Severity, string>;
  note: string;
  summary: string;
  coverage: string;
  area: string;
  scope: string;
  status: string;
  noteColumn: string;
  noCoverage: string;
  findings: string;
  newFindings: string;
  noFindingsTail: string;
  noFindingsTailPdf: string;
  newBadge: string;
  newSinceBaseline: string;
  findingStatus: Record<"confirmed" | "suspected" | "informational", string>;
  confidence: string;
  confidenceLevel: Record<"low" | "medium" | "high", string>;
  source: string;
  location: string;
  evidence: string;
  ruleGuidance: string;
  ruleRationale: string;
  ruleRemediation: string;
  standards: string;
  viaCwe: (cwe: string) => string;
  examples: (count: number) => string;
  /** Link text on a finding whose rule examples and guidance were written on an earlier finding. */
  ruleDetailsAbove: (ruleId: string) => string;
  /** PDF finding line: the rule's examples are in appendix B. */
  examplesInAppendix: string;
  vulnerable: string;
  safe: string;
  references: string;
  authorization: string;
  decision: string;
  check: string;
  reason: string;
  analysisBasis: string;
  analysisBasisNote: string;
  disclaimer: string;
  testTitle: string;
  testNote: string;
  vendoredTitle: string;
  vendoredNote: string;
  vendoredDetail: string;
  suppressedTitle: string;
  suppressedNote: string;
  baselineTitle: string;
  baselineNote: string;
  /** Null for English: the notices of `@pgard/findings` are used as written. */
  notices: NoticeTexts | null;
  suppressedByConfig: (source: string, reasonJson: string, expires: string) => string;
  svgAria: (summary: string) => string;
  // Summary line pieces.
  summaryFindings: (
    total: number,
    confirmed: number,
    suspected: number,
    informational: number,
  ) => string;
  summaryTest: (count: number) => string;
  summaryVendored: (count: number, severe: string) => string;
  summarySuppressed: (count: number, breakdown: string) => string;
  summaryBaselineGroup: (count: number) => string;
  summaryBaseline: (matched: number, fresh: number, breakdown: string) => string;
  noFindings: (outside: string, suppressed: number, breakdown: string, isNew: boolean) => string;
  outsideTestAndVendored: string;
  outsideTest: string;
  outsideVendored: string;
  // New sections.
  standardsTitle: string;
  standardsNote: string;
  standardState: Record<StandardCheckState, string>;
  standardColumns: {
    id: string;
    category: string;
    state: string;
    breadth: string;
    rules: string;
    reason: string;
  };
  breadth: (withRules: number, inCategory: number) => string;
  cweTop25Title: string;
  cweTop25Counts: (counts: Record<StandardCheckState, number>) => string;
  cweColumns: { rank: string; id: string; name: string };
  ruleStatsTitle: (count: number) => string;
  ruleStatsNote: string;
  ruleStatsColumns: {
    rule: string;
    area: string;
    targets: string;
    findings: string;
    status: string;
  };
  targetCount: (examined: number, unit: string) => string;
  targetUnknown: (reason: string) => string;
  notRecorded: string;
  // PDF appendices and licensing footer.
  appendixStats: string;
  appendixExamples: string;
  appendixLinks: string;
  appendixNote: string;
  licenseTitle: string;
  licenseIntro: string;
  licenseOwasp: string;
  licenseCwe: string;
  licenseCert: string;
}

const KO_NOTICES: NoticeTexts = {
  severe: (count, high, critical) =>
    `억제된 발견 항목 중 ${count}건이 높음 또는 치명적입니다(높음 ${high}건, 치명적 ${critical}건). "억제됨" 목록에 그대로 나열되어 있으니 pgard.config.json의 사유를 확인하세요.`,
  everything: (count) =>
    `이 검사의 발견 항목 ${count}건이 모두 pgard.config.json으로 억제되었습니다. 모두 "억제됨"에 나열되어 있으니 결과를 믿기 전에 사유를 검토하세요.`,
  incomplete:
    "억제 항목 매칭이 일찍 멈췄습니다(패턴 작업 한도). 그 이후에 확인한 발견 항목은 억제되지 않고 평소처럼 나열됩니다.",
  expired: (ruleId, path, expires) =>
    `${ruleId}의 억제 항목(${JSON.stringify(path)})은 ${expires}에 만료되어 적용되지 않았습니다.`,
  far: (ruleId, path, expires) =>
    `${ruleId}의 억제 항목(${JSON.stringify(path)})은 ${expires}까지로 1년이 넘게 남았습니다. 억제 항목은 정기적으로 검토해야 합니다.`,
  wildcard: (ruleId, path, count) =>
    `${ruleId}의 억제 항목이 ${JSON.stringify(path)}를 사용합니다. 모든 파일, 그 규칙의 모든 발견 항목에 해당합니다 (${count}건 억제).`,
  total: (count) => `억제 항목이 몇 개든 합쳐서 발견 항목 ${count}건(10건 초과)이 억제되었습니다.`,
  broad: (ruleId, path, count) =>
    `${ruleId}의 억제 항목(${JSON.stringify(path)})이 발견 항목 ${count}건에 해당합니다.`,
  baselineUncertain: (count) =>
    `새 발견 항목 ${count}건은 기준선이 충분히 다루지 못한 영역에 있어 이전부터 있던 것일 수 있습니다.`,
  baselineTool:
    "기준선을 설정한 뒤 PGARD가 업데이트되어 규칙이 바뀌었을 수 있습니다. 새 항목과 기준선 항목 수를 신중히 해석하세요.",
};

const STANDARDS_NOTE_EN =
  'The states say whether PGARD rules that map to an entry ran in this scan. "Rules ran" does not mean the project is safe or that the category is covered: see how many of its CWEs have rules (breadth). Only ids, titles and links are shown; see the linked pages for the standards themselves.';

export const REPORT_TEXT: Record<RuleLocale, ReportText> = {
  en: {
    htmlTitle: "PGARD Report",
    title: "PGARD security report",
    repository: "Repository",
    revision: "Revision",
    webTarget: "Web target",
    scan: "Scan",
    schema: "schema",
    to: "to",
    requestedScopes: "Requested scopes",
    none: "none",
    unknown: "unknown",
    unknownLabel: "Unknown",
    overallStatus: "Overall status",
    overall: {
      completed: "Completed",
      partial: "Partial - some requested areas did not fully run",
      blocked: "Blocked by the authorization gate - no analysis ran",
      failed: "Failed - an internal error stopped the scan",
    },
    coverageStatus: {
      completed: "Completed",
      partial: "Partial",
      not_tested: "Not tested",
      not_selected: "Not selected",
    },
    severity: {
      critical: "Critical",
      high: "High",
      medium: "Medium",
      low: "Low",
      info: "Info",
    },
    note: "Note",
    summary: "Summary",
    coverage: "Coverage",
    area: "Area",
    scope: "Scope",
    status: "Status",
    noteColumn: "Note",
    noCoverage: "No coverage was recorded.",
    findings: "Findings",
    newFindings: "New findings (since the baseline)",
    noFindingsTail: "This is not a statement that the project is secure; check coverage below.",
    noFindingsTailPdf: "This is not a statement that the project is secure; check coverage above.",
    newBadge: "NEW",
    newSinceBaseline: "NEW since the baseline",
    findingStatus: {
      confirmed: "confirmed",
      suspected: "suspected",
      informational: "informational",
    },
    confidence: "confidence",
    confidenceLevel: { low: "low", medium: "medium", high: "high" },
    source: "source",
    location: "Location",
    evidence: "Evidence (redacted)",
    ruleGuidance: "Rule guidance",
    ruleRationale: "Why the rule matters",
    ruleRemediation: "General fix",
    standards: "Standards",
    viaCwe: (cwe) => `via ${cwe}`,
    examples: (count) => `Examples (${count})`,
    examplesInAppendix: "Examples: see Appendix B",
    ruleDetailsAbove: (ruleId) => `Examples and guidance: see the first ${ruleId} finding`,
    vulnerable: "Vulnerable",
    safe: "Safe",
    references: "References",
    authorization: "Authorization",
    decision: "Decision",
    check: "Check",
    reason: "Reason",
    analysisBasis: "Analysis basis",
    analysisBasisNote: ANALYSIS_BASIS_NOTE,
    disclaimer: REPORT_DISCLAIMER,
    testTitle: TEST_FINDINGS_TITLE,
    testNote: TEST_FINDINGS_NOTE,
    vendoredTitle: VENDORED_FINDINGS_TITLE,
    vendoredNote: VENDORED_FINDINGS_NOTE,
    vendoredDetail: VENDORED_FINDINGS_DETAIL,
    suppressedTitle: SUPPRESSED_FINDINGS_TITLE,
    suppressedNote: SUPPRESSED_FINDINGS_NOTE,
    baselineTitle: BASELINE_FINDINGS_TITLE,
    baselineNote: BASELINE_FINDINGS_NOTE,
    notices: null,
    suppressedByConfig: (source, reasonJson, expires) =>
      `Suppressed by ${source}: ${reasonJson}${expires === "" ? "" : ` (expires ${expires})`}`,
    svgAria: (summary) => `Findings by severity: ${summary}`,
    summaryFindings: (total, confirmed, suspected, informational) =>
      `${total} finding(s): ${confirmed} confirmed, ${suspected} suspected, ${informational} informational.`,
    summaryTest: (count) => ` ${count} more in test or fixture code, listed separately.`,
    summaryVendored: (count, severe) =>
      ` ${count} suggestion${count === 1 ? "" : "s"} in vendored code${severe === "" ? "" : ` (${severe})`}, listed last.`,
    summarySuppressed: (count, breakdown) =>
      ` ${count} suppressed by pgard.config.json${breakdown === "" ? "" : ` (${breakdown})`}, listed separately.`,
    summaryBaselineGroup: (count) => ` ${count} in baseline, listed separately.`,
    summaryBaseline: (matched, fresh, breakdown) =>
      `Baseline: ${matched} in baseline${breakdown === "" ? "" : ` (${breakdown})`}, ${fresh} new. New findings: `,
    noFindings: (outside, suppressed, breakdown, isNew) =>
      `No ${isNew ? "new " : ""}${suppressed > 0 ? "unsuppressed " : ""}findings${outside} in the areas that ran${suppressed > 0 ? ` (${suppressed} suppressed: ${breakdown})` : ""}.`,
    outsideTestAndVendored: " outside test, fixture or vendored code",
    outsideTest: " outside test or fixture code",
    outsideVendored: " outside vendored code",
    standardsTitle: "Standards coverage (OWASP Top 10 2025)",
    standardsNote: STANDARDS_NOTE_EN,
    standardState: {
      rules_ran: "Rules ran",
      rules_partial: "Rules partial",
      not_run: "Not run",
      no_rules: "No rules",
    },
    standardColumns: {
      id: "ID",
      category: "Category",
      state: "State",
      breadth: "Breadth",
      rules: "Rules",
      reason: "Reason",
    },
    breadth: (withRules, inCategory) => `${withRules} of ${inCategory} mapped CWEs have rules`,
    cweTop25Title: "CWE Top 25 2025",
    cweTop25Counts: (c) =>
      `${c.rules_ran} rules ran, ${c.rules_partial} rules partial, ${c.not_run} not run, ${c.no_rules} no rules`,
    cweColumns: { rank: "Rank", id: "CWE", name: "Weakness" },
    ruleStatsTitle: (count) => `Rule statistics (${count})`,
    ruleStatsNote:
      "What each rule examined in each area it ran in. A count of 0 findings means the rule found nothing in what it examined, not that the project is free of that weakness.",
    ruleStatsColumns: {
      rule: "Rule",
      area: "Area",
      targets: "Targets examined",
      findings: "Findings",
      status: "Status",
    },
    targetCount: (examined, unit) => `${examined} ${unit}`,
    targetUnknown: (reason) => `unknown (${reason})`,
    notRecorded:
      "Standards coverage and rule statistics were not recorded in this result (written by an older PGARD).",
    appendixStats: "Appendix A: rule statistics",
    appendixExamples: "Appendix B: examples for the rules that reported findings",
    appendixLinks: "Appendix C: standards links",
    appendixNote:
      "Kept in appendices so the findings stay short; the HTML report shows them inline in collapsible sections.",
    licenseTitle: "Standards data and attribution",
    licenseIntro:
      "Only identifiers, titles and links of these standards are shown here; none of their text is copied.",
    licenseOwasp:
      "OWASP Top 10:2025, Copyright (c) 2003-2025 The OWASP Foundation, Inc., licensed under CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/).",
    licenseCwe:
      "CWE and the CWE Top 25: Copyright (c) 2006-2026, The MITRE Corporation, used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html). CWE is a trademark of The MITRE Corporation.",
    licenseCert:
      "SEI CERT Oracle Coding Standard for Java: (c) 2026 Carnegie Mellon University, licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/). Carnegie Mellon and CERT are registered trademarks of Carnegie Mellon University. This report is not endorsed by Carnegie Mellon University or the SEI. See NOTICE.md of PGARD.",
  },
  ko: {
    htmlTitle: "PGARD 보고서",
    title: "PGARD 보안 보고서",
    repository: "저장소",
    revision: "리비전",
    webTarget: "웹 대상",
    scan: "검사",
    schema: "스키마",
    to: "~",
    requestedScopes: "요청한 범위",
    none: "없음",
    unknown: "알 수 없음",
    unknownLabel: "알 수 없음",
    overallStatus: "전체 상태",
    overall: {
      completed: "완료",
      partial: "부분 완료 - 요청한 영역 일부가 끝까지 실행되지 않았습니다",
      blocked: "권한 확인에서 차단됨 - 분석이 실행되지 않았습니다",
      failed: "실패 - 내부 오류로 검사가 중단되었습니다",
    },
    coverageStatus: {
      completed: "완료",
      partial: "부분 완료",
      not_tested: "미검사",
      not_selected: "선택 안 함",
    },
    severity: {
      critical: "치명적",
      high: "높음",
      medium: "보통",
      low: "낮음",
      info: "정보",
    },
    note: "참고",
    summary: "요약",
    coverage: "검사 범위",
    area: "영역",
    scope: "범위",
    status: "상태",
    noteColumn: "비고",
    noCoverage: "기록된 검사 범위가 없습니다.",
    findings: "발견 항목",
    newFindings: "새 발견 항목 (기준선 이후)",
    noFindingsTail: "프로젝트가 안전하다는 뜻은 아니므로 아래의 검사 범위를 확인하세요.",
    noFindingsTailPdf: "프로젝트가 안전하다는 뜻은 아니므로 위의 검사 범위를 확인하세요.",
    newBadge: "신규",
    newSinceBaseline: "기준선 이후 신규",
    findingStatus: { confirmed: "확인됨", suspected: "의심", informational: "참고" },
    confidence: "신뢰도",
    confidenceLevel: { low: "낮음", medium: "보통", high: "높음" },
    source: "출처",
    location: "위치",
    evidence: "근거 (가려짐)",
    ruleGuidance: "규칙 안내",
    ruleRationale: "규칙이 중요한 이유",
    ruleRemediation: "일반적인 조치",
    standards: "표준",
    viaCwe: (cwe) => `${cwe} 경유`,
    examples: (count) => `예시 (${count})`,
    examplesInAppendix: "예시: 부록 B 참고",
    ruleDetailsAbove: (ruleId) => `예시와 안내: 첫 번째 ${ruleId} 발견 항목을 참고하세요`,
    vulnerable: "취약한 코드",
    safe: "안전한 코드",
    references: "참조",
    authorization: "권한 확인",
    decision: "결정",
    check: "항목",
    reason: "이유",
    analysisBasis: "분석 근거",
    analysisBasisNote:
      "PGARD는 취약점 데이터베이스를 포함하거나 조회하지 않습니다. 발견 항목은 코드 자체(쿼리문, 서버 코드, 설정), Git 이력, 그리고 선택한 경우 로컬 HTTP 검사에서 나옵니다. 의존성 버전은 알려진 취약점과 대조하지 않습니다.",
    disclaimer:
      "PGARD는 검사 시점에 선택한 범위에서 지원하는 규칙이 탐지한 내용만 보고합니다. 발견 항목이 없다는 것이 프로젝트가 안전하다는 뜻은 아닙니다. 부분 완료, 미검사, 선택 안 함으로 표시된 영역은 끝까지 확인되지 않았으며, 의심 항목은 수동 검토가 필요합니다. HTTP 검사는 익명 GET 요청만 사용했지만 부작용이 없었다는 것을 PGARD가 보장하지는 않습니다. 이 보고서는 로컬에서 생성되었고 민감한 취약점이 담겨 있을 수 있으니 저장소 밖에 보관하고 열람 권한이 있는 사람에게만 공유하세요.",
    testTitle: "테스트·fixture 코드",
    testNote:
      "경로만으로 테스트·fixture 코드로 분류된 파일의 항목입니다(*.test.*, *.spec.*, *_test.go, 그리고 __tests__/, __mocks__/, fixtures/, __fixtures__/, testdata/, test/, tests/ 아래의 파일. test/ 또는 tests/ 아래의 .env, YAML, .tf, .properties, .ini, .toml, .json 같은 설정 파일은 실제 설정으로 취급합니다). 신뢰도는 최대 낮음으로 제한되고 위 개수에는 포함되지 않지만 버리지는 않습니다. 테스트에 커밋된 실제 값도 노출된 것입니다.",
    vendoredTitle: "제안: 서드파티/vendored 코드",
    vendoredNote:
      "이 코드는 커밋된 의존성 코드이며 사용자의 코드가 아닙니다. 예상치 못한 것이면 검토하고, 아니면 Git에서 제거를 고려하세요 (git rm -r --cached <directory>, 그다음 해당 디렉터리를 .gitignore에 추가).",
    vendoredDetail:
      "경로로만 분류합니다. node_modules/, bower_components/, jspm_packages/, Pods/ 디렉터리 아래의 파일, 또는 src/, app/, lib/ 안에 있지 않은 vendor/, third_party/ 디렉터리 아래의 파일입니다. 신뢰도는 최대 낮음으로 제한되고 위 개수에는 포함되지 않지만 버리지는 않습니다. 거기에 커밋된 실제 비밀정보도 노출된 것입니다.",
    suppressedTitle: "억제됨",
    suppressedNote:
      "이 항목들은 검사 대상 저장소의 파일인 pgard.config.json의 억제 항목에 해당했습니다. 여기와 JSON 결과에는 그대로 보고됩니다. 사유는 PGARD가 아니라 그 파일의 문구입니다. 치명적 항목은 항상 열린 상태로 표시됩니다.",
    baselineTitle: "기준선에 있음",
    baselineNote:
      "이 항목들은 이미 기준선(pgard baseline)에 있었습니다. 새 항목은 아니지만 계속 보고됩니다.",
    notices: KO_NOTICES,
    suppressedByConfig: (source, reasonJson, expires) =>
      `${source}으로 억제됨: ${reasonJson}${expires === "" ? "" : ` (만료 ${expires})`}`,
    svgAria: (summary) => `심각도별 발견 항목: ${summary}`,
    summaryFindings: (total, confirmed, suspected, informational) =>
      `발견 항목 ${total}건: 확인됨 ${confirmed}, 의심 ${suspected}, 참고 ${informational}.`,
    summaryTest: (count) => ` 테스트·fixture 코드에 ${count}건 더 있으며 따로 나열합니다.`,
    summaryVendored: (count, severe) =>
      ` vendored 코드의 제안 ${count}건${severe === "" ? "" : ` (${severe})`}, 마지막에 나열합니다.`,
    summarySuppressed: (count, breakdown) =>
      ` pgard.config.json으로 억제됨 ${count}건${breakdown === "" ? "" : ` (${breakdown})`}, 따로 나열합니다.`,
    summaryBaselineGroup: (count) => ` 기준선에 있음 ${count}건, 따로 나열합니다.`,
    summaryBaseline: (matched, fresh, breakdown) =>
      `기준선: 기준선에 있음 ${matched}건${breakdown === "" ? "" : ` (${breakdown})`}, 새 항목 ${fresh}건. 새 발견 항목: `,
    noFindings: (outside, suppressed, breakdown, isNew) =>
      `실행된 영역에서${outside} ${isNew ? "새 " : ""}${suppressed > 0 ? "억제되지 않은 " : ""}발견 항목이 없습니다${suppressed > 0 ? ` (억제됨 ${suppressed}건: ${breakdown})` : ""}.`,
    outsideTestAndVendored: " 테스트·fixture·vendored 코드를 제외하고",
    outsideTest: " 테스트·fixture 코드를 제외하고",
    outsideVendored: " vendored 코드를 제외하고",
    standardsTitle: "표준 매핑 현황 (OWASP Top 10 2025)",
    standardsNote:
      "각 상태는 항목에 매핑된 PGARD 규칙이 이번 검사에서 실행되었는지를 나타냅니다. 규칙 실행됨은 프로젝트가 안전하다거나 그 분류를 모두 다뤘다는 뜻이 아닙니다. 분류에 속한 CWE 중 규칙이 있는 개수(범위 폭)를 함께 확인하세요. 여기에는 표준의 식별자, 제목, 링크만 표시하며 표준 자체는 링크된 페이지를 참고하세요.",
    standardState: {
      rules_ran: "규칙 실행됨",
      rules_partial: "규칙 일부 실행",
      not_run: "실행 안 됨",
      no_rules: "규칙 없음",
    },
    standardColumns: {
      id: "ID",
      category: "분류",
      state: "상태",
      breadth: "범위 폭",
      rules: "규칙",
      reason: "이유",
    },
    breadth: (withRules, inCategory) =>
      `매핑된 CWE ${inCategory}개 중 ${withRules}개에 규칙이 있음`,
    cweTop25Title: "CWE Top 25 2025",
    cweTop25Counts: (c) =>
      `규칙 실행됨 ${c.rules_ran}, 규칙 일부 실행 ${c.rules_partial}, 실행 안 됨 ${c.not_run}, 규칙 없음 ${c.no_rules}`,
    cweColumns: { rank: "순위", id: "CWE", name: "약점" },
    ruleStatsTitle: (count) => `규칙 통계 (${count})`,
    ruleStatsNote:
      "각 규칙이 실행된 영역마다 무엇을 살펴봤는지 보여 줍니다. 발견 항목 0건은 규칙이 살펴본 범위에서 아무것도 찾지 못했다는 뜻이며, 프로젝트에 그 약점이 없다는 뜻이 아닙니다.",
    ruleStatsColumns: {
      rule: "규칙",
      area: "영역",
      targets: "살펴본 대상",
      findings: "발견 항목",
      status: "상태",
    },
    targetCount: (examined, unit) => `${unit} ${examined}개`,
    targetUnknown: (reason) => `알 수 없음 (${reason})`,
    notRecorded:
      "이 결과에는 표준 매핑 현황과 규칙 통계가 기록되어 있지 않습니다(이전 버전의 PGARD가 작성).",
    appendixStats: "부록 A: 규칙 통계",
    appendixExamples: "부록 B: 발견 항목이 있는 규칙의 예시",
    appendixLinks: "부록 C: 표준 링크",
    appendixNote:
      "발견 항목을 짧게 유지하기 위해 부록에 두었습니다. HTML 보고서에는 접을 수 있는 구역으로 본문에 표시됩니다.",
    licenseTitle: "표준 데이터와 출처 표기",
    licenseIntro: "이 표준들의 식별자, 제목, 링크만 표시하며 표준의 본문은 복사하지 않았습니다.",
    licenseOwasp:
      "OWASP Top 10:2025, Copyright (c) 2003-2025 The OWASP Foundation, Inc., CC BY-SA 4.0 라이선스 (https://creativecommons.org/licenses/by-sa/4.0/).",
    licenseCwe:
      "CWE 및 CWE Top 25: Copyright (c) 2006-2026, The MITRE Corporation, CWE 이용 약관에 따라 사용 (https://cwe.mitre.org/about/termsofuse.html). CWE는 The MITRE Corporation의 상표입니다.",
    licenseCert:
      "SEI CERT Oracle Coding Standard for Java: (c) 2026 Carnegie Mellon University, CC BY 4.0 라이선스(https://creativecommons.org/licenses/by/4.0/). Carnegie Mellon과 CERT는 Carnegie Mellon University의 등록 상표입니다. 이 보고서는 Carnegie Mellon University나 SEI의 보증을 받지 않았습니다. PGARD의 NOTICE.md를 참고하세요.",
  },
};
