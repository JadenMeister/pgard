import type { Language } from "../../i18n/types";

/**
 * PROTOTYPE (#414): the texts of the one-screen code-only flow, in English and Korean. Kept apart
 * from the dashboard catalogs until the owner signs off on the wording
 * (docs/CODE_ONLY_SCAN_DESIGN.md, section "Web UX").
 */
export interface SimpleText {
  prototypeTag: string;
  title: string;
  lead: string;
  steps: [string, string, string];
  folderTitle: string;
  folderHint: string;
  candidatesTitle: string;
  candidateUse: string;
  candidateConfirm: (path: string) => string;
  useFolder: string;
  using: string;
  back: string;
  noMatch: (name: string) => string;
  noMatchFix: string;
  chosenLabel: string;
  change: string;
  scanTitle: string;
  scanWhat: string;
  scanButton: string;
  rescanButton: string;
  scanning: (seconds: number) => string;
  cancel: string;
  cancelled: string;
  failed: string;
  resultsTitle: string;
  noFindings: string;
  findingsCount: (count: number) => string;
  extraNote: string;
  partialNote: string;
  badge: string;
  badgeTitle: string;
  badgeBody: string;
  connect: string;
  connectHint: string;
  moreTitle: string;
  moreLead: string;
  moreCoverage: string;
  moreStandards: string;
  moreRules: string;
  moreTrend: string;
  moreTrendNote: string;
  moreExport: string;
  moreExportNote: string;
  moreFull: string;
  moreFullNote: string;
  moreNeedsScan: string;
  backToSimple: string;
}

const en: SimpleText = {
  prototypeTag: "Prototype",
  title: "Scan a project folder",
  lead: "PGARD checks the files in a folder on this computer for leaked secrets, risky code and known-vulnerable dependencies.",
  steps: ["Choose a folder", "Press Scan", "Fix what it finds"],
  folderTitle: "1. Folder",
  folderHint:
    "Drop the folder here, or type its name. Only the name is sent; PGARD finds the folder and shows its real path.",
  candidatesTitle: "Found",
  candidateUse: "Choose",
  candidateConfirm: (path) => `Scan the folder ${path}?`,
  useFolder: "Use this folder",
  using: "Opening…",
  back: "Back",
  noMatch: (name) => `No folder named "${name}" in the search folders.`,
  noMatchFix:
    "Add the folder that contains it with pgard web scope add <folder>, then search again.",
  chosenLabel: "Folder",
  change: "Change",
  scanTitle: "2. Scan",
  scanWhat:
    "Reads the current files only: secrets, risky code patterns and dependencies. No Git history, nothing leaves this computer and nothing is saved.",
  scanButton: "Scan",
  rescanButton: "Scan again",
  scanning: (seconds) => `Scanning the files… ${seconds} s`,
  cancel: "Cancel",
  cancelled: "The scan was cancelled.",
  failed: "The scan stopped because of an internal error. Try again.",
  resultsTitle: "3. Findings",
  noFindings: "No findings in the checked files.",
  findingsCount: (count) => (count === 1 ? "1 finding" : `${count} findings`),
  extraNote:
    "Findings in test, fixture and vendored code are listed under More › What was checked.",
  partialNote:
    "Some areas could not be checked (for example, no vulnerability data has been downloaded yet). See More › What was checked.",
  badge: "Not authorized · code only",
  badgeTitle: "Authorization was not checked",
  badgeBody:
    "This is a code-only scan of the files on this computer. PGARD did not prove that you may scan this repository, so Git history, local web checks and saved results are off.",
  connect: "Connect GitHub to also scan Git history",
  connectHint:
    "Optional. Opens the full dashboard, which asks for GitHub sign-in and owner approval.",
  moreTitle: "More",
  moreLead: "Details for the scan above. None of this is needed to fix the findings.",
  moreCoverage: "What was checked",
  moreStandards: "Standards (OWASP, CWE)",
  moreRules: "Rule statistics",
  moreTrend: "Trend",
  moreTrendNote: "Needs GitHub approval: code-only results are never saved.",
  moreExport: "Export report",
  moreExportNote:
    "Not in this prototype: an export must carry the “not authorized” label on every page.",
  moreFull: "Full dashboard",
  moreFullNote: "The current dashboard with GitHub sign-in, Git history and web checks.",
  moreNeedsScan: "Run a scan first.",
  backToSimple: "Back to the simple screen",
};

const ko: SimpleText = {
  prototypeTag: "프로토타입",
  title: "프로젝트 폴더 검사",
  lead: "PGARD는 이 컴퓨터에 있는 폴더의 파일에서 유출된 비밀값, 위험한 코드, 알려진 취약 의존성을 찾습니다.",
  steps: ["폴더 선택", "검사 누르기", "찾은 문제 고치기"],
  folderTitle: "1. 폴더",
  folderHint:
    "폴더를 여기로 끌어다 놓거나 이름을 입력하세요. 이름만 전송되며, PGARD가 폴더를 찾아 실제 경로를 보여 줍니다.",
  candidatesTitle: "찾은 폴더",
  candidateUse: "선택",
  candidateConfirm: (path) => `${path} 폴더를 검사할까요?`,
  useFolder: "이 폴더 사용",
  using: "여는 중…",
  back: "뒤로",
  noMatch: (name) => `검색 폴더에 "${name}" 폴더가 없습니다.`,
  noMatchFix: "그 폴더를 담은 상위 폴더를 pgard web scope add <폴더>로 추가한 뒤 다시 검색하세요.",
  chosenLabel: "폴더",
  change: "변경",
  scanTitle: "2. 검사",
  scanWhat:
    "현재 파일만 읽습니다: 비밀값, 위험한 코드 패턴, 의존성. Git 기록은 읽지 않고, 이 컴퓨터 밖으로 아무것도 보내지 않으며, 아무것도 저장하지 않습니다.",
  scanButton: "검사",
  rescanButton: "다시 검사",
  scanning: (seconds) => `파일 검사 중… ${seconds}초`,
  cancel: "취소",
  cancelled: "검사를 취소했습니다.",
  failed: "내부 오류로 검사가 멈췄습니다. 다시 시도하세요.",
  resultsTitle: "3. 찾은 문제",
  noFindings: "검사한 파일에서 찾은 문제가 없습니다.",
  findingsCount: (count) => `${count}건`,
  extraNote: "테스트·픽스처·벤더 코드의 결과는 더 보기 › 검사 범위에 있습니다.",
  partialNote:
    "일부 영역은 검사하지 못했습니다(예: 취약점 데이터를 아직 내려받지 않음). 더 보기 › 검사 범위를 확인하세요.",
  badge: "권한 미확인 · 코드만",
  badgeTitle: "권한을 확인하지 않았습니다",
  badgeBody:
    "이 결과는 이 컴퓨터에 있는 파일만 검사한 코드 전용 검사입니다. 이 저장소를 검사해도 된다는 권한을 PGARD가 확인하지 않았으므로 Git 기록, 로컬 웹 검사, 결과 저장은 꺼져 있습니다.",
  connect: "GitHub 연결하고 Git 기록도 검사",
  connectHint: "선택 사항입니다. GitHub 로그인과 소유자 승인을 요청하는 전체 대시보드를 엽니다.",
  moreTitle: "더 보기",
  moreLead: "위 검사의 자세한 정보입니다. 문제를 고치는 데 꼭 필요하지는 않습니다.",
  moreCoverage: "검사 범위",
  moreStandards: "표준 (OWASP, CWE)",
  moreRules: "규칙 통계",
  moreTrend: "추이",
  moreTrendNote: "GitHub 승인이 필요합니다. 코드 전용 결과는 저장하지 않습니다.",
  moreExport: "보고서 내보내기",
  moreExportNote:
    "이 프로토타입에는 없습니다. 내보낸 파일의 모든 페이지에 “권한 미확인” 표시가 있어야 합니다.",
  moreFull: "전체 대시보드",
  moreFullNote: "GitHub 로그인, Git 기록, 웹 검사가 있는 현재 대시보드입니다.",
  moreNeedsScan: "먼저 검사를 실행하세요.",
  backToSimple: "간단한 화면으로 돌아가기",
};

export function simpleText(language: Language): SimpleText {
  return language === "ko" ? ko : en;
}
