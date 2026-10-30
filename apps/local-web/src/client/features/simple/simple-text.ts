import type { FolderRefusalCode, PickerCandidate } from "../../../shared/picker-types";
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
  chooseFolder: string;
  dialogOpen: string;
  dialogUnavailable: string;
  dialogTimeout: string;
  dialogCancelled: string;
  pasteLabel: string;
  pastePlaceholder: string;
  pasteSubmit: string;
  checking: string;
  requestFailed: string;
  refusals: Record<FolderRefusalCode, { reason: string; fix: string }>;
  candidateConfirm: string;
  githubRepo: (repo: string) => string;
  codeOnlyReason: Record<NonNullable<PickerCandidate["codeOnly"]>, string>;
  useFolder: string;
  using: string;
  back: string;
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
  /** Why authorization was not verified (`scanBasis.reason`, JSON 1.7). */
  badgeReason: (reason: string) => string;
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
  folderHint: "Choose the project's folder, or paste its path.",
  chooseFolder: "Choose folder",
  dialogOpen: "Waiting for the folder window…",
  dialogUnavailable:
    "This computer has no folder window PGARD can open. Paste the folder's path below instead.",
  dialogTimeout: "The folder window closed after 5 minutes. Choose the folder again.",
  dialogCancelled: "No folder was chosen.",
  pasteLabel: "Or paste the folder's path",
  pastePlaceholder: "~/code/my-app",
  pasteSubmit: "Check",
  checking: "Checking…",
  requestFailed: "The request failed. Try again.",
  refusals: {
    bad_path: {
      reason: "This is not a folder path.",
      fix: "Paste the full path, for example ~/code/my-app or /Users/you/code/my-app.",
    },
    missing: {
      reason: "This folder does not exist.",
      fix: "Check the path, or use Choose folder.",
    },
    not_a_directory: {
      reason: "This is a file, not a folder.",
      fix: "Choose the project's folder.",
    },
    too_broad: {
      reason: "This is your home folder or a system folder, not a project.",
      fix: "Choose the project's own folder, for example ~/code/my-app.",
    },
    too_deep: {
      reason: "This folder is nested too deeply to check.",
      fix: "Choose a folder closer to your home folder.",
    },
    unreadable: {
      reason: "This folder could not be read in time.",
      fix: "Try again; a slow or disconnected network folder can cause this.",
    },
    not_owned_by_you: {
      reason: "This folder, or a folder above it, belongs to another user.",
      fix: "Copy the project into your own folder.",
    },
    group_or_world_writable: {
      reason: "Another user could change this folder or a folder above it.",
      fix: "Remove group and other write access (chmod go-w), or copy the project into your own folder.",
    },
  },
  candidateConfirm: "Scan this folder?",
  githubRepo: (repo) => `GitHub repository ${repo}`,
  codeOnlyReason: {
    not_git: "Not a Git repository: the files are scanned as they are.",
    no_github_remote: "No GitHub remote: the files are scanned as they are.",
    git_unsupported: "Git data is not used for this folder: the files are scanned as they are.",
  },
  useFolder: "Use this folder",
  using: "Opening…",
  back: "Back",
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
    "This is a code-only scan of the files on this computer. PGARD did not prove that you may scan this code, so Git history, local web checks and saved results are off.",
  badgeReason: (reason) =>
    ({
      no_github_remote:
        "This folder has no GitHub remote, so owner approval cannot be checked (it is proven through GitHub only).",
      not_a_git_repository:
        "This folder is not a Git repository, so there is no repository to authorize.",
      no_approval: "The authorization gate did not allow a full scan of this repository.",
    })[reason] ?? "Authorization was not checked for this scan.",
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
  moreExportNote: "Every page of the report carries the “not authorized: code-only scan” banner.",
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
  folderHint: "프로젝트 폴더를 선택하거나 경로를 붙여 넣으세요.",
  chooseFolder: "폴더 선택",
  dialogOpen: "폴더 선택 창을 기다리는 중…",
  dialogUnavailable:
    "이 컴퓨터에는 PGARD가 열 수 있는 폴더 선택 창이 없습니다. 아래에 폴더 경로를 붙여 넣으세요.",
  dialogTimeout: "5분이 지나 폴더 선택 창이 닫혔습니다. 다시 선택하세요.",
  dialogCancelled: "폴더를 선택하지 않았습니다.",
  pasteLabel: "또는 폴더 경로 붙여 넣기",
  pastePlaceholder: "~/code/my-app",
  pasteSubmit: "확인",
  checking: "확인 중…",
  requestFailed: "요청이 실패했습니다. 다시 시도하세요.",
  refusals: {
    bad_path: {
      reason: "폴더 경로가 아닙니다.",
      fix: "전체 경로를 붙여 넣으세요. 예: ~/code/my-app 또는 /Users/you/code/my-app",
    },
    missing: { reason: "이 폴더가 없습니다.", fix: "경로를 확인하거나 폴더 선택을 사용하세요." },
    not_a_directory: { reason: "폴더가 아니라 파일입니다.", fix: "프로젝트 폴더를 선택하세요." },
    too_broad: {
      reason: "홈 폴더나 시스템 폴더이며 프로젝트 폴더가 아닙니다.",
      fix: "프로젝트 자체의 폴더를 선택하세요. 예: ~/code/my-app",
    },
    too_deep: {
      reason: "폴더가 너무 깊이 있어 확인할 수 없습니다.",
      fix: "홈 폴더에 더 가까운 폴더를 선택하세요.",
    },
    unreadable: {
      reason: "제시간에 이 폴더를 읽지 못했습니다.",
      fix: "다시 시도하세요. 느리거나 연결이 끊긴 네트워크 폴더가 원인일 수 있습니다.",
    },
    not_owned_by_you: {
      reason: "이 폴더나 상위 폴더의 소유자가 다른 사용자입니다.",
      fix: "프로젝트를 내 폴더로 복사하세요.",
    },
    group_or_world_writable: {
      reason: "다른 사용자가 이 폴더나 상위 폴더를 바꿀 수 있습니다.",
      fix: "그룹·기타 사용자의 쓰기 권한을 없애거나(chmod go-w) 프로젝트를 내 폴더로 복사하세요.",
    },
  },
  candidateConfirm: "이 폴더를 검사할까요?",
  githubRepo: (repo) => `GitHub 저장소 ${repo}`,
  codeOnlyReason: {
    not_git: "Git 저장소가 아닙니다. 파일을 있는 그대로 검사합니다.",
    no_github_remote: "GitHub 원격 저장소가 없습니다. 파일을 있는 그대로 검사합니다.",
    git_unsupported: "이 폴더에서는 Git 데이터를 쓰지 않습니다. 파일을 있는 그대로 검사합니다.",
  },
  useFolder: "이 폴더 사용",
  using: "여는 중…",
  back: "뒤로",
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
    "이 결과는 이 컴퓨터에 있는 파일만 검사한 코드 전용 검사입니다. 이 코드를 검사해도 된다는 권한을 PGARD가 확인하지 않았으므로 Git 기록, 로컬 웹 검사, 결과 저장은 꺼져 있습니다.",
  badgeReason: (reason) =>
    ({
      no_github_remote:
        "이 폴더에는 GitHub remote가 없어 소유자 승인을 확인할 수 없습니다(승인은 GitHub로만 확인합니다).",
      not_a_git_repository: "이 폴더는 Git 저장소가 아니어서 권한을 확인할 저장소가 없습니다.",
      no_approval: "권한 확인에서 이 저장소의 전체 검사가 허용되지 않았습니다.",
    })[reason] ?? "이 검사에서는 권한을 확인하지 않았습니다.",
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
  moreExportNote: "보고서의 모든 페이지에 “권한 미확인: 코드 전용 검사” 배너가 들어갑니다.",
  moreFull: "전체 대시보드",
  moreFullNote: "GitHub 로그인, Git 기록, 웹 검사가 있는 현재 대시보드입니다.",
  moreNeedsScan: "먼저 검사를 실행하세요.",
  backToSimple: "간단한 화면으로 돌아가기",
};

export function simpleText(language: Language): SimpleText {
  return language === "ko" ? ko : en;
}
