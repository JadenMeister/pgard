import type { GateReason } from "../../../shared/api-types";
import type { FolderRefusalCode, PickerCandidate } from "../../../shared/picker-types";
import type { Language } from "../../i18n/types";

/**
 * The texts of the simple screen of `pgard web` (#414), in English and Korean: short and plain
 * (docs/CODE_ONLY_SCAN_DESIGN.md, section "Web UX").
 */
export interface SimpleText {
  title: string;
  lead: string;
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
  /** The chosen folder was inside a repository: the repository's top folder is scanned. */
  insideRepository: string;
  change: string;
  scanTitle: string;
  scanWhat: string;
  scanButton: string;
  rescanButton: string;
  /** The primary button after a code-only result: it runs the gate again. */
  recheckApprovalButton: string;
  /** Shown with the gate's reason when it replaced an earlier code-only result. */
  previousHidden: string;
  scanning: (seconds: number) => string;
  /** While the authorization gate runs (before any file is read). */
  checkingApproval: (seconds: number) => string;
  /** A sign-in started with "Sign in and check approval" waits for the user. */
  deviceCode: (code: string) => string;
  openSignIn: string;
  /** Why the gate did not pass: one plain line. */
  gateReasons: Record<GateReason, string>;
  codeOnlyButton: string;
  howToApprove: string;
  signInLink: string;
  approveSteps: string;
  approveNeedsRepo: string;
  approveInstall: string;
  approveFull: string;
  authorizedLabel: string;
  cancel: string;
  cancelled: string;
  failed: string;
  resultsTitle: string;
  noFindings: string;
  findingsCount: (count: number) => string;
  extraNote: string;
  partialNote: string;
  badge: string;
  /** One line: what a code-only result is. */
  badgeTitle: string;
  /** Why authorization was not verified (`scanBasis.reason`, JSON 1.7). */
  badgeReason: (reason: string) => string;
  connect: string;
  /** This screen's footer. */
  footer: string;
  moreTitle: string;
  moreLead: string;
  moreCoverage: string;
  moreStandards: string;
  moreRules: string;
  moreExport: string;
  moreExportNote: string;
  moreFull: string;
  moreFullNote: string;
  moreNeedsScan: string;
}

const en: SimpleText = {
  title: "Scan a project folder",
  lead: "Find leaked secrets, risky code and vulnerable dependencies in a folder on this computer.",
  folderTitle: "Folder",
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
    git_directory: {
      reason: "This is Git's own data folder (.git), not the project's files.",
      fix: "Choose the project's folder, the one that contains .git.",
    },
  },
  candidateConfirm: "Scan this folder?",
  githubRepo: (repo) => `GitHub repository ${repo}`,
  codeOnlyReason: {
    not_git: "Not a Git repository: only a code-only scan is possible.",
    no_github_remote: "No GitHub remote: only a code-only scan is possible.",
    git_unsupported: "Its Git data cannot be checked: only a code-only scan is possible.",
  },
  useFolder: "Use this folder",
  using: "Opening…",
  back: "Back",
  insideRepository:
    "This folder is inside a repository, so the whole repository (above) is checked and scanned.",
  change: "Change",
  scanTitle: "Scan",
  scanWhat:
    "PGARD checks your GitHub approval first, then the current files. Your files never leave this computer.",
  scanButton: "Scan",
  rescanButton: "Scan again",
  recheckApprovalButton: "Check approval again",
  previousHidden: "The earlier code-only findings are hidden. Scan code only to see them again.",
  scanning: (seconds) => `Scanning the files… ${seconds} s`,
  checkingApproval: (seconds) => `Checking approval, then scanning… ${seconds} s`,
  deviceCode: (code) => `To sign in, enter ${code} on GitHub.`,
  openSignIn: "Open GitHub sign-in",
  gateReasons: {
    no_approval: "No GitHub App approval for this folder.",
    not_signed_in: "Not signed in to GitHub, so approval was not checked.",
    no_github_remote: "This folder has no GitHub remote.",
    not_a_git_repository: "This folder is not a Git repository.",
    check_failed: "Approval could not be checked (network or GitHub problem).",
  },
  codeOnlyButton: "Scan code only (not authorized)",
  howToApprove: "How to approve",
  signInLink: "Sign in and check approval",
  approveSteps:
    "The repository owner installs the PGARD GitHub App and includes this repository. Then press Check approval again.",
  approveNeedsRepo:
    "Approval works only for a GitHub repository. Push this folder to GitHub, then install the PGARD GitHub App for it.",
  approveInstall: "Open the install page on GitHub",
  approveFull: "Step-by-step help in the full dashboard",
  authorizedLabel: "Authorized scan",
  cancel: "Cancel",
  cancelled: "The scan was cancelled.",
  failed: "The scan stopped because of an internal error. Try again.",
  resultsTitle: "Findings",
  noFindings: "No findings in the checked files.",
  findingsCount: (count) => (count === 1 ? "1 finding" : `${count} findings`),
  extraNote:
    "Findings in test, fixture and vendored code are listed under More › What was checked.",
  partialNote:
    "Some areas could not be checked (for example, no vulnerability data has been downloaded yet). See More › What was checked.",
  badge: "Not authorized · code only",
  badgeTitle: "Only the code was scanned (no Git history, not saved)",
  badgeReason: (reason) =>
    ({
      no_github_remote: "This folder has no GitHub remote.",
      not_a_git_repository: "This folder is not a Git repository.",
      no_approval: "There is no GitHub App approval for this folder.",
      check_failed: "Approval could not be checked.",
    })[reason] ?? "Authorization was not checked for this scan.",
  connect: "Connect GitHub to also scan Git history",
  footer: "Runs on 127.0.0.1 only · results are not saved and are gone when you stop pgard web",
  moreTitle: "More",
  moreLead: "Details for the scan above. None of this is needed to fix the findings.",
  moreCoverage: "What was checked",
  moreStandards: "Standards (OWASP, CWE)",
  moreRules: "Rule statistics",
  moreExport: "Export report",
  moreExportNote: "Every page of the report carries the “not authorized: code-only scan” banner.",
  moreFull: "Full dashboard",
  moreFullNote: "Git history, local web checks, trend and saved scans (needs approval).",
  moreNeedsScan: "Run a scan first.",
};

const ko: SimpleText = {
  title: "프로젝트 폴더 검사",
  lead: "이 컴퓨터의 폴더에서 유출된 비밀값, 위험한 코드, 취약한 의존성을 찾습니다.",
  folderTitle: "폴더",
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
    git_directory: {
      reason: "Git의 데이터 폴더(.git)이지 프로젝트 파일이 아닙니다.",
      fix: ".git이 들어 있는 프로젝트 폴더를 고르세요.",
    },
  },
  candidateConfirm: "이 폴더를 검사할까요?",
  githubRepo: (repo) => `GitHub 저장소 ${repo}`,
  codeOnlyReason: {
    not_git: "Git 저장소가 아닙니다. 코드만 검사할 수 있습니다.",
    no_github_remote: "GitHub 원격 저장소가 없습니다. 코드만 검사할 수 있습니다.",
    git_unsupported: "Git 데이터를 확인할 수 없습니다. 코드만 검사할 수 있습니다.",
  },
  useFolder: "이 폴더 사용",
  using: "여는 중…",
  back: "뒤로",
  insideRepository: "이 폴더는 저장소 안에 있어 위의 저장소 전체를 확인하고 검사합니다.",
  change: "변경",
  scanTitle: "검사",
  scanWhat:
    "GitHub 승인을 먼저 확인한 뒤 현재 파일을 검사합니다. 파일은 이 컴퓨터 밖으로 나가지 않습니다.",
  scanButton: "검사",
  rescanButton: "다시 검사",
  recheckApprovalButton: "승인 다시 확인",
  previousHidden: "이전 코드만 검사 결과는 숨겨졌습니다. 코드만 검사를 누르면 다시 볼 수 있습니다.",
  scanning: (seconds) => `파일 검사 중… ${seconds}초`,
  checkingApproval: (seconds) => `승인 확인 후 검사 중… ${seconds}초`,
  deviceCode: (code) => `로그인하려면 GitHub에서 ${code}를 입력하세요.`,
  openSignIn: "GitHub 로그인 열기",
  gateReasons: {
    no_approval: "이 폴더에 대한 GitHub App 승인이 없습니다.",
    not_signed_in: "GitHub에 로그인하지 않아 승인을 확인하지 않았습니다.",
    no_github_remote: "이 폴더에는 GitHub 원격 저장소가 없습니다.",
    not_a_git_repository: "이 폴더는 Git 저장소가 아닙니다.",
    check_failed: "승인을 확인하지 못했습니다(네트워크 또는 GitHub 문제).",
  },
  codeOnlyButton: "코드만 검사 (권한 미확인)",
  howToApprove: "승인 방법 보기",
  signInLink: "로그인하고 승인 확인",
  approveSteps:
    "저장소 소유자가 PGARD GitHub App을 설치하고 이 저장소를 포함하면 됩니다. 그다음 승인 다시 확인을 누르세요.",
  approveNeedsRepo:
    "승인은 GitHub 저장소에만 할 수 있습니다. 이 폴더를 GitHub에 올린 뒤 PGARD GitHub App을 설치하세요.",
  approveInstall: "GitHub 설치 페이지 열기",
  approveFull: "전체 대시보드에서 단계별 안내 보기",
  authorizedLabel: "권한 확인된 검사",
  cancel: "취소",
  cancelled: "검사를 취소했습니다.",
  failed: "내부 오류로 검사가 멈췄습니다. 다시 시도하세요.",
  resultsTitle: "찾은 문제",
  noFindings: "검사한 파일에서 찾은 문제가 없습니다.",
  findingsCount: (count) => `${count}건`,
  extraNote: "테스트·픽스처·벤더 코드의 결과는 더 보기 › 검사 범위에 있습니다.",
  partialNote:
    "일부 영역은 검사하지 못했습니다(예: 취약점 데이터를 아직 내려받지 않음). 더 보기 › 검사 범위를 확인하세요.",
  badge: "권한 미확인 · 코드만",
  badgeTitle: "코드만 검사했습니다 (Git 기록·저장 제외)",
  badgeReason: (reason) =>
    ({
      no_github_remote: "이 폴더에는 GitHub 원격 저장소가 없습니다.",
      not_a_git_repository: "이 폴더는 Git 저장소가 아닙니다.",
      no_approval: "이 폴더에 대한 GitHub App 승인이 없습니다.",
      check_failed: "승인을 확인하지 못했습니다.",
    })[reason] ?? "이 검사에서는 권한을 확인하지 않았습니다.",
  connect: "GitHub 연결하고 Git 기록도 검사",
  footer: "127.0.0.1에서만 실행 · 결과는 저장되지 않고, pgard web을 종료하면 사라집니다",
  moreTitle: "더 보기",
  moreLead: "위 검사의 자세한 정보입니다. 문제를 고치는 데 꼭 필요하지는 않습니다.",
  moreCoverage: "검사 범위",
  moreStandards: "표준 (OWASP, CWE)",
  moreRules: "규칙 통계",
  moreExport: "보고서 내보내기",
  moreExportNote: "보고서의 모든 페이지에 “권한 미확인: 코드 전용 검사” 배너가 들어갑니다.",
  moreFull: "전체 대시보드",
  moreFullNote: "Git 기록, 로컬 웹 검사, 추이, 저장된 검사(승인 필요).",
  moreNeedsScan: "먼저 검사를 실행하세요.",
};

export function simpleText(language: Language): SimpleText {
  return language === "ko" ? ko : en;
}
