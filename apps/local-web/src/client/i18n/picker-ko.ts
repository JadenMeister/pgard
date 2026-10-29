import type { PickerMessages } from "./picker-en";

const HINT = "경로가 아니라 폴더 이름만 입력하거나 놓아 주세요.";

/** Korean texts of the project picker; same keys as `picker-en.ts` (checked by the type). */
export const pickerKo: PickerMessages = {
  title: "프로젝트 선택",
  lead: "프로젝트 폴더를 페이지에 놓거나 이름을 입력하세요. PGARD가 터미널에서 허용한 폴더 안에서 찾아 실제 경로와 GitHub 원격 저장소를 보여 주고 확인을 요청합니다. 아직 아무것도 검사하지 않습니다.",
  dropTitle: "프로젝트 폴더를 여기에 놓으세요",
  dropHint: "폴더 이름만 사용하며 아무것도 업로드하지 않습니다.",
  dropActive: "놓으면 이 폴더를 찾습니다",
  dropLabel: "프로젝트 폴더를 놓는 영역",
  searchLabel: "또는 폴더 이름을 입력하세요",
  searchPlaceholder: "예: shop",
  searchButton: "검색",
  cancelSearch: "검색 취소",
  searching: (visited: number): string =>
    visited === 0 ? "검색 중..." : `검색 중... 항목 ${visited}개 확인`,
  nameProblem: "폴더 이름이 아닙니다:",
  nameHint: HINT,
  nameReasons: {
    empty: "비어 있습니다.",
    too_short: "2자 이상이어야 합니다.",
    too_long: "255자를 넘습니다.",
    slash: "`/` 또는 `\\`가 들어 있습니다.",
    control: "제어 문자나 방향을 바꾸는 문자가 들어 있습니다.",
    dot: "`.`와 `..`는 폴더 이름이 아닙니다.",
    malformed: "올바른 텍스트가 아닙니다.",
    not_text: "텍스트여야 합니다.",
  },
  nameExample: "경로가 아니라 폴더 이름만, 예를 들어 `shop`처럼 입력하세요.",
  droppedFile: "파일이 아니라 폴더를 놓아 주세요.",
  droppedFileFix: "프로젝트 폴더를 놓으세요.",
  droppedNothing: "폴더로 보이는 항목이 놓이지 않았습니다.",
  noMatch: (name: string): string =>
    `검색 폴더 안에서 "${name}"라는 이름의 Git 저장소를 찾지 못했습니다.`,
  noMatchFix: "이름을 확인하거나, 터미널에서 상위 폴더를 추가하세요:",
  searchedRoots: "검색 폴더",
  rootToggle: (label: string): string => `이번 세션에서 ${label} 검색`,
  noRoots: "켜진 검색 폴더가 없습니다. 위에서 하나를 켜거나 터미널에서 폴더를 추가하세요.",
  copy: "복사",
  copied: "복사됨",
  partial: (seconds: number | null, by: "time" | "entries" | "candidates" | null): string => {
    if (by === "candidates") return "일치 항목이 20개 한도에 도달해 검색을 멈췄습니다.";
    if (by === "entries") return "크기 한도에 도달해 검색을 멈췄습니다.";
    return `${seconds === null ? "시간 제한" : `${seconds}초`} 후 검색을 멈췄습니다.`;
  },
  partialFix:
    "이름을 더 길게 입력하거나, 터미널에서 검색 폴더를 줄이세요(`pgard web scope remove <folder>`).",
  uninspectedNote: (count: number): string =>
    `폴더 ${count}개를 찾았지만 제때 확인하지 못해 '확인 안 됨'으로 표시했습니다.`,
  several: "일치하는 폴더가 여러 개입니다. 이름이 아니라 경로와 태그를 보고 고르세요.",
  results: "일치 항목",
  choose: "선택",
  collisionTag: (tag: string): string => `태그 ${tag}`,
  sourceScope: "검색 폴더",
  sourceRecent: "최근",
  remoteLabel: "GitHub 저장소",
  noRemote: "github.com 원격 저장소 없음",
  pathLabel: "실제 경로",
  escapedPathLabel: "인쇄할 수 없는 문자를 이스케이프한 경로",
  blockedTitle: "선택할 수 없음",
  whyLabel: "이유",
  fixLabel: "해결 방법",
  failingPaths: "바꿔야 할 폴더와 파일",
  confirmTitle: "올바른 프로젝트인지 확인하세요",
  confirmPath: "PGARD가 읽을 폴더가 바로 이 폴더입니다.",
  confirmRemote: (repo: string): string => `원격 저장소는 github.com/${repo}여야 합니다.`,
  confirmNext:
    "다음으로 PGARD가 이 프로젝트를 검사할 권한이 있는지 확인합니다. 아직 아무것도 검사하거나 전송하지 않습니다.",
  confirmButton: "이 프로젝트 확인",
  confirming: "폴더를 다시 확인하는 중...",
  back: "뒤로",
  recentTitle: "최근 프로젝트",
  recentEmpty: "아직 최근 프로젝트가 없습니다.",
  recentValidating: "최근 프로젝트를 확인하는 중...",
  recentIgnored:
    "최근 목록을 읽을 수 없어(손상되었거나 더 새로운 PGARD가 만든 파일) 무시합니다. PGARD 데이터 폴더의 web/recent-projects.json을 삭제하거나 그냥 두세요.",
  recentRemove: "최근 목록에서 제거",
  recentRemoveLabel: (name: string): string => `최근 프로젝트에서 ${name} 제거`,
  recentOffNote: "이번 세션에서는 최근 목록이 꺼져 있습니다(--no-store).",
  blocked: {
    not_a_git_root: {
      reason: "이 폴더는 Git 저장소가 아니거나 저장소의 최상위 폴더가 아닙니다.",
      fix: "저장소의 최상위 폴더를 고르세요.",
    },
    no_commit_history: {
      reason: "저장소에 커밋이 없습니다.",
      fix: "첫 커밋을 만든 뒤 다시 검색하세요.",
    },
    isolation_failed: {
      reason: "저장소가 alternates, grafts 또는 replace ref를 사용해 기록이 독립적이지 않습니다.",
      fix: "일반 클론을 사용하세요.",
    },
    no_remote: {
      reason: "github.com을 가리키는 원격 저장소가 없습니다.",
      fix: "`git remote -v`를 실행해 github.com 원격 저장소 하나를 설정한 뒤 다시 검색하세요.",
    },
    remote_not_github: {
      reason: "이 저장소의 원격 저장소 중 github.com이 아닌 것이 있습니다.",
      fix: "PGARD는 권한이 있는 github.com 저장소만 검사합니다.",
    },
    remote_ambiguous: {
      reason: "원격 저장소가 서로 다른 저장소를 가리키거나 URL을 바꿔 쓰고 있습니다.",
      fix: "`git remote -v`를 실행해 github.com 저장소 하나만 남긴 뒤 다시 검색하세요.",
    },
    remote_unreadable: {
      reason: "이 저장소의 원격 저장소를 읽을 수 없습니다.",
      fix: "폴더에서 `git remote -v`를 실행해 나오는 문제를 고친 뒤 다시 검색하세요.",
    },
    not_owned_by_you: {
      reason: "이 폴더 또는 상위 폴더가 다른 사용자의 것입니다.",
      fix: "본인 폴더에 새로 클론하세요.",
    },
    group_or_world_writable: {
      reason: "이 폴더, 상위 폴더 또는 .git을 다른 사용자가 바꿀 수 있습니다.",
      fix: "아래 명령 하나를 실행하세요. 바꿔야 하는 모든 폴더와 파일이 나열되어 있습니다. 사용자마다 비공개 그룹을 두는 시스템에서는 폴더 여러 개가 기본으로 그룹 쓰기 가능이라 여러 개가 나올 수 있습니다. PGARD는 비공개 그룹과 공유 그룹을 구분할 수 없어 그래도 차단합니다.",
    },
    gitfile_unsupported: {
      reason:
        "이 프로젝트는 linked worktree, 서브모듈 또는 .git 포인터 파일을 사용합니다. 아직 지원하지 않습니다.",
      fix: "저장소의 메인 클론을 대신 여세요.",
    },
    git_dir_unsupported: {
      reason: "이 저장소는 Git 데이터를 프로젝트 폴더 밖에 둡니다.",
      fix: "일반 클론을 사용하세요.",
    },
    outside_scope: {
      reason: "이 최근 프로젝트는 현재 검색 폴더 밖에 있습니다.",
      fix: "터미널에서 그 폴더를 추가하거나 최근 목록에서 제거하세요.",
    },
    unsafe_display: {
      reason: "경로에 안전하게 표시할 수 없는 문자가 들어 있습니다.",
      fix: "폴더 이름을 바꾸거나 다른 폴더를 고르세요.",
    },
    not_inspected: {
      reason: "이 폴더를 확인하기 전에 검색 시간이 끝났습니다.",
      fix: "이름을 더 길게 입력하거나 터미널에서 검색 폴더를 줄이세요.",
    },
    unreadable: {
      reason: "이 폴더를 제때 읽지 못했습니다.",
      fix: "폴더를 읽을 수 있는지, 느리거나 연결이 끊긴 드라이브가 아닌지 확인한 뒤 다시 검색하세요.",
    },
  },
  errors: {
    bad_name: HINT,
    bad_source: "검색을 시작할 수 없습니다. 페이지를 새로고침하세요.",
    search_too_soon: "검색은 1초에 한 번만 할 수 있습니다.",
    inspector_busy:
      "이전 검색이 운영체제에서 아직 멈춰 있습니다(느리거나 연결이 끊긴 네트워크 폴더가 흔한 원인). 잠시 기다리거나 `pgard web scope remove <folder>`로 그 폴더를 검색 폴더에서 제거하세요.",
    candidate_changed:
      "폴더를 확인한 뒤 내용이 바뀌었습니다. 아무것도 선택하지 않았습니다. 다시 검색하세요.",
    candidate_expired: "확인 시간이 지났습니다. 아무것도 선택하지 않았습니다. 다시 검색하세요.",
    candidate_blocked: "이 폴더는 선택할 수 없습니다.",
    unknown_candidate: "그 폴더 정보가 더 이상 없습니다. 다시 검색하세요.",
    unknown_search: "그 검색 정보가 더 이상 없습니다. 다시 검색하세요.",
    project_changed: "실행 중에 프로젝트가 바뀌어 결과를 버렸습니다. 작업을 다시 실행하세요.",
    scan_running: "검사가 실행 중입니다. 먼저 취소한 뒤 프로젝트를 바꾸세요.",
    auth_running: "권한 확인이 실행 중입니다. 먼저 확인을 취소한 뒤 프로젝트를 바꾸세요.",
    unreadable: "폴더를 제때 읽지 못했습니다. 아무것도 시작하지 않았습니다. 다시 시도하세요.",
    no_project: "먼저 프로젝트를 선택하세요.",
    fixed_project:
      "이 대시보드는 프로젝트 하나로 시작했습니다. 다른 프로젝트를 고르려면 `pgard web`을 시작하세요.",
    generic: "요청에 실패했습니다. 다시 시도하세요.",
  },
  project: {
    label: "프로젝트",
    change: "프로젝트 변경",
    changeBlockedScan: "검사가 실행 중입니다. 먼저 취소하세요.",
    changeBlockedAuth: "확인이 실행 중입니다. 먼저 확인을 취소하세요.",
    cancelCheck: "확인 취소",
    cancelCheckHint: "실행 중인 확인을 멈춥니다. GitHub 로그인 대기도 멈춥니다.",
    stale: "다른 창에서 프로젝트가 바뀌었습니다. 이 화면은 최신 상태가 아닙니다.",
    reload: "상태 다시 불러오기",
  },
};
