import type { Messages } from "./types";

/** Korean catalog. Terminology follows README.ko.md (권한 확인, 발견 항목, 미검사, 차단 ...). */
export const ko: Messages = {
  language: {
    label: "언어",
    ko: "한국어",
    en: "English",
  },
  common: {
    requestFailed: "요청에 실패했습니다.",
    none: "(없음)",
    unknown: "알 수 없음",
    all: "전체",
  },
  app: {
    subtitle: (version) => `로컬 보안 대시보드${version === null ? "" : ` - v${version}`}`,
    footer: "127.0.0.1에서만 실행됩니다. 대시보드를 종료하면 결과와 로그인이 버려집니다.",
    errorNoToken:
      "이 페이지는 `pgard dashboard`가 출력한 개인 세션 URL이 필요합니다. 그 URL을 다시 여세요.",
    errorSession: "대시보드 세션을 사용할 수 없습니다. `pgard dashboard`를 다시 시작하세요.",
  },
  cards: {
    legal: "시작하기 전에",
    authorization: "권한 확인",
    target: "로컬 웹 서비스 (선택)",
    scan: "검사",
    results: "결과",
    report: "보고서 내보내기",
  },
  legal: {
    points: [
      "검사 데이터는 이 컴퓨터에서 한 번만 처리됩니다. PGARD는 소스 코드나 결과를 어떤 서버로도 업로드하지 않습니다.",
      "외부 네트워크 통신은 GitHub로만 나갑니다. github.com의 device flow 로그인(저장된 로그인 갱신 포함)과, 권한 확인에 필요한 정보(사용자 신원, App 설치, 접근 권한, 기여)를 읽는 GitHub API 호출입니다. 기여를 확인하기 위해 PGARD는 로컬 커밋의 SHA를 GitHub로 보냅니다. pgard doctor 명령도 api.github.com에 접근할 수 있는지 확인합니다.",
      "권한 확인을 통과하면 PGARD는 탐지된 각 수신 포트(127.0.0.1)에 GET / 요청을 한 번씩 보내 서비스 정체를 보여 줍니다.",
      "PGARD는 취약점 데이터베이스를 포함하거나 조회하지 않습니다. 발견 항목은 코드 자체(쿼리문, 서버 코드, 설정), Git 이력, 그리고 선택한 경우 로컬 HTTP 검사에서 나옵니다. 의존성 버전은 알려진 취약점과 대조하지 않습니다.",
      "GitHub 로그인은 OS 키체인(macOS 키체인, Windows 자격 증명 관리자, Linux Secret Service)에 저장되며 파일에는 저장하지 않으므로 CLI와 대시보드가 다시 사용할 수 있습니다. 로그인은 로컬 PGARD 프로세스 안에만 있고 브라우저로 보내지 않습니다. 키체인이 없으면 메모리에만 보관합니다. 삭제하려면 pgard logout을 쓰거나, 대시보드에서 키체인의 로그인까지 지우는 로그아웃을 사용하세요.",
      "결과와 대시보드 세션 토큰은 메모리에만 있으며 대시보드를 종료하면 버려집니다. 내보낸 보고서만 남으므로 보관과 공유는 사용자 책임입니다.",
      "웹 검사는 사용자가 확인한 로컬 서비스에 익명 GET 요청을 보냅니다. 잘못 구현된 애플리케이션은 GET으로도 상태가 바뀔 수 있으며, PGARD는 검사에 부작용이 없다고 보장하지 않습니다.",
      "검사할 권한이 있는 프로젝트만 검사하세요. 권한 확인은 매 검사 전에 실행되며 건너뛸 수 없습니다.",
    ],
    accept: "이해했습니다",
  },
  auth: {
    projectLabel: "프로젝트",
    intro: "PGARD는 매 검사 전에 owner 승인, 현재 접근 권한, merge된 기여를 확인합니다.",
    checks: {
      repository: "저장소",
      github_identity: "GitHub 신원",
      owner_approval: "owner 승인",
      current_access: "현재 접근 권한",
      contribution: "merge된 기여",
    },
    columns: { check: "항목", status: "상태", reason: "이유" },
    checking: "확인하는 중...",
    allowed: "허용",
    blocked: "차단 - 분석이 실행되지 않습니다",
    notStored: "이 결과는 저장되지 않으며, 검사할 때마다 다시 확인합니다.",
    expiresAt: (time) =>
      `로컬 서비스 탐색과 probe는 ${time}까지 열려 있습니다. 그 이후에는 다시 확인하세요.`,
    verify: "프로젝트 확인",
    recheck: "다시 확인",
    signOut: {
      sessionOnlyLabel: "대시보드 세션 종료 (키체인 로그인 유지)",
      removeStoredLabel: "로그아웃하고 OS 키체인에서 삭제",
      sessionOnlyHint:
        "이 대시보드의 GitHub 세션만 끊습니다. OS 키체인에 저장된 로그인은 그대로 남으며, 다음 확인 때 코드 없이 다시 사용합니다.",
      removeStoredHint:
        "OS 키체인에 저장된 로그인도 삭제하며 CLI에서도 지워집니다. 다음 확인 때 새 device 코드를 요구합니다.",
    },
    githubAppEnv: (clientId) =>
      `GitHub App: PGARD_GITHUB_APP_CLIENT_ID의 ${clientId} (내장 PGARD App 재정의).`,
    githubAppInvalid: (message) =>
      `${message} 그때까지 GitHub 신원은 확인 불가이며 모든 검사가 차단됩니다.`,
    storedSignIn: (login) =>
      `GitHub 로그인: ${login}, OS 키체인에 저장되어 확인할 때마다 다시 사용됩니다. 토큰은 이 컴퓨터에만 있으며 브라우저로 보내지 않습니다.`,
    noSignIn:
      "GitHub 로그인: 저장된 것이 없습니다. 다음 확인 때 device 코드를 요구하고 로그인을 OS 키체인에 저장합니다.",
    keychainUnavailable: (reason) =>
      `GitHub 로그인: OS 키체인을 사용할 수 없어(${reason}) 대시보드가 끝날 때까지 로그인을 메모리에만 보관합니다.`,
  },
  status: {
    passed: "통과",
    failed: "실패",
    unverifiable: "확인 불가",
    completed: "완료",
    partial: "부분 완료",
    not_tested: "미검사",
    not_selected: "선택 안 함",
    blocked: "차단",
    confirmed: "확인됨",
    suspected: "의심",
    informational: "참고",
    unknownStatus: "알 수 없음",
  },
  install: {
    button: "PGARD GitHub App 설치",
    waiting:
      "PGARD GitHub App 설치를 기다리는 중입니다... PGARD가 5초마다 확인하고, 설치되면 권한 확인 전체를 다시 실행합니다.",
    timedOut: "10분이 지나 PGARD GitHub App 설치 대기를 중단했습니다. 설치한 뒤 다시 확인하세요.",
    noLink: "사용할 수 있는 설치 링크가 없습니다.",
    askOwner: (account) => `${account}의 owner에게 PGARD GitHub App 설치를 요청하세요:`,
    maybeOwner: (account, url) =>
      `${account}의 owner라면 설치 페이지에서 App을 설치하세요. 아니라면 owner에게 설치를 요청하세요: ${url}`,
    owner: (account) =>
      `owner 승인: ${account}에 PGARD GitHub App을 설치하세요. GitHub에서 "Only select repositories"(이 저장소) 또는 "All repositories"를 고른 뒤 Install을 누르세요. App 설치가 곧 owner 승인이며, PGARD가 대신 설치할 수는 없습니다.`,
  },
  deviceCode: {
    required: "GitHub 로그인이 필요합니다. 다음 주소를 열고",
    enterCode: "이 코드를 입력하세요:",
    openButton: "GitHub 로그인 페이지 열기",
    expiry: (minutes) => `약 ${minutes}분 후 만료됩니다.`,
  },
  target: {
    confirmedTarget: "확인한 대상:",
    chooseAnother: "다른 서비스 선택",
    intro:
      "127.0.0.1에서 실행 중인 이 프로젝트의 서비스를 고르세요. 목록이 불완전할 수 있으므로 포트를 직접 입력해도 됩니다. 포트 번호만으로는 어느 프로젝트의 서비스인지 알 수 없습니다.",
    noServices: (note) => `발견된 로컬 HTTP 서비스가 없습니다${note === null ? "" : ` (${note})`}.`,
    otherPort: "다른 포트",
    check: "확인",
    refresh: "목록 새로고침",
    identityLabel: "서비스 정체",
    url: "URL",
    status: "상태",
    noHttp: (error) => `HTTP 응답 없음 (${error})`,
    title: "제목",
    technology: "기술 (추정, 검증되지 않음)",
    redirect: "/ 가 PGARD가 따라가지 않는 위치로 리다이렉트됩니다.",
    question: "이 서비스가 현재 프로젝트의 서비스입니까?",
    yes: "예, 이 프로젝트의 서비스입니다",
    no: "아니요",
    notHttp: "이 포트는 HTTP로 응답하지 않았습니다. 다른 포트를 고르세요.",
    access: {
      expired:
        "포트 접근이 만료되었습니다. PGARD는 권한 확인을 통과한 뒤 30분 동안만 로컬 서비스에 접근합니다. 위의 다시 확인을 눌러 계속하세요.",
      running:
        "권한 확인을 기다리는 중입니다. PGARD는 확인을 통과하기 전에는 로컬 서비스에 접근하지 않습니다.",
      blocked:
        "권한 확인이 차단되어 PGARD가 로컬 서비스를 탐색하거나 probe하지 않습니다. 위의 이유를 확인하세요.",
      failed:
        "권한 확인이 끝나지 않아 PGARD가 로컬 서비스에 접근하지 않습니다. 위에서 다시 확인하세요.",
      idle: "먼저 위에서 프로젝트를 확인하세요. PGARD는 권한 확인을 통과한 뒤에만 로컬 서비스를 탐색하고 probe합니다.",
    },
  },
  scan: {
    scope: "범위",
    scopes: {
      code: { label: "코드", hint: "현재 코드와 설정" },
      history: { label: "Git 이력", hint: "추적 파일과 과거 커밋 (비밀정보, 위험한 파일)" },
      web: { label: "로컬 웹 서비스", hint: "확인한 대상에 대한 익명 GET 검사" },
    },
    noWebTarget:
      "확인한 웹 대상이 없습니다. 웹 범위는 미검사로 기록되고 검사 결과는 부분 완료가 됩니다.",
    run: "검사 실행",
    cancel: "취소",
  },
  coverage: {
    caption: "검사 범위",
    area: "영역",
    status: "상태",
    note: "비고",
  },
  severity: {
    critical: "치명적",
    high: "높음",
    medium: "보통",
    low: "낮음",
    info: "정보",
  },
  severityInline: {
    critical: "치명적",
    high: "높음",
    medium: "보통",
    low: "낮음",
    info: "정보",
  },
  confidence: {
    low: "낮음",
    medium: "보통",
    high: "높음",
  },
  findings: {
    overall: {
      completed: "완료",
      partial: "부분 완료 - 요청한 영역 일부가 끝까지 실행되지 않았습니다",
      blocked: "권한 확인에서 차단됨 - 분석이 실행되지 않았습니다",
      failed: "실패 - 내부 오류로 검사가 중단되었습니다",
      unknown: "알 수 없음",
    },
    blockedNote: "위의 권한 확인 이유를 확인하세요.",
    headline: (overall, total, confirmed, suspected, informational, contextNote) =>
      `${overall} - 발견 항목 ${total}건: 확인됨 ${confirmed}, 의심 ${suspected}, 참고 ${informational}${contextNote === "" ? "" : ` - ${contextNote}`}`,
    filters: "필터",
    statusOptions: {
      confirmed: "확인됨",
      suspected: "의심",
      informational: "참고",
    },
    severity: "심각도",
    status: "상태",
    source: "출처",
    search: "검색",
    sources: { code: "코드", history: "이력", web: "웹" },
    confidence: (value) => `신뢰도 ${value}`,
    evidence: "근거 (가려짐)",
    impact: "영향",
    recommendation: "권장 조치",
    noMatch: "필터에 맞는 발견 항목이 없습니다.",
    noFindings: (outside) =>
      `실행된 영역에서${outside} 발견 항목이 없습니다. 프로젝트가 안전하다는 뜻은 아니므로 coverage를 확인하세요.`,
    outsideTestAndVendored: " 테스트·fixture·vendored 코드를 제외하고",
    outsideTest: " 테스트·fixture 코드를 제외하고",
    outsideVendored: " vendored 코드를 제외하고",
    testTitle: (count) => `테스트·fixture 코드 (${count})`,
    testAria: "테스트·fixture 코드의 발견 항목",
    testNote:
      "경로만으로 테스트·fixture 코드로 분류된 파일의 항목이며 신뢰도는 최대 낮음으로 제한됩니다. 위 개수에는 포함되지 않지만 검토하세요. 테스트에 커밋된 실제 값도 노출된 것입니다.",
    vendoredTitle: (count) => `제안: 서드파티/vendored 코드 (${count})`,
    vendoredAria: "서드파티·vendored 코드의 제안",
    vendoredIntro:
      "이 코드는 커밋된 의존성 코드이며 사용자의 코드가 아닙니다. 예상치 못한 것이면 검토하고, 아니면 Git에서 제거를 고려하세요 (",
    vendoredThen: ", 그다음 해당 디렉터리를 ",
    vendoredEnd: "에 추가).",
    vendoredNote:
      "경로로만 분류합니다. node_modules/, bower_components/, jspm_packages/, Pods/ 디렉터리 아래의 파일, 또는 src/, app/, lib/ 안에 있지 않은 vendor/, third_party/ 디렉터리 아래의 파일입니다. 신뢰도는 최대 낮음으로 제한되고 위 개수에는 포함되지 않지만 버리지는 않습니다. 거기에 커밋된 실제 비밀정보도 노출된 것입니다.",
    contextTest: (count) => `테스트·fixture 코드 ${count}건`,
    vendoredSuggestions: (count, severe) =>
      `vendored 코드의 제안 ${count}건${severe === "" ? "" : ` (${severe})`}`,
    plus: (parts) => `그 외 ${parts}`,
    noDatabase:
      "PGARD는 취약점 데이터베이스를 포함하거나 조회하지 않습니다. 발견 항목은 코드 자체(쿼리문, 서버 코드, 설정), Git 이력, 그리고 선택한 경우 로컬 HTTP 검사에서 나옵니다. 의존성 버전은 알려진 취약점과 대조하지 않습니다.",
    location: {
      unknownUrl: "(알 수 없는 URL)",
      unknownCommit: "알 수 없는 커밋",
      commit: (sha) => `커밋 ${sha}`,
      unknownLocation: "(알 수 없는 위치)",
    },
  },
  charts: {
    barAria: (summary) => `심각도별 발견 항목: ${summary}`,
    barTitle: (severity, count) => `${severity}: 발견 항목 ${count}건`,
    donutAria: (total) => `발견 항목 총 ${total}건`,
    donutTitle: (severity, count, total) => `${severity}: ${total}건 중 ${count}건`,
    donutSingleTitle: (severity, total) => `${severity}: ${total}`,
    findings: "발견 항목",
  },
  report: {
    downloadHtml: "HTML 다운로드",
    downloadPdf: "PDF 다운로드",
    preparing: (format) => `${format} 보고서를 준비하는 중...`,
    downloaded: (filename) =>
      `${filename}을(를) 다운로드했습니다. 브라우저의 다운로드 폴더에 저장됩니다.`,
    failed: "보고서를 다운로드하지 못했습니다. 검사를 다시 실행한 뒤 재시도하세요.",
    sessionExpired:
      "대시보드 세션이 더 이상 유효하지 않습니다. `pgard dashboard`가 출력한 개인 세션 URL을 다시 여세요.",
    noResult: "내보낼 검사 결과가 아직 없습니다. 먼저 검사를 실행하세요.",
    note: "보고서에는 민감한 취약점 내용이 포함될 수 있습니다. 다운로드한 파일은 안전한 곳에 보관하세요.",
  },
};
