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
    title: "보안 대시보드",
    lead: "권한을 확인하고 검사할 범위를 고른 뒤 결과를 살펴보세요. 모든 작업은 이 컴퓨터에서만 이루어집니다.",
    skipToContent: "본문으로 건너뛰기",
    footer:
      "127.0.0.1에서만 실행됩니다. 대시보드 검사는 저장되지 않으며, 대시보드를 종료하면 그 결과와 세션이 버려집니다.",
    errorNoToken:
      "이 페이지는 `pgard dashboard`가 출력한 개인 세션 URL이 필요합니다. 그 URL을 다시 여세요.",
    errorSession: "대시보드 세션을 사용할 수 없습니다. `pgard dashboard`를 다시 시작하세요.",
    errorRuleTexts:
      "한국어 규칙 문구를 불러오지 못했습니다. 규칙 제목과 조치 문구는 영어로 표시됩니다. 페이지를 새로고침하여 다시 시도하세요.",
  },
  cards: {
    legal: "시작하기 전에",
    authorization: "권한 확인",
    target: "로컬 웹 서비스 (선택)",
    scan: "검사",
    results: "결과",
    standards: "표준 매핑 현황 (OWASP Top 10 2025)",
    ruleStats: "규칙 통계",
    report: "보고서 내보내기",
  },
  legal: {
    points: [
      "검사 데이터는 이 컴퓨터에서 한 번만 처리됩니다. PGARD는 소스 코드나 결과를 어떤 서버로도 업로드하지 않습니다.",
      "외부 네트워크 통신은 GitHub로만 나갑니다. github.com의 device flow 로그인(저장된 로그인 갱신 포함)과, 권한 확인에 필요한 정보(사용자 신원, App 설치, 접근 권한, 기여)를 읽는 GitHub API 호출입니다. 기여를 확인하기 위해 PGARD는 로컬 커밋의 SHA를 GitHub로 보냅니다. pgard doctor 명령도 api.github.com에 접근할 수 있는지 확인합니다.",
      "권한 확인을 통과하면 PGARD는 탐지된 각 수신 포트(127.0.0.1)에 GET / 요청을 한 번씩 보내 서비스 정체를 보여 줍니다.",
      "PGARD는 취약점 데이터베이스를 포함하지 않으며 스캔은 이를 내려받거나 조회하지 않습니다. 발견 항목은 코드 자체(쿼리문, 서버 코드, 설정), Git 이력, 선택한 경우 로컬 HTTP 검사, 그리고 npm과 Go lockfile에 대해 pgard advisories update로 내려받은 OSV 데이터와의 버전 비교에서 나옵니다(취약한 코드에 도달하거나 악용할 수 있다는 증거는 아닙니다).",
      "GitHub 로그인은 OS 키체인(macOS 키체인, Windows 자격 증명 관리자, Linux Secret Service)에 저장되며 파일에는 저장하지 않으므로 CLI와 대시보드가 다시 사용할 수 있습니다. 로그인은 로컬 PGARD 프로세스 안에만 있고 브라우저로 보내지 않습니다. 키체인이 없으면 메모리에만 보관합니다. 삭제하려면 pgard logout을 쓰거나, 대시보드에서 키체인의 로그인까지 지우는 로그아웃을 사용하세요.",
      "대시보드에서 실행한 검사의 결과와 대시보드 세션 토큰은 메모리에만 있으며 대시보드를 종료하면 버려집니다. 내보낸 보고서만 남으므로 보관과 공유는 사용자 책임입니다. pgard 명령으로 실행한 검사는 다릅니다. --no-store를 주거나 PGARD_NO_STORE=1을 설정하지 않으면, 가려 처리된 결과가 이 컴퓨터의 앱 데이터 폴더에 저장됩니다(저장소당 최근 20회, 90일, 업로드 없음, macOS·Linux에서는 본인만 읽기 가능). 삭제하려면 pgard history clear --all을 사용하세요.",
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
    thisRepository: "이 저장소",
    allRepositoriesNote: (target) =>
      `GitHub에 ${target}의 접근 권한이 보이지 않습니다. PGARD GitHub App은 이미 소유자 계정의 모든 저장소(All repositories)에 설치되어 있으므로 저장소를 추가해도 해결되지 않습니다. 본인 계정에 접근 권한이 없거나, 저장소가 존재하지 않거나, git remote 주소가 잘못되었을 가능성이 큽니다.`,
    accessLead:
      "GitHub에 이 저장소의 접근 권한이 보이지 않습니다. 비공개 저장소라면 PGARD GitHub App이 이 저장소에 설치되어 있어야 합니다. PGARD는 이것을 계정의 접근 권한 부족과 구분할 수 없습니다.",
    accessPage: (target) =>
      `이 페이지는 "All repositories"가 미리 선택되어 있습니다. PGARD를 이 저장소로 한정하려면 "Only select repositories"를 고르고 ${target}을(를) 선택한 뒤 Install을 누르세요.`,
    repoAccessButton: "App의 저장소 접근 설정 열기",
    repoAccessWaiting:
      "PGARD GitHub App의 저장소 접근에 이 저장소가 추가되기를 기다리는 중입니다... PGARD가 5초마다 확인하고, 추가되면 권한 확인 전체를 다시 실행합니다.",
    repoAccessTimedOut:
      "10분이 지나 PGARD GitHub App의 저장소 접근에 저장소가 추가되기를 기다리는 것을 중단했습니다. 저장소를 추가한 뒤 다시 확인하세요.",
    repoAccessAskOwner: (account, target) =>
      `${account}의 owner에게 PGARD GitHub App의 저장소 접근에 ${target}을(를) 추가해 달라고 요청하세요:`,
    repoAccessLead: (account, target) =>
      `GitHub에 ${target}의 접근 권한이 보이지 않습니다. PGARD GitHub App은 이미 ${account}에 설치되어 있지만, App의 저장소 접근에 이 저장소가 포함되어 있지 않습니다(또는 본인 계정에 접근 권한이 없습니다).`,
    repoAccessOwner: (target) =>
      `owner 승인: PGARD GitHub App의 저장소 접근에 ${target}을(를) 추가하세요.`,
    repoAccessMaybeOwner: (account, target, url) =>
      `${account}의 owner라면 App 설정 페이지에서 PGARD GitHub App의 저장소 접근에 ${target}을(를) 추가하세요. 아니라면 owner에게 추가를 요청하세요: ${url}`,
    repoAccessSteps: (target) =>
      `GitHub의 "Repository access"에서 "Only select repositories"를 고르고 ${target}을(를) 추가한 뒤 Save를 누르세요. App의 저장소 접근을 바꾸는 것이 곧 owner 승인이며, PGARD가 대신 바꿀 수는 없습니다.`,
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
    configNotice: {
      excluded: (detail) => `pgard.config.json으로 제외된 파일이 있습니다 (상세, 영문): ${detail}`,
      config: (detail) => `pgard.config.json 경고 (상세, 영문): ${detail}`,
      test: (detail) => `pgard.config.json의 testDirectories 경고 (상세, 영문): ${detail}`,
      demoted: (count) =>
        `pgard.config.json의 testDirectories 설정이 발견 항목 ${count}건을 테스트 코드로 분류했습니다(따로 나열되고 신뢰도는 최대 낮음으로 제한). 검토하세요.`,
    },
    suppressionNotice: {
      severe: (count, high, critical) =>
        `억제된 발견 항목 중 ${count}건이 높음 또는 치명적입니다(높음 ${high}건, 치명적 ${critical}건). "억제됨" 목록에 그대로 나열되어 있으니 pgard.config.json의 사유를 확인하세요.`,
      total: (count) =>
        `억제 항목이 몇 개든 합쳐서 발견 항목 ${count}건(10건 초과)이 억제되었습니다.`,
      far: (ruleId, path, expires) =>
        `${ruleId}의 억제 항목(${JSON.stringify(path)})은 ${expires}까지로 1년이 넘게 남았습니다. 억제 항목은 정기적으로 검토해야 합니다.`,
      wildcard: (ruleId, path, count) =>
        `${ruleId}의 억제 항목이 ${JSON.stringify(path)}를 사용합니다. 모든 파일, 그 규칙의 모든 발견 항목에 해당합니다 (${count}건 억제).`,
      broad: (ruleId, path, count) =>
        `${ruleId}의 억제 항목(${JSON.stringify(path)})이 발견 항목 ${count}건에 해당합니다.`,
      expired: (ruleId, path, expires) =>
        `${ruleId}의 억제 항목(${JSON.stringify(path)})은 ${expires}에 만료되어 적용되지 않았습니다.`,
      incomplete:
        "억제 항목 매칭이 일찍 멈췄습니다(패턴 작업 한도). 그 이후에 확인한 발견 항목은 억제되지 않고 평소처럼 나열됩니다.",
      everything: (count) =>
        `이 검사의 발견 항목 ${count}건이 모두 pgard.config.json으로 억제되었습니다. 모두 "억제됨"에 나열되어 있으니 결과를 믿기 전에 사유를 검토하세요.`,
    },
    baselineNotice: {
      uncertain: (count) =>
        `새 발견 항목 ${count}건은 기준선이 충분히 다루지 못한 영역에 있어 이전부터 있던 것일 수 있습니다.`,
      tool: "기준선을 설정한 뒤 PGARD가 업데이트되어 규칙이 바뀌었을 수 있습니다. 새 항목과 기준선 항목 수를 신중히 해석하세요.",
    },
    run: "검사 실행",
    cancel: "취소",
    progress: {
      title: "검사 중",
      stoppedTitle: "검사 중단됨",
      elapsed: (time) => `경과 시간 ${time}`,
      areasLabel: "영역별 검사 진행 상황",
      authorization: "권한 확인",
      states: {
        waiting: "대기 중",
        running: "진행 중",
        done: "완료",
        failed: "실패",
        skipped: "건너뜀",
        stopped: "중단됨",
      },
      pages: (count) => `${count}개 페이지 확인`,
      announce: (area, state) => `${area}: ${state}`,
      note: "각 영역은 시작과 완료만 알려 주며, 남은 작업량은 추정하지 않습니다.",
      log: "진행 기록",
    },
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
    confidenceLabel: "신뢰도",
    evidence: "근거 (가려짐)",
    impact: "영향",
    recommendation: "권장 조치",
    noMatch: "필터에 맞는 발견 항목이 없습니다.",
    noFindings: (outside, suppressed, breakdown) =>
      `실행된 영역에서${outside} ${suppressed > 0 ? "억제되지 않은 " : ""}발견 항목이 없습니다${suppressed > 0 ? ` (억제됨 ${suppressed}건${breakdown === "" ? "" : `: ${breakdown}`})` : ""}. 프로젝트가 안전하다는 뜻은 아니므로 coverage를 확인하세요.`,
    outsideTestAndVendored: " 테스트·fixture·vendored 코드를 제외하고",
    outsideTest: " 테스트·fixture 코드를 제외하고",
    outsideVendored: " vendored 코드를 제외하고",
    testTitle: (count) => `테스트·fixture 코드 (${count})`,
    testAria: "테스트·fixture 코드의 발견 항목",
    testNote:
      "경로만으로 테스트·fixture 코드로 분류된 파일의 항목이며 신뢰도는 최대 낮음으로 제한됩니다. 위 개수에는 포함되지 않지만 검토하세요. 테스트에 커밋된 실제 값도 노출된 것입니다.",
    testNoteConfig: (count) =>
      ` 그중 ${count}건은 기본 규칙이 아니라 pgard.config.json의 testDirectories 설정으로 분류되었습니다.`,
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
    suppressedCount: (count, breakdown) =>
      `억제됨 ${count}건${breakdown === "" ? "" : ` (${breakdown})`}`,
    baselineCount: (matched, fresh, breakdown) =>
      `기준선: 기준선에 있음 ${matched}건${breakdown === "" ? "" : ` (${breakdown})`}, 새 항목 ${fresh}건`,
    baselineInBaseline: (count) => `기준선에 있음 ${count}건`,
    suppressedTitle: (count) => `억제됨 (${count})`,
    suppressedAria: "억제된 발견 항목",
    suppressedNote:
      "이 항목들은 검사 대상 저장소의 파일인 pgard.config.json의 억제 항목에 해당했습니다. 여기와 JSON 결과에는 그대로 보고됩니다. 사유는 PGARD가 아니라 그 파일의 문구입니다. 치명적 항목이 있는 구역은 펼쳐져 있습니다.",
    suppressedReason: (reason, expires) =>
      `pgard.config.json으로 억제됨: ${JSON.stringify(reason)}${expires === "" ? "" : ` (만료 ${expires})`}`,
    baselineTitle: (count) => `기준선에 있음 (${count})`,
    baselineAria: "기준선에 있는 발견 항목",
    baselineNote:
      "이 항목들은 이미 기준선(pgard baseline)에 있었습니다. 새 항목은 아니지만 계속 보고됩니다.",
    newBadge: "신규",
    suppressedMarker: (expires) => (expires === "" ? "억제됨" : `${expires}까지 억제됨`),
    pager: {
      showing: (start, end, total) => `전체 ${total}건 중 ${start}–${end}건`,
      label: (list) => `페이지: ${list}`,
      previous: "이전",
      next: "다음",
      page: (page) => `${page}페이지`,
      pageSize: "페이지당 개수",
      regular: "발견 항목",
    },
    noDatabase:
      "PGARD는 취약점 데이터베이스를 포함하지 않으며 스캔은 이를 내려받거나 조회하지 않습니다. 발견 항목은 코드 자체(쿼리문, 서버 코드, 설정), Git 이력, 선택한 경우 로컬 HTTP 검사, 그리고 npm과 Go lockfile에 대해 pgard advisories update로 내려받은 OSV 데이터와의 버전 비교에서 나옵니다(취약한 코드에 도달하거나 악용할 수 있다는 증거는 아닙니다).",
    location: {
      unknownUrl: "(알 수 없는 URL)",
      unknownCommit: "알 수 없는 커밋",
      commit: (sha) => `커밋 ${sha}`,
      unknownLocation: "(알 수 없는 위치)",
    },
  },
  details: {
    standards: "표준",
    viaCwe: (cwe) => `간접, ${cwe} 경유`,
    certDirect: "직접, Java/Kotlin",
    certNone: "SEI CERT Java: 직접 대응하는 규칙 없음",
    examples: (count) => `예시 (${count})`,
    vulnerable: "취약한 코드",
    safe: "안전한 코드",
    ruleRationale: "규칙이 중요한 이유",
    ruleRemediation: "일반적인 조치",
    opensExternally: "(공식 페이지를 새 탭에서 엽니다)",
  },
  standardsPanel: {
    note: "각 상태는 항목에 매핑된 PGARD 규칙이 이번 검사에서 실행되었는지를 나타냅니다. 규칙 실행됨은 프로젝트가 안전하다거나 그 분류를 모두 다뤘다는 뜻이 아닙니다. 분류에 속한 CWE 중 규칙이 있는 개수(범위 폭)를 함께 확인하세요. 여기에는 표준의 식별자, 제목, 링크만 표시하며 표준 자체는 링크된 페이지를 참고하세요.",
    columns: {
      id: "ID",
      category: "분류",
      state: "상태",
      breadth: "범위 폭",
      rules: "규칙",
      reason: "이유",
    },
    states: {
      rules_ran: "규칙 실행됨",
      rules_partial: "규칙 일부 실행",
      not_run: "실행 안 됨",
      no_rules: "규칙 없음",
    },
    breadth: (withRules, inCategory) =>
      `매핑된 CWE ${inCategory}개 중 ${withRules}개에 규칙이 있음`,
    cweTop25Title: "CWE Top 25 2025",
    cweTop25Counts: (ran, partial, notRun, none) =>
      `규칙 실행됨 ${ran}, 규칙 일부 실행 ${partial}, 실행 안 됨 ${notRun}, 규칙 없음 ${none}`,
    cweColumns: { rank: "순위", id: "CWE", name: "약점" },
    notRecorded:
      "이 결과에는 표준 매핑 현황과 규칙 통계가 기록되어 있지 않습니다(이전 버전의 PGARD가 작성).",
    attributionTitle: "표준 데이터와 출처 표기",
    attributionIntro:
      "이 표준들의 식별자, 제목, 링크만 표시하며 표준의 본문은 복사하지 않았습니다.",
    attributionOwasp:
      "OWASP Top 10:2025, Copyright (c) 2003-2025 The OWASP Foundation, Inc., CC BY-SA 4.0 라이선스 (https://creativecommons.org/licenses/by-sa/4.0/).",
    attributionCwe:
      "CWE 및 CWE Top 25: Copyright (c) 2006-2026, The MITRE Corporation, CWE 이용 약관에 따라 사용 (https://cwe.mitre.org/about/termsofuse.html). CWE는 The MITRE Corporation의 상표입니다.",
    attributionCert:
      "SEI CERT Oracle Coding Standard for Java: (c) 2026 Carnegie Mellon University, CC BY 4.0 라이선스. SEI CERT는 Carnegie Mellon University의 등록 상표이며, 이 대시보드는 Carnegie Mellon University나 SEI의 보증을 받지 않았습니다.",
  },
  ruleStats: {
    note: "각 규칙이 실행된 영역마다 무엇을 살펴봤는지 보여 줍니다. 발견 항목 0건은 규칙이 살펴본 범위에서 아무것도 찾지 못했다는 뜻이며, 프로젝트에 그 약점이 없다는 뜻이 아닙니다.",
    columns: {
      rule: "규칙",
      area: "영역",
      targets: "살펴본 대상",
      findings: "발견 항목",
      status: "상태",
    },
    targetCount: (examined, unit) => `${unit} ${examined}개`,
    targetUnknown: (reason) => `알 수 없음 (${reason})`,
    summary: (count) => `규칙 통계 (${count})`,
  },
  nav: {
    label: "대시보드 영역",
    overview: "개요",
    findings: "발견 항목",
    coverage: "검사 범위",
    standards: "표준",
    rules: "규칙",
    export: "내보내기",
  },
  strip: {
    label: "검사 제어",
    auth: {
      none: "확인 전",
      checking: "권한 확인 중",
      signIn: "GitHub 로그인 대기 중",
      allowed: "권한 확인됨",
      blocked: "차단됨",
      failed: "확인 실패",
    },
    authDetails: "자세히",
    target: (origin) => `웹 대상 ${origin}`,
    noTarget: "웹 대상 없음",
    scanning: (time) => `검사 중 ${time}`,
  },
  overview: {
    noScan: "아직 검사하지 않았습니다. 프로젝트를 확인하고 범위를 고른 뒤 검사를 실행하세요.",
    status: {
      completed: "완료",
      partial: "부분 완료",
      blocked: "차단됨",
      failed: "실패",
      unknown: "알 수 없음",
    },
    unfinished: (count) => `${count}개 영역이 끝나지 않음`,
    blockedDetail: "분석이 실행되지 않음",
    failedDetail: "내부 오류로 검사가 중단됨",
    stats: {
      findings: "발견 항목",
      confirmed: "확인됨",
      suspected: "의심",
      informational: "참고",
    },
    severityLabel: "심각도별 발견 항목",
    coverageTitle: "검사 범위",
    coverageCounts: (completed, partial, notTested) =>
      `완료 ${completed} · 부분 ${partial} · 미검사 ${notTested}`,
    coverageLink: "검사 범위 보기",
    topTitle: "주요 발견 항목",
    allFindings: (count) => `발견 항목 ${count}건 모두 보기`,
    summaryTitle: "요약",
    statusMeaning: {
      confirmed: "확인됨: 증거가 문제를 직접 보여 줍니다.",
      suspected: "의심: 위험한 패턴이지만 확정할 증거가 부족하니 직접 검토하세요.",
      informational: "참고: 알아 두면 좋은 내용이며 취약점의 증거는 아닙니다.",
    },
    severityBar: (summary) => `심각도별 발견 항목: ${summary}`,
    severityFilterHint: "심각도를 고르면 해당 발견 항목만 보여 줍니다.",
    partialMeaning:
      "부분은 영역의 일부만 실행되었다는 뜻이며, 빠진 내용은 메모에 있습니다. 미검사는 실행하지 못한 영역입니다.",
    categoryTitle: "분류별",
    categoryLink: (count, category) => `${category} 발견 항목 ${count}건 보기`,
    categoryEmpty: "분류에 해당하는 발견 항목이 없습니다.",
    scopeLine: "검사 범위",
    authAllowedWhy: "모든 항목을 통과해 이 저장소를 검사할 수 있습니다.",
    authBlockedWhy:
      "통과하지 못한 항목이 있어 분석을 실행하지 않습니다. 실패한 항목과 해결 방법은 아래에 있습니다.",
    authNotChecked:
      "검사 전에 프로젝트를 확인하세요. PGARD는 소유자 승인, 내 접근 권한, 병합된 기여를 확인합니다.",
  },
  categories: {
    injection: "인젝션(SQL 등)",
    xss: "크로스 사이트 스크립팅(XSS)",
    ssrf: "서버 측 요청 위조(SSRF)",
    access_control: "접근 제어",
    authentication: "인증",
    brute_force: "무차별 대입",
    cryptography: "암호화",
    misconfiguration: "설정 오류",
    csrf: "CSRF",
    file_handling: "파일 처리·경로",
    command_execution: "명령 실행",
    secret_exposure: "비밀 정보 노출",
  },
  help: {
    label: "이 영역 설명",
    authDetails: "권한 확인 세부 내용",
    signOut: "로그아웃 옵션 설명",
    session: "GitHub 세션",
  },
  linked: {
    barLabel: "적용 중인 필터",
    clearAll: "모두 해제",
    clearAllLabel: "필터 모두 해제",
    remove: (filter) => `${filter} 필터 해제`,
    fields: {
      severity: "심각도",
      status: "상태",
      source: "출처",
      category: "분류",
      rule: "규칙",
      area: "영역",
      path: "파일",
      text: "검색",
    },
    chip: (field, value) => `${field}: ${value}`,
    matching: (shown, total) => `발견 항목 ${total}건 중 ${shown}건이 필터에 맞습니다`,
    noMatch: "필터에 맞는 발견 항목이 없습니다. 필터를 해제하면 더 볼 수 있습니다.",
    filterCategory: (category, count) => `${category} 분류로 필터, 발견 항목 ${count}건`,
    filterArea: (area, count) => `${area} 영역으로 필터, 발견 항목 ${count}건`,
    areaNone: (area) => `${area}: 이 영역에 연결된 발견 항목이 없습니다`,
    filterRule: (rule) => `${rule} 규칙으로 필터`,
    filterFile: (file) => `${file} 파일로 필터`,
    hint: "심각도, 분류, 영역, 규칙, 파일을 선택하면 모든 패널과 표가 그 조건으로 걸러집니다.",
  },
  table: {
    severity: "심각도",
    finding: "발견 항목",
    status: "상태",
    location: "위치",
    rule: "규칙",
    details: "자세히",
    severityFilter: "심각도로 필터",
    category: "분류",
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
