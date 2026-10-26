/**
 * Fixed text of the commands other than the scan result screen: sign-in and sign-out, the GitHub
 * App install guidance, report export, `pgard doctor` and the `pgard rules list` screen. It is
 * part of `CliText` (`text.commands`), so the catalog test fails when a Korean entry is missing.
 *
 * Stays English on purpose: `--format json` and `sarif`, the `[ok]`/`[fail]`/`[warn]` marks of
 * `doctor`, option names and file names, and sentences written by other packages (GitHub error
 * messages, the report writer's errors, the App override warnings of scan-core).
 */

export interface CommandText {
  signIn: {
    revokeHint: (url: string) => string;
    keychainUnavailableOnLogin: (reason: string) => string;
    failed: (reason: string) => string;
    unexpectedError: string;
    signedInNotSaved: (login: string, error: string) => string;
    signedIn: (login: string) => string;
    signedInHint: string;
    keychainUnavailableOnLogout: (reason: string) => string;
    noneSaved: string;
    removedAnonymous: string;
    removed: (login: string) => string;
    deviceCode: (verificationUri: string, userCode: string, minutes: number) => string;
    removedReason: Record<"expired" | "revoked" | "refresh_failed" | "malformed", string>;
    reused: (login: string, isRefreshed: boolean) => string;
    saved: (login: string) => string;
    removedNotice: (reason: string) => string;
    memoryOnly: (reason: string) => string;
    appOverride: (clientId: string, envName: string) => string;
  };
  install: {
    thisRepository: string;
    waitingInstall: string;
    waitingRepositoryAccess: (target: string) => string;
    askOwner: (account: string, url: string) => string;
    ownerOrAsk: (account: string, url: string) => string;
    askOwnerToAdd: (account: string, target: string, url: string) => string;
    repositoryAccessIntro: (target: string, account: string) => string;
    ownerApprovalAdd: (target: string) => string;
    ownerOrAskToAdd: (account: string, target: string, url: string) => string;
    open: (url: string) => string;
    repositoryAccessStep: (target: string) => string;
    repositoryAccessFooter: string;
    accessIntro: (target: string) => string;
    ownerApprovalInstall: (account: string, target: string) => string;
    accessStep: (target: string) => string;
    installStep: (target: string) => string;
    installFooter: string;
    noInstallLink: string;
    notTerminalRepository: string;
    notTerminalInstall: string;
    stoppedWaiting: string;
    recheckFailed: string;
    found: string;
    unconfirmed: string;
    changed: string;
    stoppedAfter: (minutes: number, reason: string) => string;
  };
  report: {
    help: string;
    notDirectory: (isOption: boolean) => string;
    missingDirectory: (isOption: boolean) => string;
    insideRepositoryWarning: string;
    warning: (text: string) => string;
    cannotConfirm: string;
    confirmInside: string;
    saved: (format: string, path: string) => string;
    notSaved: (message: string) => string;
    unexpectedWriteError: string;
    savePrompt: string;
    no: string;
    both: string;
    outputDirPrompt: string;
  };
  doctor: {
    title: string;
    labels: {
      node: string;
      git: string;
      directory: string;
      reachability: string;
      app: string;
      signIn: string;
      advisories: string;
      ports: string;
    };
    node: (version: string, minimums: string) => string;
    gitNotFound: string;
    inRepository: string;
    notInRepository: string;
    reachable: string;
    notReachable: string;
    builtInApp: (clientId: string) => string;
    envApp: (clientId: string, envName: string) => string;
    invalidApp: (message: string) => string;
    signInNotChecked: (envName: string) => string;
    keychainUnreadable: string;
    keychainUnavailable: (reason: string) => string;
    signInNone: string;
    signInRefreshed: (login: string, until: string) => string;
    signInNoExpiry: (login: string) => string;
    signInExpires: (login: string, when: string) => string;
    signInExpired: (login: string) => string;
    advisoryNoHome: string;
    advisoryUnreadable: string;
    advisoryNone: (ecosystem: string) => string;
    advisoryAge: (
      ecosystem: string,
      date: string,
      days: number | null,
      isDamaged: boolean,
    ) => string;
    advisoryStale: (ages: string) => string;
    advisoryDamaged: (ages: string) => string;
    advisoryMissing: (ages: string) => string;
    portsAvailable: (method: string) => string;
    portsUnavailable: (note: string) => string;
    unknownReason: string;
    allPassed: string;
    needAttention: (count: number) => string;
  };
  rulesList: {
    header: (version: string, criteria: string) => string;
    languageFilter: (language: string, included: string[]) => string;
    headings: { code: string; history: string; other: string };
    noRules: string;
    httpHeading: string;
    notCoveredHeading: string;
    unsupportedAreas: readonly string[];
  };
}

const plural = (count: number | null, one: string, many: string): string =>
  count === 1 ? one : many;

export const UNSUPPORTED_AREAS_EN = [
  "Direct database connections",
  "Docker / container configuration",
  "Performance and load testing",
  "Remote (non-loopback) web services",
  "Authenticated (logged-in) web browsing",
  "Form submission and other state-changing requests",
  "Known-vulnerability (CVE/advisory) lookups for dependencies: PGARD ships no vulnerability database",
] as const;

export const COMMAND_TEXT_EN: CommandText = {
  signIn: {
    revokeHint: (url) =>
      `PGARD cannot revoke the token at GitHub (that needs the App's client secret, which PGARD does not have). It stays valid until it expires; to revoke it now, open ${url} and revoke the PGARD app.`,
    keychainUnavailableOnLogin: (reason) =>
      `No OS keychain is available: ${reason}. Nothing was saved; scans and the dashboard ask for a device code on each run.`,
    failed: (reason) => `GitHub sign-in failed: ${reason}`,
    unexpectedError: "unexpected error",
    signedInNotSaved: (login, error) =>
      `Signed in to GitHub as ${login}, but the OS keychain did not save it: ${error}. Nothing was saved.`,
    signedIn: (login) => `Signed in to GitHub as ${login}.`,
    signedInHint:
      "The sign-in is saved in the OS keychain and reused by `pgard scan`, `pgard project verify` and `pgard dashboard`. Owner approval, current access and a merged contribution are still checked on every scan. `pgard logout` removes it.",
    keychainUnavailableOnLogout: (reason) =>
      `No OS keychain is available: ${reason}. Nothing was removed.`,
    noneSaved: "No GitHub sign-in is saved in the OS keychain for this GitHub App.",
    removedAnonymous: "Removed the saved GitHub sign-in from the OS keychain.",
    removed: (login) => `Removed the GitHub sign-in for ${login} from the OS keychain.`,
    deviceCode: (verificationUri, userCode, minutes) =>
      [
        "GitHub sign-in is required to verify your identity and repository access.",
        `  1. Open ${verificationUri}`,
        `  2. Enter the code ${userCode} (expires in about ${minutes} min)`,
        "Waiting for approval... (Ctrl+C to cancel)",
      ].join("\n"),
    removedReason: {
      expired: "has expired",
      revoked: "was rejected by GitHub (revoked or expired)",
      refresh_failed: "could not be refreshed",
      malformed: "could not be read",
    },
    reused: (login, isRefreshed) =>
      `Using the GitHub sign-in for ${login} saved in the OS keychain${isRefreshed ? " (token refreshed)" : ""}.`,
    saved: (login) =>
      `Saved the GitHub sign-in for ${login} in the OS keychain; later runs reuse it. \`pgard logout\` removes it.`,
    removedNotice: (reason) =>
      `The saved GitHub sign-in ${reason} and was removed from the OS keychain. Sign in again below.`,
    memoryOnly: (reason) => `The GitHub sign-in is kept in memory for this run only: ${reason}.`,
    appOverride: (clientId, envName) => `Using GitHub App ${clientId} from ${envName} (override).`,
  },
  install: {
    thisRepository: "this repository",
    waitingInstall:
      "Waiting for the PGARD GitHub App to be installed... (press Ctrl+C twice to cancel)",
    waitingRepositoryAccess: (target) =>
      `Waiting for ${target} to be added to the PGARD GitHub App's repository access... (press Ctrl+C twice to cancel)`,
    askOwner: (account, url) =>
      `Ask an owner of ${account} to install the PGARD GitHub App: ${url}`,
    ownerOrAsk: (account, url) =>
      `If you are an owner of ${account}, install the App on the install page; otherwise ask an owner to install it there: ${url}`,
    askOwnerToAdd: (account, target, url) =>
      `Ask an owner of ${account} to add ${target} to the PGARD GitHub App's repository access: ${url}`,
    repositoryAccessIntro: (target, account) =>
      `GitHub shows no access to ${target}. The PGARD GitHub App is already installed on ${account}, but its repository access does not include this repository (or your account has no access to it).`,
    ownerApprovalAdd: (target) =>
      `Owner approval: add ${target} to the PGARD GitHub App's repository access.`,
    ownerOrAskToAdd: (account, target, url) =>
      `If you are an owner of ${account}, add ${target} to the PGARD GitHub App's repository access on its settings page; otherwise ask an owner to do it there: ${url}`,
    open: (url) => `  1. Open ${url}`,
    repositoryAccessStep: (target) =>
      `  2. Under "Repository access", choose "Only select repositories", add ${target}, then click Save.`,
    repositoryAccessFooter:
      "Changing the App's repository access is the owner approval; PGARD cannot change it for you.",
    accessIntro: (target) =>
      `GitHub shows no access to ${target}. If it is private, the PGARD GitHub App must be installed for it (PGARD cannot tell this from missing account access).`,
    ownerApprovalInstall: (account, target) =>
      `Owner approval: install the PGARD GitHub App on ${account} to approve PGARD for ${target}.`,
    accessStep: (target) =>
      `  2. The page pre-selects "All repositories". To limit PGARD to this repository, choose "Only select repositories" and pick ${target}, then click Install.`,
    installStep: (target) =>
      `  2. Choose "Only select repositories" (${target}) or "All repositories", then click Install.`,
    installFooter: "Installing the App is the owner approval; PGARD cannot install it for you.",
    noInstallLink: "No install link is available.",
    notTerminalRepository:
      "Not a terminal, so PGARD does not wait. Run the command again after adding the repository to the App's repository access.",
    notTerminalInstall:
      "Not a terminal, so PGARD does not wait for the installation. Run the command again after installing.",
    stoppedWaiting: "Stopped waiting for the PGARD GitHub App installation.",
    recheckFailed: "Owner approval could not be checked again.",
    found: "The PGARD GitHub App installation was found. Running the full authorization again...",
    unconfirmed: "Owner approval could not be confirmed. Running the full authorization again...",
    changed: "Owner approval changed. Running the full authorization again...",
    stoppedAfter: (minutes, reason) => `Stopped waiting after ${minutes} minutes. ${reason}`,
  },
  report: {
    help: `Reports are written only to the directory you enter. Existing files are never
overwritten. Saving inside the Git repository risks committing the report.`,
    notDirectory: (isOption) => `${isOption ? "--output-dir" : "That path"} is not a directory.`,
    missingDirectory: (isOption) =>
      `${isOption ? "--output-dir" : "That path"} does not exist. Create it first.`,
    insideRepositoryWarning:
      "The output directory is inside the Git repository. A report there could be committed and shared by mistake.",
    warning: (text) => `Warning: ${text}`,
    cannotConfirm:
      "Cannot confirm without an interactive terminal; choose a directory outside the repository.",
    confirmInside: "Save the report inside the repository anyway?",
    saved: (format, path) => `Saved ${format} report: ${path}`,
    notSaved: (message) => `Report not saved: ${message}`,
    unexpectedWriteError: "Unexpected error while writing the report.",
    savePrompt: "Save a report?",
    no: "No",
    both: "HTML and PDF",
    outputDirPrompt: "Output directory (must exist):",
  },
  doctor: {
    title: "pgard doctor (diagnosis only, not an authorization)",
    labels: {
      node: "Node.js",
      git: "Git",
      directory: "Current directory",
      reachability: "GitHub reachability",
      app: "GitHub App",
      signIn: "Saved GitHub sign-in",
      advisories: "Advisory data (OSV)",
      ports: "Local port discovery",
    },
    node: (version, minimums) => `${version} (requires ${minimums} or a newer patch on that line)`,
    gitNotFound: "not found",
    inRepository: "inside a Git repository",
    notInRepository: "not inside a Git repository (scans need one)",
    reachable: "api.github.com reachable",
    notReachable: "api.github.com not reachable",
    builtInApp: (clientId) => `built-in PGARD App (${clientId})`,
    envApp: (clientId, envName) => `${clientId} from ${envName} (override)`,
    invalidApp: (message) =>
      `${message} Until then GitHub identity is unverifiable and every scan is blocked.`,
    signInNotChecked: (envName) => `not checked (${envName} is not valid)`,
    keychainUnreadable: "the OS keychain could not be read",
    keychainUnavailable: (reason) =>
      `OS keychain unavailable (${reason}); each run asks for a device code`,
    signInNone: "none - run `pgard login` once; until then each run asks for a device code",
    signInRefreshed: (login, until) =>
      `${login} (OS keychain; refreshed automatically until ${until})`,
    signInNoExpiry: (login) => `${login} (OS keychain; the token does not expire)`,
    signInExpires: (login, when) =>
      `${login} (OS keychain; expires ${when}, then pgard signs in again)`,
    signInExpired: (login) =>
      `${login} (OS keychain; expired - the next scan removes it and asks for a device code)`,
    advisoryNoHome: "no home directory found, so there is nowhere to store it",
    advisoryUnreadable: "could not be read",
    advisoryNone: (ecosystem) => `${ecosystem} none`,
    advisoryAge: (ecosystem, date, days, isDamaged) =>
      `${ecosystem} ${date} (${days} ${plural(days, "day", "days")} old${isDamaged ? ", files damaged" : ""})`,
    advisoryStale: (ages) =>
      `stale: ${ages}; run \`pgard advisories update\` (it downloads public OSV data, uploads nothing)`,
    advisoryDamaged: (ages) => `damaged: ${ages}; run \`pgard advisories update\``,
    advisoryMissing: (ages) =>
      `none: ${ages}; run \`pgard advisories update\` to download public OSV data (needed for dependency checks)`,
    portsAvailable: (method) =>
      `${method} available (lists can be incomplete; "Other port" is always offered)`,
    portsUnavailable: (note) => `unavailable (${note})`,
    unknownReason: "unknown reason",
    allPassed: "All required checks passed.",
    needAttention: (count) => `${count} required check(s) need attention (see [fail] above).`,
  },
  rulesList: {
    header: (version, criteria) => `pgard ${version} - detection criteria ${criteria}`,
    languageFilter: (language, included) =>
      `Language filter: ${language} (${included.length > 0 ? `${included.join("/")} rules and ` : ""}rules for any language are included)`,
    headings: {
      code: "Code rules (current files)",
      history: "Git history rules",
      other: "Other rules",
    },
    noRules: "  No rules for this language.",
    httpHeading: "Local HTTP rules (anonymous GET, any language)",
    notCoveredHeading: "Not covered in this version",
    unsupportedAreas: UNSUPPORTED_AREAS_EN,
  },
};

export const COMMAND_TEXT_KO: CommandText = {
  signIn: {
    revokeHint: (url) =>
      `PGARD는 GitHub에서 토큰을 직접 폐기할 수 없습니다(App의 client secret이 필요한데 PGARD에는 없습니다). 토큰은 만료될 때까지 유효합니다. 지금 폐기하려면 ${url} 에서 PGARD 앱의 승인을 취소(Revoke)하세요.`,
    keychainUnavailableOnLogin: (reason) =>
      `사용할 수 있는 OS 키체인이 없습니다: ${reason}. 아무것도 저장하지 않았습니다. 검사와 대시보드는 실행할 때마다 기기 코드를 요청합니다.`,
    failed: (reason) => `GitHub 로그인에 실패했습니다: ${reason}`,
    unexpectedError: "예기치 않은 오류",
    signedInNotSaved: (login, error) =>
      `${login} 계정으로 GitHub에 로그인했지만 OS 키체인이 저장하지 못했습니다: ${error}. 아무것도 저장하지 않았습니다.`,
    signedIn: (login) => `${login} 계정으로 GitHub에 로그인했습니다.`,
    signedInHint:
      "로그인 정보는 OS 키체인에 저장되어 `pgard scan`, `pgard project verify`, `pgard dashboard`에서 다시 사용됩니다. 소유자 승인, 현재 접근 권한, 병합된 기여는 검사할 때마다 다시 확인합니다. `pgard logout`으로 삭제할 수 있습니다.",
    keychainUnavailableOnLogout: (reason) =>
      `사용할 수 있는 OS 키체인이 없습니다: ${reason}. 아무것도 삭제하지 않았습니다.`,
    noneSaved: "이 GitHub App에 대해 OS 키체인에 저장된 GitHub 로그인이 없습니다.",
    removedAnonymous: "OS 키체인에서 저장된 GitHub 로그인을 삭제했습니다.",
    removed: (login) => `OS 키체인에서 ${login} 계정의 GitHub 로그인을 삭제했습니다.`,
    deviceCode: (verificationUri, userCode, minutes) =>
      [
        "신원과 저장소 접근 권한을 확인하려면 GitHub 로그인이 필요합니다.",
        `  1. 다음 주소를 여세요: ${verificationUri}`,
        `  2. 다음 코드를 입력하세요: ${userCode} (약 ${minutes}분 후 만료)`,
        "승인을 기다리는 중... (취소: Ctrl+C)",
      ].join("\n"),
    removedReason: {
      expired: "만료됨",
      revoked: "GitHub에서 거부됨 (폐기 또는 만료)",
      refresh_failed: "갱신하지 못함",
      malformed: "읽을 수 없음",
    },
    reused: (login, isRefreshed) =>
      `OS 키체인에 저장된 ${login} 계정의 GitHub 로그인을 사용합니다${isRefreshed ? " (토큰 갱신됨)" : ""}.`,
    saved: (login) =>
      `${login} 계정의 GitHub 로그인을 OS 키체인에 저장했습니다. 이후 실행에서 다시 사용합니다. \`pgard logout\`으로 삭제할 수 있습니다.`,
    removedNotice: (reason) =>
      `저장된 GitHub 로그인이 사용할 수 없는 상태입니다(${reason}). OS 키체인에서 삭제했으니 아래에서 다시 로그인하세요.`,
    memoryOnly: (reason) => `GitHub 로그인은 이번 실행 동안만 메모리에 보관됩니다: ${reason}.`,
    appOverride: (clientId, envName) =>
      `${envName}에서 재정의한 GitHub App을 사용합니다: ${clientId}`,
  },
  install: {
    thisRepository: "이 저장소",
    waitingInstall: "PGARD GitHub App 설치를 기다리는 중... (취소: Ctrl+C를 두 번 누르세요)",
    waitingRepositoryAccess: (target) =>
      `${target}이(가) PGARD GitHub App의 저장소 접근 권한에 추가되기를 기다리는 중... (취소: Ctrl+C를 두 번 누르세요)`,
    askOwner: (account, url) =>
      `${account}의 소유자에게 PGARD GitHub App을 설치해 달라고 요청하세요: ${url}`,
    ownerOrAsk: (account, url) =>
      `${account}의 소유자라면 설치 페이지에서 App을 설치하세요. 아니라면 소유자에게 설치를 요청하세요: ${url}`,
    askOwnerToAdd: (account, target, url) =>
      `${account}의 소유자에게 ${target}을(를) PGARD GitHub App의 저장소 접근 권한에 추가해 달라고 요청하세요: ${url}`,
    repositoryAccessIntro: (target, account) =>
      `GitHub에서 ${target}에 대한 접근 권한이 보이지 않습니다. PGARD GitHub App은 ${account}에 이미 설치되어 있지만, 저장소 접근 권한에 이 저장소가 포함되어 있지 않습니다(또는 내 계정에 접근 권한이 없습니다).`,
    ownerApprovalAdd: (target) =>
      `소유자 승인: ${target}을(를) PGARD GitHub App의 저장소 접근 권한에 추가하세요.`,
    ownerOrAskToAdd: (account, target, url) =>
      `${account}의 소유자라면 App 설정 페이지에서 ${target}을(를) PGARD GitHub App의 저장소 접근 권한에 추가하세요. 아니라면 소유자에게 추가를 요청하세요: ${url}`,
    open: (url) => `  1. 다음 주소를 여세요: ${url}`,
    repositoryAccessStep: (target) =>
      `  2. "Repository access"에서 "Only select repositories"를 선택하고 ${target}을(를) 추가한 뒤 Save를 누르세요.`,
    repositoryAccessFooter:
      "App의 저장소 접근 권한을 바꾸는 것이 소유자 승인입니다. PGARD가 대신 바꿀 수는 없습니다.",
    accessIntro: (target) =>
      `GitHub에서 ${target}에 대한 접근 권한이 보이지 않습니다. 비공개 저장소라면 PGARD GitHub App이 설치되어 있어야 합니다(PGARD는 이것을 계정 접근 권한 부족과 구분할 수 없습니다).`,
    ownerApprovalInstall: (account, target) =>
      `소유자 승인: ${target}에 대해 PGARD를 승인하려면 ${account}에 PGARD GitHub App을 설치하세요.`,
    accessStep: (target) =>
      `  2. 이 페이지는 "All repositories"를 미리 선택해 둡니다. PGARD를 이 저장소로 제한하려면 "Only select repositories"를 선택하고 ${target}을(를) 고른 뒤 Install을 누르세요.`,
    installStep: (target) =>
      `  2. "Only select repositories"(${target}) 또는 "All repositories"를 선택한 뒤 Install을 누르세요.`,
    installFooter: "App을 설치하는 것이 소유자 승인입니다. PGARD가 대신 설치할 수는 없습니다.",
    noInstallLink: "사용할 수 있는 설치 링크가 없습니다.",
    notTerminalRepository:
      "터미널이 아니어서 PGARD는 기다리지 않습니다. 저장소를 App의 저장소 접근 권한에 추가한 뒤 명령을 다시 실행하세요.",
    notTerminalInstall:
      "터미널이 아니어서 PGARD는 설치를 기다리지 않습니다. 설치한 뒤 명령을 다시 실행하세요.",
    stoppedWaiting: "PGARD GitHub App 설치 대기를 중단했습니다.",
    recheckFailed: "소유자 승인을 다시 확인하지 못했습니다.",
    found: "PGARD GitHub App 설치를 확인했습니다. 전체 권한 확인을 다시 실행합니다...",
    unconfirmed: "소유자 승인을 확인하지 못했습니다. 전체 권한 확인을 다시 실행합니다...",
    changed: "소유자 승인 상태가 바뀌었습니다. 전체 권한 확인을 다시 실행합니다...",
    stoppedAfter: (minutes, reason) => `${minutes}분 동안 기다린 뒤 대기를 중단했습니다. ${reason}`,
  },
  report: {
    help: `보고서는 입력한 디렉터리에만 저장합니다. 기존 파일은 절대 덮어쓰지 않습니다.
Git 저장소 안에 저장하면 보고서가 커밋될 위험이 있습니다.`,
    notDirectory: (isOption) =>
      isOption ? "--output-dir 값이 디렉터리가 아닙니다." : "그 경로는 디렉터리가 아닙니다.",
    missingDirectory: (isOption) =>
      isOption
        ? "--output-dir 경로가 없습니다. 먼저 만드세요."
        : "그 경로가 없습니다. 먼저 만드세요.",
    insideRepositoryWarning:
      "출력 디렉터리가 Git 저장소 안에 있습니다. 거기에 둔 보고서는 실수로 커밋되어 공유될 수 있습니다.",
    warning: (text) => `경고: ${text}`,
    cannotConfirm: "대화형 터미널이 아니면 확인할 수 없습니다. 저장소 밖의 디렉터리를 선택하세요.",
    confirmInside: "그래도 저장소 안에 보고서를 저장할까요?",
    saved: (format, path) => `${format} 보고서를 저장했습니다: ${path}`,
    notSaved: (message) => `보고서를 저장하지 못했습니다: ${message}`,
    unexpectedWriteError: "보고서를 쓰는 중 예기치 않은 오류가 발생했습니다.",
    savePrompt: "보고서를 저장할까요?",
    no: "아니요",
    both: "HTML과 PDF",
    outputDirPrompt: "출력 디렉터리 (이미 있어야 함):",
  },
  doctor: {
    title: "pgard doctor (진단만 수행하며 권한 확인이 아닙니다)",
    labels: {
      node: "Node.js",
      git: "Git",
      directory: "현재 디렉터리",
      reachability: "GitHub 연결",
      app: "GitHub App",
      signIn: "저장된 GitHub 로그인",
      advisories: "취약점 데이터 (OSV)",
      ports: "로컬 포트 탐색",
    },
    node: (version, minimums) =>
      `${version} (${minimums} 또는 해당 라인의 더 새로운 패치가 필요합니다)`,
    gitNotFound: "찾을 수 없음",
    inRepository: "Git 저장소 안",
    notInRepository: "Git 저장소 안이 아님 (검사에는 저장소가 필요합니다)",
    reachable: "api.github.com에 연결됨",
    notReachable: "api.github.com에 연결할 수 없음",
    builtInApp: (clientId) => `내장 PGARD App (${clientId})`,
    envApp: (clientId, envName) => `${envName}의 ${clientId} (재정의)`,
    invalidApp: (message) =>
      `${message} 그때까지 GitHub 신원을 확인할 수 없어 모든 검사가 차단됩니다.`,
    signInNotChecked: (envName) => `확인하지 않음 (${envName} 값이 올바르지 않음)`,
    keychainUnreadable: "OS 키체인을 읽을 수 없었습니다",
    keychainUnavailable: (reason) =>
      `OS 키체인을 사용할 수 없음 (${reason}). 실행할 때마다 기기 코드를 요청합니다`,
    signInNone:
      "없음 - `pgard login`을 한 번 실행하세요. 그전에는 실행할 때마다 기기 코드를 요청합니다",
    signInRefreshed: (login, until) => `${login} (OS 키체인, ${until}까지 자동으로 갱신됨)`,
    signInNoExpiry: (login) => `${login} (OS 키체인, 토큰이 만료되지 않음)`,
    signInExpires: (login, when) =>
      `${login} (OS 키체인, ${when}에 만료되며 이후 pgard가 다시 로그인함)`,
    signInExpired: (login) =>
      `${login} (OS 키체인, 만료됨 - 다음 검사에서 삭제하고 기기 코드를 요청함)`,
    advisoryNoHome: "홈 디렉터리를 찾을 수 없어 저장할 곳이 없습니다",
    advisoryUnreadable: "읽을 수 없었습니다",
    advisoryNone: (ecosystem) => `${ecosystem} 없음`,
    advisoryAge: (ecosystem, date, days, isDamaged) =>
      `${ecosystem} ${date} (${days}일 전${isDamaged ? ", 파일 손상" : ""})`,
    advisoryStale: (ages) =>
      `오래됨: ${ages}. \`pgard advisories update\`를 실행하세요 (공개 OSV 데이터를 내려받으며 아무것도 올리지 않습니다)`,
    advisoryDamaged: (ages) => `손상됨: ${ages}. \`pgard advisories update\`를 실행하세요`,
    advisoryMissing: (ages) =>
      `없음: ${ages}. \`pgard advisories update\`로 공개 OSV 데이터를 내려받으세요 (의존성 검사에 필요합니다)`,
    portsAvailable: (method) =>
      `${method} 사용 가능 (목록이 불완전할 수 있으며 "다른 포트"는 항상 제공됩니다)`,
    portsUnavailable: (note) => `사용할 수 없음 (${note})`,
    unknownReason: "알 수 없는 이유",
    allPassed: "필수 점검을 모두 통과했습니다.",
    needAttention: (count) => `필수 점검 ${count}개에 확인이 필요합니다 (위의 [fail] 참고).`,
  },
  rulesList: {
    header: (version, criteria) => `pgard ${version} - 탐지 기준 ${criteria}`,
    languageFilter: (language, included) =>
      `언어 필터: ${language} (${included.length > 0 ? `${included.join("/")} 규칙과 ` : ""}모든 언어용 규칙을 포함)`,
    headings: {
      code: "코드 규칙 (현재 파일)",
      history: "Git 이력 규칙",
      other: "기타 규칙",
    },
    noRules: "  이 언어에 해당하는 규칙이 없습니다.",
    httpHeading: "로컬 HTTP 규칙 (익명 GET, 모든 언어)",
    notCoveredHeading: "이 버전에서 다루지 않는 영역",
    unsupportedAreas: [
      "데이터베이스 직접 연결",
      "Docker / 컨테이너 설정",
      "성능 및 부하 테스트",
      "원격(루프백이 아닌) 웹 서비스",
      "로그인이 필요한 웹 탐색",
      "양식 제출 및 상태를 바꾸는 요청",
      "의존성의 알려진 취약점(CVE/권고) 조회: PGARD는 취약점 데이터베이스를 포함하지 않습니다",
    ],
  },
};
