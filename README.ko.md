# PGARD

[English](README.md) | 한국어

PGARD(`pgard`)는 검사 권한이 있는 GitHub 프로젝트를 위한 로컬 보안 검사 도구입니다. 사용자 컴퓨터에서 명령줄 도구와 로컬 웹 대시보드로 동작합니다. 현재 코드·설정·의존성, Git 이력, 그리고 (선택 시) `127.0.0.1`에서 실행 중인 웹 서비스를 검사합니다.

PGARD는 검사할 때마다 저장소 owner가 PGARD를 승인했는지, 사용자가 지금 저장소에 접근할 수 있는지, 실제로 기여했는지를 확인합니다. 코드와 결과는 사용자 컴퓨터를 벗어나지 않습니다.

PGARD는 MVP입니다. 모든 취약점을 찾지는 못하며, "발견 없음"이 "안전"을 뜻하지 않습니다.

> **현재 상태:** PGARD에는 PGARD GitHub App의 client id가 내장되어 있어 로그인에 별도 설정이 필요 없습니다. 검사하려면 여전히 저장소를 소유한 개인 계정에 App이 설치되어 있어야 합니다([권한 확인 모델](#권한-확인-모델) 참고).

PGARD는 [MIT 라이선스](LICENSE)로 배포됩니다.

## 목차

- [요구 사항](#요구-사항)
- [설치와 빌드](#설치와-빌드)
- [명령](#명령)
- [권한 확인 모델](#권한-확인-모델)
- [검사 범위와 coverage](#검사-범위와-coverage)
- [분석기와 규칙](#분석기와-규칙)
- [의존성 취약점 데이터](#의존성-취약점-데이터)
- [로컬 웹 검사](#로컬-웹-검사)
- [Git 이력 검사](#git-이력-검사)
- [결과와 보고서](#결과와-보고서)
- [대시보드](#대시보드)
- [개인정보와 네트워크 통신](#개인정보와-네트워크-통신)
- [MVP 범위 밖](#mvp-범위-밖)
- [알려진 제한 사항](#알려진-제한-사항)
- [개발](#개발)
- [라이선스](#라이선스)

## 요구 사항

- Node.js 22.12 이상
- Git
- 로컬 포트 탐지를 위한 macOS 또는 Linux(macOS는 `lsof`, Linux는 `/proc/net/tcp*`). 포트는 언제든 직접 입력할 수 있습니다.
- GitHub 계정([GitHub App과 로그인](#github-app과-로그인) 참고)

## 설치와 빌드

PGARD는 npm에 배포되지 않았습니다. 소스에서 빌드합니다.

```sh
git clone https://github.com/JadenMeister/pgard.git
cd pgard
npm ci
npm run build          # TypeScript 패키지와 대시보드 UI(Vite)
npm link -w @pgard/cli # 선택: PATH에 `pgard` 등록
```

`npm link` 없이 실행하려면 저장소에서 `node apps/cli/dist/bin/pgard.js <명령>`을 사용합니다.

그다음 검사할 프로젝트의 루트에서 PGARD를 실행합니다.

```sh
cd /path/to/your/project
pgard doctor          # 환경 진단
pgard login           # GitHub에 한 번 로그인(OS 키체인에 저장)
pgard project verify  # 권한만 확인
pgard scan            # code + history
```

## 명령

검사 대상은 항상 **현재 디렉터리의 Git 루트**입니다. 다른 경로·호스트·URL을 고르는 옵션도, 권한 확인을 건너뛰는 옵션도 없습니다. 모든 검사는 권한 확인을 매번 다시 실행하며, 앞서 실행한 `project verify` 결과를 재사용하지 않습니다.

`pgard --help` 출력(일부):

```text
Usage:
  pgard                         interactive menu (arrow keys, Enter, Esc, ?)
  pgard project verify          check repository, GitHub identity, owner approval,
                                current access and merged contribution
  pgard scan                    code, configuration, dependencies + Git history
  pgard scan code               current code, configuration and dependencies
  pgard scan history            Git history and tracked files (secrets, risky files)
  pgard scan web [--port N]     anonymous read-only checks of a local HTTP service
  pgard scan all [--port N]     code + history + local HTTP service
  pgard dashboard [--target-port N]
                                start the local web dashboard
  pgard rules list [--language js|ts|react|vue|go]
                                supported rules and data versions
  pgard doctor                  diagnose the environment (not an authorization)
  pgard login                   sign in to GitHub once and save it in the OS keychain
  pgard logout                  remove the saved GitHub sign-in from the OS keychain
  pgard --help | <command> --help
  pgard --version
```

| 명령                   | 역할                                                                                                                                                                                                                                                                                                                          |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pgard`                | 대화형 메뉴: 확인, 검사, 대시보드, 규칙, 진단, 종료.                                                                                                                                                                                                                                                                          |
| `pgard project verify` | 권한 확인을 실행하고 항목별(저장소, GitHub 신원, owner 승인, 현재 접근 권한, 기여)로 통과·실패·확인 불가와 이유를 보여 줍니다. 결과는 저장하지 않습니다.                                                                                                                                                                      |
| `pgard scan`           | `code` + `history`.                                                                                                                                                                                                                                                                                                           |
| `pgard scan code`      | 현재 소스 코드, 설정, 의존성 취약점.                                                                                                                                                                                                                                                                                          |
| `pgard scan history`   | 커밋된 `.env` 파일, 추적 파일과 Git 이력 속 비밀정보.                                                                                                                                                                                                                                                                         |
| `pgard scan web`       | 사용자가 확인한 `127.0.0.1` 로컬 HTTP 서비스의 비로그인·읽기 전용 검사.                                                                                                                                                                                                                                                       |
| `pgard scan all`       | `code` + `history` + `web`. 웹 대상을 확인하지 못하면 결과는 `partial`입니다.                                                                                                                                                                                                                                                 |
| `pgard dashboard`      | 로컬 웹 대시보드를 시작합니다. [대시보드](#대시보드) 참고.                                                                                                                                                                                                                                                                    |
| `pgard rules list`     | 범위별(코드, Git 이력, 로컬 HTTP, 범위를 알 수 없는 규칙은 "Other rules")로 묶은 규칙 목록과 각 규칙의 심각도·언어, 판정 기준 버전, 취약점 데이터베이스 상태, PGARD가 다루지 않는 영역을 보여 줍니다. 프로젝트 밖에서도 실행되며 네트워크 요청을 보내지 않습니다.                                                             |
| `pgard doctor`         | Node.js, Git, GitHub 연결, 로컬 포트 탐지, 어떤 GitHub App으로 로그인하는지(내장 PGARD App 또는 재정의용 `PGARD_GITHUB_APP_CLIENT_ID`), OS 키체인에 저장된 GitHub 로그인이 있는지(어느 계정인지, 토큰은 보여 주지 않음), 취약점 데이터베이스 상태를 진단합니다. 진단일 뿐 권한 승인이 아닙니다. 프로젝트 밖에서도 실행됩니다. |
| `pgard login`          | device flow로 GitHub에 로그인하고 OS 키체인에 저장하여 이후 검사와 대시보드가 다시 사용하게 합니다. 다시 실행하면 저장된 로그인을 바꿉니다. [저장된 로그인](#저장된-로그인os-키체인) 참고.                                                                                                                                    |
| `pgard logout`         | OS 키체인에 저장된 GitHub 로그인을 지웁니다. [저장된 로그인](#저장된-로그인os-키체인) 참고.                                                                                                                                                                                                                                   |

`pgard rules list --language <lang>`은 해당 언어의 규칙만 보여 주며, 언어와 무관한 규칙(Git 이력, 로컬 HTTP 규칙)은 항상 포함되고, `--language react`나 `vue`는 JavaScript/TypeScript 규칙도 포함합니다. `rules list`와 `doctor`는 큰 데이터베이스를 전부 읽지 않고 취약점 데이터베이스 상태를 보고합니다([의존성 취약점 데이터](#의존성-취약점-데이터) 참고). 상태는 버전·갱신일과 함께 `missing`, `invalid`, `stale`, `ok` 중 하나이거나, 간단한 확인만 할 수 있었을 때는 `unverified - not fully validated`입니다. `PGARD_ADVISORY_DB`의 경로는 출력하지 않습니다. `doctor`에서 완전히 검증된 `ok`가 아닌 상태는 `[warn]` 행으로 표시됩니다.

각 명령에는 자체 도움말도 있습니다. 예: `pgard scan --help`, `pgard login --help`.

### 옵션

- `--port N`(`scan web`, `scan all` 전용): 로컬 서비스 포트, 1~65535 정수. 지정해도 서비스 확인은 필요합니다.
- `--target-port N`(`dashboard` 전용): 검사할 로컬 서비스를 미리 선택합니다. 브라우저에서 다시 확인합니다. 대시보드 자체는 별도의 빈 포트에서 실행됩니다.
- `--report html|pdf|both`와 `--output-dir <dir>`(모든 `scan`): 보고서를 저장합니다. 두 옵션은 함께 써야 합니다. 디렉터리는 이미 있어야 하며 기존 파일을 덮어쓰지 않습니다. Git 저장소 안의 디렉터리는 명시적인 `y`가 필요합니다(대화형 터미널이 없으면 거부). 기본값은 터미널에 결과만 표시하는 것입니다.
- `--language js|ts|react|vue|go`(`rules list` 전용): 언어별로 규칙 목록을 거릅니다. 언어와 무관한 규칙은 항상 포함되며, `react`와 `vue`는 JavaScript/TypeScript 규칙도 포함합니다.
- `--help` / `-h`, `pgard --version` / `-V`.

알 수 없는 명령·옵션, 잘못된 값과 조합은 Git·GitHub·네트워크 작업 전에 거부됩니다.

### 종료 코드

| 코드 | 의미                                                                                                                                               |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | 요청한 범위를 끝까지 검사했습니다(발견 항목이 있을 수 있음). `doctor`는 진단을 마쳤다는 뜻입니다.                                                  |
| 2    | 잘못된 명령·옵션·값·조합.                                                                                                                          |
| 3    | 저장소·권한·기여 확인 실패(검사 차단).                                                                                                             |
| 4    | 검사 일부가 실행되지 않아 결과가 부분 완료이거나(예: 웹 대상 미확인, 취약점 데이터베이스가 없거나 잘못되었거나 stale), 보고서 저장에 실패했습니다. |
| 5    | 내부 오류. 세부 내용은 숨기며, `PGARD_DEBUG=1`을 설정하면 정리된 메시지를 보여 줍니다.                                                             |
| 130  | 사용자가 취소했습니다.                                                                                                                             |

`doctor`는 진단을 마치면 0(문제는 `[fail]`·`[warn]` 행으로 표시), 내부 오류면 5로 끝납니다. `pgard login`과 `pgard logout`의 종료 코드는 다음과 같습니다.

| 코드 | `pgard login`                                                          | `pgard logout`                                         |
| ---- | ---------------------------------------------------------------------- | ------------------------------------------------------ |
| 0    | 로그인하고 저장했습니다.                                               | 지웠거나, 저장된 것이 없었습니다.                      |
| 3    | GitHub 로그인 실패.                                                    |                                                        |
| 4    | 사용할 수 있는 OS 키체인이 없거나 저장에 실패. 아무것도 저장하지 않음. | 사용할 수 있는 OS 키체인이 없음. 아무것도 지우지 않음. |
| 5    | 내부 오류.                                                             | 내부 오류.                                             |
| 130  | 취소.                                                                  |                                                        |

### 대화형 키

방향키(또는 `j`/`k`)로 이동, Enter로 선택, Esc로 이전 단계, `?`로 도움말을 봅니다. Ctrl+C는 `Cancel and exit? [y/N]`을 묻습니다. 검사나 GitHub 로그인이 진행 중일 때는 5초 안에 Ctrl+C를 두 번 누르면 취소됩니다(종료 코드 130).

## 권한 확인 모델

PGARD는 사용자에게 검사 권한이 있다는 근거가 있을 때만 저장소를 검사합니다. 검사할 때마다 다음 항목을 (이 순서로) 보고합니다.

1. **저장소.** 현재 디렉터리가 유효한 이력을 가진 Git 저장소의 루트여야 합니다. 저장소 자신의 객체와 이력만 사용해야 하고(alternates, grafts, replace ref 없음), 모호하지 않은 `github.com` remote가 정확히 하나 있어야 합니다.
2. **GitHub 신원.** device flow로 GitHub에 로그인하거나, OS 키체인에 저장된 로그인을 다시 사용합니다(아래 참고). 다시 쓰는 것은 로그인뿐이며, 3~5번 확인은 매번 GitHub에서 다시 실행합니다.
3. **Owner 승인.** PGARD GitHub App이 저장소 owner의 **개인 계정**에 설치되어 있고, 그 설치에 이 저장소가 포함되어야 합니다. 개인 계정에 App을 설치할 수 있는 사람은 그 계정의 owner뿐입니다.
4. **현재 접근 권한.** GitHub가 사용자에게 현재 저장소 읽기 이상의 권한이 있다고 응답해야 합니다.
5. **기여.** 사용자의 기여가 기본 브랜치 이력에 있어야 합니다. GitHub가 기본 브랜치에 있다고 보여 주는 커밋이어야 하고, 사용자가 작성해 기본 브랜치에 merge된 pull request에 속하거나, GitHub가 서명을 검증하고 committer를 사용자로 인정한 커밋이어야 합니다. 작성자 이름·이메일, co-author trailer, merge되지 않은 pull request, 다른 브랜치나 fork에 merge된 pull request, 서명 없는 직접 push, 로컬에만 있는 커밋은 근거로 인정하지 않습니다. PGARD는 로컬 커밋(`HEAD`의 조상)을 최대 30개까지 살펴봅니다. 그중 조건을 충족하는 커밋이 없고 로컬 커밋이 더 있으면 기여는 `unverifiable`입니다.

각 항목은 `passed`, `failed`, `unverifiable` 중 하나이며 이유가 함께 표시됩니다. 항목은 이 순서로 보고하지만 반드시 이 순서로 평가하지는 않습니다. 예를 들어 owner 승인을 확인하기 전에 GitHub에서 저장소를 읽습니다(현재 접근 권한). 모든 항목이 통과해야만 검사합니다. 근거가 없거나 불분명하면 검사는 **차단**되고(종료 코드 3) 어떤 항목이 왜 실패했는지 보고합니다.

### 조직 저장소

조직(organization) 소유 저장소는 항상 차단됩니다(#43). GitHub API로는 저장소 관리자가 아닌 조직 owner가 PGARD GitHub App을 설치했는지 증명할 수 없어, owner 승인이 `unverifiable`로 보고됩니다.

### GitHub App과 로그인

PGARD는 PGARD GitHub App을 통해 OAuth device flow로 로그인합니다. App의 client id(`Iv23liKDf0mhnPl2c7zj`)가 내장되어 있어 따로 설정할 것이 없습니다. client id는 원래 공개되는 값입니다. device flow에는 client secret이 필요 없고, PGARD에도 없습니다.

`PGARD_GITHUB_APP_CLIENT_ID`는 fork나 직접 등록한 GitHub App을 쓸 때만 설정하는 선택적 재정의 값입니다.

```sh
export PGARD_GITHUB_APP_CLIENT_ID=<직접 등록한 GitHub App의 client id>
```

비어 있거나 공백뿐인 값은 설정하지 않은 것으로 봅니다. 올바른 client id가 아닌 값은 무시되며 `pgard doctor`가 경고합니다. 어떤 App을 쓰는지는 `pgard doctor`가 보여 줍니다. 예: `[ok] GitHub App: built-in PGARD App (Iv23liKDf0mhnPl2c7zj)` 또는 `[ok] GitHub App: <id> from PGARD_GITHUB_APP_CLIENT_ID (override)`. 바꿀 수 있는 것은 client id의 출처뿐이며, owner 승인, 현재 접근 권한, 기여 확인은 어느 App이든 똑같이 검사합니다.

로그인이 필요하면 PGARD가 `https://github.com/login/device` 주소와 짧은 사용자 코드를 보여 줍니다. 주소를 열어 코드를 입력하고 승인하면 됩니다. 토큰은 화면·로그·프로세스 인자·환경 변수에 남기지 않으며 파일에 쓰지 않습니다.

#### 저장된 로그인(OS 키체인)

device flow 로그인(`pgard login`, 검사, `project verify`, 대시보드 어디서든)이 끝나면 PGARD는 로그인을 **OS 키체인**(macOS 키체인, Windows 자격 증명 관리자, Linux Secret Service)에 저장합니다. 이후 CLI 실행(`scan`, `project verify`)과 대시보드 세션이 이를 다시 사용하므로 검사할 때마다 코드를 입력하지 않아도 됩니다. 다시 쓰는 것은 로그인뿐이며, owner 승인, 접근 권한, 기여 확인은 여전히 검사 전마다 GitHub에서 실행합니다. 저장된 로그인을 바꾸려면(예: 계정 전환) `pgard login`을 다시 실행합니다.

- 항목은 GitHub 호스트와 App client id로 구분합니다. 내장 App과 같은 client id로 재정의한 경우에는 한 항목을 함께 쓰고, 다른 client id로 재정의하면 내장 App의 토큰을 다시 쓰지 않습니다(반대도 마찬가지입니다).
- App이 만료되는 토큰(8시간, 6개월짜리 refresh token)을 발급하면 PGARD가 액세스 토큰을 자동으로 갱신합니다. device flow로 받은 토큰은 client secret 없이 갱신할 수 있으므로 PGARD에는 client secret이 없습니다.
- 저장된 토큰을 쓰기 전에 PGARD는 GitHub에서 토큰을 확인합니다(`GET /user`). 항목이 만료되었거나, 형식이 잘못되었거나, 취소되었거나(GitHub가 401 응답), 갱신할 수 없으면 PGARD는 항목을 지우고 그 사실을 알린 뒤 device flow를 다시 실행합니다.
- 사용할 수 있는 키체인이 없으면(예: Secret Service가 없는 Linux 서버) PGARD는 이유를 알리고, 이전처럼 현재 CLI 프로세스나 대시보드 세션 동안 메모리에만 보관합니다.
- `pgard logout`(또는 대시보드의 **Sign out and remove from OS keychain**)은 항목을 지웁니다. GitHub에서 토큰을 취소하지는 **않습니다**. 취소하려면 App의 client secret이 필요하므로 PGARD는 취소할 수 없습니다. 토큰은 만료될 때까지(App이 만료되는 토큰을 발급하지 않으면 취소될 때까지) 유효하며, 필요하면 <https://github.com/settings/apps/authorizations>에서 취소하세요.
- `pgard doctor`는 저장된 로그인이 있는지와 어느 계정인지를 보여 주며, 토큰은 보여 주지 않습니다.
- macOS에서는 키체인 항목이 `node` 실행 파일을 신뢰하므로, 같은 사용자가 실행하는 다른 Node.js 스크립트도 확인 창 없이 이 항목을 읽을 수 있습니다.

GitHub App 소유자는 App 설정(**Optional features → User-to-server token expiration**)에서 토큰 만료를 켜거나 끌 수 있습니다. PGARD는 어느 쪽이든 동작합니다. 만료가 켜져 있으면 갱신하고, 꺼져 있으면 취소될 때까지 저장된 토큰을 사용합니다.

## 검사 범위와 coverage

| 범위      | 검사 대상                                                         | 선택하는 명령                      |
| --------- | ----------------------------------------------------------------- | ---------------------------------- |
| `code`    | 현재 소스 코드, 설정, 의존성 취약점                               | `scan`, `scan code`, `scan all`    |
| `history` | 커밋된 `.env` 파일, 추적 파일과 Git 이력 속 비밀정보              | `scan`, `scan history`, `scan all` |
| `web`     | 사용자가 확인한 `127.0.0.1` 서비스의 비로그인·읽기 전용 HTTP 검사 | `scan web`, `scan all`             |

모든 결과는 영역별 coverage를 보고하므로 무엇을 검사했고 무엇을 검사하지 못했는지 알 수 있습니다.

| 상태           | 의미                                                                   |
| -------------- | ---------------------------------------------------------------------- |
| `completed`    | 영역을 끝까지 검사했습니다. 발견 항목은 있을 수도, 없을 수도 있습니다. |
| `partial`      | 영역의 일부만 검사했습니다. 무엇이 빠졌는지 설명이 붙습니다.           |
| `not_tested`   | 사용자가 선택했지만 실행할 수 없었습니다.                              |
| `not_selected` | 사용자가 요청하지 않았습니다.                                          |

`scan all`(과 `scan web`)은 웹 대상을 확인하지 못하면(**Continue without web checks**를 골랐거나 대화형 터미널이 없을 때) `partial`과 종료 코드 4를 보고합니다. 확인 질문에 아니오로 답하면 포트 선택으로 돌아갑니다. 이때 `web` 범위는 `not_tested`입니다.

## 분석기와 규칙

| 분석기        | 범위      | 규칙 id                                                                                                                            |
| ------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| 소스 분석     | `code`    | `PG-SQL-*`, `PG-XSS-*`, `PG-SSRF-*`, `PG-CMD-*`, `PG-PATH-*`, `PG-CRYPTO-*`, `PG-AUTH-*`, `PG-COOKIE-*`, `PG-CSRF-*`, `PG-BRUTE-*` |
| 의존성 취약점 | `code`    | `PG-DEP-001`                                                                                                                       |
| Git 이력      | `history` | `PG-SECRET-001`(커밋된 환경 파일), `PG-SECRET-002`(추적 파일 속 비밀정보), `PG-SECRET-003`(이력에만 남은 비밀정보)                 |
| 로컬 HTTP     | `web`     | `PG-WEB-001` ~ `PG-WEB-013`                                                                                                        |

소스 분석은 JavaScript, TypeScript, React(JSX/TSX), Vue, Go 파일을 다룹니다. 규칙과 심각도의 최신 목록은 이 README의 사본 대신 `pgard rules list`(필요하면 `--language` 사용)로 확인하세요.

HTML sink(`innerHTML`, `outerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`)에 sanitizer 호출(예: `DOMPurify.sanitize(...)`)을 바로 거친 값을 넣으면 보고하지 않습니다. JavaScript와 TypeScript에서는 PGARD가 (파일 안에서 TypeScript의 심볼 해석으로) 변수를 그 변수 자신의 `var`/`let`/`const` 선언으로 해석할 수 있고 그 변수에 대한 모든 대입이 sanitizer 호출일 때도 sanitize된 것으로 봅니다. import, 매개변수, 전역 변수, 클래식 스크립트의 최상위 `var`/`let`, 그리고 `eval`, `with`, `Function`, 문자열 타이머를 쓰는 파일의 변수는 sanitize된 것으로 보지 않습니다. sanitizer는 함수 이름으로만 인식하며, sanitizer 설정은 확인하지 않습니다.

## 의존성 취약점 데이터

`code` 범위는 해석된(resolved) 의존성 버전을 [OSV](https://osv.dev/) 형식의 **로컬** 취약점 데이터베이스와 비교합니다. PGARD가 취약점 데이터를 직접 내려받지는 않습니다.

```sh
export PGARD_ADVISORY_DB=/path/to/osv-data   # JSON 파일 또는 OSV .json 파일이 있는 디렉터리
```

- 지원 입력: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `go.mod`, `go.sum`.
- `testdata` 디렉터리 아래의 Go 모듈은 건너뜁니다(Go가 빌드하지 않는 테스트 fixture). 그곳의 npm lockfile은 그대로 검사합니다.
- 파일에는 OSV 레코드 배열이나 `{ "version", "updatedAt", "vulnerabilities": [...] }`를 담을 수 있습니다.
- 512 MiB보다 큰 데이터베이스(단일 파일 또는 디렉터리 전체 합계)나 파일이 500,000개보다 많은 데이터베이스는 `invalid`입니다.
- 변수가 없거나 데이터가 없거나 잘못되면 취약점 데이터베이스 영역은 `not_tested`입니다. 30일보다 오래된 데이터는 stale이며 그 영역은 `partial`입니다. 두 경우 모두 `code` 범위가 완전하지 않으므로 `scan`, `scan code`, `scan all`은 `partial`과 종료 코드 4를 보고합니다.
- 검사는 항상 데이터베이스 전체를 읽습니다. `rules list`와 `doctor`는 간단히 살펴보기만 합니다. 8 MiB 이하 파일은 전부 읽고, 512 MiB를 넘는 파일은 `invalid`로 보고하며, 그 밖에는 샘플 레코드(디렉터리)나 앞부분 바이트(파일)만 확인합니다. 이 간단한 확인만 통과한 데이터베이스는 버전·최신 여부 없이 `unverified - not fully validated`로 표시되고, `doctor`에서는 `[warn]` 행입니다. 검사에서는 여전히 잘못되었거나 stale로 판정될 수 있습니다.
- 버전이 일치해도 취약한 코드가 실제로 호출되는지는 알 수 없습니다.

취약점 데이터베이스의 배포·갱신 방식은 아직 정해지지 않았습니다(#46). 업데이트 명령은 없습니다.

## 로컬 웹 검사

`scan web`, `scan all`, 대시보드는 사용자가 확인한 웹 서비스만 검사합니다.

1. CLI와 대시보드 모두, 권한 확인을 통과해야만 PGARD가 포트에 접근합니다(대시보드에서는 확인 후 30분이 지나면 포트 접근도 만료됩니다. [대시보드](#대시보드) 참고).
2. 각 서비스의 정체를 보여 주기 위해, PGARD는 (권한 확인을 통과한 뒤) `127.0.0.1`에서 발견한 각 열린 포트에 `GET /`를 한 번 보냅니다. HTTP로 응답하는 포트를 보여 줍니다. 목록은 불완전할 수 있으므로 **Other port**를 항상 제공합니다. 포트 번호만으로는 어떤 프로젝트의 서비스인지 알 수 없습니다.
3. 서비스의 URL, HTTP 상태, 페이지 제목, 추정 기술을 보여 줍니다.
4. `Is this the current project's service? [y/N]`에 답합니다. 명시적인 `y`만 확인으로 인정합니다. `--port`를 지정해도 이 확인을 거칩니다.
5. 대화형 터미널이 없으면 대상을 확인할 수 없어 `web`은 `not_tested`, 검사는 `partial`(종료 코드 4)이 됩니다.

검사는 `127.0.0.1:<port>`에만 비로그인 `GET`/`HEAD` 요청을 보냅니다. 같은 loopback origin 안의 리다이렉트만 따라가고, 로그아웃·삭제·초기화처럼 보이는 링크는 건너뜁니다. 한도는 20페이지, 깊이 2, 요청당 5초, 전체 60초, 응답 본문 1MB입니다. 보안 헤더, 쿠키 속성, 자격 증명과 함께 쓰인 CORS, 서버 버전 노출, 디렉터리 목록, `/.env`·`/.git` 노출(존재 여부만 확인하며 값은 보관하지 않음)을 살핍니다. 헤더가 없다는 사실은 정보성 항목으로 보고하며 취약점의 증거로 보지 않습니다.

잘못 만들어진 애플리케이션은 `GET` 요청에도 상태가 바뀔 수 있습니다. PGARD는 검사에 부작용이 없다고 보장할 수 없습니다.

## Git 이력 검사

`scan history`는 `HEAD`에서 추적 중인 파일과 최근 커밋 1,000개(first-parent만이 아닌 도달 가능한 모든 커밋)의 변경을 60초 한도 안에서 읽습니다. 1 MiB를 넘는 blob, 내용을 64 MiB 읽은 뒤 건너뛴 blob, 시간 초과가 있으면 그 영역은 설명과 함께 `partial`입니다. 바이너리 파일은 비밀정보를 검사하지 않으며 설명에 그 개수를 표시합니다. 비밀정보 값은 메모리에서만 비교하며 발견 항목·보고서에 넣지 않습니다.

- `PG-SECRET-001`: 커밋된 환경 파일(`.env`, `.env.local`, `prod.env` 등. `.env.example` 같은 템플릿은 제외). 값은 보여 주지 않습니다.
- `PG-SECRET-002`: `HEAD`에서 추적 중인 파일 속 비밀정보.
- `PG-SECRET-003`: 이력에는 있지만 현재 파일에는 더 이상 없는 비밀정보.

비밀정보는 개인 키, 잘 알려진 토큰 형식(AWS, GitHub, Slack, Stripe, Google API 키), 일반적인 자격 증명 대입(`password = ...`, `api_key: ...`)입니다. 일반 대입은 값이 충분히 무작위로 보이는 리터럴이고 placeholder가 아닐 때만 인정합니다. 소스 파일에서 확실히 코드로 보이는 줄의 따옴표 없는 값(타입, 매개변수 목록, 상수·변수 이름)은 자격 증명으로 보지 않습니다. 탐지는 패턴 기반이며 알려진 누락이 있습니다(#145).

PGARD는 현재 파일에 비밀정보나 `.env` 파일이 더 이상 없다는 것을 보일 수 있을 때만 "삭제됨(removed)"이라고 합니다. 그 전에 `git grep -F`로 현재 커밋을 검색하며(값은 인자가 아닌 stdin으로 전달), 이 검색은 PGARD가 직접 읽지 않은 파일(너무 크거나, 읽기 한도를 넘었거나, 바이너리)도 다룹니다. `git grep`이 검색하지 못하는 UTF-16 텍스트 파일은 디코딩해 메모리에서 검색합니다. 파일을 읽지 못했거나 검색이 끝나지 않는 등 현재 상태를 확정할 수 없으면, 삭제되었다고 하는 대신 값이나 파일이 아직 남아 있는지 **확인할 수 없었다**(could not be checked)고 표시합니다.

## 결과와 보고서

터미널 결과는 심각도 차트, `파일:줄` 또는 URL이 붙은 발견 항목(확정·의심·정보), 가려진 근거, 가이드, 영역별 coverage를 보여 줍니다.

### 테스트·fixture 코드의 발견 항목

테스트·fixture 코드의 발견 항목은 다른 발견 항목 뒤에 별도 그룹(**In test or fixture code (N)**)으로 표시됩니다. 규칙, 심각도, 근거는 그대로이지만 신뢰도(confidence)는 최대 `low`로 제한됩니다. 상단 개수와 심각도 차트는 일반 코드만 셉니다(예: `Findings by severity (3 total) - plus 2 in test or fixture code`). 테스트에 커밋된 실제 비밀정보도 노출된 것이므로 이 항목들은 버리지 않습니다. CLI, 대시보드, HTML/PDF 보고서가 모두 같은 방식으로 묶습니다.

분류는 파일 내용이 아니라 경로로만 합니다. 다음에 해당하면 테스트·fixture 코드입니다.

- 파일 이름이 `*.test.*`, `*.spec.*`, `*_test.go`와 일치하거나,
- `__tests__/`, `__mocks__/`, `__fixtures__/`, `fixtures/`, `testdata/` 디렉터리 아래에 있거나,
- `test/` 또는 `tests/` 디렉터리 아래에 있는 경우. **단** 설정 파일(`.env*`, `.npmrc`, `Dockerfile*`, `settings.py`, `*_settings.py`, `config.py`, 또는 `.yml`, `.yaml`, `.tf`, `.tfvars`, `.properties`, `.ini`, `.toml`, `.json`, `.conf`, `.cfg`, `.xml` 파일)은 제외합니다. 이런 파일은 실제로 배포된 테스트 환경을 설정할 수 있으므로 일반 코드로 봅니다.

디렉터리 이름은 대소문자를 구분하지 않습니다. 이 규칙은 모든 범위의 발견 항목에 적용되므로, `fixtures/` 아래의 `.env`는 테스트 항목이지만 `deploy/test/.env`는 아닙니다.

HTML·PDF 보고서는 같은 가려진 결과로 만듭니다. HTML 보고서는 스크립트가 없고 엄격한 CSP를 쓰는 단일 파일입니다. 보고서는 사용자가 지정한 디렉터리에만 저장되고, 기존 파일을 덮어쓰지 않으며, 권한 `0600`으로 만들어집니다. 실수로 커밋되지 않도록 보고서는 저장소 밖에 보관하세요.

## 대시보드

`pgard dashboard`는 현재 디렉터리의 Git 루트를 찾아 보여 주고 `Start the dashboard for this project? [y/N]`을 묻습니다. 대화형 터미널이 필요하며, 없으면 종료 코드 2로 끝납니다. 확인하면 로컬 웹 앱을 시작하고 개인 세션 URL을 출력합니다.

```text
PGARD dashboard is running on 127.0.0.1 only.
Open this private session URL in your browser (valid until you stop the dashboard): http://127.0.0.1:<port>/#token=<random>
```

대시보드는 CLI 결과를 읽지 않고 직접 검사합니다. 권한 확인 결과와 GitHub device 코드를 보여 주고, 로컬 서비스 선택·확인, 범위 선택, 진행 상황 확인, 발견 항목 필터(테스트·fixture 항목은 별도 그룹), HTML/PDF 보고서 내보내기를 제공합니다. OS 키체인에 저장된 GitHub 로그인은 서버 쪽에서 다시 사용하며, 토큰은 브라우저로 보내지 않습니다. 로그아웃 버튼은 두 가지입니다. **End dashboard session (keep keychain sign-in)** 버튼은 이 대시보드의 세션만 끝내고 다음 확인 때 키체인 로그인을 다시 사용합니다. **Sign out and remove from OS keychain**은 저장된 로그인도 지웁니다(CLI에서도 지워짐). Ctrl+C로 종료하면 대시보드의 GitHub 세션이 끝나고(키체인 로그인은 유지) 모든 결과를 버립니다.

포트 탐지, 서비스 정체 확인 요청, 대상 확인은 이 프로젝트에 대한 대시보드의 가장 최근 권한 확인이 통과한 뒤에만, 그리고 그 확인이 끝난 뒤 30분 동안만 허용됩니다. 대시보드는 이 시간이 언제 끝나는지 보여 주며, 그 뒤에는(또는 시스템 시계가 뒤로 가면) 다시 확인해야 로컬 서비스에 접근합니다. 새 확인이나 로그아웃은 즉시 이 시간을 끝내고 진행 중인 요청을 중단하며, 페이지는 이전 확인 때의 포트 목록과 확인 결과를 버립니다. 이 시간과 관계없이 모든 검사는 권한 확인 전체를 다시 실행합니다.

대시보드 보호 방식:

- `127.0.0.1`의 빈 포트에만 바인딩합니다.
- 32바이트 임의 세션 토큰을 URL **fragment**로 전달하므로 브라우저가 요청이나 `Referer` 헤더에 싣지 않습니다. 페이지는 주소창에서 토큰을 지우고 메모리에만 보관합니다. URL을 공유하지 마세요.
- 모든 API 호출은 `x-pgard-token` 헤더에 토큰이 있어야 합니다. `Host` 헤더는 정확히 `127.0.0.1:<port>`여야 합니다(DNS rebinding 방어). 다른 `Origin`에서 온 요청과 cross-site 요청은 거부하며, CORS 헤더는 보내지 않습니다.
- 모든 응답에 `Cache-Control: no-store`, 엄격한 Content-Security-Policy, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`를 적용합니다.
- 브라우저는 프로젝트 파일을 고르거나 읽을 수 없습니다. 프로젝트 루트는 대시보드를 시작할 때 고정됩니다. 브라우저가 지정하는 경로는 보고서를 내보낼 기존 디렉터리뿐이며, 그곳의 파일은 덮어쓰지 않고, 저장소 안의 디렉터리는 확인이 필요합니다. 브라우저는 가려진 발견 항목(짧게 가려진 코드 조각 포함)만 받고, 전체 소스 파일이나 GitHub 토큰은 받지 않습니다.

## 개인정보와 네트워크 통신

- 코드, Git 이력, 검사 결과는 사용자 컴퓨터에서 처리되며 어디에도 업로드되지 않습니다. 결과는 메모리에만 있고 프로세스나 대시보드가 끝나면 버려지며, 사용자가 내보낸 보고서만 저장됩니다.
- GitHub 로그인은 파일이 아닌 OS 키체인에 저장되며 브라우저로 보내지 않습니다. 키체인이 없으면 메모리에만 보관합니다. [저장된 로그인](#저장된-로그인os-키체인) 참고.
- 외부 네트워크 통신은 GitHub뿐입니다. device flow 로그인(및 저장된 로그인 갱신)과, 권한 확인에 필요한 메타데이터(사용자 신원, App 설치, 접근 권한, 기여)를 읽는 GitHub API 호출입니다. 기여를 확인하기 위해 로컬 커밋의 SHA를 GitHub에 보냅니다. `pgard doctor`는 `api.github.com` 연결 가능 여부도 확인합니다.
- 권한 확인을 통과한 뒤, PGARD는 서비스의 정체를 보여 주기 위해 `127.0.0.1`에서 발견한 각 열린 포트에 `GET /`를 한 번 보냅니다. 이후 웹 검사는 사용자가 확인한 서비스에만 요청을 보냅니다.
- 취약점 데이터는 `PGARD_ADVISORY_DB`의 로컬 경로에서 읽습니다.

## MVP 범위 밖

- 데이터베이스 직접 접속
- Docker·컨테이너 설정
- 성능·부하 테스트
- 원격(loopback이 아닌) 서비스 검사
- 공격 요청, 폼 제출 등 상태를 바꾸는 요청
- 로그인한 상태의 웹 탐색(#45). `web:authenticated` 영역은 항상 `not_selected`이며, PGARD는 애플리케이션 비밀번호를 묻지 않습니다.

## 알려진 제한 사항

- [#43](https://github.com/JadenMeister/pgard/issues/43) owner 승인을 증명할 수 없어 조직 저장소는 차단됩니다.
- [#44](https://github.com/JadenMeister/pgard/issues/44) PDF 보고서는 Latin-1 밖의 문자(예: 한국어)를 `?`로 바꿉니다. 전체 텍스트는 HTML 보고서를 사용하세요.
- [#45](https://github.com/JadenMeister/pgard/issues/45) 로그인한 상태의 웹 탐색은 지원하지 않습니다.
- [#46](https://github.com/JadenMeister/pgard/issues/46) 취약점 데이터베이스의 배포·갱신 방식이 정해지지 않았습니다.
- [#47](https://github.com/JadenMeister/pgard/issues/47) squash merge와 공동 작성 기여는 보수적으로 처리합니다. co-author trailer와 서명 없는 직접 push는 기여로 인정하지 않습니다.
- [#143](https://github.com/JadenMeister/pgard/issues/143) 키체인 로그인 리뷰의 후속 작업: 키체인 저장과 삭제 사이의 짧은 경쟁 상태, 토큰 갱신 중 대시보드 세션만 끝내는 로그아웃을 하면 다음 사용 때 새 device 코드를 요구할 수 있는 문제, `pgard login`으로 계정을 바꾼 뒤에도 대시보드가 이전 계정의 포트 접근을 최대 30분 유지하는 문제(검사는 권한을 다시 확인함).
- [#145](https://github.com/JadenMeister/pgard/issues/145) 비밀정보 탐지가 일부 형태를 놓칩니다. 예: 템플릿 리터럴, TypeScript 타입 표기가 붙은 선언, Go `:=` 선언, `postgres://` URL 속 자격 증명, `headers["x-api-key"] = "..."` 같은 인덱스 대입.
- 탐지는 완전하지 않습니다. 발견 항목이 없다고 프로젝트가 안전한 것은 아닙니다.
- 포트 탐지는 불완전하거나 사용할 수 없을 수 있습니다. 그럴 때는 포트를 직접 입력하세요.

## 개발

TypeScript로 작성된 npm workspaces 모노레포입니다.

| 경로                       | 내용                                                      |
| -------------------------- | --------------------------------------------------------- |
| `apps/cli`                 | `pgard` 명령줄 도구                                       |
| `apps/local-web`           | 로컬 웹 대시보드(서버와 React UI)                         |
| `packages/policy`          | 권한 확인                                                 |
| `packages/github-auth`     | GitHub device flow, API 클라이언트, OS 키체인 로그인 저장 |
| `packages/scan-core`       | 검사 실행, 범위, coverage                                 |
| `packages/source-analysis` | 소스 코드 규칙                                            |
| `packages/advisory`        | 로컬 OSV 데이터 기반 의존성 취약점 검사                   |
| `packages/git-history`     | Git 이력과 비밀정보 검사                                  |
| `packages/http-local`      | 로컬 HTTP 검사와 포트 탐지                                |
| `packages/findings`        | 공통 발견 항목·coverage 타입, 민감정보 가림               |
| `packages/report`          | HTML·PDF 보고서                                           |
| `tests/integration`        | 패키지 간 통합 테스트                                     |

```sh
npm ci
npm run build         # 모든 패키지와 대시보드 UI 빌드
npm run typecheck     # 타입 검사만
npm test              # Vitest 테스트 실행
npm run format        # Prettier로 포맷
npm run format:check  # 포맷 확인
npm run check         # typecheck + format:check + test
```

CI는 pull request와 `main` push마다 `npm ci`, `npm run build`, `npm run format:check`, `npm test`를 실행합니다.

## 라이선스

[MIT](LICENSE)
