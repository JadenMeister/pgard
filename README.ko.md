# PGARD

[![CI](https://img.shields.io/github/actions/workflow/status/JadenMeister/pgard/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white)](https://github.com/JadenMeister/pgard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/JadenMeister/pgard?color=blue)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-22.23.4%20%7C%2024.22.1%20%7C%2026.12.1-339933?logo=nodedotjs&logoColor=white)](#요구-사항)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)](tsconfig.base.json)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey?logo=apple&logoColor=white)](#요구-사항)
[![Status: MVP](https://img.shields.io/badge/status-MVP-orange)](#mvp-범위-밖)
[![Data stays local](https://img.shields.io/badge/data-stays%20local-2ea44f)](#개인정보와-네트워크-통신)
[![Last commit](https://img.shields.io/github/last-commit/JadenMeister/pgard/main)](https://github.com/JadenMeister/pgard/commits/main)

[English](README.md) | 한국어

PGARD(`pgard`)는 검사 권한이 있는 GitHub 프로젝트를 위한 로컬 보안 검사 도구입니다. 사용자 컴퓨터에서 명령줄 도구와 로컬 웹 대시보드로 동작합니다. 현재 코드·설정, Git 이력, 그리고 (선택 시) `127.0.0.1`에서 실행 중인 웹 서비스를 검사합니다. 발견 항목은 코드 자체로 판정하며, PGARD는 취약점 데이터베이스를 포함하거나 조회하지 않습니다([코드 기반 분석](#코드-기반-분석) 참고).

PGARD는 검사할 때마다 저장소 owner가 PGARD를 승인했는지, 사용자가 지금 저장소에 접근할 수 있는지, 사용자가 저장소의 owner이거나 실제로 기여했는지를 확인합니다. 코드와 결과는 사용자 컴퓨터를 벗어나지 않습니다.

PGARD는 MVP입니다. 모든 취약점을 찾지는 못하며, "발견 없음"이 "안전"을 뜻하지 않습니다.

> **현재 상태:** PGARD에는 PGARD GitHub App의 client id가 내장되어 있어 로그인에 별도 설정이 필요 없습니다. 검사하려면 여전히 저장소를 소유한 계정, 즉 본인의 개인 계정이나 본인이 owner인 조직에 App이 설치되어 있어야 합니다([권한 확인 모델](#권한-확인-모델) 참고).

PGARD는 [MIT 라이선스](LICENSE)로 배포됩니다.

## 목차

- [요구 사항](#요구-사항)
- [설치와 빌드](#설치와-빌드)
- [명령](#명령)
- [권한 확인 모델](#권한-확인-모델)
- [검사 범위와 coverage](#검사-범위와-coverage)
- [분석기와 규칙](#분석기와-규칙)
- [코드 기반 분석](#코드-기반-분석)
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

- Node.js 22.23.4, 24.22.1, 26.12.1 이상(같은 버전 라인의 더 새로운 패치 포함). [2026년 10월 21일 Node.js 보안 릴리스](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)에서 고친 취약점이 반영된 버전입니다. 원격 코드 실행으로 이어질 수 있는 Brotli 디코더 범위 밖 쓰기(CVE-2026-111497)와 TLS 호스트 이름 검증 우회가 여기에 포함됩니다. PGARD는 `fetch`와 TLS로 GitHub API를 호출하므로 이전 버전은 지원하지 않으며, `pgard doctor`의 Node.js 검사도 실패합니다. Node.js 20 이하와 홀수 버전 라인은 수정이 제공되지 않습니다. 버전은 `node --version`으로 확인하세요.
- Git
- 로컬 포트 탐지를 위한 macOS 또는 Linux(macOS는 `lsof`이며 실패하면 `netstat`으로 대체, Linux는 `/proc/net/tcp*`). 포트는 언제든 직접 입력할 수 있습니다.
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
  pgard scan                    code and configuration + Git history
  pgard scan code               current code and configuration
  pgard scan history            Git history and tracked files (secrets, risky files)
  pgard scan web [--port N]     anonymous read-only checks of a local HTTP service
  pgard scan all [--port N]     code + history + local HTTP service
  pgard dashboard [--target-port N]
                                start the local web dashboard
  pgard rules list [--language js|ts|react|vue|go]
                                supported rules and unsupported areas
  pgard doctor                  diagnose the environment (not an authorization)
  pgard login                   sign in to GitHub once and save it in the OS keychain
  pgard logout                  remove the saved GitHub sign-in from the OS keychain
  pgard --help | <command> --help
  pgard --version
```

| 명령                   | 역할                                                                                                                                                                                                                                                                                                      |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pgard`                | 대화형 메뉴: 확인, 검사, 대시보드, 규칙, 진단, 종료.                                                                                                                                                                                                                                                      |
| `pgard project verify` | 권한 확인을 실행하고 항목별(저장소, GitHub 신원, owner 승인, 현재 접근 권한, 기여)로 통과·실패·확인 불가와 이유를 보여 줍니다. 결과는 저장하지 않습니다.                                                                                                                                                  |
| `pgard scan`           | `code` + `history`.                                                                                                                                                                                                                                                                                       |
| `pgard scan code`      | 현재 소스 코드와 설정.                                                                                                                                                                                                                                                                                    |
| `pgard scan history`   | 커밋된 `.env` 파일, 추적 파일과 Git 이력 속 비밀정보.                                                                                                                                                                                                                                                     |
| `pgard scan web`       | 사용자가 확인한 `127.0.0.1` 로컬 HTTP 서비스의 비로그인·읽기 전용 검사.                                                                                                                                                                                                                                   |
| `pgard scan all`       | `code` + `history` + `web`. 웹 대상을 확인하지 못하면 결과는 `partial`입니다.                                                                                                                                                                                                                             |
| `pgard dashboard`      | 로컬 웹 대시보드를 시작합니다. [대시보드](#대시보드) 참고.                                                                                                                                                                                                                                                |
| `pgard rules list`     | 범위별(코드, Git 이력, 로컬 HTTP, 범위를 알 수 없는 규칙은 "Other rules")로 묶은 규칙 목록과 각 규칙의 심각도·언어, 판정 기준 버전, PGARD가 다루지 않는 영역(PGARD에는 취약점 데이터베이스가 없으므로 의존성 취약점 조회 포함)을 보여 줍니다. 프로젝트 밖에서도 실행되며 네트워크 요청을 보내지 않습니다. |
| `pgard doctor`         | Node.js, Git, GitHub 연결, 로컬 포트 탐지, 어떤 GitHub App으로 로그인하는지(내장 PGARD App 또는 재정의용 `PGARD_GITHUB_APP_CLIENT_ID`), OS 키체인에 저장된 GitHub 로그인이 있는지(어느 계정인지, 토큰은 보여 주지 않음)를 진단합니다. 진단일 뿐 권한 승인이 아닙니다. 프로젝트 밖에서도 실행됩니다.       |
| `pgard login`          | device flow로 GitHub에 로그인하고 OS 키체인에 저장하여 이후 검사와 대시보드가 다시 사용하게 합니다. 다시 실행하면 저장된 로그인을 바꿉니다. [저장된 로그인](#저장된-로그인os-키체인) 참고.                                                                                                                |
| `pgard logout`         | OS 키체인에 저장된 GitHub 로그인을 지웁니다. [저장된 로그인](#저장된-로그인os-키체인) 참고.                                                                                                                                                                                                               |

`pgard rules list --language <lang>`은 해당 언어의 규칙만 보여 주며, 언어와 무관한 규칙(Git 이력, 로컬 HTTP 규칙)은 항상 포함되고, `--language react`나 `vue`는 JavaScript/TypeScript 규칙도 포함합니다.

각 명령에는 자체 도움말도 있습니다. 예: `pgard scan --help`, `pgard login --help`. `pgard scan --help` 출력(발췌):

```text
Options:
  --port N                 local service port 1-65535 (web and all only). You
                           still confirm the service identity with y/N.
  --report html|pdf|both   save a report (requires --output-dir)
  --output-dir <dir>       existing directory for the report (requires --report);
                           files are never overwritten; a directory inside the
                           Git repository needs explicit confirmation
  --no-browser             do not open GitHub pages (device sign-in, App
                           install) in the browser; the links are printed.
                           Pages open automatically only when stdout is a
                           terminal

If owner approval is the only failed check and the PGARD GitHub App just needs to
be installed, PGARD opens the install page, waits for it, re-runs the full
authorization and continues the scan.
```

### 옵션

- `--port N`(`scan web`, `scan all` 전용): 로컬 서비스 포트, 1~65535 정수. 지정해도 서비스 확인은 필요합니다.
- `--target-port N`(`dashboard` 전용): 검사할 로컬 서비스를 미리 선택합니다. 브라우저에서 다시 확인합니다. 대시보드 자체는 별도의 빈 포트에서 실행됩니다.
- `--report html|pdf|both`와 `--output-dir <dir>`(모든 `scan`): 보고서를 저장합니다. 두 옵션은 함께 써야 합니다. 디렉터리는 이미 있어야 하며 기존 파일을 덮어쓰지 않습니다. Git 저장소 안의 디렉터리는 명시적인 `y`가 필요합니다(대화형 터미널이 없으면 거부). 기본값은 터미널에 결과만 표시하는 것입니다.
- `--language js|ts|react|vue|go`(`rules list` 전용): 언어별로 규칙 목록을 거릅니다. 언어와 무관한 규칙은 항상 포함되며, `react`와 `vue`는 JavaScript/TypeScript 규칙도 포함합니다.
- `--no-browser`(`scan`, `project verify`, `login`, `dashboard`): GitHub 페이지(device 로그인 페이지, App 설치 페이지)를 브라우저로 열지 않고 링크만 출력합니다. 이 옵션이 없으면 stdout이 터미널일 때만 자동으로 엽니다. 링크는 항상 함께 출력하며, 브라우저를 열지 못해도 오류가 아닙니다.
- `--help` / `-h`, `pgard --version` / `-V`.

알 수 없는 명령·옵션, 잘못된 값과 조합은 Git·GitHub·네트워크 작업 전에 거부됩니다. 알 수 없는 검사 종류(예: `dependencies`)는 종료 코드 2로 끝나며 올바른 값 `code`, `history`, `web`, `all`을 알려 줍니다.

### 종료 코드

| 코드 | 의미                                                                                                                                |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------- |
| 0    | 요청한 범위를 끝까지 검사했습니다(발견 항목이 있을 수 있음). `doctor`는 진단을 마쳤다는 뜻입니다.                                   |
| 2    | 잘못된 명령·옵션·값·조합.                                                                                                           |
| 3    | 저장소·권한·기여 확인 실패(검사 차단).                                                                                              |
| 4    | 검사 일부가 실행되지 않아 결과가 부분 완료이거나(예: 웹 대상 미확인, Git 이력 검사가 시간 한도에 도달), 보고서 저장에 실패했습니다. |
| 5    | 내부 오류. 세부 내용은 숨기며, `PGARD_DEBUG=1`을 설정하면 정리된 메시지를 보여 줍니다.                                              |
| 130  | 사용자가 취소했습니다.                                                                                                              |

`doctor`는 진단을 마치면 0(문제는 `[fail]`·`[warn]` 행으로 표시), 내부 오류면 5로 끝납니다. `pgard login`과 `pgard logout`의 종료 코드는 다음과 같습니다.

| 코드 | `pgard login`                                                                                                                      | `pgard logout`                                                                |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| 0    | 로그인하고 저장했습니다.                                                                                                           | 지웠거나, 저장된 것이 없었습니다.                                             |
| 3    | GitHub 로그인 실패 또는 `PGARD_GITHUB_APP_CLIENT_ID`가 올바른 client id가 아님(또는 `PGARD_GITHUB_APP_SLUG`가 올바른 slug가 아님). | `PGARD_GITHUB_APP_CLIENT_ID`가 올바른 client id가 아님. 아무것도 지우지 않음. |
| 4    | 사용할 수 있는 OS 키체인이 없거나 저장에 실패. 아무것도 저장하지 않음.                                                             | 사용할 수 있는 OS 키체인이 없음. 아무것도 지우지 않음.                        |
| 5    | 내부 오류.                                                                                                                         | 내부 오류.                                                                    |
| 130  | 취소.                                                                                                                              |                                                                               |

### 대화형 키

방향키(또는 `j`/`k`)로 이동, Enter로 선택, Esc로 이전 단계, `?`로 도움말을 봅니다. Ctrl+C는 `Cancel and exit? [y/N]`을 묻습니다. 검사나 GitHub 로그인이 진행 중일 때는 5초 안에 Ctrl+C를 두 번 누르면 취소됩니다(종료 코드 130).

## 권한 확인 모델

PGARD는 사용자에게 검사 권한이 있다는 근거가 있을 때만 저장소를 검사합니다. 검사할 때마다 다음 항목을 (이 순서로) 보고합니다.

1. **저장소.** 현재 디렉터리가 유효한 이력을 가진 Git 저장소의 루트여야 합니다. 저장소 자신의 객체와 이력만 사용해야 하고(alternates, grafts, replace ref 없음), 모호하지 않은 `github.com` remote가 정확히 하나 있어야 합니다.
2. **GitHub 신원.** device flow로 GitHub에 로그인하거나, OS 키체인에 저장된 로그인을 다시 사용합니다(아래 참고). 다시 쓰는 것은 로그인뿐이며, 3~5번 확인은 매번 GitHub에서 다시 실행합니다.
3. **Owner 승인.** **개인 계정** 소유 저장소는 PGARD GitHub App이 그 계정에 설치되어 있고, 그 설치에 이 저장소가 포함되어야 합니다. 개인 계정에 App을 설치할 수 있는 사람은 그 계정의 owner뿐입니다. **조직** 소유 저장소는 [조직 저장소](#조직-저장소)를 참고하세요.
4. **현재 접근 권한.** GitHub가 사용자에게 현재 저장소 읽기 이상의 권한이 있다고 응답해야 합니다.
5. **기여.** 사용자가 **검증된 owner**이면 본인의 기여를 증명하지 않아도 되지만, 로컬 이력이 저장소의 기본 브랜치와 커밋을 하나 이상 공유해야 합니다. 개인 저장소에서는 사용자의 GitHub 계정 id가 저장소 owner 계정 id와 같아야 합니다(둘 다 remote 문자열이 아니라 GitHub API에서 읽음). 이때 이유는 "`<user>` owns `<owner>/<repo>` (verified by GitHub account id); a separate contribution is not required."입니다. 조직 저장소에서는 사용자가 조직의 활성 owner여야 하며, 같은 실행에서 owner 승인이 얻은 멤버십 근거를 그대로 사용합니다(다시 조회하지 않음). 이때 이유는 "`<user>` is an owner of the organization "`<org>`"; a separate contribution is not required."입니다. 두 경우 모두 `HEAD`의 조상 커밋(최신순, 같은 최대 30개 로컬 커밋) 중 하나 이상이 GitHub의 기본 브랜치 이력에 있어야 하며, 기여와 같은 방식으로 확인합니다. 이것으로 디스크의 코드를 저장소와 연결하므로, `origin`을 본인이 소유한 다른 저장소로 바꿔도 관계없는 코드를 검사할 수 없습니다. 통과하면 이유 끝에 "Local HEAD is linked to `<owner>/<repo>` by commit `<sha>`."가 붙습니다. `HEAD`의 더 오래된 커밋이 기본 브랜치에 있으면 push하지 않은 로컬 커밋이 있어도 괜찮습니다. 연결되는 커밋이 없으면(GitHub의 저장소가 비어 있는 경우 포함) 기여는 "None of the last `<N>` local commits is on `<owner>/<repo>`'s default branch "`<branch>`"; the local code can't be tied to this repository. Push or pull so local history shares a commit with the default branch." 이유로 실패합니다. 이 확인 중 GitHub API 오류가 나면 기여는 `unverifiable`입니다. 이 예외는 같은 실행에서 owner 승인이 통과했을 때만 적용됩니다. 오류, 불일치, 알 수 없는 상태가 하나라도 있으면 예외는 없고 아래의 일반 규칙을 적용합니다. owner 승인과 현재 접근 권한을 대신하지 않으며, 두 확인은 각자 통과해야 합니다. 그 밖의 사용자는 기여가 기본 브랜치 이력에 있어야 합니다. GitHub가 기본 브랜치에 있다고 보여 주는 커밋이어야 하고, 사용자가 작성해 기본 브랜치에 merge된 pull request에 속하거나, GitHub가 서명을 검증하고 committer를 사용자로 인정한 커밋이어야 합니다. 작성자 이름·이메일, co-author trailer, merge되지 않은 pull request, 다른 브랜치나 fork에 merge된 pull request, 서명 없는 직접 push, 로컬에만 있는 커밋은 근거로 인정하지 않습니다. PGARD는 로컬 커밋(`HEAD`의 조상)을 최대 30개까지 살펴봅니다. 그중 조건을 충족하는 커밋이 없고 로컬 커밋이 더 있으면 기여는 `unverifiable`입니다. 기여가 통과하지 못하면 이유 끝에 자격을 얻는 방법을 덧붙입니다: "To qualify, get a pull request merged into "`<default branch>`", or sign your commits (GitHub shows them as Verified) and push them to "`<default branch>`"."

각 항목은 `passed`, `failed`, `unverifiable` 중 하나이며 이유가 함께 표시됩니다. 항목은 이 순서로 보고하지만 반드시 이 순서로 평가하지는 않습니다. 예를 들어 owner 승인을 확인하기 전에 GitHub에서 저장소를 읽습니다(현재 접근 권한). 모든 항목이 통과해야만 검사합니다. 근거가 없거나 불분명하면 검사는 **차단**되고(종료 코드 3) 어떤 항목이 왜 실패했는지 보고합니다.

### 처음 실행: 로그인, App 설치, 계속 진행

저장소에서 처음 `pgard scan`(또는 `pgard project verify`, 대시보드)을 실행하면 다음과 같이 진행됩니다.

1. **로그인.** PGARD가 코드를 출력하고 브라우저에서 `https://github.com/login/device`를 엽니다(`--no-browser` 참고). 코드를 입력하고 PGARD GitHub App을 승인합니다.
2. **빠진 것이 App 설치뿐이면 설치.** owner 승인만 실패했고, 그 이유가 PGARD GitHub App이 owner 계정에 설치되어 있지 않거나 설치에 이 저장소가 포함되지 않았기 때문이며, 본인이 승인할 수 있는 사람일 수 있으면(개인 저장소는 본인이 owner, 조직은 GitHub가 본인을 활성 owner로 보여 주거나 아직 역할을 보여 주지 못하는 경우), PGARD가 owner 계정과 이 저장소가 미리 선택된 App 설치 페이지를 출력하고 엽니다.

   ```text
   https://github.com/apps/<slug>/installations/new/permissions?suggested_target_id=<owner account id>&repository_ids[]=<repository id>
   ```

   GitHub에서 **Only select repositories**(이 저장소) 또는 **All repositories**를 고르고 **Install**을 누릅니다. 그동안 PGARD는 `Waiting for the PGARD GitHub App to be installed... (press Ctrl+C twice to cancel)`을 출력하고 최대 10분 동안 5초마다 owner 승인을 다시 확인합니다.

3. **계속 진행.** 설치가 확인되면 PGARD는 **다섯 항목 전체를 처음부터 다시** 확인하고, 그 뒤에만 계속 진행합니다. `scan`은 검사하고, `project verify`는 결과를 출력합니다.

**App 설치가 곧 owner의 승인이며, PGARD가 대신 설치할 수는 없습니다.** PGARD는 App을 직접 설치하지 않고, 어떤 항목도 건너뛰지 않으며, 승인을 캐시하지 않습니다. 설치를 확인한 것만으로는 통과가 아닙니다. 그사이 접근 권한이 사라졌다면 새 확인에서 차단됩니다.

- 10분 안에 설치되지 않거나 stdout이 터미널이 아니면(링크만 출력하고 기다리지 않음) 평소 사유와 함께 차단됩니다(종료 코드 3). 기다리는 중 Ctrl+C로 취소를 확정하면 취소됩니다(종료 코드 130).
- 기다리는 동안의 재확인은 기존 로그인(메모리 또는 OS 키체인)만 사용하며 새 device 로그인을 시작하지 않습니다. 로그인이 사라졌거나 GitHub가 rate limit 또는 오류로 응답하면 PGARD는 `Owner approval could not be confirmed. Running the full authorization again...`을 출력하고 기다림을 멈춘 뒤 전체 확인을 실행하며, 필요하면 이 확인에서 평소처럼 로그인합니다.
- App이 조직에 설치되기 전에는 GitHub가 보통 App에 본인의 멤버십을 보여 주지 않습니다(403/404). 이때도 PGARD는 안내를 진행하고 `If you are an owner of <org>, install the App on the install page; otherwise ask an owner to install it there: <link>`를 출력합니다. 안내는 어떤 항목도 통과시키지 않으므로 안전합니다. 설치는 조직의 실제 owner만 완료할 수 있고, 설치가 확인되면 활성 owner 멤버십 확인을 포함한 전체 확인을 처음부터 다시 실행합니다.
- GitHub가 본인이 승인할 수 없다고 보여 주면(owner가 아니거나 대기 중인 조직 멤버십, 다른 사람의 개인 저장소 협업자) PGARD는 기다리거나 아무것도 열지 않습니다. 사유와 함께 `Ask an owner of <account> to install the PGARD GitHub App: <link>`를 출력합니다. 링크에는 GitHub의 숫자 id만 들어 있어 공유해도 안전합니다.
- **App 설치에 포함되지 않은 비공개 저장소.** PGARD GitHub App의 로그인 토큰은 App 설치에 포함된 비공개 저장소만 볼 수 있습니다. 그 밖의 비공개 저장소는 GitHub가 404로 응답하므로 현재 접근 권한은 "GitHub returned no access to github.com/<owner>/<repo>. For a private repository this usually means the PGARD GitHub App is not installed for it, or your account has no access." 이유로 `failed`로 유지됩니다. PGARD는 둘 중 어느 경우인지(또는 저장소가 아예 없는지) 알 수 없으므로 아무것도 통과시키지 않습니다. 그런 다음 owner의 계정 id(`GET /users/<owner>`, 공개 API)를 조회해 같은 안내형 설치 페이지를 보여 줍니다. 저장소 id를 알 수 없으므로 owner 계정만 미리 선택되며, 이후 기다렸다가 다섯 항목 전체를 처음부터 다시 확인합니다. 조회에 실패하면 이유만 보여 줍니다. 조직은 설치 전에 본인의 역할을 확인할 수 없으므로 멤버십을 읽을 수 없을 때와 같은 방식으로 안내합니다. 설치 후에는 전체 확인이 결정합니다.
- 다른 항목도 실패했다면 App 설치만으로는 부족하므로 설치 링크를 보여 주지 않습니다.
- `PGARD_GITHUB_APP_SLUG` 없이 `PGARD_GITHUB_APP_CLIENT_ID`만 설정하면 어느 App 페이지를 열지 알 수 없으므로, 사유는 그대로 두고 `Set PGARD_GITHUB_APP_SLUG to enable the guided install.`을 덧붙입니다. 링크는 `github.com` 링크만 보여 주고 엽니다.

### 조직 저장소

조직(organization) 소유 저장소는 **조직의 owner**만 검사할 수 있습니다. 다음 두 조건을 모두 충족해야 owner 승인이 통과합니다.

- PGARD GitHub App이 조직 계정에 설치되어 있고, 그 설치에 이 저장소가 포함되어 있습니다.
- 사용자가 그 조직의 owner입니다. GitHub의 `GET /user/memberships/orgs/{org}`가 사용자의 멤버십을 `state: active`, `role: admin`으로 응답해야 합니다.

설치만으로는 근거가 되지 않습니다. 조직 설정에 따라 저장소 관리자도 App을 설치할 수 있고, GitHub는 누가 설치했는지 알려 주지 않기 때문입니다. 역할이 `admin`이 아닌 활성 멤버(예: 일반 멤버, billing manager)는 "`<user>` is not an owner of `<org>` (role: `<role>`); an organization owner must run the scan." 이유로 차단됩니다(`failed`). 대기 중(pending)인 멤버십은 "`<user>`'s membership in `<org>` is pending, not active; an organization owner with an active membership must run the scan." 이유로 차단됩니다(`failed`). 외부 협력자(outside collaborator)는 멤버가 아니어서 GitHub가 404로 응답하므로, owner 승인은 아래의 404 이유와 함께 `unverifiable`이 됩니다. 현재 접근 권한은 개인 저장소와 똑같이 확인합니다. 조직 owner만 owner 승인을 통과하므로, 그 owner는 별도의 기여도 면제됩니다(5번 확인 참고). owner가 아닌 멤버는 owner 승인에서 차단되며, 기여는 여전히 일반 규칙으로 확인합니다.

근거가 불분명하면 검사는 차단되고 owner 승인은 이유와 함께 `unverifiable`이 됩니다. 멤버십 조회에 GitHub가 403이나 404로 응답한 경우, rate limit, 네트워크 오류, 예상하지 못한 응답, 그리고 Git remote의 조직 이름이 GitHub의 이름과 다른 경우(대소문자만 달라도 해당하며, remote를 GitHub에 표시되는 정확한 이름으로 바꾸면 됩니다)가 여기에 포함됩니다. 외부 협력자나 멤버가 아닌 사용자가 받는 멤버십 404는 "GitHub did not return `<user>`'s membership in `<org>` (404): `<user>` may not be a member, or the PGARD GitHub App cannot read the organization's members. An owner of `<org>` must run the scan, with the App's Members: Read-only permission approved."로 보고됩니다.

**필요한 App 권한.** 멤버십을 읽으려면 PGARD GitHub App에 조직 권한 **Members: Read-only**가 있어야 합니다(**Organization permissions → Members → Read-only**). App owner가 App 설정에서 이 권한을 추가해야 하고, 기존의 모든 조직 설치가 새 권한을 수락해야 합니다(조직 owner가 조직의 **Settings → GitHub Apps**에서 승인). 그 전까지 GitHub는 403으로 응답하고, PGARD는 "GitHub refused to show `<user>`'s membership in `<org>` (403): the PGARD GitHub App needs the organization permission Members: Read-only, approved by an owner of `<org>`."라고 보고합니다.

### GitHub App과 로그인

PGARD는 PGARD GitHub App을 통해 OAuth device flow로 로그인합니다. App의 client id(`Iv23liKDf0mhnPl2c7zj`)가 내장되어 있어 따로 설정할 것이 없습니다. client id는 원래 공개되는 값입니다. device flow에는 client secret이 필요 없고, PGARD에도 없습니다.

`PGARD_GITHUB_APP_CLIENT_ID`는 fork나 직접 등록한 GitHub App을 쓸 때만 설정하는 선택적 재정의 값입니다.

```sh
export PGARD_GITHUB_APP_CLIENT_ID=<직접 등록한 GitHub App의 client id>
```

비어 있거나 공백뿐인 값은 설정하지 않은 것으로 봅니다. 올바른 client id가 아닌 값은 **차단**됩니다. 내장 App으로 대신 진행하면 설정한 App이 아닌 다른 App으로 owner 승인을 증명하게 되므로, PGARD는 내장 App으로 넘어가지 않습니다. GitHub 신원은 "PGARD_GITHUB_APP_CLIENT_ID is set but is not a valid client id; unset it to use the built-in PGARD App." 사유와 함께 `unverifiable`이 되고, 검사와 `project verify`는 차단되며(종료 코드 3), `pgard login`과 `pgard logout`은 3으로 끝나고(logout은 아무것도 지우지 않음), `pgard doctor`는 `[fail]` 행을 보여 주며, 대시보드도 같은 사유를 보여 주고 키체인에서 아무것도 지우지 않습니다. 잘못된 값 자체는 출력하지 않습니다. 어떤 App을 쓰는지는 `pgard doctor`가 보여 줍니다. 예: `[ok] GitHub App: built-in PGARD App (Iv23liKDf0mhnPl2c7zj)` 또는 `[ok] GitHub App: <id> from PGARD_GITHUB_APP_CLIENT_ID (override)`. 재정의 값을 쓰는 동안에는 `login`, `scan`, `project verify`도 `Using GitHub App <id> from PGARD_GITHUB_APP_CLIENT_ID (override).`를 출력합니다. 바꿀 수 있는 것은 client id의 출처뿐이며, owner 승인, 현재 접근 권한, 기여 확인은 어느 App이든 똑같이 검사합니다.

`PGARD_GITHUB_APP_SLUG`는 그 App 페이지(`https://github.com/apps/<slug>`)의 slug를 지정하는 선택적 값이며, [안내형 설치](#처음-실행-로그인-app-설치-계속-진행)의 설치 링크에만 쓰입니다. 내장 App의 slug는 `pgard-jadenmeister`입니다. 값은 소문자, 숫자, `-`로만 이루어져야 하며(최대 100자), 그 밖의 값은 잘못된 client id와 똑같이 **차단**되고 사유는 "PGARD_GITHUB_APP_SLUG is set but is not a valid GitHub App slug (lowercase letters, digits and "-"); fix or unset it."입니다. client id를 재정의하고 slug를 지정하지 않으면 설치 링크가 없습니다. 키체인 항목은 client id만으로 정해지므로, 잘못된 slug는 `pgard logout`이나 대시보드의 **Sign out and remove from OS keychain**을 막지 않습니다. `PGARD_GITHUB_APP_CLIENT_ID` 없이 `PGARD_GITHUB_APP_SLUG`만 지정하면(로그인은 내장 App, 설치 링크는 다른 App) `scan`, `project verify`, 대시보드가 경고를 한 번 보여 줍니다. 그 다른 App을 설치해도 PGARD를 승인할 수 없기 때문입니다.

```sh
export PGARD_GITHUB_APP_SLUG=<직접 등록한 GitHub App의 slug>
```

로그인이 필요하면 PGARD가 `https://github.com/login/device` 주소와 짧은 사용자 코드를 보여 주고, stdout이 터미널이면(`--no-browser`가 없을 때) 브라우저에서 주소를 엽니다. 주소를 열어 코드를 입력하고 승인하면 됩니다. 토큰은 화면·로그·프로세스 인자·환경 변수에 남기지 않으며 파일에 쓰지 않습니다.

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
| `code`    | 현재 소스 코드와 설정                                             | `scan`, `scan code`, `scan all`    |
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

| 분석기    | 범위      | 규칙 id                                                                                                                                                            |
| --------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 소스 분석 | `code`    | `PG-SQL-*`, `PG-XSS-*`, `PG-SSRF-*`, `PG-CMD-*`, `PG-PATH-*`, `PG-CRYPTO-*`, `PG-AUTH-*`, `PG-COOKIE-*`, `PG-CSRF-*`, `PG-BRUTE-*`                                 |
| Git 이력  | `history` | `PG-SECRET-001`(커밋된 환경 파일), `PG-SECRET-002`(추적 파일 속 비밀정보), `PG-SECRET-003`(이력에만 남은 비밀정보), `PG-HYGIENE-001`(커밋된 의존성 디렉터리, 제안) |
| 로컬 HTTP | `web`     | `PG-WEB-001` ~ `PG-WEB-013`                                                                                                                                        |

소스 분석은 JavaScript, TypeScript, React(JSX/TSX), Vue, Go 파일을 다룹니다. 작업 트리를 탐색하며 빌드 결과물·캐시(`dist/`, `build/`, `out/`, `.next/`, `coverage/` 등)와 의존성 디렉터리에는 들어가지 않습니다. 의존성 디렉터리는 위치와 상관없이 `node_modules/`, `bower_components/`이고, `vendor/`는 저장소 루트에 있거나 같은 디렉터리에 `composer.json`, `go.mod`, `Gemfile`이 있을 때만입니다(`src/`, `app/`, `lib/` 아래는 제외하므로 직접 만든 `src/vendor/` 모듈은 분석합니다). 건너뛴 의존성 디렉터리는 `source:dependency-directories` coverage 설명에 표시됩니다(예: `Skipped 2 dependency directories (third-party code, not analyzed): node_modules/, vendor/ (composer.json).`, 최대 5개까지 이름을 보여 주되 경로가 길면 더 적게 보여 주고, 나머지는 개수로 표시). 옆에 매니페스트가 없는 루트 `vendor/`는 서드파티로 가정하고 건너뛰며 `vendor/ (repository root, no manifest; assumed third-party)`로 표시합니다. 규칙과 심각도의 최신 목록은 이 README의 사본 대신 `pgard rules list`(필요하면 `--language` 사용)로 확인하세요.

HTML sink(`innerHTML`, `outerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`)에 sanitizer 호출(예: `DOMPurify.sanitize(...)`)을 바로 거친 값을 넣으면 보고하지 않습니다. JavaScript와 TypeScript에서는 PGARD가 (파일 안에서 TypeScript의 심볼 해석으로) 변수를 그 변수 자신의 `var`/`let`/`const` 선언으로 해석할 수 있고 그 변수에 대한 모든 대입이 sanitizer 호출일 때도 sanitize된 것으로 봅니다. import, 매개변수, 전역 변수, 클래식 스크립트의 최상위 `var`/`let`, 그리고 `eval`, `with`, `Function`, 문자열 타이머를 쓰는 파일의 변수는 sanitize된 것으로 보지 않습니다. sanitizer는 함수 이름으로만 인식하며, sanitizer 설정은 확인하지 않습니다.

## 코드 기반 분석

PGARD는 취약점 데이터베이스를 포함하거나 내려받거나 조회하지 않으며, 의존성 버전을 알려진 취약점 정보(CVE, OSV 등)와 비교하지 않습니다. 발견 항목은 코드 자체로 판정합니다. 현재 파일의 쿼리 문장, 서버 코드, 설정, Git 이력 속 비밀정보, 그리고 사용자가 확인한 로컬 HTTP 서비스의 응답입니다. lockfile에서 알려진 취약 버전을 찾지는 않습니다.

선택한 모든 영역이 끝까지 실행된 검사는 `completed`를 보고하고 종료 코드 0으로 끝납니다. 종료 코드 4는 선택한 coverage 일부가 실제로 빠졌다는 뜻입니다. 예를 들어 웹 대상을 확인하지 못했거나 이력 검사가 한도에 도달한 경우입니다.

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
- `PG-HYGIENE-001`(info, 제안으로 표시): `HEAD`에서 의존성 디렉터리를 추적 중인 경우. 검사마다 발견 항목 하나가 루트 디렉터리와 추적 파일 수를 최대 5개까지 보여 줍니다. 해결 방법: 로컬 사본은 지우지 않고 인덱스에서만 제거하고(`git rm -r --cached node_modules`), `.gitignore`에 추가한 뒤 패키지 관리자로 복원합니다. 추적 중인 경로만 보고 판단하며 작업 트리는 읽지 않습니다. 루트는 vendored 경로([서드파티·vendored 코드의 제안](#서드파티vendored-코드의-제안) 참고)에서 대상이 되는 가장 바깥쪽 디렉터리이며, 중첩된 `node_modules/`는 그 루트에 포함됩니다.
  - `node_modules/`, `bower_components/`, `jspm_packages/`, `Pods/`는 항상 대상입니다.
  - `vendor/`는 저장소 루트에 있거나, 같은 디렉터리에 추적 중인 `composer.json`, `go.mod`, `Gemfile`이 있을 때만 대상입니다. Go 모듈 vendoring(추적 중인 `go.mod` 옆에 있고 `vendor/modules.txt`도 추적 중인 경우)은 Go가 지원하는 방식이므로 대상이 아닙니다. 직접 만든 `src/vendor/` 모듈은 vendored가 아니므로 대상이 되지 않습니다.
  - Rails importmap 고정 패키지는 대상이 아닙니다. `vendor/` 옆에 `config/importmap.rb`가 추적 중이면 `vendor/javascript/`의 파일은 `bin/importmap pin`이 일부러 커밋한 것이므로 세지 않습니다. 이때 나머지 하위 디렉터리는 하나씩 보고하므로, 커밋된 `vendor/bundle/`(설치된 gem)은 `vendor/bundle/`로 그대로 대상이 되고 제안하는 `git rm`은 고정 패키지를 건드리지 않습니다. `vendor/` 바로 아래의 파일(`vendor/jquery.min.js`)은 그대로 `vendor/`로 세되, 해결 방법은 `vendor/` 전체가 아니라 그 파일들을 하나씩(`git rm --cached vendor/jquery.min.js`, 최대 5개, 나머지는 개수로) 지정하고, 고정 패키지 안에 중첩된 의존성 디렉터리(`vendor/javascript/node_modules/`)도 그대로 대상입니다.
  - 디렉터리를 Git에 남기기 위한 placeholder 파일(`.keep`, `.gitkeep`. 예: `rails new`가 만드는 `vendor/.keep`)은 세지 않습니다.
  - `third_party/`는 의도적으로 복사해 둔 코드가 대부분이므로 대상이 아닙니다.
  - 바깥 디렉터리가 대상이 아닐 때(Go 모듈 `vendor/`, `third_party/`)도 그 안의 `node_modules/`, `bower_components/`, `jspm_packages/`, `Pods/`는 대상입니다(예: `vendor/node_modules/`). 대상이 아닌 디렉터리 안의 발견 항목도 그대로 vendored 제안으로 표시됩니다.

비밀정보는 개인 키, 잘 알려진 토큰 형식(AWS, GitHub, Slack, Stripe, Google API 키), URL 속 비밀번호(`postgres://user:password@host`), 일반적인 자격 증명 대입(`password = ...`, `api_key: ...`, `password := ...`, `headers["x-api-key"] = ...`, 타입 표기가 붙은 선언이나 `cond ? "..." : ...`처럼 조건 뒤에 오는 따옴표 값 포함)입니다. 일반 대입은 값이 충분히 무작위로 보이는 리터럴이고 placeholder가 아닐 때만 인정합니다. URL 속 비밀번호는 placeholder(`user:pass`, `${DB_PASSWORD}`, `$DB_PASSWORD`, 사용자 이름과 같은 값)가 아니면 보고하며, 짧거나 단순한 비밀번호는 낮은 신뢰도로 보고합니다. 소스 파일에서 확실히 코드로 보이는 줄의 따옴표 없는 값(타입, 매개변수 목록, 상수·변수 이름)은 자격 증명으로 보지 않습니다. 여러 줄 문자열(템플릿 리터럴, `"""` 블록, heredoc, raw 문자열)을 포함해 문자열 리터럴 안의 줄은 코드로 보지 않으며, 파일을 확실히 읽을 수 없을 때(예: 닫히지 않은 문자열)는 보고합니다. 탐지는 패턴 기반이라 흔하지 않은 형태는 여전히 놓칠 수 있습니다.

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

### 서드파티·vendored 코드의 제안

저장소에 커밋된 서드파티 의존성 코드의 발견 항목은 일반 발견 항목이 아니라 제안으로 표시됩니다. 사용자가 소유한 코드가 아니고 그 자리에서 고칠 수도 없기 때문입니다. 이 항목들은 테스트·fixture 그룹 뒤, 맨 마지막에 **Suggestions: in third-party/vendored code (N)** 그룹으로 표시되며 "This code is a committed dependency, not your code. Review it if it's unexpected; otherwise consider removing it from Git."(커밋된 의존성 코드이며 사용자의 코드가 아님. 예상치 못한 것이면 검토하고, 아니면 Git에서 제거를 고려) 안내가 붙습니다. 규칙, 심각도, 근거는 그대로이지만 신뢰도(confidence)는 최대 `low`로 제한됩니다. 상단 개수와 심각도 차트에는 포함되지 않습니다(예: `Findings by severity (3 total) - plus 2 in test or fixture code, 5 suggestions in vendored code (1 high)`. 제안 중 critical·high 항목은 합계에 묻히지 않도록 괄호 안에 개수를 보여 줍니다). `node_modules/`에 커밋된 실제 비밀정보도 노출된 것이므로 이 항목들은 버리지 않습니다. coverage, 전체 상태, 종료 코드는 바뀌지 않습니다. CLI, 대시보드(같은 필터 적용), HTML/PDF 보고서가 모두 같은 방식으로 묶으며, `PG-HYGIENE-001` 제안([Git 이력 검사](#git-이력-검사) 참고)도 같은 그룹에 표시됩니다.

분류는 파일 내용이 아니라 경로로만 합니다. 경로의 디렉터리가 다음에 해당하면 vendored 코드입니다.

- 경로 어디에 있든 정확히 `node_modules`, `bower_components`, `jspm_packages`, `Pods`인 경우, 또는
- 정확히 `vendor` 또는 `third_party`인 경우. **단** 그 앞의 디렉터리 중에 `src`, `app`, `lib`가 있으면(대소문자 무관, 따라서 `Src/vendor/`도 사용자의 코드) 제외합니다. 이 이름들은 직접 만든 모듈 이름으로도 흔하므로(`nest g module vendor`는 `src/vendor/`를 만듦) `src/vendor/vendor.service.ts`, `packages/web/src/third_party/a.ts`, `app/vendor/client.rb`는 사용자의 코드로 봅니다.

그 밖에:

- 디렉터리 이름 전체가 일치해야 합니다. vendored 이름은 대소문자를 구분합니다. 패키지 관리자는 정확히 그 이름으로 만들고, 소문자 `pods/`는 Kubernetes 설정인 경우가 많기 때문입니다. `src/vendored.ts`, `my_node_modules_x/index.js`, `Vendor/`, `k8s/pods/`는 vendored가 아닙니다.
- 프로젝트나 패키지 최상위에 있는 Go와 PHP(Composer)의 `vendor/` 디렉터리(`vendor/`, `api/vendor/`)는 둘 다 의존성 사본이므로 모두 해당합니다.
- `dist/`, `build/` 같은 빌드 결과물은 사용자 자신의 산출물이므로 vendored가 아닙니다.
- vendored이면서 테스트 코드이기도 한 경로(`node_modules/pkg/test/a.js`)는 vendored로 봅니다.

HTML·PDF 보고서는 같은 가려진 결과로 만듭니다. HTML 보고서는 스크립트가 없고 엄격한 CSP를 쓰는 단일 파일입니다. 보고서는 사용자가 지정한 디렉터리에만 저장되고, 기존 파일을 덮어쓰지 않으며, 권한 `0600`으로 만들어집니다. 실수로 커밋되지 않도록 보고서는 저장소 밖에 보관하세요.

## 대시보드

`pgard dashboard`는 현재 디렉터리의 Git 루트를 찾아 보여 주고 `Start the dashboard for this project? [y/N]`을 묻습니다. 대화형 터미널이 필요하며, 없으면 종료 코드 2로 끝납니다. 확인하면 로컬 웹 앱을 시작하고 개인 세션 URL을 출력합니다.

```text
PGARD dashboard is running on 127.0.0.1 only.
Open this private session URL in your browser (valid until you stop the dashboard): http://127.0.0.1:<port>/#token=<random>
```

대시보드는 CLI 결과를 읽지 않고 직접 검사합니다. 권한 확인 결과와 GitHub device 코드를 보여 주고, 로컬 서비스 선택·확인, 범위 선택, 진행 상황 확인, 발견 항목 필터(테스트·fixture 항목과 vendored 코드의 제안은 각각 별도 그룹), HTML/PDF 보고서 내보내기를 제공합니다. OS 키체인에 저장된 GitHub 로그인은 서버 쪽에서 다시 사용하며, 토큰은 브라우저로 보내지 않습니다. 로그아웃 버튼은 두 가지입니다. **End dashboard session (keep keychain sign-in)** 버튼은 이 대시보드의 세션만 끝내고 다음 확인 때 키체인 로그인을 다시 사용합니다. **Sign out and remove from OS keychain**은 저장된 로그인도 지웁니다(CLI에서도 지워짐). 대시보드가 실행되는 동안 `pgard login`으로 다른 GitHub 계정으로 바꾸면 대시보드는 마지막 확인 결과를 버리므로, 로컬 서비스 탐색과 probe에는 새 확인이 필요합니다. Ctrl+C로 종료하면 대시보드의 GitHub 세션이 끝나고(키체인 로그인은 유지) 모든 결과를 버립니다.

device 코드가 필요하면 대시보드는 **Open the GitHub sign-in page** 버튼을 보여 주고, `pgard dashboard --no-browser`가 아니면 페이지를 직접 엽니다. 권한 확인 패널이 이 저장소에 PGARD GitHub App이 설치되지 않았다는 이유로만 차단되었고 본인이 승인할 수 있으면(또는 GitHub가 아직 조직 역할을 보여 주지 못하면. 문구는 CLI와 같음) **Install the PGARD GitHub App** 버튼(새 탭에서 열림)을 보여 주고, 최대 10분 동안 5초마다 owner 승인을 다시 확인한 뒤 전체 확인을 자동으로 다시 실행합니다. 두 제한은 서버가 강제합니다. 재확인은 5초에 한 번까지, 확인이 끝난 때부터 10분 안에만 허용되므로 패널을 새로 고쳐도 기다리는 시간이 늘어나지 않습니다. 그렇지 않으면 CLI와 같은 `Ask an owner of <account> ...` 링크를 보여 줍니다.

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
- 외부 네트워크 통신은 GitHub뿐입니다. device flow 로그인(및 저장된 로그인 갱신)과, 권한 확인에 필요한 메타데이터(사용자 신원, App 설치, 조직 멤버십(조직 저장소인 경우), 접근 권한, 기여)를 읽는 GitHub API 호출입니다. 기여를 확인하기 위해 로컬 커밋의 SHA를 GitHub에 보냅니다(검증된 owner일 때는 로컬 이력이 기본 브랜치와 커밋을 공유하는지 확인하는 데만 사용). `pgard doctor`는 `api.github.com` 연결 가능 여부도 확인합니다.
- 권한 확인을 통과한 뒤, PGARD는 서비스의 정체를 보여 주기 위해 `127.0.0.1`에서 발견한 각 열린 포트에 `GET /`를 한 번 보냅니다. 이후 웹 검사는 사용자가 확인한 서비스에만 요청을 보냅니다.
- PGARD는 취약점 데이터베이스를 포함하거나 내려받거나 조회하지 않습니다.

## MVP 범위 밖

- 데이터베이스 직접 접속
- Docker·컨테이너 설정
- 성능·부하 테스트
- 원격(loopback이 아닌) 서비스 검사
- 공격 요청, 폼 제출 등 상태를 바꾸는 요청
- 로그인한 상태의 웹 탐색(#45). `web:authenticated` 영역은 항상 `not_selected`이며, PGARD는 애플리케이션 비밀번호를 묻지 않습니다.
- 의존성 취약점(CVE/advisory) 조회: PGARD에는 취약점 데이터베이스가 없습니다.

## 알려진 제한 사항

- [#44](https://github.com/JadenMeister/pgard/issues/44) PDF 보고서는 Latin-1 밖의 문자(예: 한국어)를 `?`로 바꿉니다. 전체 텍스트는 HTML 보고서를 사용하세요.
- [#45](https://github.com/JadenMeister/pgard/issues/45) 로그인한 상태의 웹 탐색은 지원하지 않습니다. MVP 범위 밖입니다([MVP 범위 밖](#mvp-범위-밖) 참고).
- 검증된 owner가 아닌 사용자의 기여는 보수적으로 확인합니다. co-author trailer와 서명 없는 직접 push는 기여로 인정하지 않으므로, 커밋을 공동 작성만 했거나 서명 없이 push한 협력자는 본인의 pull request가 merge되거나 서명된 커밋을 push할 때까지 기여에서 차단됩니다.
- [#143](https://github.com/JadenMeister/pgard/issues/143) 키체인 로그인 리뷰의 후속 작업: 키체인 저장과 삭제 사이의 짧은 경쟁 상태, 토큰 갱신 중 대시보드 세션만 끝내는 로그아웃을 하면 다음 사용 때 새 device 코드를 요구할 수 있는 문제, `pgard login`으로 계정을 바꾼 뒤에도 대시보드가 이전 계정의 포트 접근을 최대 30분 유지하는 문제(검사는 권한을 다시 확인함).
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

### 설계 문서

PGARD는 [`docs/`](docs/)에 있는 기획 문서 세 개를 바탕으로 구현했습니다.

- [`PGARD_AGENT_BRIEF_KO.md`](docs/PGARD_AGENT_BRIEF_KO.md): 구현 브리프입니다. 제품 범위, 권한 게이트, 검사 경계, 완료 조건을 정했습니다.
- [`PGARD_CLI_AND_STRUCTURE_KO.md`](docs/PGARD_CLI_AND_STRUCTURE_KO.md): CLI 명령 체계와 앱·패키지 구조를 정했습니다.
- [`PGARD_DEVELOPMENT_CONVENTIONS_KO.md`](docs/PGARD_DEVELOPMENT_CONVENTIONS_KO.md): 커밋 단위, 메시지, 네이밍, 검증, PR 규칙을 정했습니다.

구현하면서 나중에 바뀐 결정이 있어서, 이 문서들과 README가 다르면 README와 코드가 맞습니다.

## 라이선스

[MIT](LICENSE)
