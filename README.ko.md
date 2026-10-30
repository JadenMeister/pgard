<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand/pgard-symbol-light.png" />
    <img src="docs/assets/brand/pgard-symbol.png" alt="PGARD" width="120" />
  </picture>
</p>

# PGARD

[![CI](https://img.shields.io/github/actions/workflow/status/JadenMeister/pgard/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white)](https://github.com/JadenMeister/pgard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/JadenMeister/pgard?color=blue)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-22.23.4%20%7C%2024.22.1%20%7C%2026.12.1-339933?logo=nodedotjs&logoColor=white)](#요구-사항)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)](tsconfig.base.json)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey?logo=apple&logoColor=white)](#요구-사항)
[![Status: pre-release](https://img.shields.io/badge/status-pre--release-orange)](#알려진-제한-사항)
[![Data stays local](https://img.shields.io/badge/data-stays%20local-2ea44f)](#개인정보와-네트워크-통신)
[![Last commit](https://img.shields.io/github/last-commit/JadenMeister/pgard/main)](https://github.com/JadenMeister/pgard/commits/main)

[English](README.md) | 한국어

PGARD(`pgard`)는 검사 권한이 있는 GitHub 프로젝트를 위한 로컬 보안 검사 도구입니다. 사용자 컴퓨터에서 명령줄 도구와 로컬 웹 대시보드로 동작합니다. 현재 코드·설정, Git 이력, 그리고 (선택 시) `127.0.0.1`에서 실행 중인 웹 서비스를 검사합니다. 발견 항목은 코드 자체로 판정하며, 검사는 취약점 데이터베이스를 내려받거나 조회하지 않습니다([코드 기반 분석](#코드-기반-분석) 참고). 이후의 의존성 검사를 위해 공개 OSV 데이터를 내려받는, 사용자가 직접 실행하는 선택 명령이 있습니다([개인정보와 네트워크 통신](#개인정보와-네트워크-통신) 참고).

PGARD는 검사할 때마다 저장소 owner가 PGARD를 승인했는지, 사용자가 지금 저장소에 접근할 수 있는지, 사용자가 저장소의 owner이거나 실제로 기여했는지를 확인합니다. 코드와 결과는 사용자 컴퓨터를 벗어나지 않습니다.

PGARD는 활발히 개발 중인 사전 출시(pre-release) 버전입니다. 첫 릴리스(v0.1.0)를 계획하고 있습니다. PGARD는 모든 취약점을 찾지는 못하며, "발견 없음"이 "안전"을 뜻하지 않습니다.

> **현재 상태:** PGARD에는 PGARD GitHub App의 client id가 내장되어 있어 로그인에 별도 설정이 필요 없습니다. 검사하려면 여전히 저장소를 소유한 계정, 즉 본인의 개인 계정이나 본인이 owner인 조직에 App이 설치되어 있어야 합니다([권한 확인 모델](#권한-확인-모델) 참고).

PGARD는 [MIT 라이선스](LICENSE)로 배포됩니다.

## 목차

- [정책](#정책)
- [요구 사항](#요구-사항)
- [설치와 빌드](#설치와-빌드)
- [명령](#명령)
- [권한 확인 모델](#권한-확인-모델)
- [검사 범위와 coverage](#검사-범위와-coverage)
- [분석기와 규칙](#분석기와-규칙)
- [코드 기반 분석](#코드-기반-분석)
- [로컬 웹 검사](#로컬-웹-검사)
- [Git 이력 검사](#git-이력-검사)
- [프로젝트 설정 파일](#프로젝트-설정-파일)
- [결과와 보고서](#결과와-보고서)
- [대시보드](#대시보드)
- [개인정보와 네트워크 통신](#개인정보와-네트워크-통신)
- [범위 밖](#범위-밖)
- [정확도](#정확도)
- [알려진 제한 사항](#알려진-제한-사항)
- [개발](#개발)
- [라이선스](#라이선스)

## 정책

PGARD가 따르는 규칙입니다. 항목마다 정책의 내용을 설명하고, 전체 내용이 적힌 곳으로 연결합니다. 이 README와 [`docs/RESULT_SCHEMA.ko.md`](docs/RESULT_SCHEMA.ko.md)는 현재 동작을 설명합니다. [`docs/`](docs/README.ko.md)의 한국어 기획 문서는 MVP 기획 기록이며, 내용이 다르면(예를 들어 기획 문서는 advisory 데이터베이스를 제외했지만, PGARD에는 이제 사용자가 직접 실행하는 공개 OSV 데이터 다운로드가 있습니다. npm과 Go의 lockfile 버전을 이 데이터와 오프라인으로 대조합니다) 이 README가 맞습니다.

- **권한 확인 게이트.** 저장소, GitHub 신원, owner 승인, 현재 접근, 기여의 다섯 가지 확인을 Git 기록, 로컬 웹 서비스, 저장된 결과를 검사할 때마다 다시 실행합니다. 건너뛰거나 이전 결과를 재사용하는 옵션은 없으며, 근거가 없거나 불분명하면 검사를 차단합니다(종료 코드 3). [권한 확인 모델](#권한-확인-모델) 참고.
- **코드 전용 검사.** 모든 검사는 먼저 권한을 확인합니다. `pgard scan`이나 `pgard scan code`에서 확인이 실패하면 터미널에서 "Git 기록은 빼고 현재 코드만 검사할까요? (권한 미확인으로 표시됩니다) [y/N]"라고 묻고, `--code-only`를 주면 확인을 건너뜁니다(로그인·네트워크 없음). 코드 전용 결과는 어떤 폴더든 현재 파일을 검사하고, 저장하지 않으며, 언제나 "코드 전용 검사: 권한 미확인"을 표시합니다(JSON과 SARIF는 `scanBasis`). [코드 전용 검사](#코드-전용-검사--code-only) 참고.
- **조직 저장소.** 조직 저장소는 조직의 활성 owner만 검사할 수 있으며, PGARD GitHub App이 조직에 설치되어 해당 저장소를 포함해야 합니다. [조직 저장소](#조직-저장소) 참고.
- **로컬 처리와 네트워크 통신.** 코드, Git 이력, 결과는 사용자 컴퓨터에서 처리되며 업로드되지 않습니다. 검사가 연결하는 곳은 로그인과 권한 확인 메타데이터를 위한 GitHub뿐입니다. 그 밖의 유일한 대상은 OSV 내보내기 호스트이며, 사용자가 `pgard advisories update`를 직접 실행할 때만 연결합니다. 공개 데이터를 내려받을 뿐 아무것도 업로드하지 않습니다. [개인정보와 네트워크 통신](#개인정보와-네트워크-통신) 참고.
- **자격 증명.** GitHub 토큰은 OS 키체인에만 저장하고, 키체인이 없으면 메모리에만 보관합니다. 파일에 쓰거나 출력하거나 로그에 남기거나 브라우저로 보내지 않습니다. `pgard logout`은 저장된 로그인을 지웁니다(GitHub의 토큰을 폐기하지는 않습니다). [저장된 로그인](#저장된-로그인os-키체인) 참고.
- **민감정보 가림.** PGARD가 인식한 비밀정보는 터미널 출력, 발견 항목, HTML/PDF 보고서, 대시보드에서 비밀의 종류로 대체됩니다. 무엇을 비밀로 보는지는 [Git 이력 검사](#git-이력-검사)에 정의되어 있으며, [결과와 보고서](#결과와-보고서)도 참고하세요. 탐지는 패턴 기반이므로 특이한 형태는 놓칠 수 있습니다.
- **로컬 웹 대시보드 보안.** `127.0.0.1`에서만 수신하고, 세션마다 토큰을 요구하며, `Host`와 `Origin` 헤더를 검사하고, 엄격한 Content-Security-Policy를 적용하며, 보고서는 파일을 쓰지 않고 브라우저 다운로드로 제공합니다. [대시보드 보호 방식](#대시보드-보호-방식) 참고.
- **웹 검사.** 검사는 `127.0.0.1`에 익명 `GET`/`HEAD` 요청만 보내며, 사용자가 확인한 서비스에만 보냅니다(권한 확인 후 발견한 각 로컬 포트에는 정체를 확인하는 `GET /` 한 번만 보냅니다). PGARD는 POST/PUT/DELETE 요청이나 폼 제출을 보내지 않지만, 잘못 만들어진 앱은 `GET` 요청에도 상태가 바뀔 수 있습니다. [로컬 웹 검사](#로컬-웹-검사) 참고.
- **결과 스키마 버전 관리.** 검사 결과는 `major.minor` 형식의 `schemaVersion`을 가지며, 읽는 쪽은 다른 major 버전을 거부합니다. [`docs/RESULT_SCHEMA.ko.md`](docs/RESULT_SCHEMA.ko.md) 참고.
- **저장된 결과.** `pgard scan`은 민감정보를 가린 결과를 로컬에 보관합니다(저장소당 최근 20회, 90일, macOS·Linux에서 본인만 읽기 가능, 업로드 없음). 권한 확인 게이트는 캐시하지 않으며 검사할 때마다 다시 실행합니다. 저장된 결과에는 결과가 담는 내용이 그대로 들어가며, 권한 확인 사유(GitHub 로그인, 조직 이름과 역할)도 포함되므로 이 폴더는 비공개로 다루세요. 끄려면 `--no-store` 또는 `PGARD_NO_STORE=1`, 삭제는 `pgard history clear --all`. 대시보드 검사는 저장하지 않습니다. [저장된 결과](#저장된-결과) 참고.
- **범위 밖.** 원격 서비스, 공격 요청이나 상태를 바꾸는 요청, 로그인한 상태의 웹 탐색, npm과 Go 이외 생태계의 의존성 권고, 도달 가능성·악용 가능성 분석 등은 아직 지원하지 않습니다. [범위 밖](#범위-밖) 참고.
- **개발 컨벤션.** 커밋 단위와 메시지, 브랜치·PR 경계, 이슈·프로젝트 보드·병합 전 리뷰 운영은 한국어 문서 [`PGARD_DEVELOPMENT_CONVENTIONS_KO.md`](docs/PGARD_DEVELOPMENT_CONVENTIONS_KO.md)에 있습니다. [개발](#개발)도 참고하세요.

## 요구 사항

- Node.js 22.23.4, 24.22.1, 26.12.1 이상(같은 버전 라인의 더 새로운 패치 포함). [2026년 10월 21일 Node.js 보안 릴리스](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)에서 고친 취약점이 반영된 버전입니다. 원격 코드 실행으로 이어질 수 있는 Brotli 디코더 범위 밖 쓰기(CVE-2026-111497)와 TLS 호스트 이름 검증 우회가 여기에 포함됩니다. PGARD는 `fetch`와 TLS로 GitHub API를 호출하므로 이전 버전은 지원하지 않으며, `pgard doctor`의 Node.js 검사도 실패합니다. Node.js 20 이하와 홀수 버전 라인은 수정이 제공되지 않습니다. 버전은 `node --version`으로 확인하세요.
- Git
- macOS, Linux 또는 Windows. CI가 세 운영체제 모두에서 전체 테스트를 실행합니다. 로컬 포트 탐지는 macOS에서 `lsof`(실패하면 `netstat`으로 대체), Linux에서 `/proc/net/tcp*`, Windows에서 `%SystemRoot%\System32\netstat.exe`를 사용합니다. 포트는 언제든 직접 입력할 수 있습니다.
- Windows 참고: 로그인은 Windows 자격 증명 관리자에 보관되고, 브라우저는 `explorer.exe`로 열립니다. Windows에는 `0600` 같은 권한 모드가 없어 보고서를 그 모드로 만들 수 없습니다. 보고서는 선택한 폴더의 기본 권한을 따르므로 본인만 읽을 수 있는 폴더를 고르세요. 터미널 출력: `NO_COLOR`는 색상만 끕니다. `TERM=dumb`는 색상을 끄고, Windows가 아닌 시스템에서는 텍스트도 ASCII로 바꿉니다. Windows에서는 호스트가 Windows Terminal, VS Code 또는 비슷한 터미널이 아니면 텍스트가 ASCII이고, 색상은 호스트와 관계없이 켜진 상태로 유지됩니다.
- GitHub 계정([GitHub App과 로그인](#github-app과-로그인) 참고)
- 언어: 영어 또는 한국어이며 자동으로 정해집니다. `--lang en|ko`가 가장 먼저이고, 다음은 `PGARD_LANG`, 그다음은 시스템 언어(`LC_ALL`, `LC_MESSAGES`, `LANG`, Windows는 OS 언어)입니다. 한국어 로캘일 때만 한국어가 나오고 그 밖에는 모두 영어입니다. 한국어 시스템에서 영어로 쓰려면 `PGARD_LANG=en`을 설정하세요.

## 설치와 빌드

### npm 또는 Homebrew로 설치(첫 릴리스부터)

첫 릴리스(v0.1.0 예정)는 아직 배포되지 않았습니다. 그때까지 npm 이름 `pgard`는 CLI가 없는 자리 표시용 패키지(0.0.1)가 선점하고 있습니다. `npm install -g pgard`는 이 자리 표시용 패키지만 설치하며 `pgard` 명령은 생기지 않습니다. 릴리스 전에는 아래처럼 소스에서 설치하세요. 첫 릴리스 이후에는 다음과 같이 설치합니다.

```sh
npm install -g pgard   # `pgard` 명령 설치
npx pgard doctor       # 설치 없이 한 번 실행
```

Homebrew(macOS, Linux)로는 첫 릴리스 이후 다음과 같이 설치합니다.

```sh
brew tap jadenmeister/pgard   # 처음 한 번
brew install pgard            # 업데이트: brew upgrade pgard
```

한 줄로 `brew install jadenmeister/pgard/pgard`를 실행해도 됩니다. tap이 자동으로 추가됩니다.

패키지 이름과 명령은 모두 `pgard`입니다. 버전과 릴리스 절차는 [docs/RELEASING.ko.md](docs/RELEASING.ko.md), 변경 내역은 [CHANGELOG.md](CHANGELOG.md)에 있습니다.

### 소스에서 빌드

소스에서 빌드합니다.

```sh
git clone https://github.com/JadenMeister/pgard.git
cd pgard
npm ci
npm run build          # TypeScript 패키지와 대시보드 UI(Vite)
npm link -w @pgard/cli # 선택: PATH에 `pgard` 등록
```

`npm link` 없이 실행하려면 저장소에서 `node apps/cli/dist/bin/pgard.js <명령>`을 사용합니다.

### 패키지를 로컬에서 빌드하기

배포물은 CLI, 대시보드, PDF 글꼴, tree-sitter 문법과 사용하는 순수 JavaScript 서드파티 라이브러리를 하나로 묶은 npm 패키지 `pgard`입니다(라이브러리 버전은 패키지를 만들 때 고정됩니다. [SECURITY.md](SECURITY.md#supply-chain)와 [NOTICE.md](NOTICE.md) 참고). npm에서 의존성으로 설치되는 것은 `@napi-rs/keyring`과 `web-tree-sitter`뿐입니다. 아직 배포하지 않았습니다. 빌드하고, 설치했을 때 동작하는지 확인하려면 다음을 실행합니다.

```sh
npm run pack:pgard   # 빌드 후 .pack/pgard-<버전>.tgz 생성(git 추적 제외)
npm run smoke:pack   # 그 tarball을 임시 디렉터리에 설치해 실행
```

`smoke:pack`은 `pgard --version`, `--help`, `scan code --help`, `help scan`, `rules list`, `doctor`를 실행하고, 내장 글꼴로 한국어 PDF를 만들며(대체 글꼴이면 실패), 문법 하나를 불러오고, 대시보드 서버를 시작합니다. CI도 Linux, macOS, Windows에서 같은 단계를 실행합니다.

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
  pgard <command> [options]
  pgard help <command> [<subcommand>]   same as pgard <command> --help

Common commands:
  pgard                         interactive menu (arrow keys, Enter, Esc, ?)
  pgard scan                    code and configuration + Git history (the default
                                scan; see "pgard scan --help" for what it does)
  pgard scan code               current code and configuration
  pgard scan --code-only        current code only, no GitHub sign-in or approval,
                                any folder (also without Git); not verified
  pgard scan history            Git history and tracked files (secrets, risky files)
  pgard report                  build a report from the last stored scan of this
                                repository (no new scan) and open it
  pgard sbom                    write a CycloneDX SBOM of the dependencies in this
                                repository's lockfiles (local files only)
  pgard project verify          check repository, GitHub identity, owner approval,
                                current access and merged contribution
  pgard precommit               check the staged changes for secrets and risky
                                patterns (for a Git pre-commit hook; code-only,
                                no sign-in needed)
  pgard login                   sign in to GitHub once and save it in the OS keychain
  pgard doctor                  diagnose the environment (not an authorization)

Common options:
  --lang en|ko                  language of the screen, progress and rule texts
                                (scan, report, rules list)
  --format text|json|sarif      scan output (scan); html|pdf (report)
  --report html|pdf|both        save a report after a scan, with --output-dir DIR
                                (scan only)
  --output-dir DIR              existing directory for saved reports (scan, report)
  --no-browser                  print GitHub links instead of opening them
                                (scan, project verify, login, dashboard, web)
  --help                        help for a command, e.g. pgard scan code --help

Advanced commands:
  pgard scan web [--port N]     anonymous read-only checks of a local HTTP service
  pgard scan all [--port N]     code + history + local HTTP service
  pgard dashboard [--target-port N]
                                start the local web dashboard for this project
  pgard web [--no-store]        choose a folder in the browser and scan it
                                (macOS and Linux)
  pgard web scope list | add <folder> | remove <folder>
                                the folders pgard web searches for projects
  pgard rules list [--language js|ts|react|vue|go|java|kotlin|python|php] [--lang en|ko]
  pgard history clear --all | --repo owner/name
  pgard baseline set [--from-current] | show | clear
  pgard advisories update       download public OSV vulnerability data (npm, Go)
  pgard logout                  remove the saved GitHub sign-in from the OS keychain
  pgard --version

Advanced options (pgard <command> --help has the details):
  scan:        --all-findings  --fixes  --panels  --full  --no-store  --report-lang en|ko
               --port N (web, all)
  report:      --no-open
  dashboard:   --target-port N
  web:         --no-store
  rules list:  --language <name>
  history clear:     --all  --repo owner/name
  baseline set:      --from-current
  advisories update: --force
  precommit:         install | uninstall | snippet  --lang en|ko
```

| 명령                      | 역할                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pgard`                   | 대화형 메뉴: 확인, 검사, 대시보드, 규칙, 진단, 종료.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `pgard project verify`    | 권한 확인을 실행하고 항목별(저장소, GitHub 신원, owner 승인, 현재 접근 권한, 기여)로 통과·실패·확인 불가와 이유를 보여 줍니다. 결과는 저장하지 않습니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `pgard precommit`         | 스테이징된 변경에서 비밀정보와 위험한 패턴을 검사합니다(Git 훅): `install`, `uninstall`, `snippet`. [커밋 전 검사](#커밋-전-검사pgard-precommit) 참고.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `pgard scan`              | `code` + `history`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `pgard scan code`         | 권한 확인 뒤 현재 소스 코드와 설정을 검사합니다. 확인이 실패하면 터미널에서 코드 전용으로 검사할지 묻고, `--code-only`를 주면 확인을 건너뜁니다. [코드 전용 검사](#코드-전용-검사--code-only) 참고.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `pgard scan history`      | 커밋된 `.env` 파일, 추적 파일과 Git 이력 속 비밀정보.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `pgard scan web`          | 사용자가 확인한 `127.0.0.1` 로컬 HTTP 서비스의 비로그인·읽기 전용 검사.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `pgard scan all`          | `code` + `history` + `web`. 웹 대상을 확인하지 못하면 결과는 `partial`입니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `pgard dashboard`         | 로컬 웹 대시보드를 시작합니다. [대시보드](#대시보드) 참고.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `pgard web`               | 프로젝트 없이 로컬 페이지를 시작합니다. 폴더를 고르고(시스템 선택 창 또는 붙여 넣은 경로) 검사를 누르면 찾은 문제가 나옵니다(macOS와 Linux). 권한 확인이 먼저 실행되고, 코드만 검사는 따로 눌러야 합니다. `--no-store`는 최근 목록을 이 컴퓨터에 남기지 않습니다. `pgard web scope list \| add <folder> \| remove <folder>`는 전체 대시보드의 검색 선택기가 검색할 폴더를 터미널에서만 관리합니다. [프로젝트 고르기](#프로젝트-고르기-pgard-web) 참고.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `pgard rules list`        | 범위별(코드, Git 이력, 로컬 HTTP, 범위를 알 수 없는 규칙은 "Other rules")로 묶은 규칙 목록과 각 규칙의 심각도·언어, 판정 기준 버전, PGARD가 다루지 않는 영역(npm과 Go 이외 생태계의 의존성 권고 포함)을 보여 줍니다. 프로젝트 밖에서도 실행되며 네트워크 요청을 보내지 않습니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `pgard doctor`            | Node.js, Git, GitHub 연결, 로컬 포트 탐지, 어떤 GitHub App으로 로그인하는지(내장 PGARD App 또는 재정의용 `PGARD_GITHUB_APP_CLIENT_ID`), OS 키체인에 저장된 GitHub 로그인이 있는지(어느 계정인지, 토큰은 보여 주지 않음), 내려받은 advisory 데이터(있음 또는 없음, 내려받은 날짜와 경과 일수, 가장 최근 레코드의 날짜, 둘 중 하나라도 7일 이상 지나면 오래됨, 데이터 버전(저장 스키마와 압축 파일 SHA-256의 앞 12자), 저장 위치. 로컬 파일만 읽으며 네트워크를 쓰지 않음)를 진단합니다. 네트워크 요청은 `api.github.com`에 보내는 인증 없는 `HEAD` 하나뿐입니다. 진단일 뿐 권한 승인이 아닙니다. 프로젝트 밖에서도 실행됩니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `pgard advisories update` | 사용자가 직접 실행하는 명령으로, npm과 Go의 공개 OSV 대량 내보내기를 `osv-vulnerabilities.storage.googleapis.com`에서 내려받습니다(https만, 그 호스트만). 아무것도 업로드하지 않고 패키지 이름도 보내지 않습니다. 압축 파일을 검증(zip 구조, 레코드별 체크섬, 크기·시간 제한. OSV는 대조할 체크섬을 공개하지 않으므로 무결성은 그 호스트에 대한 https 신뢰, 즉 처음 받을 때 신뢰에 의존)한 뒤 압축된 색인으로 기존 데이터를 원자적으로 교체하며, 실패하면 기존 데이터가 그대로 남습니다. 가장 최근 레코드가 설치된 데이터보다 오래되었거나 레코드 수가 절반 미만이면 거부하며(오래된 압축 파일로 되돌리면 advisory가 누락될 수 있습니다), `--force`로 허용할 수 있습니다. 검사나 `doctor` 중에는 실행되지 않습니다. 생태계 하나라도 실패하면 종료 코드 4.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `pgard login`             | device flow로 GitHub에 로그인하고 OS 키체인에 저장하여 이후 검사와 대시보드가 다시 사용하게 합니다. 다시 실행하면 저장된 로그인을 바꿉니다. [저장된 로그인](#저장된-로그인os-키체인) 참고.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `pgard logout`            | OS 키체인에 저장된 GitHub 로그인을 지웁니다. [저장된 로그인](#저장된-로그인os-키체인) 참고.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `pgard report`            | 이 저장소에 마지막으로 저장된 검사로 HTML(기본) 또는 PDF(`--format pdf`) 보고서를 만들어 엽니다. 다시 검사하지 않습니다. 저장소 확인을 먼저 실행하고, 이 저장소의 GitHub id로 저장된 결과만 읽습니다(`pgard baseline`과 같은 규칙). 저장소를 확인하지 못하면 아무것도 읽지 않습니다(종료 코드 3). 저장된 검사가 없으면 먼저 `pgard scan`을 실행하라고 안내합니다(종료 코드 2). `--output-dir DIR`은 이미 있는 디렉터리를 지정하며, 파일 이름은 고정이고 파일은 모드 0600으로 만들어지며 절대 덮어쓰지 않습니다. Git 저장소 안의 디렉터리는 명시적인 확인이 필요합니다. `--output-dir`을 쓰지 않으면 실행할 때마다 시스템 임시 디렉터리 아래에 새 비공개 디렉터리(모드 0700)를 만들어 그 경로를 출력하므로 반복 실행해도 충돌하지 않습니다. Linux에서 snap으로 설치한 브라우저는 `/tmp`를 읽지 못할 수 있으니 그럴 때는 `--output-dir ~/Downloads`(또는 비슷한 경로)를 사용하세요. `--no-open`은 파일을 쓰고 경로만 출력합니다. 터미널이 아니거나 CI(`CI`, `GITHUB_ACTIONS`, `BUILDKITE`, `TF_BUILD`, `JENKINS_URL`, `TERM=dumb`)에서는 보고서를 절대 열지 않습니다. 검사 이후 HEAD가 바뀌었으면 한 줄로 알려 주며, 보고서 머리글에는 검사 시각과 커밋이 표시됩니다. `--lang en\|ko`로 언어를 정합니다. 대화형 메뉴에도 있습니다. `PGARD_NO_STORE=1`이면 거부합니다.                                                                                                                                                                                                                                                                                                                                          |
| `pgard sbom`              | 이 저장소의 lockfile(`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `go.mod`/`go.sum`)에 있는 패키지로 CycloneDX 1.6 JSON 소프트웨어 자재 명세서(SBOM)를 만듭니다. 이름, 버전, 패키지 URL(purl), 각 패키지가 나온 lockfile이 들어갑니다. 직접 의존성은 저장소 구성 요소에서 연결되며, PGARD의 파서는 나머지 패키지 사이의 연결과 범위(dev/prod)를 읽지 않으므로(일부 lockfile에는 기록되어 있습니다) 그래프는 `direct-only`(`pgard:dependency-graph`)로 표시하고 범위는 기록하지 않습니다. 모든 패키지는 이름과 버전으로 레지스트리 purl과 함께 나열되며, git·tarball URL·`file:` 경로에서 해석된 의존성은 아직 구분하지 않습니다. 읽지 못했거나 아직 지원하지 않는 lockfile(예: `composer.lock`)은 `pgard:unparsed-lockfile` 속성으로 나열하고 SBOM을 불완전(`pgard:complete`)으로 표시하므로, 빠진 패키지가 안전한 것으로 오해되지 않습니다. 로컬 파일만 읽으며 아무것도 업로드하지 않고 패키지 관리자나 빌드 도구도 실행하지 않습니다. 저장소를 읽으려면 `pgard report`와 같은 권한 확인이 필요합니다. 저장소 확인(GitHub에 연결)을 먼저 실행하고 실패하면 아무것도 읽지 않습니다(종료 코드 3). `--output-dir DIR`은 이미 있는 디렉터리를 지정하며, 파일 이름은 `pgard-sbom-<시각>-<커밋>.cdx.json`이고 모드 0600으로 만들어지며 절대 덮어쓰지 않습니다. Git 저장소 안의 디렉터리는 명시적인 확인이 필요합니다. 쓰지 않으면 실행할 때마다 시스템 임시 디렉터리 아래에 새 비공개 디렉터리(모드 0700)를 만들어 그 경로를 출력합니다. 경로와 이름은 검사 결과와 같은 가림 규칙을 거칩니다. `--format cyclonedx-json`이 유일한 형식이며 `--lang en\|ko`로 메시지 언어를 정합니다. |
| `pgard baseline`          | `set`은 이 저장소에 가장 최근에 저장된 검사를 기준선으로 보관하고(`--from-current`: 지금 검사하고 그 검사를 보관), `show`는 내용을 보여 주고, `clear`는 삭제합니다. 이후 검사는 기준선에 있는 발견 항목을 따로 나열하고 새 항목을 강조합니다. 숨기는 것은 없고 종료 코드는 바뀌지 않습니다. [기준선](#기준선baseline) 참고.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `pgard history clear`     | `pgard scan`이 이 컴퓨터에 저장한 검사 결과와 기준선을 삭제합니다. 옵션이 하나 필요합니다. `--all`은 전부, `--repo owner/name`은 한 저장소의 결과를 지웁니다. 업로드하지 않고 로그인도 필요 없습니다. [저장된 결과](#저장된-결과) 참고.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

`pgard rules list --language <lang>`은 해당 언어의 규칙만 보여 주며, 언어와 무관한 규칙(Git 이력, 로컬 HTTP 규칙)은 항상 포함되고, `--language react`나 `vue`는 JavaScript/TypeScript 규칙도 포함합니다.

**옵션 없는 `pgard scan`의 동작.** 권한 확인 뒤 저장소의 현재 코드와 설정, Git 이력을 검사합니다(로컬 웹 서비스는 검사하지 않습니다). 결과는 텍스트로 출력하고(터미널에서는 이어서 전체 화면 패널 보기가 저절로 열립니다), 저장소 안에는 아무것도 쓰지 않으며 보고서 파일도 저장하지 않습니다. 확인된 저장소의 완료된 검사는 이 컴퓨터의 앱 데이터 폴더에 저장되고(저장소당 최근 20건, 90일, 업로드되지 않음), 다음 검사는 그 이후 바뀐 부분만 봅니다. `--full`은 전부 다시 검사하고, `--no-store`는 아무것도 저장하지 않으며, `--report`와 `--output-dir`은 보고서를 저장하고, `scan web`이나 `scan all`은 로컬 HTTP 서비스를 더합니다.

모든 명령과 하위 명령에는 자체 도움말이 있으며(`pgard scan code --help`, `pgard rules list --help`, `pgard login --help`), `pgard help scan`이나 `pgard help rules list`도 같습니다. 도움말은 영어로만 제공합니다. 명령이 받는 모든 옵션이 그 명령의 도움말에 있는지 테스트가 확인합니다. `pgard scan --help` 출력(발췌):

```text
Options:
  --port N                 local service port 1-65535 (web and all only). You
                           still confirm the service identity with y/N.
  --code-only              (pgard scan, pgard scan code) skip authorization
                           and scan the current files code-only, with no
                           network; never exit 3
  --report html|pdf|both   save a report (requires --output-dir)
  --output-dir <dir>       existing directory for the report (requires --report);
                           files are never overwritten; a directory inside the
                           Git repository needs explicit confirmation
  --all-findings           list every finding in full (evidence, fix,
                           standards, every location). In a terminal the
                           default is compact: critical and high first, at most
                           10 groups of one or two lines, then "+N more"; test
                           and vendored code is counted, with its critical and
                           high findings and secrets listed. Not in a terminal
                           (pipe, file) the text is always the full form. It
                           also lists every suppressed finding (see
                           pgard.config.json) and every finding in the baseline
  --fixes                  also show a suggested-fix diff under the findings that
                           have one (implies --all-findings). A suggestion to
                           review: PGARD never applies it, writes to your files
                           or checks that it compiles or keeps behaviour
  --panels                 open the read-only full-screen view (summary, charts,
                           coverage, findings; keys: Tab, arrows, ? help, Esc
                           back, Ctrl+D leaves) after the text result. In a
                           terminal pgard scan already opens it by itself, but
                           not when CI, GITHUB_ACTIONS, BUILDKITE, TF_BUILD or
                           JENKINS_URL is set, or TERM=dumb. PGARD_PANELS=off
                           (also 0, false, no) turns it off: use it for script,
                           expect, VS Code tasks and docker run -it. --panels
                           still forces it (not with TERM=dumb); so does
                           PGARD_PANELS=on in CI. Never opens without a
                           terminal. Not with --format json or sarif. pgard
                           dashboard is the separate local web app
  --lang en|ko             language of the result screen, progress lines and rule
                           texts (default: PGARD_LANG, then the system locale,
                           then en). JSON and SARIF output are always English
  --report-lang en|ko      language of saved reports (default: the
                           --lang language)
  --format text|json|sarif json prints only the redacted result (schema in
                           docs/RESULT_SCHEMA.md) to stdout; sarif prints the
                           same result as SARIF 2.1.0 (for GitHub code
                           scanning; PGARD uploads nothing). Progress and
                           messages go to stderr. With web checks it needs --port
                           (prompts go to stderr). Exit codes are unchanged
  --no-browser             do not open GitHub pages (device sign-in, App
                           install) in the browser; the links are printed.
                           In a terminal, PGARD asks you to press Enter
                           before opening a page

If owner approval is the only failed check and the PGARD GitHub App just needs to
be installed, PGARD prints the install page link (in a terminal it opens after you press Enter), waits for it, re-runs the full
authorization and continues the scan.
```

### 옵션

- `--port N`(`scan web`, `scan all` 전용): 로컬 서비스 포트, 1~65535 정수. 지정해도 서비스 확인은 필요합니다.
- `--code-only`(`scan`과 `scan code` 전용): 권한 확인을 건너뛰고 코드 전용 검사를 실행합니다(로그인·네트워크·저장 없음). `pgard scan --code-only`는 `pgard scan code --code-only`와 같습니다. 다른 범위는 언제나 권한 확인이 필요하므로 이 옵션을 거부합니다(종료 코드 2). `--require-authorization`은 없어졌습니다. 이제 권한 확인이 먼저인 것이 기본입니다.
- `--target-port N`(`dashboard` 전용): 검사할 로컬 서비스를 미리 선택합니다. 브라우저에서 다시 확인합니다. 대시보드 자체는 별도의 빈 포트에서 실행됩니다.
- `--report html|pdf|both`와 `--output-dir <dir>`(모든 `scan`): 보고서를 저장합니다. 두 옵션은 함께 써야 합니다. 디렉터리는 이미 있어야 하고(맨 앞의 `~`는 홈 폴더로 바뀝니다) 기존 파일을 덮어쓰지 않습니다. 대화형 메뉴의 "보고서를 저장할까요?"는 "저장할 폴더 [~/Downloads]:"를 묻고, Enter를 누르면 기본 폴더(다운로드, 없으면 문서, 없으면 홈)에 저장합니다. 없는 폴더는 `y`를 누르면 만들 수 있습니다(권한 0700). Git 저장소 안의 디렉터리는 명시적인 `y`가 필요합니다(대화형 터미널이 없으면 거부). 기본값은 터미널에 결과만 표시하는 것입니다.
- `--panels`(모든 `scan`): 텍스트 결과 뒤에 그 결과를 읽기 전용 전체 화면으로 보여 주는 [패널 화면](#패널-화면)을 엽니다. 터미널에서는 메뉴든 `pgard scan …`이든 모든 스캔이 이 화면을 자동으로 열므로, 이 옵션은 `PGARD_PANELS=off`를 무시하고 열고 싶을 때만 필요합니다. `PGARD_PANELS=off`(`0`, `false`, `no`도 가능)로 자동 열림을 끌 수 있고, 명시적인 `--panels`가 이 설정보다 우선합니다. `--format json`, `sarif`와는 함께 쓸 수 없습니다(로그인·스캔 전에 사용법 오류 2). 터미널이 아니면(CI, 파이프, 리다이렉트) 절대 열리지 않으며 평소처럼 텍스트 결과만 출력되고, `--panels`를 준 경우 stderr에 한 줄 안내가 나갑니다. 로컬 웹 앱인 `pgard dashboard`와는 별개입니다.
- `--all-findings`(모든 `scan`): 터미널의 간단한 목록 대신 전체 내용을 출력합니다. 모든 발견 항목과 위치를 각자의 근거, 조치, 표준과 함께 나열하며 아무것도 접지 않습니다. 터미널에서 기본값은 간단한 목록이고([터미널 결과 화면](#터미널-결과-화면) 참고), 터미널이 아니면 텍스트는 항상 전체 형식입니다. 기본값에서는 그룹마다 위치를 최대 3개만 보여 주고(근거는 모든 항목이 같을 때만 한 번 보여 주며 다르면 다르다고 표시), 테스트·fixture·vendored 코드의 발견 항목이 5개를 넘으면 심각도가 낮은 항목을 요약으로 대체합니다([그룹화와 접기](#그룹화와-접기) 참고). 억제된 발견 항목과 기준선에 있는 발견 항목도 모두 나열합니다([억제](#억제suppressions), [기준선](#기준선baseline) 참고).
- `--fixes`(모든 `scan`, 텍스트 출력): `--all-findings`를 포함하며, 수정 제안이 있는 발견 항목 아래에 검토용 제안임을 밝힌 diff를 출력합니다. [수정 제안](#수정-제안)을 참고하세요. JSON과 SARIF에는 항상 수정 제안이 들어 있고, `--fixes`는 터미널 텍스트만 바꿉니다.
- `--format text|json|sarif`(모든 `scan`, 기본값 `text`): `sarif`는 대신 SARIF 2.1.0을 출력합니다([SARIF 출력](#sarif-출력) 참고). stdout, stderr, `--port`, 종료 코드는 `json`과 같은 규칙을 따릅니다. `json`은 가려진 스캔 결과만 stdout에 출력하며, 형식은 [docs/RESULT_SCHEMA.md](docs/RESULT_SCHEMA.md)와 같고 `readScanResult`로 읽을 수 있습니다. 진행 상황, 안내, 프롬프트는 stderr로 나가므로 `pgard scan code --format json > result.json`은 올바른 JSON입니다. 프롬프트는 stdout을 쓰지 않으며 `scan web`, `scan all`은 `--port`가 필요합니다(없으면 스캔 전에 사용법 오류 2로 종료). 종료 코드는 바뀌지 않습니다. JSON에는 항상 모든 발견 항목이 들어 있어 `--all-findings`는 영향이 없습니다. 여전히 가능한 프롬프트(`--port` 확인, GitHub App 설치 안내, 저장소 안에 보고서 저장)는 stdout이 파일로 리다이렉트되어 있어도 stdin과 stderr가 터미널이면 stderr에 표시됩니다. stdout에는 최종 결과 문서가 정확히 하나 출력되며, 권한 확인에 실패하면 blocked 결과가 출력됩니다. stdout이 비어 있는 경우는 사용법 오류(종료 코드 2), 취소, 저장소가 아닌 디렉터리(종료 코드 3), 내부 오류뿐입니다.
- `--lang en|ko`(모든 `scan`, `rules list`): 터미널에 표시되는 규칙 문구(제목, 영향, 조치)의 언어입니다. [규칙 문구의 언어](#규칙-문구의-언어) 참고.
- `--report-lang en|ko`(`--report`와 함께 쓰는 모든 `scan`): 저장되는 HTML·PDF 보고서 전체(규칙 문구만이 아님)의 언어이며, 기본값은 `--lang` 언어입니다.
- `--language js|ts|react|vue|go|java|kotlin|python|php`(`rules list` 전용): 언어별로 규칙 목록을 거릅니다. 언어와 무관한 규칙은 항상 포함되며, `react`와 `vue`는 JavaScript/TypeScript 규칙도 포함합니다.
- `--no-browser`(`scan`, `project verify`, `login`, `dashboard`, `web`): GitHub 페이지(device 로그인 페이지, App 설치 페이지)를 브라우저로 열지 않고 링크만 출력합니다. 이 옵션이 없으면 터미널(stdin과 stdout 모두)에서 링크를 출력한 뒤 `Press Enter to open github.com in your browser...`라고 묻고, Enter를 눌러야 페이지를 엽니다(다른 키는 무시). 로그인·설치 대기는 이 질문과 무관하게 진행되며, 대기가 끝나면 질문은 사라집니다. 터미널이 아니면 열지도 묻지도 않습니다. 링크는 항상 함께 출력하며, 브라우저를 열지 못해도 오류가 아닙니다.
- `--no-store`(`scan`과 `web`) 또는 환경 변수 `PGARD_NO_STORE=1`: 이번 검사 결과를 이 컴퓨터에 보관하지 않습니다. `pgard web`에서는 선택기의 파일을 읽지도 쓰지도 않습니다. 최근 목록이 없고, 저장된 검색 폴더도 쓰지 않습니다. `PGARD_NO_STORE=1`이면 `pgard web scope add`와 `remove`는 거부됩니다. 값이 정확히 `1`일 때만 적용됩니다. 이 경우 폴더도 안내문도 만들지 않으며 [기준선](#기준선baseline)도 읽거나 적용하지 않습니다. [저장된 결과](#저장된-결과) 참고.
- `--full`(`scan`만): 모든 것을 다시 검사합니다. 기본적으로 검사는 이 저장소에 마지막으로 저장된 검사를 바탕으로 바뀐 부분만 보며, 결과가 그렇게 했다고 알려 줍니다. 웹 검사는 항상 실시간입니다. [증분 검사](#증분-검사) 참고.
- `--all` 또는 `--repo owner/name`(`history clear`만, 둘 중 정확히 하나): 모든 저장소 또는 한 저장소의 저장된 결과를 삭제합니다. `--repo`는 결과 안에 저장된 `owner/name`과 대소문자 무시로 비교하며 오프라인에서 동작합니다. 저장소 이름을 바꾸거나 이전한 경우 이전에 저장된 결과에는 옛 이름이 들어 있으므로 그 이름을 쓰거나 `--all`을 쓰세요.
- `--help` / `-h`, `pgard --version` / `-V`.

알 수 없는 명령·옵션, 잘못된 값과 조합은 Git·GitHub·네트워크 작업 전에 거부됩니다. 알 수 없는 검사 종류(예: `dependencies`)는 종료 코드 2로 끝나며 올바른 값 `code`, `history`, `web`, `all`을 알려 줍니다.

### 코드 전용 검사(`--code-only`)

**권한 확인이 먼저.** `pgard scan`과 `pgard scan code`는 이전처럼 먼저 권한을 확인합니다. 확인이 실패하고(승인 없음, 확인을 실행하지 못함, GitHub 원격 없음, Git 저장소 아님) 표준 입력과 출력이 모두 터미널이면 이렇게 묻습니다.

```text
Git 기록은 빼고 현재 코드만 검사할까요? (권한 미확인으로 표시됩니다) [y/N]
```

N(기본값, Enter도 같음)은 평소의 승인 안내와 함께 종료 코드 3으로 끝납니다. y는 코드 전용 검사를 실행하며, `scanBasis.reason`에 권한을 확인하지 못한 이유가 남습니다. 터미널이 없으면(CI, 파이프, 파이프로 보내는 `--format json`/`sarif`) 묻지 않고 종료 코드 3과 "For a code-only scan, add --code-only." 한 줄로 끝납니다. `scan history`, `scan web`, `scan all`은 이 질문을 하지 않습니다.

`--code-only`(`pgard scan` 또는 `pgard scan code`)는 권한 확인을 건너뛰고 게이트와 네트워크 없이 **현재 파일**을 검사합니다. 내 컴퓨터에 있는 내 코드를 위한 검사이며, 편집기로 이미 열 수 있는 것만 읽습니다.

- **실행하는 것.** 소스 규칙(JavaScript, TypeScript, Vue, Go, Java, Kotlin, Python, PHP), 디스크에 이미 있는 OSV 데이터로 하는 의존성 확인(`pgard advisories update`), 디스크의 파일에 대한 비밀정보 검사(`secrets:working-tree`: `.env` 파일과 자격 증명, UTF-8과 UTF-16, 한도 있음. 빠뜨린 것이 있으면 영역이 partial이 되고 이름을 적습니다). 검사 대상 폴더 자신의 `pgard.config.json` `exclude`는 이 단계에 적용하지 않습니다(그 폴더가 파일을 숨기는 데 쓸 수 있기 때문이며, 메모에 무시한 패턴 수를 적습니다). 20초 제한은 엄격해서(응답 없는 네트워크나 FUSE 마운트가 있어도 제시간에 partial로 끝남) 심볼릭 링크로 바뀐 폴더는 따라가지 않고, 마운트 지점(다른 장치)은 이름을 적고 들어가지 않습니다. 취소는 `pgard web`에서도 즉시 돌아옵니다.
- **실행하지 않는 것.** GitHub 로그인, API 호출, 키체인 읽기, 네트워크 연결이 없습니다. Git 기록과 웹 검사도 없습니다. 결과, 증분 상태, 추세, 기준선 등 아무것도 저장하지 않습니다.
- **어떤 폴더든.** Git 저장소에서는 이전처럼 저장소 최상위 폴더부터 검사합니다. 최상위 폴더는 Git을 실행하지 않고 가장 가까운 `.git` 항목까지 올라가서(홈 폴더 위로는 올라가지 않음) 찾으므로, 저장소 자체의 `core.worktree` 설정이 검사를 다른 폴더로 보낼 수 없습니다. Git이 없는 폴더(zip 다운로드, 새 프로젝트)에서는 현재 폴더를 검사합니다. 한 프로젝트로 보기에 너무 넓은 폴더는 거부합니다(종료 코드 2): 파일 시스템 최상위 폴더, 최상위 바로 아래 폴더(`/Users`, `/home`, `/Volumes`, `/etc`, `C:\Users` 등), 홈 폴더 또는 그 위의 폴더입니다. 입력한 경로와 실제 경로를 모두 확인합니다(심볼릭 링크를 따라가므로 macOS의 `/tmp` -> `/private/tmp`도 해당하며, macOS와 Windows에서는 대소문자를 구분하지 않음). 별칭 경로(macOS `/System/Volumes/Data/...`, Windows `\\?\C:\...`, `\\host\C$\...`)와 동일성(장치·inode를 `/`, 홈 폴더, 그 상위 폴더와 비교)도 확인합니다. `/proc`, `/sys`, `/dev` 아래도 거부합니다. `HOME`이 비어 있으면 계정의 홈 폴더를 쓰고, 둘 다 알 수 없으면 검사를 거부합니다. 저장소의 최상위 폴더에도 같은 규칙을 적용하므로 홈 폴더에 있는 dotfiles 저장소는 통째로 검사하지 않습니다. 위로 올라가는 탐색은 홈 폴더에서 멈추고, 그런 저장소 안의 프로젝트 폴더는 그 폴더 자체로 검사하며, 홈 폴더 자체는 거부합니다. 자체 저장소가 있는 프로젝트 안에서 실행하세요. `.git` 폴더나 bare 저장소도 그 `config`에 자격 증명이 있을 수 있으므로 거부합니다. 다른 사용자 소유이거나 그룹·다른 사용자가 쓸 수 있는 폴더(홈 폴더 아래의 상위 폴더 포함)도 거부합니다. 웹 폴더 선택도 같은 공용 규칙으로 같은 폴더를 거부합니다. GitHub remote가 없는 저장소도 같은 방식으로 검사합니다. 대화형 메뉴의 항목 이름은 "현재 파일 검사(코드 전용)"이고, 패널 화면의 제목은 "! 코드 전용, 권한 미확인"으로 시작합니다.
- **표시.** 텍스트 결과의 첫 줄은 `! 코드 전용 검사: 권한 미확인(현재 파일만 검사, Git 기록·웹 검사 없음, 저장하지 않음).`이며(터미널 요약 끝에도 다시 나옵니다), 이어서 권한 있는 검사를 받는 방법을 안내합니다. `--format json`과 `--format sarif`에는 `scanBasis`가 들어갑니다(`mode: "code_only"`, `authorization: "not_verified"`, `reason`: `--code-only`면 `not_checked`, y를 고른 뒤면 `no_approval`·`check_failed`·`no_github_remote`, Git 밖이면 `not_a_git_repository`. 스키마 1.7, [docs/RESULT_SCHEMA.ko.md](docs/RESULT_SCHEMA.ko.md) 참고). SARIF는 `pgard/code-only/` 카테고리를 씁니다. 보고서(`--report`)는 모든 페이지에 "권한 미확인: 코드 전용 검사" 배너를 넣습니다.
- **종료 코드.** 코드 검사 범위가 완료되면 0(발견 항목이 있을 수 있음), partial이면 4, 사용법 오류는 2입니다. 3은 나오지 않습니다. 아무 확인도 하지 않으므로 막을 것이 없습니다.
- **엄격한 범위.** `scan history`, `scan web`, `scan all`은 그대로입니다. 게이트가 먼저 실행되고 막히면 종료 코드 3이며, "`pgard scan code --code-only`는 승인 없이 현재 파일을 검사합니다." 안내가 붙습니다. `pgard project verify`도 막히면 같은 안내를 덧붙이고, `pgard doctor`는 이를 `[info]` 줄로 보여 줍니다.

### 커밋 전 검사(`pgard precommit`)

`pgard precommit`은 **다음 커밋에 스테이징된 변경**에서 비밀정보와 위험한 패턴을 찾습니다. Git 훅으로 돌릴 수 있을 만큼 빠릅니다. `pgard precommit install`은 훅을 쓰고, `pgard precommit uninstall`은 훅을 지우며, `pgard precommit snippet`은 pre-commit 프레임워크나 husky에 넣을 줄을 출력합니다.

- **스테이징된 내용만.** 내용은 작업 트리가 아니라 Git 인덱스에서 읽습니다. 그래서 스테이징하지 않은 수정이 스테이징된 비밀정보를 가리거나 거짓 경보를 만들지 못합니다. `git commit -a`와 `git commit <path>`에서는 Git이 훅에 넘기는 임시 인덱스(`GIT_INDEX_FILE`)를 읽되, 이 저장소의 `.git` 안에 있는 일반 파일인지 먼저 확인합니다. PGARD가 이미 허용한 Git 명령(`ls-files -s`, `ls-tree -r`, `cat-file`)만, 검사와 같은 보호된 실행기로 사용합니다.
- **무엇을 검사하나.** 비밀정보(새 `.env` 파일은 `PG-SECRET-001`, 자격 증명은 `PG-SECRET-002`)와 JavaScript, TypeScript, Vue, Go의 파일 단위 소스 규칙입니다. 이번 커밋이 **추가하거나 바꾼 것**만 보고합니다. 비밀정보는 HEAD의 같은 파일에 같은 값이 없거나, 그 비밀정보가 걸친 줄 중 하나라도 추가되었을 때 새것입니다(개인 키는 여러 줄에 걸치므로 헤더는 그대로이고 키 본문만 바뀌어도 보고합니다). 소스 발견 항목은 그 줄이나 구문이 바뀌었을 때 새것입니다. 건드리지 않은 부분의 발견 항목은 개수만 알려 주고("보고하지 않았습니다") `pgard scan`에 맡깁니다. 프로젝트 전체가 필요한 규칙(CSRF 보호 누락, 보호되지 않은 라우트, 의존성)은 여기가 아니라 `pgard scan`에서 실행됩니다. 이름만 바꾼 파일은 옛 내용을 그대로 갖고 있어 이름을 바꾸며 한 수정만 대상이고(새 `.env` 이름은 여전히 표시), 삭제된 파일은 검사할 것이 없습니다. 새 `.env` 파일은 내용이 바이너리이거나 너무 크거나 읽을 수 없어도 **이름**으로 표시합니다. **알려진 형식의 바이너리 파일**(PNG, JPEG, GIF, TIFF, PSD, PDF, ZIP/JAR, gzip, RAR, ELF, Mach-O, PE, `.pyc`, WebP, MP3, FLAC, AIFF, woff, TrueType 컬렉션, Apple 아이콘과 속성 목록, `.DS_Store`, ICC 프로필, NumPy, HDF5, JKS, SQLite 같은 파일 형식 서명이 있고 Git과 같이 처음 8 KB 안에 NUL이 있거나 압축된 것처럼 보이는 파일. 크기 무관)과 심볼릭 링크, 서브모듈은 설계상 건너뛰며, 매번 이름을 적어 보여 줍니다("설계상 검사하지 않음: ..."). 검사하지 못한 것으로 세지 않습니다. 알려진 서명이 **없는데** 처음과 끝의 내용만 바이너리처럼 보이는 파일(제어 바이트가 많거나 압축·무작위 바이트. 예: 색상 코드가 가득한 로그)도 읽지 않습니다. 텍스트일 수 있으므로 매번 **경고**로 이름을 적지만("바이너리처럼 보이지만 PGARD가 아는 파일 형식이 아님"), 실제 바이너리 형식 중 PGARD가 서명을 모르는 것이 많으므로 `whenNotScanned` 설정과 관계없이 커밋을 막지 않습니다. NUL 바이트가 있다는 이유만으로 바이너리로 보지 않습니다. 끝에 NUL이 붙었거나 처음에 NUL이 많은 텍스트는 NUL을 공백으로 읽어 검사하고, UTF-16 텍스트는 바이트 순서 표시(BOM)가 있든 없든 디코딩해 검사하며(한 파일에 UTF-16과 UTF-8 부분이 섞일 수 있으므로 UTF-8로도 읽어서 어느 부분의 비밀정보든 찾습니다). 처음만 바이너리처럼 보일 뿐 분명한 바이너리가 아닌 1 MiB 초과 파일은 큰 텍스트 파일로 셉니다. **큰 텍스트 파일**(1 MiB 초과, 예: 큰 lockfile)은 검사하지 않고 그렇게 표시하며 "검사하지 못함"으로 셉니다(아래 참고). 이런 커밋을 경고만 하고 통과시키려면 `"whenNotScanned": "warn"`을 설정하거나 변경을 나누세요.
- **코드 전용, 로그인 불필요(#414부터).** 기본적으로 훅은 코드 전용 검사입니다. 권한 확인 관문, GitHub 로그인, 네트워크, 키체인을 쓰지 않으므로 `pgard login` 없이 모든 기여자와 CI에서 동작합니다. stderr에 `코드 전용, 권한 미확인`이라는 짧은 줄 하나만 출력합니다. Git 저장소 밖에서는 스테이징된 것이 없으므로 안내 한 줄을 출력하고 종료 코드 0으로 끝납니다(Git이 `core.worktree`로 작업 트리를 옮기는 저장소는 종료 코드 3으로 거부합니다). 이 모드에서는 기준선(baseline)을 적용하지 않습니다(권한이 확인된 저장소에 속하기 때문). 억제 목록은 적용합니다.
- **전체 관문 선택.** 스테이징된 `pgard.config.json`에 `"precommit": { "requireAuthorization": true }`를 넣으면 이전처럼 동작합니다. `pgard scan`과 같은 관문으로 다섯 가지 확인을 매번 모두 하고, 아무것도 캐시하지 않으며, 기준선을 적용합니다. 훅은 로그인을 시작하지 않으므로(`pgard login`을 한 번 실행하세요) 저장된 로그인이 없으면 관문이 막고 아무것도 검사하지 않습니다. 관문을 통과하지 못하면 `whenNotScanned`가 정합니다. `"warn"`이면 아무것도 검사하지 않은 채 경고만 하고 커밋이 진행됩니다(코드 전용 검사였다면 실행되었을 것입니다). 복제한 저장소에 `requireAuthorization: true`가 커밋되어 있을 수 있습니다. 그러면 훅은 커밋할 때 저장된 로그인으로 GitHub를 호출하지만, 기기 로그인을 시작하지는 않습니다.
- **차단 또는 경고.** `pgard.config.json`에 `"precommit": { "mode": "block" | "warn", "whenNotScanned": "block" | "warn", "requireAuthorization": true | false }`를 둡니다. `block`(기본값)은 발견 항목이 있으면 종료 코드 1로 커밋을 막고, `warn`은 발견 항목을 출력하고 종료 코드 0으로 끝납니다(Node 자체가 비정상 종료해도 1이며 이 경우에도 커밋이 차단됩니다). 이 설정은 **인덱스에 있는** `pgard.config.json`, 곧 커밋될 버전에서 읽으므로 `git add pgard.config.json`을 실행하세요. 추적되지 않는 파일은 안내와 함께 무시합니다. 억제와 `exclude`도 스테이징된 사본에서 읽으며, 작업 트리의 파일이 사본과 다르거나 추적되지 않으면 안내합니다(추적되지 않는 파일은 아무 설정도 주지 않습니다). 발견 항목을 묶어 보여 줄 뿐인 `testDirectories`만 작업 트리의 파일에서 읽습니다. 심각도 `info`, 억제된 발견 항목, [기준선](#기준선baseline)에 있는 발견 항목은 세지 않습니다.
- **조용히 통과하지 않습니다.** 아무것도, 또는 일부를 검사하지 못했을 때(오류, 크기 제한을 넘는 파일, 너무 많은 변경 파일, 해결되지 않은 병합 충돌. `requireAuthorization`이면 권한 없음과 시간 초과도) 출력에 `NOT scanned`(검사하지 못함)와 이유를 적습니다. 이때의 동작은 `whenNotScanned`가 정하며, 설정하지 않으면 `mode`와 같아서 차단하는 훅은 차단합니다(권한이 없으면 종료 코드 3으로 `requireAuthorization`일 때만, 그 밖의 경우 4). 경고만 하고 통과시키려면 `"whenNotScanned": "warn"`을 직접 설정하세요. 올바르지 않은 `pgard.config.json`은 통째로 무시되고 `block`으로 동작합니다.
- **속도와 제한.** 스테이징된 변경을 읽고 검사하는 데 **5초** 제한이 있습니다(보통 1초 미만). `requireAuthorization`이면 그 전에 권한 확인이 최대 15초(`PGARD_PRECOMMIT_TIMEOUT_MS`, 1000~120000) 걸릴 수 있고, 기본 코드 전용 검사에는 이 단계가 없습니다. 파일은 1 MiB까지, 변경 파일은 최대 500개, 내용은 합쳐서 16 MiB까지입니다. 남은 파일이나 시간 초과는 조용히 넘기지 않고 목록으로 보여 줍니다. 요약 줄에 걸린 시간이 나옵니다.
- **설치 안전.** `install`은 스캔과 같은 저장소 구조 검사를 거친 뒤, 이 저장소 자신의 훅 디렉터리(`<git dir>/hooks`, 연결된 worktree가 공유)에만 씁니다. `core.hooksPath`가 기본 훅 디렉터리가 아닌 곳으로 설정되어 있으면 거부합니다(저장소 밖이면 안전하지 않아서, 안이면 훅 관리 도구가 소유한 디렉터리에는 쓰지 않으므로 `snippet`을 사용하세요). 훅 디렉터리가 `.git` 밖으로 향하는 심볼릭 링크일 때도 거부합니다. 훅은 모드 0755로 배타적으로 만들고, PGARD가 만들지 않은 훅은 터미널에서 확인해 주지 않으면 덮어쓰지 않으며(기존 훅은 `pre-commit.pgard-backup`으로 보관), 터미널이 없으면 거부합니다. `uninstall`은 PGARD가 쓴 스크립트와 정확히 같은 훅만 지우고, 수정된 파일, 다른 도구의 훅, 심볼릭 링크는 그대로 둡니다. 훅은 안전하게 실패합니다. `PATH`에 `pgard`가 없으면 커밋을 막고 이유를 알립니다. 한 번만 건너뛰려면 `git commit --no-verify`를 쓰세요. PGARD는 이 저장소의 Git 설정만 읽으므로 전역 `core.hooksPath`는 보지 못합니다. 훅이 실행되지 않으면 `git config --get core.hooksPath`로 확인하세요.
- **병합 커밋.** Git은 일반 커밋과 충돌을 해결해 마무리하는 병합에는 `pre-commit`을 실행하지만, **충돌 없는 병합 커밋은 대신 `pre-merge-commit`을 실행하며** `install`은 이 훅을 쓰지 않습니다. 병합 결과도 검사하려면 같은 `pgard precommit` 줄을 `.git/hooks/pre-merge-commit`에 넣으세요(`pgard precommit snippet`이 출력합니다). 병합은 HEAD("ours")와 비교하므로 다른 브랜치가 가져오는 모든 내용이 추가된 것으로 취급됩니다. 변경 파일 500개 제한을 넘을 수 있고(검사하지 못한 것으로 보고하므로 block 모드에서는 차단됩니다. 한 번만 `git commit --no-verify`를 쓰거나 `"whenNotScanned": "warn"`을 설정하세요) 그 브랜치에서 온 발견 항목이 보고될 수 있습니다.

### 종료 코드

| 코드 | 의미                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | 요청한 범위를 끝까지 검사했습니다(발견 항목이 있을 수 있음). `doctor`는 진단을 마쳤다는 뜻입니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 1    | `pgard precommit` 차단 모드: 스테이징된 변경에 발견 항목이 있어 커밋을 막습니다. 이 명령만 1을 반환합니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 2    | 잘못된 명령·옵션·값·조합(터미널 없이 실행한 `pgard login`, 거부된 `pgard precommit install`·`uninstall` 포함).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| 3    | 권한 확인을 통과하지 못해 아무것도 검사하지 않았습니다. 승인 없음, 끝내지 못한 확인(네트워크 오류, 또는 GitHub가 10초 안에 응답하지 않음), GitHub 원격 없음, Git 저장소 아님이 해당합니다. 모든 범위(`scan`, `scan code`, `scan history`, `scan web`, `scan all`)에 똑같이 적용됩니다. 터미널에서 `scan`과 `scan code`는 먼저 코드 전용으로 검사할지 묻고(N이면 3), 터미널이 없으면 "For a code-only scan, add --code-only."를 출력합니다. 터미널이 없고 저장된 로그인도 없으면 기다리지 않고 바로 이 코드("Not signed in")로 끝납니다. [터미널이 없을 때](#터미널이-없을-때ci-파이프) 참고. 코드 전용 검사는 3이 아니라 0 또는 4로 끝납니다. |
| 4    | 검사 일부가 실행되지 않아 결과가 부분 완료이거나(예: 웹 대상 미확인, Git 이력 검사가 시간 한도에 도달), 보고서 저장에 실패했습니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 5    | 예상하지 못한 내부 오류만 해당합니다(권한 확인 실패는 아님). 세부 내용은 숨기며, `PGARD_DEBUG=1`을 설정하면 정리된 메시지를 보여 줍니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 130  | 사용자가 취소했습니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| 143  | 패널 화면이 열려 있는 동안 SIGTERM으로 종료되었습니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

`doctor`는 진단을 마치면 0(문제는 `[fail]`·`[warn]` 행으로 표시), 내부 오류면 5로 끝납니다. `pgard login`과 `pgard logout`의 종료 코드는 다음과 같습니다.

| 코드 | `pgard login`                                                                                                                      | `pgard logout`                                                                |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| 0    | 로그인하고 저장했습니다.                                                                                                           | 지웠거나, 저장된 것이 없었습니다.                                             |
| 2    | 터미널 없음(stdin과 stderr가 모두 터미널이어야 함). GitHub에는 아무것도 요청하지 않음.                                             | -                                                                             |
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

이 확인들은 지정한 GitHub 저장소와, 로컬 이력의 커밋 하나가 그곳에 알려져 있다는 점만 확인합니다. 작업 트리가 GitHub의 내용과 일치하는지는 증명하지 않습니다. 저장소 설정이 remote URL을 다시 쓰거나(`url.*.insteadOf`), `objects/info/alternates` 같은 `.git` 메타데이터가 심볼릭 링크, 특수 파일, 지나치게 큰 파일 또는 읽을 수 없는 파일이면 저장소 확인도 차단하며 이유에 해결 방법을 안내합니다.

각 항목은 `passed`, `failed`, `unverifiable` 중 하나이며 이유가 함께 표시됩니다. 항목은 이 순서로 보고하지만 반드시 이 순서로 평가하지는 않습니다. 예를 들어 owner 승인을 확인하기 전에 GitHub에서 저장소를 읽습니다(현재 접근 권한). 모든 항목이 통과해야만 검사합니다. 근거가 없거나 불분명하면 검사는 **차단**되고(종료 코드 3) 어떤 항목이 왜 실패했는지 보고합니다.

### 안내형 첫 실행(대화형 메뉴)

터미널에서 저장소 안에서 `pgard`(메뉴)를 실행했는데 **저장된 GitHub 로그인이 아직 없으면** 첫 실행을 안내합니다. 아래의 권한 확인 게이트 주변에 안내와 재시도만 더할 뿐이며, 아무것도 캐시하지 않고 어떤 확인도 건너뛰거나 순서를 바꾸거나 약화하지 않습니다.

```text
$ pgard
아직 GitHub에 로그인하지 않았습니다.
지금 로그인할까요? [Y/n] Y
(기존 device 로그인: 코드 입력과 승인)
octo 계정으로 GitHub에 로그인했습니다.
로그인했습니다. 이 저장소를 확인합니다...
이 저장소의 권한을 확인합니다 (5가지 확인 전체)...
Repository octo/app @ 546b9f0284bc
권한 확인: 차단됨 - 분석이 실행되지 않았습니다
  [통과] 저장소 (Git repository with remote "origin" -> github.com/octo/app.)
  [통과] GitHub 계정 (Signed in to GitHub as octo.)
  [실패] 소유자 승인 (No PGARD GitHub App installation on the owner account "octo" was found for octo/app.)
  [통과] 현재 접근 권한 (The signed-in user currently has access to octo/app.)
  [통과] 기여 이력 (Commit 546b9f0284bc is in the default branch "main" (signature-verified commit by octo).)
This result is not stored. Every scan checks again.
소유자 승인: octo/app에 대해 PGARD를 승인하려면 octo에 PGARD GitHub App을 설치하세요.
  1. 다음 주소를 여세요: https://github.com/apps/pgard-jadenmeister/installations/new/permissions?suggested_target_id=1001&repository_ids%5B%5D=555
  2. "Only select repositories"(octo/app) 또는 "All repositories"를 선택한 뒤 Install을 누르세요.
App을 설치하는 것이 소유자 승인입니다. PGARD가 대신 설치할 수는 없습니다.
Enter를 누르면 브라우저에서 페이지를 엽니다 (건너뛰려면 s)...
설치한 뒤 Enter를 누르세요 (종료하려면 q)...
처음부터 다시 확인합니다. 5가지 권한 확인 전체입니다 (3회 중 1회째)...
Repository octo/app @ 546b9f0284bc
권한 확인: 허용됨
  [통과] 저장소 / GitHub 계정 / 소유자 승인 / 현재 접근 권한 / 기여 이력 (다섯 항목 모두, 각각 이유 포함)
This result is not stored. Every scan checks again.
권한 확인을 통과했습니다. 검사를 시작합니다...
```

그 뒤 메뉴에서와 같이 검사가 실행되고, 패널 화면은 평소 규칙대로 열립니다.

- **저장된 로그인이 없을 때:** 한 줄로 알리고 `지금 로그인할까요? [Y/n]`를 묻습니다. 예를 고르면 기존 device 로그인을 실행합니다(브라우저를 열기 전에 Enter를 묻는 것도 그대로). 아니요를 고르면 메뉴가 열립니다. 준비되면 `pgard login`을 실행하세요.
- **이 저장소에 App이 설치되지 않았거나 접근 권한이 없어서만 차단된 경우:** 계정 또는 조직의 정확한 설치·설정 링크를 보여 주고, Enter를 누르면 열어 주며, `설치한 뒤 Enter를 누르세요 (종료하려면 q)`에서 기다립니다. 재시도할 때마다 **다섯 항목 전체를 처음부터 다시** 확인합니다. 재시도는 최대 3번이며, 그래도 App이 없으면 차단 결과를 그대로 두고 메뉴를 엽니다.
- **그 밖의 이유로 차단된 경우**(조직 owner가 아님, 기여 증거 없음, 읽기 권한 없음, GitHub 원격이 아님 등): App을 설치해도 해결되지 않으므로 재시도 없이 차단 결과와 이유만 보여 줍니다.
- 이 질문들에서 Ctrl+C는 `Cancel and exit? [y/N]`를 묻고, `y`면 종료 코드 130으로 끝납니다.
- OS 키체인에 저장된 로그인이 없을 때만 시작합니다. 저장된 로그인이 있거나 쓸 수 있는 키체인이 없으면 메뉴가 바로 열리고, 검사는 아래 설명대로 동작합니다.

### 처음 실행: 로그인, App 설치, 계속 진행

저장소에서 처음 `pgard scan`(또는 `pgard project verify`, 대시보드)을 실행하면 다음과 같이 진행됩니다.

1. **로그인.** PGARD가 코드와 `https://github.com/login/device` 링크를 출력하고, 터미널에서는 Enter를 누르면 브라우저에서 엽니다(`--no-browser` 참고). 코드를 입력하고 PGARD GitHub App을 승인합니다.
2. **빠진 것이 App 설치뿐이면 설치.** owner 승인만 실패했고, 그 이유가 PGARD GitHub App이 owner 계정에 설치되어 있지 않거나 설치에 이 저장소가 포함되지 않았기 때문이며, 본인이 승인할 수 있는 사람일 수 있으면(개인 저장소는 본인이 owner, 조직은 GitHub가 본인을 활성 owner로 보여 주거나 아직 역할을 보여 주지 못하는 경우), PGARD가 owner 계정과 이 저장소가 미리 선택된 App 설치 페이지를 출력하고(터미널에서는 Enter를 누르면 엽니다).

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
- **App 설치에 포함되지 않은 비공개 저장소.** PGARD GitHub App의 로그인 토큰은 App 설치에 포함된 비공개 저장소만 볼 수 있습니다. 그 밖의 비공개 저장소는 GitHub가 404로 응답하므로 현재 접근 권한은 "GitHub returned no access to github.com/<owner>/<repo>. For a private repository this usually means the PGARD GitHub App is not installed for it, or your account has no access." 이유로 `failed`로 유지됩니다. PGARD는 둘 중 어느 경우인지(또는 저장소가 아예 없는지) 알 수 없으므로 아무것도 통과시키지 않습니다. 그런 다음 owner의 계정 id(`GET /users/<owner>`, 공개 API)와 본인의 App 설치 목록을 조회해 두 페이지 중 하나를 안내합니다. owner 계정에 App이 **이미 설치되어 있으면**(보통 일부 저장소만 선택) 그 설치의 설정 페이지(`https://github.com/settings/installations/<id>` 또는 `https://github.com/organizations/<org>/settings/installations/<id>`)를 열고, **Repository access → Only select repositories**에서 저장소를 추가한 뒤 **Save**를 누르라고 안내합니다. App을 다시 설치하는 것이 아닙니다. **설치되어 있지 않으면** 저장소 id를 알 수 없으므로 owner 계정만 미리 선택된 설치 페이지를 안내합니다. 이 페이지는 **All repositories**가 미리 선택되어 있으므로, PGARD를 이 저장소로 한정하려면 **Only select repositories**를 고르고 저장소를 선택하세요. 어느 쪽이든 이후 PGARD는 기다렸다가 다섯 항목 전체를 처음부터 다시 확인합니다. 조회나 설치 목록 조회에 실패하면 이유만 보여 주며 페이지를 추측하지 않습니다. 조직은 변경 전에 본인의 역할을 확인할 수 없으므로 멤버십을 읽을 수 없을 때와 같은 방식으로 안내하고, 다른 사람의 개인 계정이면 owner에게 요청하라고 안내합니다. 그 뒤에는 전체 확인이 결정합니다.
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

로그인이 필요하면 PGARD가 `https://github.com/login/device` 주소와 짧은 사용자 코드를 보여 주고, 터미널이면(`--no-browser`가 없을 때) Enter를 누르면 브라우저에서 주소를 엽니다. 주소를 열어 코드를 입력하고 승인하면 됩니다. 토큰은 화면·로그·프로세스 인자·환경 변수에 남기지 않으며 파일에 쓰지 않습니다.

#### 터미널이 없을 때(CI, 파이프)

로그인은 사람이 github.com에 코드를 입력해야 하므로, PGARD는 **stdin과 stderr가 모두 터미널일 때만** device 로그인을 시작합니다. 둘 중 하나라도 터미널이 아니고(파이프, `< /dev/null`, CI 러너) 사용할 수 있는 저장된 로그인이 없으면(OS 키체인이 없거나, 잠겨 있거나, 비어 있거나, 쓸 수 없음) 어떤 명령도 기기 코드를 요청하거나 기다리지 않습니다. `scan`(모든 형태와 형식), `baseline`, `project verify`는 즉시 blocked 결과와 종료 코드 **3**으로 끝나며, GitHub 신원 확인의 이유는 ``Not signed in to GitHub, and there is no terminal to sign in with. Run `pgard login` in a terminal first.`` 입니다. `--format json`/`--format sarif`에서는 stdout에 평소와 같은 올바른 blocked 문서가 나옵니다(실행되지 않은 검사의 SARIF는 업로드하지 마세요). 사용할 수 있는 저장된 로그인이 있으면 터미널이 없어도 그대로 재사용합니다. `pgard login` 자체는 터미널이 없으면 실행을 거부합니다(사용법 오류, 종료 코드 2). 대시보드는 영향이 없습니다. 대시보드의 로그인은 브라우저에서 처리합니다.

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

언어별 지원 현황:

| 언어                                        | 규칙                                                                                                                                                                                                                                      | 범위                                                                                                                                              |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| JavaScript, TypeScript, React, Vue          | SQL, XSS, SSRF, 명령, 경로, 암호화, 인증, 쿠키, CSRF, 무차별 대입                                                                                                                                                                         | 전체 규칙                                                                                                                                         |
| Go                                          | SQL, SSRF, 명령, 경로, 암호화, 쿠키                                                                                                                                                                                                       | 구문 수준 휴리스틱                                                                                                                                |
| Java, Kotlin                                | SQL(`PG-SQL-005`), XSS(`PG-XSS-004`), SSRF(`PG-SSRF-002`), 명령(`PG-CMD-003`), 경로(`PG-PATH-002`), 암호화(`PG-CRYPTO-001`~`003`), 비밀번호 저장(`PG-AUTH-001`), Spring Security·세션 설정(`PG-CSRF-001`, `PG-COOKIE-001`, `PG-CONF-001`) | 일곱 범주. 사용자 정의 configurer나 외부 도우미로 만든 Spring 필터 체인은 partial. FreeMarker, Velocity, Pebble, Mustache 템플릿은 partial로 보고 |
| PHP(`.php`, `.phtml`, Laravel·Symfony 감지) | SQL(`PG-SQL-007`), 명령(`PG-CMD-005`)                                                                                                                                                                                                     | XSS, 파일 포함·경로, SSRF, 암호화, 설정은 아직 검사하지 않음. Blade(`.blade.php`)는 감지하며 Blade XSS 검사는 이후에 추가                         |
| Python (Django, Flask, FastAPI 감지)        | SQL(`PG-SQL-006`), 명령(`PG-CMD-004`)                                                                                                                                                                                                     | 다른 범주는 아직 검사하지 않음                                                                                                                    |

소스 분석은 JavaScript, TypeScript, React(JSX/TSX), Vue, Go 파일을 다루며, 규칙 일곱 범주(SQL 인젝션, XSS, SSRF, OS 명령 실행, 경로 조작, 암호화, Spring Security·세션 설정)에 한해 Java와 Kotlin 파일, MyBatis 매퍼 XML, JSP·Thymeleaf 템플릿, Spring Boot 설정 파일도, 두 범주(SQL 인젝션, OS 명령 실행)에 한해 Python 파일과 PHP 파일도 다룹니다(아래 참고). 작업 트리를 탐색하며 빌드 결과물·캐시(`dist/`, `build/`, `out/`, `.next/`, `coverage/` 등)와 의존성 디렉터리에는 들어가지 않습니다. 의존성 디렉터리는 위치와 상관없이 `node_modules/`, `bower_components/`이고, `vendor/`는 저장소 루트에 있거나 같은 디렉터리에 `composer.json`, `go.mod`, `Gemfile`이 있을 때만입니다(`src/`, `app/`, `lib/` 아래는 제외하므로 직접 만든 `src/vendor/` 모듈은 분석합니다). 건너뛴 의존성 디렉터리는 `source:dependency-directories` coverage 설명에 표시됩니다(예: `Skipped 2 dependency directories (third-party code, not analyzed): node_modules/, vendor/ (composer.json).`, 최대 5개까지 이름을 보여 주되 경로가 길면 더 적게 보여 주고, 나머지는 개수로 표시). 옆에 매니페스트가 없는 루트 `vendor/`는 서드파티로 가정하고 건너뛰며 `vendor/ (repository root, no manifest; assumed third-party)`로 표시합니다. 압축(minified) 번들(파일 이름이 `.min.js`, `.min.mjs`, `.min.cjs`로 끝나는 파일)도 분석하지 않으며, 개수와 최대 5개 경로를 담은 `partial` 상태의 `source:minified` coverage 영역으로 표시합니다(예: `2 minified bundles skipped (minified bundle, not analyzed): "public/vendor/widgets.min.js", "public/vendor/x.min.mjs".`). 건너뛴 파일이 없으면 항목이 없습니다. 파일 이름만 보고 내용은 보지 않으므로 `bundle.js`처럼 일반적인 이름의 번들은 분석합니다(파일당 finding 상한 적용). 규칙과 심각도의 최신 목록은 이 README의 사본 대신 `pgard rules list`(필요하면 `--language` 사용)로 확인하세요.

악의적인 저장소가 검사를 붙잡아 두지 못하도록 소스 분석에는 강제 한도가 있습니다. JavaScript, TypeScript, Vue, Go 파일은 파일마다 워커 스레드에서 20초 한도로 분석하며(검사 시간 예산이 먼저 끝나면 더 짧게), Ctrl+C를 누르면 바로 멈춥니다. 한도에 걸려 멈춘 파일, 중첩이 너무 깊어 스택 한도에 닿은 파일, 분석에 허용된 메모리를 넘은 파일, 분석 워커가 실패한 파일(연속 3번 실패하면 워커를 더 띄우지 않음)은 **분석하지 않으며**, 해당 언어 영역은 파일 이름을 밝힌 설명과 함께 `partial`이 됩니다(예: `1 file(s) took longer than the per-file limit of 20 s (stopped; not analyzed: "src/gen.go")`, `1 file(s) nested too deeply to analyze (stack limit reached; not analyzed: "deep.js")`). 디렉터리 탐색도 시간 예산에 포함되며 항목 300,000개를 본 뒤에는 멈춥니다. 어느 쪽이든 `source:walk` 영역이 `partial`이 되어 어디서 멈췄는지 알려 주고, 다른 모든 `source:*` 영역도 "The directory walk stopped early"로 시작하는 설명과 함께 `partial`이 됩니다.

Java와 Kotlin은 일곱 범주를 다룹니다: **SQL 인젝션**(`PG-SQL-005`), **XSS**(`PG-XSS-004`), **SSRF**(`PG-SSRF-002`), **OS 명령 실행**(`PG-CMD-003`), **경로 조작**(`PG-PATH-002`), **암호화**(`PG-CRYPTO-001`, `PG-CRYPTO-002`, `PG-CRYPTO-003`, `PG-AUTH-001`), **Spring Security·세션 설정**(`PG-CSRF-001`, `PG-COOKIE-001`, `PG-CONF-001`. 아래에서 설명합니다). Python과 PHP는 아래에 따로 설명합니다. 처음 다섯 규칙은 하나의 프로시저 내부(intra-procedural) 분석을 공유합니다. 한 파일의 한 메서드 안에서만 따라가며, 메서드나 파일 사이의 데이터 흐름, 타입 해석, Spring 빈 연결은 보지 않습니다. 요청 입력 출처도 같고, 무엇을 보고하는지에 대한 원칙도 같습니다. 구문상 고정된 값만 보고하지 않으며, 그 밖의 값은 숨기지 않고 낮은 신뢰도로 낮춰 근거 끝에 `; inferred`를 붙입니다(`rules list --language java`와 `--language kotlin`에 표시됩니다). `PG-SQL-005`가 보는 것은 다음과 같습니다.

- 싱크: JDBC(`Statement.executeQuery/execute/executeUpdate/addBatch`, `Connection.prepareStatement/prepareCall`), Spring `JdbcTemplate`과 `NamedParameterJdbcTemplate`(`query`, `queryForObject`, `queryForList`, `update`, `execute` 등), JPA와 Hibernate(`createQuery`, `createNativeQuery`, `createSQLQuery`), 메서드 인자를 읽는 SpEL `#{...}`이 든 Spring Data `@Query`, MyBatis 매퍼 XML(`<select>`, `<insert>`, `<update>`, `<delete>`)과 `@Select`, `@Insert`, `@Update`, `@Delete` 애너테이션의 `${...}`. `#{...}`, `?`, `:name`, `setParameter`는 값을 바인딩하므로 보고하지 않습니다.
- 요청 입력: Spring 핸들러 매개변수(`@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, `@ModelAttribute`, 매핑된 핸들러의 애너테이션 없는 매개변수), `HttpServletRequest.getParameter/getHeader/getQueryString/getCookies`, Ktor의 `call.parameters`, `call.receive`, `call.request.*`. 입력 출처를 추적할 수 없는 동적 문자열(예: 자신의 `String` 매개변수를 이어 붙이는 DAO 메서드)은 낮은 신뢰도로 보고합니다.
- 문자열 만들기: `+`, `String.format`, `.formatted()`, `StringBuilder` 체인, Kotlin 템플릿(`"$x"`, `"${x}"`), `buildString`, `String.join`을 지역 변수와 재할당을 거쳐 따라갑니다.
- 고정된 텍스트는 보고하지 않습니다: 리터럴, 리터럴로만 만든 `final`(또는 인터페이스) 문자열 상수, 리터럴로 초기화한 Kotlin `const val`과 `open`이 아닌 `val`, 같은 파일에 선언된 enum의 `.name()`. `StringBuilder`나 값을 쓰는 배열·컬렉션은 `final` 필드여도 고정 텍스트가 아닙니다. 필드와 같은 이름의 지역 변수나 매개변수는 그 필드의 값을 물려받지 않습니다.
- 안전하다고 추정만 되는 값은 숨기지 않고 낮은 신뢰도(심각도는 최대 medium)로 보고하며 근거 끝에 `; inferred`가 붙습니다: 허용 목록 검사(`if (!ALLOWED.contains(x)) throw ...`, `require(x in ALLOWED)`, 삼항 연산자), `Integer.parseInt` 같은 형 변환, 숫자 타입 매개변수, 고정된 `Map.of(...)` 표 조회, 다른 파일의 상수, 숫자 `parameterType`·OGNL 정적 필드·`<sql>` 조각에 쓰인 MyBatis `${}`.
- MyBatis `${}`는 추적된 출처가 없어도 보고합니다. 매퍼 매개변수는 호출자에게서 오기 때문입니다. 심각도 high, 상태 suspected, 신뢰도 medium입니다.
- 한계: 분석은 프로시저 내부(intra-procedural)입니다. 한 파일의 한 메서드 안에서만 따라가며, 메서드나 파일 사이의 데이터 흐름, 타입 해석, Spring 빈 연결은 보지 않습니다. 헬퍼 메서드가 돌려준 값, 변경 가능한 빌더 필드의 값, 다른 파일에 정의된 상수는 따라가지 않습니다. 그런 값이 들어간 조립 문자열은 낮은 신뢰도("no input source identified" 또는 "; inferred")로 보고하고, 헬퍼가 돌려준 값을 그대로 넘기는 경우도 "value from helper(), not followed; inferred"라는 낮은 신뢰도로 보고합니다. 필드, 컬렉션, 배열에 저장했거나 다른 메서드에 넘겼거나 조건부로 대입한 `StringBuilder`는 알 수 없는 값도 담고 있는 것으로 취급합니다. SQL로 보이는 호출, 명령을 실행하는 호출, 파일을 여는 호출이 든 익명 클래스, 지역 클래스, Kotlin 익명 객체, Kotlin 지역 함수는 분석하지 않으며(세 규칙 모두 해당), 이 경우 해당 영역은 파일 이름과 함께 `partial`이 됩니다. jOOQ, Exposed, Room, MyBatis `@SelectProvider`/`@InsertProvider`/`@UpdateProvider`/`@DeleteProvider`(SQL 빌더)는 분석하지 않으며, 감지된 라이브러리마다 `partial` 상태의 `source:orm:*` 영역이 추가됩니다. Java와 Kotlin 파일은 매 스캔마다 다시 분석합니다(증분 스캔용으로 결과를 캐시하지 않습니다).

`PG-CMD-003`(OS 명령 실행)이 보는 것은 다음과 같습니다.

- 싱크: `Runtime.exec(String)`과 `Runtime.exec(String[])`(`Runtime.getRuntime()`, `Runtime` 타입 변수, 또는 `runtime`·`rt`라는 이름의 변수에 대한 호출), `new ProcessBuilder(...)`, `ProcessBuilder.command(...)`, `command().add(...)` / `addAll(...)`, Kotlin의 같은 호출, Apache Commons Exec(`CommandLine.parse(x)`, `new CommandLine(program)`, `addArgument(x)`, `addArgument(x, false)`). 마지막 묶음은 `org.apache.commons.exec`를 import한 파일에서만 봅니다.
- 심각도: `exec(String)`이나 `CommandLine.parse`에 넘기는 문자열, 셸 래퍼(`sh -c`, `bash -lc`, `cmd /c`, `powershell -Command`, `pwsh -c`. 플래그 자리에 동적 값이 와도 해당)의 스크립트, 프로그램 이름에 요청 입력이 들어가면 **critical**입니다(신뢰도 high, 직접 읽으면 confirmed, 변수를 거치면 suspected). 고정된 프로그램의 인자(`new ProcessBuilder("git", "log", ref)`, 셸 없음)에 요청 입력이 들어가면 **인자 주입**으로 보고하며 심각도 **medium**, suspected, 신뢰도 medium입니다. `addArgument(x, false)`(따옴표 처리 끔)는 high입니다. `--`나 `--end-of-options` 인자 뒤에 놓인 값은 낮은 신뢰도(`; inferred`)로 낮춥니다.
- 인자 목록은 배열과 리스트 리터럴(`new String[]{...}`, `Arrays.asList`, `List.of`, Kotlin `listOf`, `arrayOf`, `mutableListOf`, `*arrayOf(...)`)에서, 그리고 단계적으로 채운 리스트와 배열(`add`, `addAll`, `Collections.addAll`, 인덱스 대입)에서 읽습니다. 후자는 원소의 위치를 더 이상 알 수 없으므로, 고정된 첫 원소는 프로그램으로, 고정 원소 안에 셸 이름과 그 플래그가 함께 있으면 래퍼로 봅니다.
- 낮은 신뢰도(`; inferred`)로 낮추는 경우: 값에 대한 허용 목록 검사, 숫자나 UUID, 고정된 표에서의 조회, 헬퍼 메서드가 돌려준 값. 출처를 알 수 없는 값도 low이며, 전체 명령이나 전체 인자 목록으로 그대로 넘어온 매개변수와 다른 파일에 정의된 상수도 low입니다(`no input source identified`, `callers not followed`). 알 수 없는 값은 조용히 넘어가지 않습니다. 리터럴과 같은 파일의 리터럴로만 만든 상수만 고정 값입니다. `Runtime`으로 인식하지 못한 수신자(정적 수신자, 다른 타입의 변수)의 `exec`와 타입이 적혀 있지 않은 수신자의 `command(...)`는 요청 입력이 인자에 도달할 때만 낮은 신뢰도로 보고합니다. 셸 래퍼는 런처(`env`, `sudo -u app`, `nohup`, `timeout 10`, `nice -n 5`, `xargs`) 뒤에 있어도 찾습니다.
- 한계: `envp`와 작업 디렉터리 인자, `ProcessBuilder.environment()`, 시작된 프로그램이 실행하는 스크립트, 리플렉션, 다른 메서드나 파일에서 만든 명령은 검사하지 않습니다. 자체 프로세스 API를 가진 라이브러리(zt-exec, NuProcess)는 분석하지 않으며, 감지된 라이브러리마다 `partial` 상태의 `source:process:*` 영역이 추가됩니다.

`PG-PATH-002`(경로 조작, zip slip)가 보는 것은 다음과 같습니다.

- 싱크: 경로를 만드는 `new File(...)`, `Paths.get(...)`, `Path.of(...)`, `resolve(...)` / `resolveSibling(...)`(`Path`, `File`, 경로 값, 또는 `baseDir` 같은 이름의 수신자), `FileSystems.getDefault().getPath(...)`, `ServletContext.getRealPath(...)`, Kotlin `File(...)`, 그리고 그 경로를 쓰는 `Files.readAllBytes`, `readString`, `readAllLines`, `lines`, `newInputStream`, `newOutputStream`, `newBufferedReader`, `newBufferedWriter`, `write`, `writeString`, `copy`, `move`, `delete`, `deleteIfExists`, `createFile`, `createDirectories`, `list`, `walk`; `FileInputStream`, `FileOutputStream`, `FileReader`, `FileWriter`, `RandomAccessFile`, `PrintWriter`·`PrintStream`·`Formatter`(스트림이 아닌 파일 이름을 받을 때), `ZipFile`, `JarFile`, `java.util.logging.FileHandler`, `FileSystemResource`, `UrlResource("file:" + x)`; 파일을 읽거나 쓰거나 바꾸는 `File`·`Path` 값의 메서드(`delete`, `mkdirs`, `renameTo`, `list`, `listFiles`, Kotlin `readText`, `writeText`, `readBytes`, `inputStream` 등); Commons IO `FileUtils`; Spring `ResourceLoader.getResource("file:" + x)`(`ResourceLoader`나 `ApplicationContext`에서. 다른 수신자는 `file:` 접두사가 있을 때만).
- 경로는 사용되는 곳에서 한 번만 보고합니다. 반환하거나 저장하거나 다른 메서드에 넘기기만 한 경로, 또는 목록에 없는 호출(예: `ImageIO.read(new File(x))`)이 쓰는 경로는 만든 곳에서 보고합니다.
- 요청 입력: `PG-SQL-005`와 같고, 거기에 더해 클라이언트가 정한 파일 이름(`MultipartFile.getOriginalFilename()`, `Part.getSubmittedFileName()`, Ktor `originalFileName`. 컨트롤러뿐 아니라 업로드 타입 변수가 나오는 모든 곳)과, zip slip의 경우 압축 파일 항목 이름(`ZipEntry.getName()`, tar·jar·Zip4j 항목, Kotlin `entry.name`)이 있습니다. 항목 타입의 변수, `getNextEntry()`의 결과, `ZipFile`·`ZipInputStream`의 `entries()` / `stream()` 요소(`asSequence().forEach { it.name }`, `for (e in zip.entries())` 포함), 또는 타입이 적혀 있지 않을 때 압축 라이브러리를 import한 파일에서 항목처럼 이름 붙인 변수가 해당합니다(마지막 형태는 신뢰도 medium으로 보고). 다른 타입의 변수(`LogEntry`)와 `listFiles()`의 파일은 항목이 아닙니다. **`PG-SQL-005`의 의도된 변경:** 이 두 출처는 공유되므로, 압축 항목 이름이나 업로드 파일 이름을 SQL에 이어 붙이면 이제 거기서도 요청 입력으로 봅니다(이전에는 낮은 신뢰도의 알 수 없는 값이었습니다).
- 낮은 신뢰도(`; inferred`)로 낮추는 경우: 정규화한 경로의 접두사 검사(`p.normalize().startsWith(base)`, `toRealPath()`나 `getCanonicalPath()`와 `startsWith`. 조건식에 직접 쓰거나 그렇게 만든 변수에 사용하며, 예외를 던지는 가드, `require`, `assert`, 사용 부분을 감싼 `if` 모두 해당), `..` 거부(`name.contains("..")`), 허용 목록 검사, `FilenameUtils.getName`, `Paths.get(x).getFileName()`, Kotlin `File(x).name`, 숫자나 UUID. 가드는 이름을 든 변수(와 그 변수의 원본 변수)에만 적용됩니다. 다른 변수에 대한 검사, `normalize()`나 실제 경로 없는 접두사 검사, 사용 부분을 덮지 못하는 검사, 변수를 다시 대입하기 전의 검사, 같은 입력으로 경로를 다시 만든 경우에는 아무것도 낮추지 않습니다.
- 한계: 클래스패스 조회(`ClassPathResource`, `ClassLoader.getResource`, `getResourceAsStream`)는 그 자체로는 분석하지 않습니다. 다만 거기서 꺼낸 `File`(`ClassPathResource(...).getFile()`)은 파일로 쓰일 때 다른 파일과 똑같이 검사합니다. 리터럴 `file:` 접두사 없이 사용자가 전부 정하는 URL을 받는 `new UrlResource(...)`는 다루지 않습니다(SSRF라는 별도 범주). `Files.exists`·`size`·`isDirectory`와 `File`의 같은 종류(`exists`, `length` 등)는 내용을 읽지 않으므로 요청 입력일 때만 낮은 신뢰도와 낮은 심각도로 보고합니다. 심볼릭 링크(`toRealPath()`만 해석)와 다른 메서드나 파일로 넘어간 경로는 따라가지 않습니다. 검사한 뒤 쓰지 않은 경로는 보고하지 않고, 검사 아래에서 반환하거나 저장한 경로는 low입니다. 타입이 적혀 있지 않은 변수의 `resolve(...)`는 요청 입력이 도달할 때 낮은 신뢰도로 보고합니다. Okio, Vert.x, Commons VFS의 파일 API는 분석하지 않으며, 감지된 라이브러리마다 `partial` 상태의 `source:file:*` 영역(`PG-PATH-002`)이 추가됩니다(`PG-CMD-003`은 `source:process:*`).

`PG-XSS-004`(XSS)가 보는 것은 다음과 같습니다.

- 코드의 싱크: `response.getWriter()`와 `response.getOutputStream()`의 `write`, `print`, `println`, `append`, `printf`(`PrintWriter` 변수나 래퍼를 거쳐도 해당), Kotlin `response.writer`, Ktor `call.respondText(text, ContentType.Text.Html)`, `ResponseEntity.ok().contentType(TEXT_HTML).body(x)`, WebFlux `contentType(TEXT_HTML).bodyValue(x)`, 그리고 응답 본문인 Spring 핸들러(`@ResponseBody` 또는 `@RestController`의 메서드)가 `String`이나 `ResponseEntity<String>`으로 돌려주는 값.
- 템플릿의 싱크: JSP `<%= ... %>`, 스크립틀릿의 `out.print/println/write/append(...)`, 템플릿 본문과 HTML 태그 속성(태그 라이브러리 태그의 속성은 제외)의 `${...}`, `<c:out escapeXml="false">`, Thymeleaf `th:utext`, `data-th-utext`, `[( ... )]`. `.jsp`, `.jspx`, `.jspf`, `.tag`, `.tagx`와 Thymeleaf를 쓰는 모든 `.html` 파일을 패턴과 작은 토크나이저로 읽으며, 템플릿 엔진을 실행하지는 않습니다.
- 보고하지 않는 경우(템플릿이 값을 이스케이프하거나 응답이 HTML이 아님): `th:text`, `[[ ... ]]`, `<c:out>`, `fn:escapeXml`, JSON을 돌려주는 `@RestController`(객체, `Map`, JSON으로 지정한 `produces`), HTML이 아닌 값으로 고정된 content type, `@Controller`의 뷰 이름, 던진 예외 메시지, 리터럴, `isELIgnored="true"`, 주석.
- 요청 입력: 코드에서는 `PG-SQL-005`와 같습니다. 템플릿에서는 스크립틀릿의 `request.getParameter/getHeader/getQueryString/getRequestURI/...`(스크립틀릿 변수를 거쳐도 해당), EL의 `param`, `paramValues`, `header`, `cookie`, Thymeleaf의 `${param.x}`와 `#request.getParameter(...)`입니다. Thymeleaf 모델 값은 다른 파일의 컨트롤러가 요청 입력으로 채우는 속성(`model.addAttribute("name", x)`, `modelAndView.addObject`, `new ModelAndView(view, "name", x)`, `request.setAttribute`)과 연결합니다. 그 핸들러가 리터럴 뷰 이름을 돌려주면 그 이름의 템플릿(`templates/` 아래)에만 중간 신뢰도로 연결하고 근거에 컨트롤러 파일과 줄이 표시됩니다. 핸들러의 뷰를 알 수 없으면 속성 이름만 일치하는 경우는 낮은 신뢰도(`; inferred`)입니다.
- 심각도: HTML인 응답에 요청 입력을 쓰면 high(직접 읽으면 confirmed)입니다. 쓰기 전에 content type을 지정하지 않았다면 신뢰도는 medium입니다. `@RestController`가 요청 입력으로 만든 String 본문은 HTML 마크업이 들어 있지 않으면 낮은 신뢰도, 들어 있으면 medium입니다.
- 낮은 신뢰도(`; inferred`, 심각도 최대 medium)로 낮추는 경우: 이스케이프 도우미(`HtmlUtils.htmlEscape`, `StringEscapeUtils.escapeHtml4`, OWASP `Encode.forHtml*`, `encodeFor*`, Guava `htmlEscaper().escape`, Thymeleaf `#strings.escapeXml`, JSP 사용자 정의 이스케이프)를 거친 값, 실패 시 빠져나가는 허용 목록·패턴 검사(또는 성공 분기 안의 사용), 고정되지 않은 content type(일부 분기에서만 지정한 경우 포함), 그리고 응답에 쓰거나 응답 본문 핸들러가 돌려주는 출처 불명의 상수가 아닌 모든 값: 헬퍼 결과(`render(name)`: `value from render(), not followed`), 필드, 단순 매개변수, 출처를 따라가지 않는 값을 쓰는 `th:utext`나 `${bean.property}`. 리터럴, 숫자·불리언, 알려진 JSON 직렬화 도구의 결과(`writeValueAsString`, `writeValueAsBytes`, `toJson`, `toJSONString`, `encodeToString`)만 보고하지 않습니다.
- 한계: 핸들러의 반환값은 선언된 타입(`String`, `ResponseEntity<String>`. 다른 선언 타입은 JSON 본문)으로, 선언된 타입이 없으면(Kotlin 표현식 본문) 텍스트를 만드는 표현식(리터럴, 템플릿, 연결, 변수)으로 판단하며 호출 결과만 있는 값은 텍스트로 읽지 않습니다. 메서드 호출을 거친 요청 입력은 그 호출의 결과로 보고하고 따라가지 않습니다. Thymeleaf 모델 값은 속성 이름과 돌려주는 뷰 이름으로만 연결합니다(빈 메서드 분석 없음). JSP 파일(`.jsp`, `.jspx`, `.jspf`, `.tag`, `.tagx`)은 항상 읽고, Thymeleaf `.html`과 다른 엔진의 파일은 Java·Kotlin 프로젝트(Java·Kotlin 파일, 또는 `pom.xml`·`build.gradle(.kts)`)에서만 읽으며, `.html`·`.mustache`·`.vm` 파일이 있는 Node나 Python 저장소에는 템플릿 영역이 생기지 않습니다. 다른 템플릿 엔진은 읽지 않습니다. FreeMarker, Velocity, Pebble, Mustache, JTE(파일 또는 API import)는 `partial`인 `source:template:*` 영역(규칙 `PG-XSS-004`)을 추가하고, `<jsp:scriptlet>`·`<jsp:expression>`·`<jsp:declaration>`은 템플릿 영역을 partial로 만들며, 서블릿·URL·HTTP 클라이언트 API와 함께 리플렉션으로 호출하는 파일이나 응답에 쓰는 Kotlin 확장 함수도 해당 영역을 partial로 만듭니다. 템플릿 결과는 `source:jvm-templates` 영역에 표시됩니다.

Spring Security와 세션 설정 규칙(`PG-CSRF-001`, `PG-COOKIE-001`, 새 규칙 `PG-CONF-001`. Java·Kotlin 소스와 `application*.properties` / `application*.yml`을 봅니다)이 보는 것은 다음과 같습니다.

- `PG-CSRF-001`: CSRF 보호를 끄는 설정(`http.csrf().disable()`, `csrf(c -> c.disable())`, `csrf(AbstractHttpConfigurer::disable)`, Kotlin DSL `csrf { disable() }`)을 필터 체인마다 판단합니다. **세션·쿠키 인증**(`formLogin`, `rememberMe`, `oauth2Login`, STATELESS가 아닌 `sessionManagement` 정책, 또는 `sessionCreationPolicy`가 아예 없는 경우)은 medium으로 보고합니다. **명시적으로 STATELESS이고 `oauth2ResourceServer`의 기본 bearer 처리를 쓰는 체인**은 위조된 요청에 실릴 쿠키가 없으므로 보고하지 않습니다. STATELESS와 `httpBasic`(브라우저가 basic 자격 증명을 자동으로 보냄), `formLogin`, `rememberMe`, 폼 본문 토큰을 받는 resource server가 함께 있으면 medium입니다. 판단할 수 없는 경우는 낮은 신뢰도로 보고하고 `; inferred`를 붙입니다. 이름만 알 수 있는 JWT·토큰 필터, 사용자 정의 `bearerTokenResolver`나 폼·쿼리 파라미터 토큰, bearer 설정이 전혀 없는 STATELESS, 고정 값이 아닌 정책, 정책 없이 bearer만 있는 경우, customizer의 분기 안에서나 조건식·변수 customizer로 CSRF를 끄는 경우, 일부 경로만 CSRF에서 제외하는 경우(`ignoringRequestMatchers(...)`. `"/**"`나 `anyRequest()`는 전체 해제로 봅니다)입니다. 사용자 정의 configurer(`apply`, `with`), 이 파일에 없는 도우미 메서드, 변수에 담긴 customizer로 끝나는 필터 체인은 영역을 partial로 만듭니다. 같은 파일의 도우미는 따라갑니다.
- `PG-COOKIE-001`: `setHttpOnly(true)`와 `setSecure(true)`(또는 Kotlin 프로퍼티, `apply { }` 블록)가 없는 서블릿 `Cookie`(`new Cookie(...)`, Kotlin `Cookie(...)`), `httpOnly(true)`, `secure(true)`, `sameSite(...)`가 없는 Spring `ResponseCookie.from(...)`, HttpOnly나 Secure가 없는 직접 쓴 `Set-Cookie` 헤더, Spring Session의 `setUseHttpOnlyCookie(false)` / `setUseSecureCookie(false)`, false로 설정한 `SessionCookieConfig`, `application.properties` / `application.yml`의 `server.servlet.session.cookie.http-only` 또는 `secure`=false를 봅니다. 세션·인증 쿠키처럼 보이는 쿠키(이름이나 값을 만드는 표현식 기준)만 판단하며, 서블릿 `Cookie`와 프로퍼티는 SameSite가 없다는 이유만으로는 보고하지 않습니다. 삭제용 쿠키(`setMaxAge(0)`, 빈 값)는 건너뜁니다. 변수, 분기, 다른 메서드로 넘긴 쿠키에서 정해지는 플래그는 낮은 신뢰도로 보고하고 inferred를 붙이며, 리터럴로 고정된 안전한 값만 보고하지 않습니다.
- `PG-CONF-001`: 마지막 규칙의 `anyRequest().permitAll()`(또는 `requestMatchers("/**").permitAll()`, Kotlin `authorize(anyRequest, permitAll)`), 정적 리소스가 아닌 경로의 `web.ignoring()`(`/css/**`, `/js/**`, 파일 확장자, `PathRequest.toStaticResources()`는 괜찮고, 문서 엔드포인트와 읽을 수 없는 경로는 low), 자격 증명과 함께 쓴 와일드카드 CORS(`allowedOrigins("*")`, `allowedOriginPatterns("*")`, `@CrossOrigin(origins = "*")`), `@EnableWebSecurity(debug = true)`와 보안 디버그 로그(낮은 심각도), 프로젝트의 Java·Kotlin 파일과 Maven·Gradle 파일 어디에도 웹 보안(`spring-boot-starter-security`, `spring-security-web`·`-config`, `SecurityFilterChain`·`@EnableWebSecurity` import. 인코더나 `spring-security-crypto`만으로는 해당하지 않음)이 보이지 않을 때의 `management.endpoints.web.exposure.include=*`(항상 low, inferred)를 봅니다. 앞선 제한 규칙, `securityMatcher`, 개발 프로파일은 신뢰도를 낮춥니다.
- 설정 파일: `application.properties`, `application-*.properties`, `application.yml`, `application-*.yml`(`.yaml` 포함)은 Java·Kotlin 프로젝트에서만 읽으며, 작은 YAML 리더(블록 매핑, 스칼라 목록, 한 줄 flow 목록, `---` 문서. 앵커와 여러 줄 flow 컬렉션은 아님)를 사용합니다. `application-dev`, `-local`, `-test` 같은 프로파일이나 리터럴이 아닌 값(`${VAR}`, `${VAR:false}`, `@token@`, `!!bool false`)은 low이며 inferred입니다. `false`, `off`, `no`, `0`은 false로, `true`, `on`, `yes`, `1`만 안전한 값으로 봅니다. 256 KiB를 넘는 파일, 4 KiB를 넘는 줄, 형식이 깨졌거나 읽을 수 없는 파일, 앵커·별칭·병합 키·중첩 flow 맵이 있는 YAML은 커버리지 영역 `source:jvm-config`에서 partial로 보고합니다. 디버그와 Actuator 발견 항목은 규칙 수준 CWE(CWE-942, CWE-862)를 그대로 쓰며, 항목별 CWE는 기록하지 않습니다.

`PG-SSRF-002`(SSRF)가 보는 것은 다음과 같습니다.

- 싱크: `URL.openConnection()`, `openStream()`, `getContent()`, Kotlin `URL.readText()`, `HttpRequest.newBuilder(URI)`와 `.uri(x)`(`java.net.http`), Spring `RestTemplate`(`getForObject`, `getForEntity`, `postForObject`, `postForEntity`, `exchange`, `execute` 등), `WebClient.get().uri(x)`, `RestClient`, `WebClient.create(x)`와 `.baseUrl(x)`, OkHttp `Request.Builder().url(x)`, Apache `new HttpGet(x)`(`HttpPost` 등 포함)·`Request.Get(x)`·`setUri`, Ktor `client.get(x)`·`post`·`request` 등과 `url(x)`, `Jsoup.connect(x)`, `Unirest.get(x)`, `new UrlResource(x)`(`file:` 제외), 그리고 `ImageIO.read`, `IOUtils.toString`, `FileUtils.copyURLToFile`, `ObjectMapper.readValue`에 넘기는 `URL`. `new URL(x)`, `URI.create(x)`, `UriComponentsBuilder`(`fromHttpUrl`, `path`, `pathSegment`, `queryParam`, `build`, `toUri`), OkHttp `HttpUrl.parse`로 만든 URL은 따라갑니다.
- 심각도: 호스트가 고정되지 않은 URL에 요청 입력이 들어가면 high(직접 읽으면 confirmed, 높은 신뢰도)입니다. 스킴과 호스트가 고정이고 경로나 쿼리만 요청에서 오는 URL(`"https://api.example.com/users/" + id`)은 **낮은 신뢰도**, 심각도 medium이며 근거에 고정된 기준 URL이 표시됩니다(`../`나 `@` 같은 경로 주입으로 그 호스트의 다른 엔드포인트에 닿을 수 있기 때문). 고정 문자열 바로 뒤에 요청 입력이 오면(`BASE + id`, `/` 없음) 고정된 기준 URL로 보지 않습니다. URI 템플릿 변수(`getForObject("https://h/{id}", String.class, id)`)는 인코딩되고 URL이 고정이므로 보고하지 않습니다.
- 가드: 호스트 허용 목록 검사는 실패 시 빠져나가거나(`if (!ALLOWED.contains(uri.getHost())) throw ...`, `require(host in ALLOWED)`) 요청이 성공 분기 안에 있을 때만 인정하며, 그때 낮은 신뢰도가 됩니다. 인식하는 검사: `contains`, `equals`, `matches`, 리터럴과 함께 쓰는 `startsWith`/`endsWith`, 검증자 이름의 호출, 호스트나 `InetAddress.getByName(host)`에 대한 사설 주소 검사(`isLoopbackAddress`, `isSiteLocalAddress` 등). 호스트에 대한 검사는 그 호스트를 읽어 낸 URL(`host = new URL(url).getHost()`)에도 적용됩니다. 빠져나가지 않는 검사나 다른 변수에 대한 검사는 아무것도 낮추지 않습니다.
- 그 밖에 낮은 신뢰도: 고정 표 조회, 숫자, 헬퍼의 결과, 출처를 알 수 없는 단순 매개변수. 구문상 고정된 URL만 보고하지 않습니다.
- 한계: 리다이렉트, DNS rebinding, `endsWith("example.com")` 같은 약한 검사는 판단하지 않습니다. 클라이언트는 타입이 아니라 이름과 import로 인식합니다. 리플렉션은 따라가지 않습니다. Retrofit, Feign 같은 선언형 클라이언트는 분석하지 않습니다.

암호화 규칙(`PG-CRYPTO-001`, `PG-CRYPTO-002`, `PG-CRYPTO-003`)과 비밀번호 저장 규칙(`PG-AUTH-001`)이 보는 것. 이 규칙들은 JavaScript, Go 버전과 같은 규칙 id를 쓰며, 그 버전들처럼 taint 규칙이 아니라 한 파일 안의 패턴 규칙입니다. 값은 한 번만 대입되는 지역 변수, `final` 상수, 같은 파일의 필드까지만 따라갑니다.

- `PG-CRYPTO-001`(비밀번호의 약한 해시): `MessageDigest.getInstance("MD5" | "SHA-1" | "SHA")`(상수, `MessageDigestAlgorithms.MD5`, `DigestUtils.getDigest`를 거친 경우 포함), Guava `Hashing.md5()`·`Hashing.sha1()`, Commons Codec와 Spring의 `DigestUtils.md5Hex`·`sha1Hex`·`md5DigestAsHex` 등입니다. 같은 호출 체인, 다이제스트 변수, 또는 매개변수를 해시하는 같은 파일의 헬퍼 메서드를 통해 비밀번호 이름의 값(`password`, `pwd`, `getPassword()` 등)이 해시될 때 보고합니다. 다른 값(ETag, 체크섬, 캐시 키)의 해시는 JavaScript, Go와 같이 보고하지 않습니다. 비밀번호 이름의 메서드나 클래스 안에 있지만 비밀번호 값이 보이지 않는 약한 해시는 낮은 신뢰도로 보고합니다. 더 이상 권장되지 않는 Spring 인코더 `StandardPasswordEncoder`, `LdapShaPasswordEncoder`, `MessageDigestPasswordEncoder`, `Md4PasswordEncoder`는 생성되는 곳에서 보고합니다.
- `PG-CRYPTO-002`(하드코딩된 키·비밀정보): `new SecretKeySpec(...)`, `Keys.hmacShaKeyFor`, JJWT `signWith`·`setSigningKey`, Auth0 `Algorithm.HMAC256/384/512`, Nimbus `MACSigner`·`MACVerifier`, Shiro `setCipherKey`, `PBEKeySpec`에 전달되는 문자열 리터럴(`"...".getBytes()`, Kotlin `toByteArray()`), 리터럴 바이트 배열, 모두 0인 배열, 리터럴의 Base64·16진수 디코딩입니다. 직접 전달하거나 파일 안의 `final` 상수, Kotlin `const val`, 한 번만 대입되는 지역 변수를 거쳐도 읽습니다. 리터럴 키는 높은 신뢰도입니다. `@Value("${jwt.secret:literal}")`(`${a:${B:literal}}` 같은 중첩 기본값 포함), `System.getProperty(name, "literal")`, `getOrDefault`, `Optional.orElse`, 삼항 연산자, Kotlin `?:`에서 오는 비어 있지 않은 리터럴 기본값은 설정이 없을 때 그 기본값이 쓰이므로 중간 신뢰도이며 evidence는 "default value in source"입니다. 빈 기본값이나 기본값이 없는 경우는 보고하지 않습니다. 키 API에 닿는 키 기본값은 설정이 없을 때 그 기본값이 곧 키이므로 중간 신뢰도이고, 약한 암호 알고리즘의 기본값은 환경마다 설정으로 덮어쓰는 것이 보통이고 변환 이름 자체는 비밀정보가 아니므로 낮은 신뢰도로 둡니다. 키 API에서 읽히지 않는 필드나 매개변수의 `@Value` 기본값은 속성 이름이나 필드 이름이 비밀정보처럼 보일 때(`secret`, `signing-key`, `hmac`, `passphrase`, `password` 등. `cache.key`, `site-key`, `publishable-key`, `sort.key`는 제외)만 낮은 신뢰도("; inferred")로 보고하며 `server.port`나 `jwt.public-key`는 보고하지 않습니다. 다른 곳에서 덮어쓰는 변수나 final이 아닌 필드의 리터럴은 낮거나 중간 신뢰도로 보고합니다.
- `PG-CRYPTO-003`(깨진 암호, 고정 IV, 약한 난수): DES, DESede, RC2, RC4, Blowfish, 비밀번호 기반 `PBEWith...And...DES`, 모드 없는 `AES`(JCA는 ECB로 처리), `ECB` 모드(`RSA/ECB/...`는 블록 모드가 아니므로 제외)를 쓰는 `Cipher.getInstance`와, `KeyGenerator.getInstance`·`SecretKeyFactory.getInstance`·`SecretKeySpec`의 알고리즘에 쓰인 같은 약한 이름입니다. 고정 IV는 리터럴, 리터럴 배열, 모두 0인 배열, 상수로 만든 `new IvParameterSpec(...)`이나 `GCMParameterSpec`의 nonce입니다. 이후 채워지는 배열(`SecureRandom.nextBytes(iv)`, `in.read(iv)`)은 실행 시점 데이터로 보고 보고하지 않습니다. 리터럴이 아닌 `x`를 쓰는 `Cipher.getInstance(x)`는 보고하지 않습니다(매개변수, 메서드 결과, 환경 변수 값은 알 수 없음). 단 `x`가 약한 리터럴 기본값을 가진 설정값(`@Value("${cipher:DES}")`, `getProperty("cipher", "DES")`)에서 오면 "algorithm not fixed; inferred"로 낮은 신뢰도 보고합니다.
- 약한 난수(역시 `PG-CRYPTO-003`): `new java.util.Random()`, `ThreadLocalRandom`, `Math.random()`, Kotlin `Random`, `RandomStringUtils.random*`, `RandomUtils`의 값은 키, IV, salt, 토큰, nonce 맥락에 닿을 때만 보고합니다. 암호화 API(`SecretKeySpec`, `IvParameterSpec`, `GCMParameterSpec`, `PBEKeySpec`의 salt, `Keys.hmacShaKeyFor`, `Algorithm.HMAC*`)에 직접, 또는 지역 변수나 `random.nextBytes(...)`로 채운 버퍼를 거쳐 닿으면 중간 신뢰도입니다. 이름이 token, key, IV, salt, nonce, OTP, CSRF, secret, reset code인 변수, 필드, setter, 반환 메서드에만 닿으면 낮은 신뢰도("; inferred")입니다. `SecureRandom`, `UUID.randomUUID()`, 요소 선택·지터·셔플에 쓴 난수는 보고하지 않습니다.
- `PG-AUTH-001`(해시 없이 저장된 비밀번호): 비밀번호 이름의 값(`dto.getPassword()`, `req.password` 같은 요청 DTO의 필드나 getter, `@RequestParam`·`@RequestBody` 매개변수, `request.getParameter("password")`, `password`라는 이름의 지역 변수나 매개변수)이 `setPassword`, 생성자, `builder().password(...)`, Kotlin 프로퍼티 대입으로 엔티티에 들어가고 그 엔티티가 `save`, `saveAndFlush`, `persist`, `merge`, `insert` 등에 전달되는 경우, `updatePassword` 같은 저장소 메서드, `password` 컬럼에 쓰는 JDBC `INSERT`·`UPDATE`(`update(sql, ...)`, `PreparedStatement.setString`), 비밀번호 필드가 있는 같은 파일의 `@RequestBody` 엔티티를 그대로 저장하는 경우입니다. 메서드에 해시 호출(`passwordEncoder.encode`, `BCrypt.hashpw`, Argon2, `DigestUtils.sha256Hex` 등)이 있으면 보고하지 않습니다. 값을 요청에서 읽었으면 중간 신뢰도, 이름만 비밀번호이면 JavaScript와 같이 낮은 신뢰도("; inferred")입니다. `NoOpPasswordEncoder`는 평문 저장으로 보고합니다.
- 한계: 프로시저 내부 분석입니다. 다른 메서드, 다른 파일, 주입된 빈에서 오는 키·알고리즘·비밀번호는 따라가지 않습니다. `User#setPassword` 안에서 해시하거나 `@PrePersist` 훅에서 해시하는 경우는 보지 못하므로 일반 비밀번호 매개변수는 낮은 신뢰도로만 보고합니다. Bouncy Castle, Google Tink, Jasypt, Apache Shiro의 암호화 API는 읽지 않으며, 감지된 라이브러리마다 `partial` `source:crypto:*` 영역이 추가되고, 익명 클래스·로컬 클래스·Kotlin 로컬 함수 안의 암호화 호출은 영역을 partial로 만듭니다. 익명 클래스 안의 약한 난수는 따라가지 않습니다. 보고하지 않으며, 그 클래스에 암호화 호출도 있을 때만 영역이 partial이 됩니다. `RSA/ECB/PKCS1Padding` 같은 약한 패딩, 작은 키 크기, 인증서 검증, TLS 설정은 판단하지 않습니다.

Python은 두 범주만 다룹니다: **SQL 인젝션**(`PG-SQL-006`)과 **OS 명령 실행**(`PG-CMD-004`). XSS(Jinja2 `|safe`, `Markup`, `mark_safe`), SSRF, 경로 조작, 암호화, 설정 점검(`DEBUG`, `SECRET_KEY`)은 Python에서 아직 구현되지 않았습니다. coverage에는 `source:python:other-categories` 영역이 `not_tested`로 표시되므로, Python 결과에 문제가 없다고 나와도 그 범주에 대해서는 아무것도 알려 주지 않습니다. Django, Flask, FastAPI는 import와 `requirements*.txt`, `pyproject.toml`, `Pipfile`, `setup.py` / `setup.cfg`(텍스트로만 읽고 실행하지 않음)에서 감지해 `source:python` coverage 설명에 표시합니다. 두 규칙은 Java·Kotlin 규칙과 같은 방식의 분석을 씁니다. 한 파일의 한 함수 안에서만 따라가며 함수나 파일 사이의 데이터 흐름, 타입 해석은 보지 않습니다. 무엇을 보고하는지에 대한 원칙도 같습니다. 구문상 고정된 값만 보고하지 않으며, 그 밖의 값은 숨기지 않습니다. 안전하다고 추정만 하는 값은 낮은 신뢰도(최대 medium 심각도)로 낮추고 근거 끝에 `; inferred`를 붙입니다. 가드 원칙도 같습니다. 검사가 실패했을 때 코드가 빠져나가거나(`return`, `raise`, `continue`, `break`, `abort()`, `sys.exit()`), 사용 지점이 검사가 성립하는 분기 안일 때만 가드로 인정합니다. `rules list --language python`으로 확인할 수 있습니다. `PG-SQL-006`이 보는 것은 다음과 같습니다.

- 싱크: DB-API `execute`, `executemany`, `executescript`(sqlite3, psycopg2/3, PyMySQL, mysqlclient, mysql-connector, pyodbc, cx_Oracle, asyncpg 등의 cursor, connection, session, engine), SQLAlchemy `text()`와 `literal_column()`(문자열을 만든 자리에서 보고하며 `session.execute(text(...))`는 두 번 보고하지 않음), `engine.execute(str)`와 `exec_driver_sql`, Django `.raw()`, `.extra()`(`select`, `where`, `order_by`, `tables`), `RawSQL`, `connection.cursor().execute`, `pandas.read_sql` / `read_sql_query`. 두 번째 인자의 매개변수(`cursor.execute("... WHERE id = %s", (x,))`, dict와 `:name`, `.raw(sql, [x])`, `.extra(where=[...], params=[...])`)는 값을 바인딩하므로 보고하지 않습니다.
- 요청 입력: Flask `request.args/form/values/json/data/cookies/headers/files/view_args`와 `get_json()`, 웹 프레임워크를 import한 파일의 뷰(첫 매개변수가 `request`인 함수나 클래스 기반 뷰 메서드)에서 쓰는 Django `request.GET/POST/COOKIES/META/body/FILES`, DRF `request.data` / `query_params`, 라우트로 장식된 함수(`@app.route`, `@app.get`, `@router.post`, `@api_view`, `@action`)의 매개변수. `int`, `float`, `bool`, `UUID`, 날짜로 주석을 단 라우트 매개변수와 Flask `<int:id>` 변환기는 추정된 숫자로 봅니다. `Depends(...)` 매개변수와 프레임워크 객체(`Session`, `Response`)는 입력이 아닙니다. 명령줄 입력도 `command-line input`으로 보고합니다: `sys.argv`, `input()`, argparse `parse_args()` 결과, `click` 명령의 매개변수.
- 문자열 조립: `+`, `%`, `.format()`, f-string, `str.join`, `+=`, `list.append`를 지역 변수, 튜플, 클로저, 재할당을 거치며 따라갑니다. `%d`와 `{:d}`는 숫자만 받으므로 추정(inferred)으로 처리합니다.
- 고정 문자열은 보고하지 않습니다: 리터럴, 고정 `text(...)` 뒤의 `.bindparams(...)`, 고정 값으로만 만든 f-string·`%`·`.format()`·연결, 그런 값을 한 번만 대입한 모듈 수준·클래스 수준 이름(`TABLE = "users"`, `self.TABLE`, `Repo.TABLE`), `",".join(["?"] * n)` 같은 반복, 리터럴 튜플에 대한 반복문.
- 낮은 신뢰도로 낮춤(`; inferred`): 허용 목록 또는 형태 검사(`if col not in ALLOWED: abort(400)`, `col.isalnum()`, `re.fullmatch(...)`, `is_valid_*()` 호출, `isinstance(x, int)`, 형태 검사는 근거에 그렇게 표시), `int()`·`float()` 등 숫자 변환, 리터럴 dict 조회(`ORDERS[key]`, `ORDERS.get(key, "id")`, 호출자가 정한 기본값(`ORDERS.get(key, key)`)은 그 값 자체의 신뢰도를 유지), 다른 모듈에서 가져온 상수 이름, `psycopg2.sql.Identifier`, `cursor.mogrify()`. 도우미 함수의 결과(`value from build_sql(), not followed`)와 출처를 찾을 수 없는 조립 문자열(함수 자신의 매개변수)도 낮은 신뢰도입니다.
- 한계: 분석은 함수 내부(intra-procedural)입니다. 반복문 본문이나 `if` 안에서 한 검사는 그 블록과 함께 끝나며(`if bad: continue`는 반복문 뒤가 아니라 본문의 나머지를 보호), `except`가 있는 `try` 안의 `raise`는 빠져나가는 것으로 보지 않습니다. `.extra()`는 어느 파일에서든 보고하고, `.raw()`는 Django import나 매니페스트, SQL처럼 보이는 문자열, `objects` 매니저가 있을 때 보고합니다. 매개변수를 SQL 문자열 전체로 그대로 넘기는 경우(`def run(sql): cur.execute(sql)`)는 Java·Kotlin 규칙과 같이 보고하지 않지만, 명령에 들어가는 출처 불명 값은 낮은 신뢰도로 보고합니다. 다른 함수나 파일에서 온 값, 다른 메서드에서 설정한 `self.x`, 재할당되는 전역 변수는 따라가지 않습니다. 객체는 타입이 아니라 이름과 import로 알아봅니다. 이름이 `c`인 cursor는 SQL처럼 보이는 문자열이 있어야 합니다. Peewee, Pony, Tortoise ORM, Records 등 자체 raw SQL API는 분석하지 않으며, 감지될 때마다 `partial` `source:orm:*` 영역이 추가됩니다. `getattr(...)(...)`, `__import__(...)` 호출과 `os`·`subprocess` 별표 import는 대상을 가리므로, 해당 영역이 `partial`이 되고 파일을 알려 줍니다. Python 파일은 매 스캔마다 다시 분석합니다(증분 스캔에서 결과를 재사용하지 않음).

`PG-CMD-004`(OS 명령 실행)가 보는 것은 다음과 같습니다.

- 싱크: `os.system`, `os.popen`, `commands.getoutput` / `getstatusoutput`(Python 2), `subprocess.run/call/check_call/check_output/Popen`과 `getoutput` / `getstatusoutput`, `asyncio.create_subprocess_shell` / `create_subprocess_exec`, `pty.spawn`, `os.exec*` / `os.spawn*`. import를 따라갑니다(`import subprocess as sp`, `from os import system`). 같은 이름의 지역 변수나 매개변수가 있으면 import를 가립니다.
- 심각도: `os.system` / `os.popen`의 문자열, `shell=True` 명령, 리스트가 아닌 명령 문자열, 셸 래퍼(`sh -c`, `bash -lc`, `cmd /c`, `powershell -Command`, 그리고 `env`, `sudo -u app`, `nohup`, `timeout 10`, `nice -n 5`, `xargs` 같은 실행기 뒤의 래퍼)의 스크립트, 리스트의 프로그램 자리에 요청 입력이 들어가면 **critical**입니다(신뢰도 high, 직접 읽으면 confirmed, 변수를 거치면 suspected). 고정된 프로그램의 인자(`subprocess.run(["git", "log", ref])`, 셸 없음)에 들어가면 **인자 주입**으로 심각도 **medium**, suspected, 신뢰도 medium입니다. `--`나 `--end-of-options` 뒤에 놓인 값은 낮은 신뢰도(`; inferred`)로 낮춥니다.
- 고정 명령은 보고하지 않습니다: `subprocess.run(["ls", "-l"])`, `os.system("uptime")`, 상수로만 만든 명령의 `shell=True`. `+`, `*`, `append`, `extend`, `+=`로 상수에서 만든 리스트도 같습니다.
- `shlex.quote()`와 `pipes.quote()`는 알아보지만 믿지는 않습니다. `shell=True`와 함께 쓴 인용 값도 낮은 신뢰도로 결과에 남습니다(`quoted with shlex.quote() (POSIX shells only); inferred`). SQL 이스케이프로는 절대 취급하지 않습니다.
- 낮은 신뢰도로 낮춤(`; inferred`): 값에 대한 허용 목록·형태 검사, 숫자, 리터럴 dict 조회, 도우미 함수의 결과, 출처를 찾을 수 없는 값(함수 자신의 매개변수), 리터럴이 아닌 `shell=` 플래그.
- 한계: `env=`, `cwd=`, `stdin`, 시작된 프로그램이 실행하는 스크립트, `os.environ`, 다른 함수나 파일에서 만든 명령은 확인하지 않습니다. `sh`, `plumbum`, `pexpect`, Fabric, Invoke, Paramiko, asyncssh처럼 자체 프로세스 API를 가진 라이브러리는 분석하지 않으며, 감지될 때마다 `partial` `source:process:*` 영역이 추가됩니다.

HTML sink(`innerHTML`, `outerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`)에 sanitizer 호출(예: `DOMPurify.sanitize(...)`)을 바로 거친 값을 넣으면 보고하지 않습니다. JavaScript와 TypeScript에서는 PGARD가 (파일 안에서 TypeScript의 심볼 해석으로) 변수를 그 변수 자신의 `var`/`let`/`const` 선언으로 해석할 수 있고 그 변수에 대한 모든 대입이 sanitizer 호출일 때도 sanitize된 것으로 봅니다. import, 매개변수, 전역 변수, 클래식 스크립트의 최상위 `var`/`let`, 그리고 `eval`, `with`, `Function`, 문자열 타이머를 쓰는 파일의 변수는 sanitize된 것으로 보지 않습니다. sanitizer는 함수 이름으로만 인식하며, sanitizer 설정은 확인하지 않습니다.

PHP는 두 범주만 다룹니다: **SQL 인젝션**(`PG-SQL-007`), **OS 명령 실행**(`PG-CMD-005`). 대상 파일은 `.php`와 `.phtml`이며, Blade 템플릿(`.blade.php`)은 감지하고 `<?php ?>` 블록만 파싱합니다. Blade XSS 검사가 생기기 전까지는 `source:php:blade` 영역이 `not_tested`로 표시됩니다. Laravel과 Symfony는 `composer.json`과 네임스페이스(`use Illuminate\...`, Symfony 프레임워크 네임스페이스)에서 감지해 coverage 설명에 표시합니다. 그 밖의 범주(XSS, 파일 포함·경로, SSRF, 암호화, 설정)는 PHP에서 아직 검사하지 않으며 `source:php` 설명에도 그렇게 적습니다. 따라서 PHP 결과에 문제가 없다고 나와도 그 범주에 대해서는 아무것도 알려 주지 않습니다. 두 규칙은 하나의 프로시저 내부(intra-procedural) 분석을 공유합니다. 한 파일의 한 함수나 메서드 안에서만 따라가며, 함수나 파일 사이의 데이터 흐름과 타입 해석은 보지 않습니다. 보고 원칙은 Java·Kotlin 규칙과 같습니다. 구문상 고정된 값만 보고하지 않으며, 그 밖의 값은 숨기지 않고 낮은 신뢰도와 최대 medium 심각도로 낮춰 근거 끝에 `; inferred`를 붙입니다.

- `PG-SQL-007` 싱크: `mysqli_query`, `mysqli_real_query`, `mysqli_multi_query`, `mysql_query`, `pg_query`; 데이터베이스 핸들(`$pdo`, `$mysqli`, `$conn`, `$this->db`처럼 이름 붙인 변수·프로퍼티, `PDO`/`mysqli` 객체나 매개변수, 또는 문자열이 SQL처럼 보이는 모든 수신자)의 `->query`, `->exec`, `->prepare`, `->real_query`, `->multi_query`; Laravel `DB::raw`, `DB::select`/`statement`/`unprepared`/`insert`/`update`/`delete`(`DB::connection()->...` 포함)와 `whereRaw`, `orWhereRaw`, `selectRaw`, `orderByRaw`, `havingRaw`, `groupByRaw`, `fromRaw`; Doctrine `createQuery`, `createNativeQuery`, 그리고 커넥션의 `executeQuery`, `executeStatement`, `fetchAssociative` 등 `fetch*` 호출.
- 문자열 만들기: `.` 연결, `.=`, 큰따옴표 보간(`"$x"`, `"{$x['k']}"`), heredoc, `sprintf`/`vsprintf`, `implode`를 지역 변수, 재대입, 분기, 반복문을 거쳐 따라갑니다. 플레이스홀더와 바인딩된 매개변수(`prepare('... = ?')`, `DB::select('... = ?', [$x])`, `whereRaw('a = ?', [$x])`, Doctrine `setParameter`)는 안전합니다. 이미 만들어진 문자열을 `prepare`하는 것은 보고합니다.
- `PG-CMD-005` 싱크: `exec`, `system`, `shell_exec`, `passthru`, `popen`, `proc_open`, `pcntl_exec`, 백틱 연산자, Symfony `Process::fromShellCommandline`과 `new Process("...")`(문자열 형태), Laravel `Process::run("...")`. 요청 데이터가 든 문자열은 critical입니다. 프로그램이 상수인 배열 명령(`proc_open([...])`, `new Process([...])`, `Process::run([...])`)은 셸을 시작하지 않지만, 인자에 든 요청 입력은 여전히 옵션으로 읽힙니다(인자 주입). 이 경우 medium 심각도와 medium 신뢰도로 보고하고, 옵션 구분자(`--`, `--end-of-options`) 뒤에 있거나 요청 입력과 이어지지 않는 값은 low 심각도와 low 신뢰도로 보고합니다. 셸 래퍼(`['sh', '-c', $script]`)이거나 프로그램 자체가 데이터에서 오면 critical이고, 모두 상수인 배열은 보고하지 않습니다. 출처가 확인되지 않은 값(매개변수, 알 수 없는 변수)이 그대로 명령에 들어가면 낮은 신뢰도로 보고합니다("callers not followed"). SQL은 매개변수를 그대로 넘기는 경우를 보고하지 않습니다.
- 요청 입력: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, 클라이언트가 정하는 `$_SERVER` 키(`HTTP_*`, `REQUEST_URI`, `QUERY_STRING`, `PHP_SELF`, `PATH_INFO`), `php://input`, `filter_input`, `getallheaders()`, 요청 객체(`Request` 타입 매개변수 또는 `$request`라는 이름, `request()`, `Request` 파사드, `$this->request`)의 `input`, `get`, `query`, `all`, `post`, `header`, `cookie`, `route`와 프로퍼티 접근. 변수에 담았다가 나중에 쓰면 "via variable"로 보고합니다.
- 고정된 텍스트는 보고하지 않습니다: 리터럴, 리터럴로만 만든 상수(같은 파일의 `const`, `define`, 클래스 `const`, enum case), `intval`, `floatval`, `(int)`, `(float)`, `(bool)` 캐스트, 그런 값들의 `match`, 삼항, `??`.
- 낮은 신뢰도(`; inferred`)로 낮추는 경우: `mysqli_real_escape_string`, `addslashes`, `pg_escape_*`, `esc_sql`, PDO `quote()`, `escapeshellarg`/`escapeshellcmd`(숫자, 식별자, 옵션처럼 보이는 값에는 충분하지 않음), `sprintf`의 숫자 변환, 숫자·다이제스트 함수, `urlencode`, 고정 배열 조회, 리터럴로 초기화되고 클래스 안에서 다시 대입되지 않는 private 프로퍼티, 다른 파일의 상수 스타일 이름, 가드를 통과한 값. 가드는 실패했을 때 빠져나가거나(`return`, `throw`, `exit`/`die`, `abort()`, `continue`, `break`, `check($x) or die()`) 사용 부분이 성공 분기 안에 있을 때만 인정합니다: `in_array`, `ctype_*`, `is_numeric`, `is_int`, `isset($allowed[$x])`, `array_key_exists`, 앵커가 있는 `preg_match('/^...$/')`, 정수·실수·불리언·IP 필터의 `filter_var`, `=== '리터럴'`, `validate*`/`check*` 함수 이름. 빠져나가지 않는 검사, 다른 변수에 대한 검사, 실패 분기는 아무것도 낮추지 않습니다.
- 한계: 분석은 프로시저 내부(intra-procedural)입니다. 헬퍼(같은 파일이나 다른 파일의 함수·메서드)가 돌려준 값은 따라가지 않습니다. 그런 값이 들어간 조립 문자열은 낮은 신뢰도로 보고하고, 헬퍼가 돌려준 값을 그대로 넘기는 경우는 "value from helper(), not followed; inferred"로 보고합니다. SQL에서는 매개변수를 그대로 넘기는 경우 텍스트를 어떻게 만들었는지 알 수 없으므로 보고하지 않습니다(명령에 출처 불명 값이 그대로 들어가면 낮은 신뢰도로 보고합니다). `array_map`, `array_walk`, `array_filter`, `usort`에 리터럴 명령 콜백을 주면 싱크로 검사하고, 리터럴이 아닌 콜백에 데이터를 넘기면 해당 영역을 `partial`로 만듭니다. 클로저와 화살표 함수는 각각 하나의 함수로 분석합니다. `call_user_func('system', ...)`, `call_user_func_array('exec', [...])`, `$f = 'exec'; $f(...)`(리터럴 하나를 담은 변수)는 해석해서 직접 호출처럼 검사합니다. 그 밖에 변수나 계산된 이름으로 호출하면서(`$fn(...)`, `$object->$method(...)`, `call_user_func($name, ...)`) 상수가 아닌 데이터를 넘기는 호출은 SQL이나 명령 싱크에 닿을 수 있지만 따라가지 않으며 해당 영역을 `partial`로 만듭니다. `$wpdb->prefix`는 "WordPress table prefix"로 낮추고, `$wpdb`는 `->query`, `->prepare`, `get_results`, `get_row`, `get_var`, `get_col`을 평가하지만 `insert`, `update`, `delete`, `replace`는 평가하지 않습니다. Doctrine `QueryBuilder`, RedBeanPHP, Laminas/Zend Db, Yii DAO, CakePHP database, Medoo, Amp process, Spatie shell은 분석하지 않으며, 감지된 라이브러리마다 `partial` 상태의 `source:orm:*` 또는 `source:process:*` 영역이 추가됩니다. PHP 파일은 매 스캔마다 다시 분석합니다(결과를 캐시하지 않습니다).

## 코드 기반 분석

PGARD는 취약점 데이터베이스를 포함하지 않으며, 검사는 이를 내려받거나 조회하지 않습니다. 발견 항목은 코드 자체(현재 파일의 쿼리문, 서버 코드, 설정, Git 이력의 비밀정보, 확인한 로컬 HTTP 서비스의 응답)와, npm과 Go lockfile에 대해서는 `pgard advisories update`로 **직접 내려받은 OSV 데이터와의 버전 비교**로 결정됩니다.

**`pgard scan`의 의존성.** 의존성은 기본 `code` 범위에 포함됩니다(`pgard scan`, `scan code`, `scan all`이 모두 포함하며 별도 플래그는 없습니다). PGARD는 패키지 관리자나 빌드 도구를 실행하지 않고 `package-lock.json` / `npm-shrinkwrap.json`(v1~v3), `pnpm-lock.yaml`, `yarn.lock`(classic, berry), `go.mod` / `go.sum`을 읽고(파일은 파싱만 하며 실행하지 않습니다. 심볼릭 링크는 따라가지 않고, 하드 링크는 한 번만 읽으며, 바이트(256 MiB)·패키지(500,000개)·시간(30초) 제한이 있고, `node_modules`와 빌드 디렉터리는 건너뜁니다), 고정된 각 버전을 로컬 OSV 권고의 영향 범위와 비교합니다(npm은 semver, Go는 모듈 버전). 규칙 `PG-DEP-001`이 일치 항목을 보고하며, 각 항목에는 패키지와 버전, 권고 ID(GHSA, 없으면 GO, 없으면 다른 레코드 ID이며, 다른 ID가 전혀 없을 때만 CVE입니다. CVE 별칭은 이후 업데이트에서 채워지기 때문입니다. `pgard compare`와 기준선도 같은 패키지 버전의 발견 항목을 겹치는 ID·별칭으로 짝지으므로, 대표 ID가 바뀌어도 해결 + 새 항목으로 보이지 않습니다)와 별칭, 영향 범위, 현재 버전보다 높은 수정 버전, 심각도가 담깁니다. 심각도는 권고의 벡터로 PGARD가 계산한 CVSS v3 기본 점수이고, 없으면 권고 데이터베이스 자체의 등급이며, 둘 다 없으면 `medium`으로 표시하되 알 수 없음으로 표기합니다(CVSS v4 벡터는 보관하지만 점수는 계산하지 않습니다). 철회된 권고는 무시하고, 여러 ID로 올라온 같은 문제는 한 번만 보여 줍니다.

**발견 항목의 의미.** 고정된 버전이 권고의 _영향 받는 버전 범위_ 안에 있다는 뜻입니다. 코드가 취약한 함수를 호출하는지, 도달 가능한지, 악용할 수 있는지는 확인하지 않으므로 상태는 `suspected`이고 신뢰도는 `high`가 아닙니다(`medium`. lockfile이 개발 전용으로 표시한 패키지, 단독 `go.sum`, 테스트·픽스처 경로는 `low`). 개발 전용 패키지는 lockfile이 알려 주는 경우(npm `dev`) 그렇게 표시합니다. 지문은 lockfile 경로, 패키지, 버전, 권고 ID로 만들며 데이터 버전에는 의존하지 않으므로, 재검사·기준선·`pgard compare`는 다른 발견 항목과 같게 동작합니다. 새 권고는 새 발견 항목입니다.

**커버리지.** lockfile이 있는 생태계마다 `deps:npm` 또는 `deps:Go` 영역이 생깁니다. 내려받은 데이터가 없으면 `not_tested`이고 `pgard advisories update`를 안내하며(전체 상태는 `partial`), 데이터가 손상되었으면 `not_tested`입니다. **오래된** 데이터(내려받은 시점이나 가장 새 레코드가 7일 이상 지남, `pgard doctor`와 같은 기준)이면 찾은 것은 그대로 보고하지만 영역은 `partial`이고 메모에 경과 일수를 적습니다. 더 새 권고가 빠져 있을 수 있어 "발견 없음"이 안전하다는 뜻으로 읽히면 안 되기 때문입니다. 이해하지 못한 lockfile, 비교하지 못한 패키지 버전, lockfile 없는 package.json, 도달한 제한도 `partial`로 만듭니다. 메모에는 데이터를 내려받은 날짜, 가장 새 레코드, 짧은 버전 태그가 적힙니다. 다른 생태계(Python, Java, PHP, Rust 등)의 lockfile은 규칙 없는 영역 `deps:unsupported`에 나타나며 "취약한 의존성 없음"으로 처리되지 않습니다. Go는 모듈 버전만 비교하며 Go 표준 라이브러리와 툴체인의 권고는 확인하지 않습니다(`deps:Go` 메모에 적습니다). Maven, PyPI, Packagist는 PGARD가 아직 lockfile을 읽지도, OSV 데이터를 내려받지도 않으므로 대조하지 않습니다.

선택한 모든 영역이 끝까지 실행된 검사는 `completed`를 보고하고 종료 코드 0으로 끝납니다. 종료 코드 4는 선택한 coverage 일부가 실제로 빠졌다는 뜻입니다. 예를 들어 웹 대상을 확인하지 못했거나 이력 검사가 한도에 도달한 경우입니다. 그래서 npm이나 Go lockfile이 있는데 내려받은 OSV 데이터가 없는 저장소도 종료 코드 4로 끝납니다(`deps:*` 영역이 `not_tested`, 오래된 데이터는 `partial`). `pgard advisories update`를 한 번 실행하면 해결되고, `pgard doctor`가 데이터가 오래되었다고 알리면 다시 실행하세요.

## 로컬 웹 검사

`scan web`, `scan all`, 대시보드는 사용자가 확인한 웹 서비스만 검사합니다.

1. CLI와 대시보드 모두, 권한 확인을 통과해야만 PGARD가 포트에 접근합니다(대시보드에서는 확인 후 30분이 지나면 포트 접근도 만료됩니다. [대시보드](#대시보드) 참고).
2. 각 서비스의 정체를 보여 주기 위해, PGARD는 (권한 확인을 통과한 뒤) `127.0.0.1`에서 발견한 각 열린 포트에 `GET /`를 한 번 보냅니다. HTTP로 응답하는 포트를 보여 줍니다. 목록은 불완전할 수 있으므로 **Other port**를 항상 제공합니다. 포트 번호만으로는 어떤 프로젝트의 서비스인지 알 수 없습니다.
3. 서비스의 URL, HTTP 상태, 페이지 제목, 추정 기술을 보여 줍니다.
4. `이 프로젝트의 서비스가 맞습니까? [y/N]`(영어: `Is this the current project's service? [y/N]`)에 답합니다. 명시적인 `y`만 확인으로 인정합니다. `--port`를 지정해도 이 확인을 거칩니다.
   - 질문 전에 PGARD는 서비스가 이미 알려 준 정보(페이지 제목, `Server`/`X-Powered-By` 헤더, 추정 기술)를 프로젝트(폴더·저장소 이름, `package.json`·`pyproject.toml`·`composer.json`·`go.mod`의 `name`, 선언된 프레임워크)와 견줘 봅니다. 분명히 다른 프로젝트처럼 보이면(Django와 Next.js 같은 프레임워크 불일치, 또는 프로젝트가 의존하지 않는 Grafana, Jupyter, pgAdmin, Docker Desktop, Ollama, LM Studio, 데이터베이스 웹 UI, Kubernetes 대시보드 같은 잘 알려진 무관한 도구) 먼저 노란 줄 하나가 나옵니다: `이 서비스는 현재 프로젝트와 관련 없어 보입니다 (서비스: 'Grafana', 프로젝트: 'shop').` 대시보드도 같은 줄을 보여 줍니다.
   - 로컬 데이터만으로 만든 힌트입니다(추가 요청 없음). 기본값은 계속 `N`이고 `y`로 답할 수 있으며(아래 "이 프로젝트의 서비스가 아닌 것을 확인했다면" 참고), 일치한다고 해서 증거가 되지는 않습니다. 서버가 여러 개면 이름이나 프레임워크가 맞는 서버가 먼저 나오고 `(이 프로젝트일 수 있음)`이 붙습니다.
5. 대화형 터미널이 없으면 대상을 확인할 수 없어 `web`은 `not_tested`, 검사는 `partial`(종료 코드 4)이 됩니다.

**이 프로젝트의 서비스가 아닌 것을 확인했다면.** 포트만으로는 어느 프로젝트의 서비스인지 알 수 없으므로 PGARD는 사용자의 `y`를 믿습니다. 그러면 그 서비스에 아래와 같은 한도로 검사가 진행됩니다. `127.0.0.1`에만 비로그인 `GET`/`HEAD`를 보내고, POST·PUT·DELETE·폼 제출은 하지 않으며, 로그아웃·삭제·초기화처럼 보이는 링크는 건너뛰고, 20페이지, 깊이 2, 60초까지만 봅니다. 원격 호스트로는 아무것도 나가지 않습니다. 그 서비스의 발견 항목(헤더, 쿠키 속성 등)이 이 프로젝트의 결과에 섞여 나옵니다. 모든 웹 발견 항목에는 출처 URL이 표시되므로 잘못 고른 것을 거기서 알 수 있고, 다시 검사하면서 그 서비스에 `N`으로 답하면 됩니다. 잘못 만든 앱은 `GET`만으로도 상태가 바뀔 수 있으니(아래 참고) 알아보는 서비스만 확인하세요.

**`pgard scan`이 제안하는 감지된 서버(메뉴의 코드 + 히스토리 항목 포함).** 대화형 터미널에서 범위 단어, `--port`, `--format json|sarif` 없이 `pgard scan`을 실행하면 먼저 `127.0.0.1`에서 대기 중인 포트를 찾습니다(최대 약 1초, 실패하거나 시간이 지나면 무시). 권한 확인을 통과하면(아직 로그인하지 않았다면 제안하지 않음) 제목을 읽기 위해 대기 중인 각 포트에 `GET /` 요청을 한 번씩 보내고, HTTP에 응답하는 서버가 있으면 `http://127.0.0.1:3000 (Acme Shop)도 함께 검사할까요(웹 검사)? [y/N]`라고 묻고, 서버가 여러 개면 하나를 고르거나 "아니요"를 고릅니다. 기본값, Esc, Ctrl+C는 모두 아니오이며 이때 검사는 이전과 똑같이 실행됩니다. 고른 서버는 `--port`와 완전히 같은 신원 확인, `이 프로젝트의 서비스가 맞습니까? [y/N]` 확인, 요청 한도를 거치며 그 밖의 요청은 보내지 않습니다. 터미널이 없을 때, CI(`CI`, `GITHUB_ACTIONS` 등), `--format json|sarif`, `--port`, 명시적 범위(`scan code`, `scan history`, `scan web`, `scan all`)에서는 제안하지 않습니다.

검사는 `127.0.0.1:<port>`에만 비로그인 `GET`/`HEAD` 요청을 보냅니다. 같은 loopback origin 안의 리다이렉트만 따라가고, 로그아웃·삭제·초기화처럼 보이는 링크는 건너뜁니다. 한도는 20페이지, 깊이 2, 요청당 5초, 전체 60초, 응답 본문 1MB입니다. 보안 헤더, 쿠키 속성, 자격 증명과 함께 쓰인 CORS, 서버 버전 노출, 디렉터리 목록, `/.env`·`/.git` 노출(존재 여부만 확인하며 값은 보관하지 않음)을 살핍니다. 헤더가 없다는 사실은 정보성 항목으로 보고하며 취약점의 증거로 보지 않습니다.

잘못 만들어진 애플리케이션은 `GET` 요청에도 상태가 바뀔 수 있습니다. PGARD는 검사에 부작용이 없다고 보장할 수 없습니다.

## Git 이력 검사

`scan history`는 `HEAD`에서 추적 중인 파일과 최근 커밋 1,000개(first-parent만이 아닌 도달 가능한 모든 커밋)의 변경을 60초 한도 안에서 읽습니다. 1 MiB를 넘는 blob, 내용을 64 MiB 읽은 뒤 건너뛴 blob, 시간 초과가 있으면 그 영역은 설명과 함께 `partial`입니다. 바이너리 파일은 비밀정보를 검사하지 않으며 설명에 그 개수를 표시합니다. 비밀정보 값은 메모리에서만 비교하며 발견 항목·보고서에 넣지 않습니다.

- `PG-SECRET-001`: 커밋된 환경 파일(`.env`, `.env.local`, `prod.env` 등. `.env.example` 같은 템플릿은 제외). 값은 보여 주지 않습니다.
- `PG-SECRET-002`: `HEAD`에서 추적 중인 파일 속 비밀정보.
- `PG-SECRET-003`: Git 이력에서 발견된 비밀정보(현재 파일에 아직 있는지는 근거에 표시됩니다).
- `PG-HYGIENE-001`(info, 제안으로 표시): `HEAD`에서 의존성 디렉터리를 추적 중인 경우. 검사마다 발견 항목 하나가 루트 디렉터리와 추적 파일 수를 최대 5개까지 보여 줍니다. 해결 방법: 로컬 사본은 지우지 않고 인덱스에서만 제거하고(`git rm -r --cached node_modules`), `.gitignore`에 추가한 뒤 패키지 관리자로 복원합니다. 추적 중인 경로만 보고 판단하며 작업 트리는 읽지 않습니다. 루트는 vendored 경로([서드파티·vendored 코드의 제안](#서드파티vendored-코드의-제안) 참고)에서 대상이 되는 가장 바깥쪽 디렉터리이며, 중첩된 `node_modules/`는 그 루트에 포함됩니다.
  - `node_modules/`, `bower_components/`, `jspm_packages/`, `Pods/`는 항상 대상입니다.
  - `vendor/`는 저장소 루트에 있거나, 같은 디렉터리에 추적 중인 `composer.json`, `go.mod`, `Gemfile`이 있을 때만 대상입니다. Go 모듈 vendoring(추적 중인 `go.mod` 옆에 있고 `vendor/modules.txt`도 추적 중인 경우)은 Go가 지원하는 방식이므로 대상이 아닙니다. 직접 만든 `src/vendor/` 모듈은 vendored가 아니므로 대상이 되지 않습니다.
  - Rails importmap 고정 패키지는 대상이 아닙니다. `vendor/` 옆에 `config/importmap.rb`가 추적 중이면 `vendor/javascript/`의 파일은 `bin/importmap pin`이 일부러 커밋한 것이므로 세지 않습니다. 이때 나머지 하위 디렉터리는 하나씩 보고하므로, 커밋된 `vendor/bundle/`(설치된 gem)은 `vendor/bundle/`로 그대로 대상이 되고 제안하는 `git rm`은 고정 패키지를 건드리지 않습니다. `vendor/` 바로 아래의 파일(`vendor/jquery.min.js`)은 그대로 `vendor/`로 세되, 해결 방법은 `vendor/` 전체가 아니라 그 파일들을 하나씩(`git rm --cached vendor/jquery.min.js`, 최대 5개, 나머지는 개수로) 지정하고, 고정 패키지 안에 중첩된 의존성 디렉터리(`vendor/javascript/node_modules/`)도 그대로 대상입니다.
  - 디렉터리를 Git에 남기기 위한 placeholder 파일(`.keep`, `.gitkeep`. 예: `rails new`가 만드는 `vendor/.keep`)은 세지 않습니다.
  - `third_party/`는 의도적으로 복사해 둔 코드가 대부분이므로 대상이 아닙니다.
  - 바깥 디렉터리가 대상이 아닐 때(Go 모듈 `vendor/`, `third_party/`)도 그 안의 `node_modules/`, `bower_components/`, `jspm_packages/`, `Pods/`는 대상입니다(예: `vendor/node_modules/`). 대상이 아닌 디렉터리 안의 발견 항목도 그대로 vendored 제안으로 표시됩니다.

비밀정보는 개인 키, 잘 알려진 토큰 형식(AWS, GitHub, Slack, Stripe, Google API 키), URL 속 비밀번호(`postgres://user:password@host`), 일반적인 자격 증명 대입(`password = ...`, `api_key: ...`, `password := ...`, `headers["x-api-key"] = ...`, 타입 표기가 붙은 선언이나 `cond ? "..." : ...`처럼 조건 뒤에 오는 따옴표 값 포함)입니다. 일반 대입은 값이 충분히 무작위로 보이는 리터럴이고 placeholder가 아닐 때만 인정합니다. URL 속 비밀번호는 placeholder(`user:pass`, `${DB_PASSWORD}`, `$DB_PASSWORD`, 사용자 이름과 같은 값)가 아니면 보고하며, 짧거나 단순한 비밀번호는 낮은 신뢰도로 보고합니다. 소스 파일에서 확실히 코드로 보이는 줄의 따옴표 없는 값(타입, 매개변수 목록, 상수·변수 이름)은 자격 증명으로 보지 않습니다. 여러 줄 문자열(템플릿 리터럴, `"""` 블록, heredoc, raw 문자열)을 포함해 문자열 리터럴 안의 줄은 코드로 보지 않으며, 파일을 확실히 읽을 수 없을 때(예: 닫히지 않은 문자열)는 보고합니다. 탐지는 패턴 기반이라 흔하지 않은 형태는 여전히 놓칠 수 있습니다.

PGARD는 현재 파일에 비밀정보나 `.env` 파일이 더 이상 없다는 것을 보일 수 있을 때만 "삭제됨(removed)"이라고 합니다. 그 전에 `git grep -F`로 현재 커밋을 검색하며(값은 인자가 아닌 stdin으로 전달), 이 검색은 PGARD가 직접 읽지 않은 파일(너무 크거나, 읽기 한도를 넘었거나, 바이너리)도 다룹니다. `git grep`이 검색하지 못하는 UTF-16 텍스트 파일은 디코딩해 메모리에서 검색합니다. 파일을 읽지 못했거나 검색이 끝나지 않는 등 현재 상태를 확정할 수 없으면, 삭제되었다고 하는 대신 값이나 파일이 아직 남아 있는지 **확인할 수 없었다**(could not be checked)고 표시합니다.

## 프로젝트 설정 파일

프로젝트는 Git 루트에 선택적으로 `pgard.config.json`을 둘 수 있습니다. (예외: `pgard precommit`은 커밋될 버전인 Git 인덱스의 사본을 읽습니다. [커밋 전 검사](#커밋-전-검사pgard-precommit) 참고.) 제외 경로와 테스트 디렉터리를 지정하고 suppression 목록을 담습니다. PGARD가 할 수 있는 일을 바꾸는 수단이 **아닙니다**. 권한 확인, 호스트, 포트, 네트워크 대상, 규칙 심각도는 설정할 수 없고, 아래에 없는 키는 모두 거부됩니다. 이 파일은 검사 대상 저장소의 일부이므로 PGARD는 신뢰할 수 없는 데이터로 다룹니다. 읽기 전용으로 읽고, 실행하지 않으며, 심볼릭 링크를 따라가지 않고, 64 KiB로 제한합니다. 운영체제에 `O_NOFOLLOW`가 있으면(macOS, Linux) 파일을 여는 도중 바꿔치기된 링크는 open 자체가 거부합니다. 그런 플래그가 없는 Windows에서는 열린 파일이 검사한 바로 그 파일(같은 장치와 파일 ID)이어야 하며, 아니면 설정을 거부합니다. Git 루트의 설정 파일만 읽으며 하위 디렉터리의 `pgard.config.json`은 무시합니다. PGARD는 작업 트리의 파일을 읽습니다. 추적되지 않거나 수정된 파일이어도 마찬가지이며 `HEAD`는 참조하지 않습니다.

```json
{
  "version": 1,
  "exclude": ["legacy/**", "*.generated.ts"],
  "testDirectories": ["e2e", "tools/samples"],
  "suppressions": [
    {
      "ruleId": "PG-SQL-001",
      "path": "scripts/**",
      "reason": "관리자 전용 스크립트이며 입력은 사용자가 제어하지 않음",
      "expires": "2027-01-31"
    }
  ],
  "precommit": { "mode": "block", "whenNotScanned": "block", "requireAuthorization": false }
}
```

- `version`(필수): 숫자 `1`.
- `exclude`(패턴 최대 200개): 소스 분석에서 제외할 소스 파일.
- `testDirectories`(패턴 최대 100개): 테스트 코드로 분류할 경로([테스트·fixture 코드의 발견 항목](#테스트fixture-코드의-발견-항목) 참고). 테스트 컨텍스트를 **추가**만 할 수 있습니다. 기본 규칙으로 이미 테스트 코드인 경로는 그대로 테스트 코드이고, vendored 코드는 그대로 vendored입니다. 소스 코드 발견 항목에만 적용되며 Git 이력에는 적용되지 않습니다.
- `precommit`(선택): `mode`와 `whenNotScanned`(각각 `"block"` 또는 `"warn"`), `requireAuthorization`(`true` 또는 `false`, 기본값 `false`). [`pgard precommit`](#커밋-전-검사pgard-precommit)용입니다. `mode`와 `whenNotScanned`는 결과를 어떻게 끝낼지만 정하고, `requireAuthorization: true`는 검사 전에 권한 확인 관문을 추가합니다(기본값은 코드 전용). 관문을 통과하지 못하면 `whenNotScanned`가 정합니다.
- `suppressions`(항목 최대 200개): `ruleId`(예: `PG-SQL-001`), `path`(패턴), `reason`(필수, 300자 이내), 선택 항목 `expires` 날짜(`YYYY-MM-DD`). 적용됩니다. 해당한 발견 항목은 결과에 그대로 남고 `Suppressed (N)` 아래에 나열됩니다. 매칭, 만료, 치명적 항목, 경고는 [억제](#억제suppressions)를 참고하세요. coverage 설명에 개수가 표시됩니다.

패턴은 `/` 구분자를 쓰는 저장소 기준 상대 경로이고 대소문자를 구분합니다. `*`는 한 경로 구간 안에서, `?`는 한 글자, `**`는 임의 개수의 구간과 일치합니다. `/`가 없는 패턴은 어느 깊이에서나 일치하고(`*.generated.ts`), 패턴은 일치하는 디렉터리 아래 전부와도 일치합니다(`legacy`와 `legacy/**`는 같습니다). 절대 경로, `..`, 역슬래시, `[ ] { }`, 앞의 `!`, 한 구간에 `*` 10개 초과, 보이지 않는 문자(제어·C1 제어 문자, 줄·문단 구분자, 양방향 제어 문자, 폭 없는 문자 등 서식 문자, 결합 문자소 연결자, 한글 채움 문자, 단독 서로게이트)는 패턴과 파일의 모든 문자열에서 거부합니다. 매칭은 패턴으로 정규식을 만들지 않으므로 지수적 폭증이 없습니다. 패턴 하나와 경로 하나에 드는 작업은 최대 패턴 길이 × 경로 길이(표를 채울 뿐 되돌아가지 않음)이고, 패턴은 200자, 경로는 4,096자로 제한합니다. 이 제한은 한 번의 매칭만 묶을 뿐 전체는 묶지 못하므로, 검사에는 모든 매칭을 합쳐 표 셀 5억 개라는 하드 작업 예산도 있습니다. 측정상 별 개수 제한과 사전 필터를 피하도록 만든 악의적 패턴 200개(`*?a?a...?a*` 변형)는 예산이 없으면 일반 경로 10,000개에 약 19초, 255자 이름 10,000개에 약 43초가 걸렸고, 예산이 있으면 약 1초(일반 경로), 0.3초(긴 이름)에서, 4,000자 경로 사례는 약 0.25초에서 멈춥니다. 일반 패턴은 예산의 아주 작은 일부만 씁니다. 예산이 바닥나면 그 지점 이후의 파일은 제외하지도 재분류하지도 **않고**(어떤 패턴도 적용되지 않은 것처럼 검사합니다), `source:config` coverage 영역이 `WARNING`과 함께 `partial`(종료 코드 4)이 됩니다. 패턴을 단순하게 고치세요. 매칭은 대소문자를 구분하고 유니코드 정규화를 하지 않으므로 `src/**`는 `Src/x.js`를 제외하지 않습니다. 이 방향은 안전한 쪽입니다. 덜 제외하고 더 검사합니다.

검증은 엄격합니다. 키와 타입이 정확해야 하고, 길이와 개수 제한이 있으며, 알 수 없는 키와 중복 키는 거부합니다.

**조용히 제외되는 것은 없습니다.** 소스 검사는 제외한 파일을 `source:config-excluded` coverage 영역(JSON 결과에도 포함)에 표시합니다. 파일 수, 찾은 소스 파일 수, 패턴(따옴표로 감싸 최대 5개 표시 후 개수), 그리고 패턴 집합과 제외된 파일 집합의 짧은 해시가 들어 있어서, 이후 `pgard scan` 비교에서 제외 설정의 변경을 알아챕니다. 터미널 결과에는 발견 항목 위에 눈에 띄는 줄이 나옵니다. 예: `! 12 files excluded by pgard.config.json (of 140 source files; 2 patterns, set 3fa91c2e5b7d4a60).` 새로 제외된 파일은 이전 검사와의 비교에서 "더 이상 보고되지 않음"으로 표시되지 않습니다. 모든 파일과 일치하는 패턴(`**`)이나 분석할 것이 남지 않는 제외는 `WARNING`을 붙이고 그 영역을 `partial`(종료 코드 4)로 만듭니다.

**`testDirectories`도 발견 항목을 조용히 강등할 수 없습니다.** 테스트 코드의 발견 항목은 따로 나열되고 confidence가 `low`로 제한되므로, 운영 코드를 "테스트"라고 부르는 설정은 실제 발견 항목을 가볍게 보이게 만듭니다. 이 설정이 발견 항목을 하나라도 테스트 그룹으로 옮기면 터미널, HTML·PDF 보고서, 대시보드가 발견 항목 위에 눈에 띄는 안내를 표시하고(`! 3 findings were classified as test code by the testDirectories setting of pgard.config.json`), 테스트 그룹 설명에도 그중 몇 개가 기본 규칙이 아니라 설정 때문에 분류되었는지 표시합니다. `source:config-test` coverage 영역은 패턴이 강등하는 운영 파일(기본 규칙이 이미 테스트나 vendored 코드로 보지 않는 파일)의 수를 셉니다. 패턴이 그런 파일 전부와 일치하거나 절반 이상이면서 20개를 넘으면 그 영역은 `WARNING`과 함께 `partial`(종료 코드 4)입니다. 실제 프로젝트는 코드 대부분이 테스트 경로 밖에 있으므로, 이런 비율은 `*.*`나 `src` 같은 잘못되었거나 악의적인 패턴의 신호입니다.

**Git 이력은 제외하지 않습니다.** `exclude`는 소스 분석에만 적용됩니다. Git 이력과 추적 중인 파일의 비밀정보는 항상 전부 검사합니다. 한 번 커밋된 비밀정보는 지금 파일 이름이 무엇이든 모든 clone에 노출된 채로 남고, 오래된 커밋의 경로는 현재 트리와 대응하지 않기 때문입니다. `history:config-excluded` coverage 설명에 패턴이 이력에 적용되지 않았다고 표시합니다.

**잘못된 파일은 발견 항목을 숨기지 않습니다.** `pgard.config.json`이 유효하지 않으면(알 수 없는 키, 중복 키, 너무 큼, 심볼릭 링크 등) 검사는 설정이 전혀 없는 것처럼 그대로 실행됩니다. 유효한 부분도 포함해 아무것도 제외하지 않습니다. `source:config` coverage 영역은 처음 몇 가지 문제와 함께 `partial`이 되고, 터미널에 눈에 띄는 줄이 나오며, 종료 코드는 4입니다. 파일을 고치거나 삭제하면 `completed`가 됩니다.

## 결과와 보고서

터미널 결과는 심각도 차트, `파일:줄` 또는 URL이 붙은 발견 항목(확정·의심·정보), 가려진 근거, 가이드, 영역별 coverage를 보여 줍니다.

### 터미널 결과 화면

터미널에서 `pgard scan`은 발견 항목을 먼저, 요약을 마지막에 출력합니다. 그래서 숫자와 다음 단계가 화면 아래에 남고 위로 밀려 사라지지 않습니다.

1. **머리말**: 상태 줄 하나와 저장소·리비전·범위 줄 하나, 그리고 `pgard.config.json`·억제·기준선에 대한 `!` 안내.
2. **발견 항목(기본은 간단히)**: 치명적·높음을 먼저, 최대 10개 그룹(같은 규칙·같은 원인)을 그룹마다 한두 줄로 보여 줍니다. 심각도, 제목, 첫 위치(`외 N곳`), 규칙 ID, 상태입니다. 목록 아래에 `+19건 더 있음 (보통 17, 낮음 2) - --all-findings로 실행`이 나오므로 낮은 심각도는 조용히 빠지지 않고 개수로 남으며, 근거·조치·표준은 `--all-findings`, [패널 화면](#패널-화면), 대시보드 또는 보고서에 있다는 안내가 함께 나옵니다. 테스트·fixture 코드와 vendored 코드의 항목은 심각도별 개수가 있는 제목 줄(`테스트·fixture 코드 (14): 높음 2, 보통 4, 낮음 8`)로 구분되며, 그 아래에 치명적·높음 그룹(그리고 모든 `PG-SECRET-*` 그룹)을 같은 두 줄 형식으로 최대 5개(비밀 값은 제한 없이) 나열하고 나머지는 `+N건 더 있음`으로 셉니다. 비밀 값은 10개 그룹 제한을 넘어서도 나열됩니다. 억제된 항목과 기준선의 항목은 자기 구역을 유지하며, 치명적 항목은 간단한 형식으로 계속 나열됩니다(억제된 항목은 `pgard.config.json`의 사유와 함께).
3. **마무리 요약**: `결과: <상태> - 발견 N건 (...)`, 검사가 끝까지 되지 않았거나 일부·미검사 영역이 있으면 항상 나오는 `! 안전하다는 결과가 아닙니다` 경고, **요약** 블록(영역, 규칙, "규칙별 최대 검사 대상", 소요 시간, 증분/전체 여부, 지난 검사 이후), 심각도·OWASP Top 10 2025 분류·영역별 **차트**, **검사 범위**(`정상 2, 일부 1, 검사 안 됨 1` 한 줄과, 일부이거나 검사 안 된 영역의 이름과 설명. `--all-findings`에서는 모든 영역 목록), **표준 매핑 현황**(개수 두 줄과 "규칙 실행됨은 통과가 아님" 안내. 표는 `--all-findings`에서), 분석 근거, 그리고 **다음** 줄.

터미널에서 `--all-findings`는 전체 내용(근거, 조치, 링크가 있는 표준, 모든 위치, 접기 없음)을 같은 순서로, 요약을 마지막에, 너비에 맞춰 줄바꿈해 출력하고, 터미널이 아니면 안정된 형식을 출력합니다. 차트: 색이 켜져 있으면 막대는 심각도 색의 블록 문자이고, `NO_COLOR`·터미널이 아닌 출력·`TERM=dumb`에서는 일반 `#` 막대이며, 60열 미만에서는 막대 없이 `라벨  개수` 줄만 나옵니다. 막대는 터미널 너비에 맞춰집니다.

**너비.** 모든 줄은 터미널 너비에 맞춰 줄바꿈되며, 이어지는 줄은 라벨(`! `, `[부분 완료] `, `근거: `) 아래로 들여쓰기됩니다. 공백에서만 끊으므로 검사 범위 설명이 단어 중간에서 잘리지 않습니다. 공백 없이 줄보다 긴 단어는 글자 단위로 나누어 출력하며(이스케이프 시퀀스나 결합 문자 안에서는 자르지 않고 조각마다 색을 유지합니다), 유일한 예외는 PGARD 자체의 표준 링크(OWASP·CWE·CERT 참조)로, 잘린 링크는 복사할 수 없으므로 통째로 두며 오른쪽 끝을 넘을 수 있습니다. 검사한 코드나 웹 페이지에서 올 수 있는 그 밖의 URL은 너비의 두 배에서 `...`로 줄입니다.

**스크립트가 기대할 수 있는 안정된 형식은 터미널이 아닐 때의 출력**(파이프, 파일, CI)이며 바뀌지 않습니다. 요약과 차트가 먼저, 모든 발견 항목이 전체 내용으로, 그다음 검사 범위가 나오며 줄바꿈과 `다음` 줄은 없습니다. `--format json`, `--format sarif`는 영향을 받지 않습니다.

**이전 배치:** 터미널에서 예전의 요약 우선 전체 텍스트를 보려면 출력을 파이프로 넘기세요(`pgard scan | cat`).

표준 매핑 현황은 네 가지 상태만 씁니다: 규칙 실행됨(`rules ran`), 규칙 일부 실행(`rules partial`), 실행 안 됨(`not run`), 규칙 없음(`no rules`). 항목에 매핑된 PGARD 규칙이 이번 검사에서 실행되었는지를 나타낼 뿐 "안전"이나 "모두 다룸"이라는 뜻이 아니며, 표에 초록색은 쓰지 않습니다.

### 패널 화면

터미널에서 실행한 모든 `pgard scan`(대화형 메뉴로 시작한 스캔 포함)은 끝난 스캔 위에 읽기 전용 화면을 엽니다. 간단한 텍스트 결과(주 화면에 그대로 남으며 Esc로 돌아옵니다)를 출력하고 결과를 저장한 다음에 열립니다. 보고서 저장 같은 후속 질문은 화면을 닫은 뒤에만 합니다. 완료·부분 완료된 스캔 뒤에(실패한 스캔은 보여 줄 것이 적어 제외) `PGARD_PANELS=off`(대소문자 무관하게 `0`, `false`, `no`도 가능)가 아니면 자동으로 열리며, 알 수 없는 값이면 stderr에 한 줄 안내를 내고 켠 채로 둡니다. 자동화: `CI`가 비어 있지 않고 `0`·`false`도 아닌 값일 때, `GITHUB_ACTIONS`, `BUILDKITE`, `TF_BUILD`, `JENKINS_URL` 중 하나가 설정되어 있을 때, `TERM=dumb`일 때는 저절로 열리지 않으며 `pgard baseline set --from-current`에서도 열리지 않습니다. `--panels`는 그래도 엽니다(전체 화면을 그릴 수 없는 `TERM=dumb`는 제외하며 stderr에 안내가 나갑니다). 명시적인 `PGARD_PANELS=on`도 마찬가지입니다. **가상 터미널은 있지만 키를 누르는 사람이 없는 곳(`script`, `expect`, VS Code 작업, `docker run -it`, 일부 CI 래퍼)에서 `pgard scan`을 실행한다면 `PGARD_PANELS=off`를 설정하세요.** 그렇지 않으면 화면이 키 입력을 기다립니다. Ctrl+D와 닫힌 터미널은 Esc처럼 화면을 닫습니다. `--panels`는 `PGARD_PANELS=off`여도 엽니다. stdin과 stdout이 모두 터미널이 아니면, 그리고 `--format json`, `sarif`에서는 절대 열리지 않습니다. 화면 자체가 실패하면 터미널을 되돌리고 stderr에 한 줄 안내를 내며 스캔의 종료 코드는 그대로입니다. 차단된 스캔에 `--panels`를 쓰면 열지 않고 이유를 stderr에 알립니다. 네트워크 요청을 하지 않고 아무것도 바꾸지 않습니다. 패널은 다섯 개이며 Tab, Shift+Tab, 왼쪽/오른쪽으로 전환합니다.

- **개요**: 텍스트 결과와 같은 요약 블록과 심각도 막대.
- **차트**: OWASP Top 10 2025 분류별, 영역별 발견 항목.
- **검사 범위**: 모든 영역의 상태와 설명(완료된 영역이 통과라는 뜻은 아닙니다).
- **추이**: 이 저장소의 저장된 검사를 로컬 결과 저장소에서만 읽어(다시 검사하지 않으며 소스나 비밀 값도 읽지 않습니다. 저장된 결과는 이미 가려져 있고 개수만 셉니다) 최신순으로 최대 20건 보여 줍니다. 최근 검사와 직전 검사의 신규·더 이상 보고되지 않음·변화 없음 개수(텍스트 요약과 같은 표현), 그리고 검사별 심각도 합계를 누적 막대로 보여 주며(심각도마다 다른 문자를 써서 `#` `=` `+` `-` `:`, 색만으로 구분하지 않습니다) 날짜와 상대 시간(`어제`, `3일 전`)이 함께 나옵니다. 60칸 이하에서는 심각도마다 한 글자를 쓰는 일반 텍스트 표가 됩니다. 저장된 검사가 하나뿐이거나 `--no-store`·`PGARD_NO_STORE=1`이거나 이 검사의 이력을 보관하지 않으면 「아직 이력이 없습니다」와 이유를 알려 주고, 더 새로운 PGARD 버전이 만든 검사는 안내와 함께 건너뛰고, 저장되지 않은 검사는 그렇다고 알리며, 저장소를 읽을 수 없으면 짧은 이유를 보여 주며 화면의 나머지에는 영향이 없습니다. 추이가 비어 있으면 실제 이유를 먼저 알려 주고(코드 전용 검사는 「코드 전용 검사는 결과를 저장하지 않아 추이가 쌓이지 않습니다」) 추이가 비는 흔한 이유를 나열합니다: 코드 전용 검사(GitHub 승인으로 `pgard scan` 실행), 저장된 검사가 1건뿐(나중에 다시 검사해 비교), 저장이 꺼져 있음(`--no-store`, `PGARD_NO_STORE=1`). 코드 전용 결과에는 항상 코드 전용 이유가 먼저 나옵니다. 추이 제목 뒤의 `(?)`가 도움말 표시이며, 추이 탭에서 `?`를 누르면 도움말이 추이 항목(추이가 보여 주는 것, 기록이 쌓이는 방법)부터 열립니다.
- **발견 항목**: 심각한 것부터, 한 줄에 심각도, 상태, `파일:줄`(또는 URL, 커밋)이 나오고 터미널이 60칸보다 넓으면 제목도 나옵니다. 목록 위 한 줄에 항상 `전체 중 N개`와 적용 중인 필터가 나오며, 필터에 맞는 항목이 없으면 빈 목록 대신 그렇다고 알려 줍니다.

키: 위/아래(또는 `k`/`j`)는 스크롤하거나 선택을 옮기고, PageUp/PageDown은 한 페이지, Home/End는 처음·마지막 줄, `?`는 도움말, Esc는 도움말을 닫은 뒤 화면을 나가고, `q`는 바로 나가며, Ctrl+C는 `Cancel and exit? [y/N]`을 묻습니다(`y`면 종료 코드 130). 발견 항목 패널에서는 `Enter`가 선택한 항목을 열어(결과 화면처럼 가려진 근거, 해결 방법, 그 규칙의 OWASP·CWE·CERT 링크; 위/아래/PageUp/PageDown/Home/End로 스크롤) `Enter`나 Esc로 닫고, `1`~`5`는 한 심각도만 보여 주며(치명~정보, 다시 누르면 해제, `0`은 해제), `s`는 심각도를, `a`는 영역(코드, 이력, 웹)을, `r`은 규칙을 차례로 넘기고, `c`는 모든 필터를 지웁니다. `/`는 제목·규칙 ID·경로 검색을 엽니다(입력하면 바로 걸러지고, `Enter`로 유지, `Esc`로 지우며, 한 번 더 `Esc`를 누르면 화면을 나갑니다). 선택된 행은 반전 표시와 함께 `>`로도 표시됩니다. 아래 줄에는 현재 상태의 키가 영어 또는 한국어로 나오고 `?`는 전체 목록을 보여 줍니다. 대체 화면을 쓰며, 정상 종료, 오류, SIGINT(취소와 같게 처리), SIGTERM(종료 코드 143)에서 항상 커서와 화면을 되돌리고, 터미널 크기가 바뀌면 다시 그립니다. `NO_COLOR`와 `TERM=dumb`를 따르고(`#` 막대, 색 없음), 60칸 이하에서는 막대 대신 개수 줄을 쓰며, 40칸 또는 10줄 미만이면 "터미널이 너무 작습니다" 메시지만 보여 줍니다. 한국어 화면은 `--lang ko` 또는 `PGARD_LANG=ko`로 켜며, 규칙 제목은 텍스트 결과와 같은 언어 설정을 따릅니다.

테스트와 버그 보고용 비대화형 경로가 있습니다. `PGARD_PANELS_ONCE=1 pgard scan --panels`는 텍스트 결과 뒤에 화면 제어 코드도, 키 입력도 없는 일반 텍스트 한 프레임을 출력하며 크기는 `COLUMNS`와 `LINES`(기본 80x24)로 정합니다. 지원되는 인터페이스는 아닙니다.

### 표준 coverage와 규칙 통계

결과는 어떤 규칙이 실행되었는지, 그리고 그 규칙이 어떤 표준 항목에 연결되는지 알려 줍니다. 두 정보는 JSON 결과(`ruleStats`, `standardsCoverage`, 스키마 1.1)에 들어 있고, 터미널 결과의 끝에 간단한 요약이 붙습니다. 아래는 Java 파일 하나가 있는 작은 TypeScript 프로젝트(code와 history 범위)의 예시이며, 여기서는 각 줄을 앞의 200자까지만 보여 줍니다.

```
Standards coverage (OWASP Top 10 2025)
  [rules partial] A01 Broken Access Control - 9 of 40 mapped CWEs have rules (PG-COOKIE-001, PG-CSRF-001, PG-PATH-001, PG-SECRET-001 +2); web rules not run: scope not selected; no completed mapped rule covers java (1 file) ...
  [rules ran] A03 Software Supply Chain Failures - 1 of 6 mapped CWEs have rules (PG-HYGIENE-001)
  [rules partial] A05 Injection - 3 of 37 mapped CWEs have rules (PG-CMD-001, PG-SQL-001, PG-SQL-002, PG-XSS-001 +1); no completed mapped rule covers java (1 file) ...
  [no rules] A08 Software or Data Integrity Failures - no rules
  CWE Top 25 2025: 0 rules ran, 6 rules partial, 0 not run, 19 no rules
```

**상태의 의미.** 어느 상태도 프로젝트가 안전하다는 뜻이 아니며, 분류 전체를 다룬다는 뜻도 아닙니다. 이번 검사에서 그 항목에 연결된 PGARD 규칙이 실행되었는지를 알려 줄 뿐이며, 각 줄은 그 분류의 CWE 중 규칙이 있는 것이 얼마나 적은지(`1 of 6 mapped CWEs have rules`)도 보여 줍니다. 초록색으로는 표시하지 않습니다.

- **규칙 통계**(`ruleStats`): 어떤 영역에서 실행된 규칙마다 항목이 하나씩 있습니다(여러 언어에서 실행되는 규칙은 영역마다 하나). 영역, 그 영역의 상태, 규칙이 확인한 대상 수, 그 영역에서 보고한 발견 항목 수가 들어 있습니다. 대상 수는 추정하지 않고 분석기가 직접 셉니다. 언어 분석기가 실제로 분석한 파일(바이너리, 크기 제한 초과, 시간 예산 때문에 건너뛴 파일은 세지 않음), 이력 규칙이 읽은 커밋과 텍스트로 읽은 이력 blob, 웹 규칙의 페이지와 응답입니다. 측정할 수 없는 수는 추측하지 않고 `null`과 `reason`으로 표시합니다. 선택되지 않았거나 실행되지 못한 영역의 규칙에는 항목이 없습니다. 같은 발견 항목이 두 항목에 나타날 수 있는 경우는 `source:react`와 `source:heuristics`뿐입니다. 이 영역들은 언어 영역과 같은 파일을 보므로, 모든 항목의 수를 더하지 마세요.
- **표준 지도**(`standardsCoverage`): OWASP Top 10 2025의 각 분류(A01~A10)와 CWE Top 25 2025의 각 항목마다 항목이 하나씩 있습니다. 규칙은 자체 `standards` 메타데이터(`pgard rules list`와 같은 데이터)의 OWASP·CWE id로, id가 정확히 같을 때만 항목에 연결됩니다. 상위·하위 CWE는 추정하지 않습니다. 상태는 다음과 같습니다.
  - `rules_ran`: 연결된 규칙이 하나 이상 실행되었고 이를 제한하는 것이 없습니다. 실행된 모든 영역이 완료되었고, `partial`인 코드 영역이 없고(`source:large-files`, `source:minified`, `source:unreadable`, `source:config`, `source:orm:typeorm` 같은 ORM 영역이 `partial`이면 코드 규칙이 연결된 모든 항목이 제한됩니다), 연결된 규칙이 있는 모든 범위가 실행되었고(history만 검사하면 코드 규칙도 연결된 항목은 `rules_ran`이 될 수 없습니다), 프로젝트에 있는 각 언어가 완료된 연결 규칙으로 확인되었고, 대상을 0개 본 규칙이 없습니다. 이력·웹 규칙은 언어와 관계없이 추적 파일과 실행 중인 서비스를 보므로, 언어 확인은 코드 규칙이 연결된 항목에만 적용됩니다.
  - `rules_partial`: 연결된 규칙 일부가 실행되었지만 위 조건 중 하나가 충족되지 않았습니다. 이유에 어느 조건인지 적혀 있습니다.
  - `not_run`: 항목에 연결된 규칙이 있지만 하나도 실행되지 않았습니다(해당 범위를 선택하지 않았거나 실행할 수 없었음).
  - `no_rules`: 항목에 연결된 PGARD 규칙이 없습니다(이유 `no rules`).

  항목마다 실행된 규칙(`ruleIds`), 연결된 모든 규칙(`mappedRuleIds`), 짧은 이유가 들어 있습니다. OWASP 항목에는 `breadth`도 있습니다. 분류의 "List of Mapped CWEs"에 있는 CWE 중 PGARD 규칙이 하나라도 있는 것의 수입니다(예: A03은 6개 중 1개). CWE Top 25 항목은 CWE 하나가 약점 하나이므로 `breadth: null`입니다.

- **`rules_ran`이 뜻하지 않는 것.** 취약점이 없다는 뜻도, 그 취약점을 만드는 모든 방식을 탐지한다는 뜻도, 분류 전체를 다룬다는 뜻도 아닙니다. 여러 분류가 좁은 규칙 하나에만 연결되어 있으므로 `breadth`와 규칙 id를 함께 보세요. A03 소프트웨어 공급망 실패는 `PG-HYGIENE-001`(커밋된 의존성 디렉터리)과 `PG-DEP-001`(OSV 권고의 영향 범위에 있는 lockfile 버전)에 연결됩니다. `PG-DEP-001`은 `deps:*` 영역이 실행되었을 때만 반영되며, 부분 실행되었거나 검사하지 못한 의존성 영역은 그 규칙이 연결된 항목(A03, CWE-1395)에만 영향을 줍니다.

터미널 요약은 OWASP 분류마다 한 줄과 CWE Top 25 개수를 보여 줍니다. 항목별 자세한 내용과 규칙 통계는 `--format json`으로 확인하세요. 이전에 저장된 결과(스키마 1.0)에는 두 필드가 없으며 이전과 같이 읽힙니다. 이 경우 터미널에는 표준 섹션이 나타나지 않습니다. 보고서와 대시보드는 지도와 통계도 보여 줍니다([보고서와 대시보드의 규칙 상세, 표준, 통계](#보고서와-대시보드의-규칙-상세-표준-통계) 참고). 웹 스캐너를 주입하는 실행기는 웹 규칙 목록(`webRules`)도 함께 넘겨야 하며, 그렇지 않으면 `runScan`이 실행을 거부합니다.

### 보고서와 대시보드의 규칙 상세, 표준, 통계

HTML·PDF 보고서와 대시보드는 터미널과 같은 정보에 더해 다음을 보여 줍니다.

- **발견 항목별:** 규칙이 연결된 표준(OWASP Top 10 2025, CWE, 규칙이 SEI CERT Java 규칙에 연결된 경우 그 규칙)을 각각 공식 페이지 링크로 보여 주고, 규칙의 취약한 코드와 안전한 코드 예시를 보여 줍니다. 발견 항목의 영향·권장 조치는 이미 선택한 언어의 규칙 근거·조치 문구이므로, 발견 항목이 규칙 기본값과 다른 자체 문구를 가진 경우에만 규칙의 일반 문구를 덧붙여 둘이 모순되지 않게 합니다. 예시는 텍스트로 표시되는 코드 블록이며(HTML에서는 이스케이프, React에서는 일반 텍스트), HTML 보고서와 대시보드에서는 접힌 `<details>` 구역에 들어 있습니다. HTML 보고서에서는 예시와 규칙의 일반 문구가 규칙마다 첫 발견 항목에 한 번만 나오며(그 항목이 링크 대상), 같은 규칙의 이후 발견 항목에는 그곳으로 가는 한 줄 링크가 붙어, 한 규칙의 발견 항목이 많아도 보고서가 커지지 않습니다. PDF에서는 각 발견 항목에 "부록 B 참고"라고 표시됩니다. 링크는 `rel="noopener noreferrer"`로 새 탭에서 열리며, 보고서에는 스크립트가 없고 대시보드의 CSP는 그대로입니다. CWE id를 통해서만 연결된 CERT 규칙에는 `(CWE-89 경유)`처럼 표시합니다.
- **검사별:** **표준 매핑 현황**(OWASP Top 10 2025 분류마다 한 행에 상태, `breadth`, 규칙, 이유를 보여 주고 CWE Top 25는 접힌 목록)과 **규칙 통계** 표(규칙, 영역, 살펴본 대상, 발견 항목, 상태, HTML에서는 접힘). 현황은 터미널과 같은 상태와 문구 원칙을 따릅니다. `규칙 실행됨`은 안전하다는 뜻도 전부 다뤘다는 뜻도 아니며 초록색은 쓰지 않습니다. 억제·기준선 개수는 요약 줄과 그 위의 안내에 그대로 있습니다.
- **PDF 구성.** PDF는 접을 수 없으므로 발견 항목을 짧게 유지합니다. 각 발견 항목에는 표준 id가 클릭 가능한 링크로 나옵니다. 규칙 통계, CWE Top 25 목록, 예시(발견 항목마다가 아니라 규칙마다 한 번), 표준의 전체 URL(인쇄본에도 남도록)은 발견 항목 뒤의 부록 A~C에 있습니다.
- **이전 결과.** 스키마 1.0으로 저장된 결과에는 `ruleStats`와 `standardsCoverage`가 없으며, 보고서와 대시보드는 두 구역 대신 짧은 안내를 보여 주고 오류를 내지 않습니다. 규칙 상세에는 규칙 카탈로그가 필요합니다. CLI와 대시보드는 항상 넘기며, `ruleTexts` 없이 만든 보고서는 이 정보 없이 발견 항목만 보여 줍니다.
- **라이선스.** 표준의 식별자, 제목, 링크만 보여 주고 본문은 보여 주지 않습니다. 보고서 하단과 표준 패널에 [NOTICE.md](NOTICE.md)가 요구하는 출처 표기가 있습니다. OWASP Top 10:2025는 CC BY-SA 4.0, CWE는 MITRE CWE 이용 약관, SEI CERT는 CC BY 4.0이며 Carnegie Mellon University나 SEI의 보증을 받지 않았습니다.

### SEI CERT Java 매핑 (Java, Kotlin)

Java 또는 Kotlin에 적용되는 모든 규칙은 같은 약점을 다루는 SEI CERT Oracle Coding Standard for Java 규칙에 **직접** 연결되거나, 직접 대응하는 규칙이 없다고 명시합니다. id와 규칙-CWE 표는 번들 데이터(SEI `secure-coding-standards` 커밋 `72e8a32`, 2026-10-26 수집, CC BY 4.0)에서 가져옵니다. SEI가 규칙이 아니라 권고(recommendation)로만 두는 항목(예: MSC61-J)은 연결하지 않습니다.

| PGARD 규칙                                                                                                 | 직접 연결되는 CERT Java 규칙                                                                                                                                               |
| ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PG-SQL-005` SQL 인젝션                                                                                    | IDS00-J Prevent SQL injection                                                                                                                                              |
| `PG-CMD-003` OS 명령 실행                                                                                  | IDS07-J Sanitize untrusted data passed to the Runtime.exec() method                                                                                                        |
| `PG-PATH-002` 경로 탐색, zip slip                                                                          | FIO16-J Canonicalize path names before validating them (압축 파일 항목이 아닌 경로 발견 항목), IDS04-J Safely extract files from ZipInputStream (압축 파일 항목 발견 항목) |
| `PG-CRYPTO-002` 하드코딩된 키·서명 비밀정보                                                                | MSC03-J Never hard code sensitive information                                                                                                                              |
| `PG-CRYPTO-003` 약한 난수, 깨진 암호, 고정 IV                                                              | MSC02-J Generate strong random numbers. 약한 난수 발견 항목에만 해당(DES, ECB, 고정 IV 발견 항목에는 붙지 않음)                                                            |
| `PG-XSS-004`, `PG-SSRF-002`, `PG-CRYPTO-001`, `PG-AUTH-001`, `PG-COOKIE-001`, `PG-CSRF-001`, `PG-CONF-001` | 없음: "직접 대응하는 CERT 규칙 없음"과 그 이유, 그리고 있으면 관련 권고(XSS는 IDS51-J, 비밀번호 해시·저장은 MSC62-J. 권고는 연결하지 않음)를 표시(`pgard rules list`)      |

- **Java와 Kotlin 발견 항목에만.** 직접 링크(와 JSON 결과의 `references.cert` 필드, 스키마 1.4)는 `.java` 또는 `.kt` 파일의 발견 항목에만 나타납니다. JavaScript, TypeScript, Go, Python, PHP 발견 항목에는 나타나지 않습니다. 이런 규칙이 CERT Java 규칙 링크를 유지하는 경우(`PG-CMD-001`과 `PG-CMD-002`는 CWE-78, `PG-CRYPTO-002`와 비밀정보 규칙은 CWE-798 경유)에는 연결에 쓰인 CWE와 함께 **간접**으로 표시합니다. 매핑이 아니라 Java 표준에 대한 상호 참조입니다.
- **원인별 적용.** MSC02-J, IDS04-J, FIO16-J는 PGARD 규칙이 보고하는 내용의 일부만 다루므로, 분석기가 발견 항목마다 어느 쪽인지 정하고(분석기가 만드는 근거 문구로 판단: "non-cryptographic random" 출처 또는 "archive entry name" 경로) `references.cert`에 기록합니다. 발견 항목의 링크는 이 필드를 따릅니다.
- **표시되는 곳.** `pgard rules list`(Java·Kotlin 규칙마다 CERT 줄, `--lang`으로 영어·한국어), 터미널 결과와 패널 화면, JSON 결과(`references.cert`), SARIF(규칙 태그 `CERT-Java-<id>`, 규칙 도움말, 결과의 `properties.pgard.certJava`), HTML·PDF 보고서와 대시보드. 모두 영어와 한국어로 제공합니다.
- **준수(compliance) 주장이 아닙니다.** 링크는 CERT 표준의 관련 규칙을 가리킬 뿐입니다. PGARD는 자체 규칙이 탐지하는 약점만 확인하며 CERT 표준의 준수 여부는 확인하지 않습니다. "직접 대응하는 CERT 규칙 없음"은 그 표준에 해당 약점을 다루는 규칙이 없다는 뜻이지 코드가 괜찮다는 뜻이 아닙니다. SEI도 자신의 CWE 표가 "SEI CERT가 검증하지 않았다"고 밝힙니다.

### 규칙 문구의 언어

규칙 제목, 영향 설명, 조치 설명을 한국어나 영어로 볼 수 있습니다. 언어는 `--lang en|ko`, 환경 변수 `PGARD_LANG`(`en` 또는 `ko`), 시스템 로케일(`LC_ALL`, `LC_MESSAGES`, `LANG` 중 먼저 값이 있는 것이 결정하며 `ko`로 시작하면 한국어, 보통 이 변수가 없는 Windows에서는 런타임 로케일 사용), 마지막으로 영어 순서로 정해집니다. 값은 대소문자를 구분하지 않습니다(`KO`도 가능). `--lang`, `--report-lang`, `PGARD_LANG`에 잘못된 값을 주면 사용법 오류(종료 코드 2)이며, 언어 옵션이 있는 명령(`scan`, `rules list`, 메뉴)에서는 이 경우가 모두 사용법 오류입니다. `doctor`, `login`, `logout`은 `--lang` 옵션이 없지만 `PGARD_LANG`과 시스템 로케일을 똑같이 읽으며, `PGARD_LANG` 값이 잘못되어도 멈추지 않고 stderr에 한 줄을 출력한 뒤 시스템 언어를 사용합니다. `project verify`, `dashboard`, `advisories update`, `history clear`, `baseline`은 영어로 유지됩니다.

- **터미널:** 검사 결과 화면 전체(제목, 라벨, 상태 단어, 차트, 안내, `testDirectories`가 발견 항목을 테스트 코드로 분류했다는 설명, 지난 검사와의 비교), stderr의 진행·상태 줄, 처음 실행 시의 저장 안내가 해당 언어로 표시되며, 규칙 제목·영향·조치 줄과 `pgard rules list`의 제목도 마찬가지입니다. 한국어 글자는 두 칸을 차지하므로 표시 너비 기준으로 맞춰 열이 어긋나지 않습니다. 번역하지 않는 것: 경로, 근거, `pgard.config.json`에서 인용한 사유, 검사가 쓴 coverage 비고, 권한 확인 사유, 표준의 공식 제목. `pgard doctor`, `pgard login`, `pgard logout`의 고정 문구와 `pgard rules list`의 제목도 번역되며, `scan`이나 메뉴에서 나오는 로그인, GitHub App 설치, 보고서 내보내기 메시지도 마찬가지입니다. 기계가 읽는 출력(`--format json`, `sarif`)은 항상 영어이며, `doctor`의 `[ok]`/`[fail]`/`[warn]` 표시, GitHub의 오류 메시지, GitHub App 재정의 경고도 영어로 남습니다.
- **보고서:** `--report-lang en|ko`(기본값: 터미널 언어)가 보고서 전체의 고정 문구(제목, 라벨, 표 머리글, 요약, 안내문, 면책 문구, 새 표준·통계 구역)와 규칙 제목, 영향, 조치 문구의 언어를 정하며 `<html lang>`도 이를 따릅니다. PDF는 내장 한국어 글꼴을 쓰며, 글꼴 부분집합이 모든 규칙 문구와 예시를 포함하는지 테스트로 확인합니다. 근거, 위치, 권한 확인 사유, 검사 범위 비고, 표준 지도의 이유는 검사에서 나온 데이터이므로 그대로(영어) 둡니다.
- **대시보드:** 규칙 제목, 영향, 조치 문구가 대시보드의 언어 토글을 따르며, 보고서 다운로드도 같은 언어를 씁니다. 서버는 두 언어의 규칙 메타데이터만 보내며(`/api/rule-texts`: 제목, 문구, 표준 링크, 예시) 검사 데이터는 추가되지 않습니다. 이 요청이 계속 실패하면 알림을 보여 주며 규칙 문구는 영어로 남습니다.
- **JSON 출력**(`--format json`)과 저장된 결과는 바뀌지 않으며 항상 영어입니다.
- **발견 항목 고유 문구:** 일부 발견 항목은 규칙 기본 문구 대신 자체 문구를 가집니다(예: 커밋된 의존성 디렉터리의 권장 조치). 이 문구는 영어 그대로 표시되며 규칙 기본 문구가 그 옆에 함께 표시되지는 않습니다. 의존성 발견 항목(`PG-DEP-001`)은 규칙의 기본 문구(번역됨)를 쓰며, 패키지·버전·권고 ID·범위는 그대로 표시되는 근거(evidence)에 들어 있습니다.

### 그룹화와 접기

발견 항목은 심각도(critical, high, medium, low, info) 순, 같으면 확정 → 의심 → 정보 순, 그다음 위치 순으로 정렬됩니다. 같은 규칙과 원인의 항목은 한 그룹이 됩니다. 제목에 위치 개수가 표시되고 줄에는 최대 3개의 위치가 나옵니다(`src/db.ts:10, src/db.ts:30, src/orders.ts:7 and 2 more`). 근거는 모든 항목이 같을 때 그대로 보여 주고, 다르면 `Evidence: varies by location`이라고 표시합니다. 결과에는 원인 문장이 없고(줄이 포함된 fingerprint만 있음) "같은 원인"은 규칙, 제목, 심각도, 상태, 신뢰도, 위치 종류, context가 같다는 뜻입니다.

테스트·fixture·vendored 코드의 발견 항목이 5개(상수 `COLLAPSE_THRESHOLD`)를 넘으면 CLI는 심각도가 낮은 항목(medium, low, info)의 목록 대신 요약을 보여 줍니다. 개수, context별·규칙별 개수, 심각도, 전체를 보는 방법이 포함됩니다. 정확히 5개면 그대로 나열합니다. critical·high 항목과 내 코드의 발견 항목은 절대 접지 않습니다. `--all-findings`를 쓰거나 HTML 보고서(`--report html --output-dir <dir>`)를 보면 전부 볼 수 있습니다. 상단에는 테스트 코드의 critical·high 개수가 표시되고(예: `plus 8 in test or fixture code (1 critical, 2 high)`) 상태별 개수도 표시됩니다(`Findings (6): 1 confirmed, 5 suspected (needs review)`). 터미널이 아니거나 `NO_COLOR`가 설정되어 있으면 색 없는 같은 텍스트가 출력됩니다.

### 억제(suppressions)

`pgard.config.json`의 `suppressions` 목록은 검토를 마친 오탐이나 감수하기로 한 발견 항목을 표시합니다. 억제는 발견 항목을 **어디에 나열할지만 바꾸며, 항목의 존재는 바꾸지 않습니다**. 설정 파일은 검사 대상 저장소의 일부이므로 신뢰하지 않습니다. 억제가 하는 모든 일은 화면에 드러나며, 권한 확인, 상태, 종료 코드는 바꿀 수 없습니다.

- **매칭.** 규칙 ID가 같고 경로 패턴(`exclude`와 같은 문법)이 발견 항목의 저장소 기준 상대 경로와 맞으면 항목이 해당합니다. 파일 경로가 있는 모든 발견 항목에 적용됩니다(소스 코드, 그리고 Git 이력에서는 비밀정보가 든 파일). 파일에서 가장 먼저 맞는 활성 항목이 발견 항목에 기록되며, 활성 항목은 각자 맞는 발견 항목 수를 계속 셉니다.
- **파일 경로가 없는 발견 항목**(URL을 가진 로컬 웹 발견 항목)은 모든 파일에 맞는 패턴(`**`, `*`)의 항목만 해당합니다. 이런 항목은 항상 와일드카드로 경고됩니다(아래). `src/**` 같은 좁은 경로는 웹 발견 항목에 맞지 않습니다.
- **만료.** `expires`(`YYYY-MM-DD`)는 UTC 기준 그날이 끝날 때까지 유효합니다. 만료된 항목은 **적용되지 않습니다**. 해당 발견 항목은 일반 그룹에 그대로 남고, 항목은 경고로 알려 줍니다.
- **아무것도 지우지 않습니다.** 해당한 발견 항목은 `suppression: { reason, expires?, source: "pgard.config.json" }`과 함께 결과에 남고, 결과에는 `suppressions` 요약(억제된 수, 그중 치명적인 수, 항목별로 맞은 발견 항목 수, 상태 `active`/`expired`, 경로가 모든 파일에 맞는지 여부)이 들어갑니다. JSON 결과와 저장된 결과에는 모두 들어 있습니다. `source:config` coverage 설명에도 개수가 표시됩니다(`2 suppressions (5 findings suppressed, 1 expired, not applied)`).
- **항상 보이며 심각도가 함께 나옵니다.** 억제된 발견 항목의 모든 개수에는 심각도별 내역이 붙습니다. 터미널 결과는 발견 항목 위에 `Suppressed by pgard.config.json: 12 (12 high)`를 출력하고, 심각도 제목에 `12 suppressed (12 high)`를 더하며, 억제된 항목을 심각도 그룹과 차트에서 빼고 자체 그룹 `Suppressed (N)`에 나열합니다. 억제되지 않은 항목이 하나도 남지 않으면 "발견 항목 없음" 문장이 그 사실을 알려 줍니다: `No unsuppressed findings outside test or fixture code in the areas that ran (12 suppressed: 12 high)`(터미널, HTML, PDF, 대시보드). 기본적으로 이 그룹은 규칙별·심각도별 개수를 보여 주고, `--all-findings`는 억제된 항목을 모두 사유(설정 파일의 문구임을 따옴표로 표시)와 함께 나열합니다. HTML 보고서와 대시보드는 제목에 개수가 있는 접힌 구역(`<details>` 요소)으로 보여 주며, PDF는 접을 수 없으므로 다른 발견 항목 뒤에 전부 나열합니다. JSON `suppressions` 요약에는 `bySeverity`가 있습니다.
- **높음·치명적 발견 항목.** 치명적(또는 높음) 항목도 억제할 수 있지만 조용히는 안 됩니다. 터미널, 두 보고서, 대시보드(영어·한국어), `source:config` coverage 설명에 `!` 경고 `K suppressed findings are high or critical (H high, C critical)`가 나오고, 모든 개수에 심각도별 내역이 붙으며, 억제된 치명적 항목은 `--all-findings` 없이도 항상 전체 내용으로 나열됩니다(HTML 구역은 펼쳐진 상태). 이유: 전면 금지는 검토를 거친 실제 예외에 설정을 쓸 수 없게 만들고, 가장 심각한 항목의 조용한 억제는 공격자가 바꾼 설정이 노리는 바입니다.
- **넓거나 오래가거나 와일드카드인 억제는 경고합니다.** 경로가 모든 파일에 맞는 항목(`**`, `*`, `**/*`), 발견 항목 10건을 넘게 맞는 항목(`BROAD_SUPPRESSION_THRESHOLD`), 항목 수와 상관없이 **합계가 10건을 넘는 억제**(좁은 항목 열두 개로 항목별 한도를 피할 수 없습니다), 만료된 항목, 검사의 모든 발견 항목이 억제된 경우에 `!` 경고가 나옵니다. 1년(366일, `MAX_SUPPRESSION_HORIZON_DAYS`)을 넘게 남은 `expires`도 경고입니다. 억제는 다시 보겠다는 약속이며 `9999-12-31`은 만료가 없는 것과 같습니다. `expires`가 없는 활성 항목은 터미널에 조용한 안내 한 줄(`N suppressions have no expiry date`)이 나옵니다. 같은 경고가 HTML·PDF 보고서와 대시보드(영어·한국어)에도 나옵니다. `ruleId`는 항상 정확한 규칙 ID 하나(`PG-SQL-001`)이며 규칙 와일드카드는 없습니다.
- **작업량 한도.** 억제 매칭은 glob 작업량 한도(표 셀 5억 개)를 함께 씁니다. 한도를 넘으면 남은 발견 항목은 **억제되지 않으며**, 매칭이 일찍 멈췄다는 경고가 나옵니다(요약의 `incomplete`). 실패 방향은 "더 많이 보여 주기"입니다.
- **상태와 종료 코드는 그대로입니다.** 전체 상태는 발견 항목이 아니라 coverage에서 나오므로 억제로 `partial` 검사를 `completed`로 만들 수 없습니다. 유효하지 않은 설정 파일은 `exclude`처럼 억제도 전혀 적용하지 않습니다.
- **비교.** 억제된 발견 항목도 "Since the last scan"과 기준선에서 다른 항목처럼 짝지어집니다(식별 방식은 억제 여부를 보지 않습니다). 그래서 항목을 억제해도 "no longer reported"로 읽히지 않습니다.

### 기준선(baseline)

기준선은 이 저장소의 검사 중 기준으로 삼기로 한 검사입니다. 이후 검사는 기준선과 맞는 발견 항목을 `In baseline (N)` 그룹으로 묶고 새 항목을 강조합니다. 기준선은 발견 항목을 숨기지 않습니다. 개수는 항상 표시되며 상태와 종료 코드는 바뀌지 않습니다.

```text
pgard baseline set [--from-current]
pgard baseline show
pgard baseline clear
```

- **`baseline set`**은 이 저장소의 **가장 최근에 저장된 검사**를 씁니다. 새 검사도, 권한 확인 외의 네트워크 통신도 없습니다. 보통 `pgard scan`으로 검사하고 검토한 뒤 `pgard baseline set`을 실행합니다. 부분 완료된 검사도 경고와 함께 받아들입니다(다루지 못한 영역의 발견 항목은 새 항목으로 보입니다). 저장된 검사가 아직 없으면 안내와 함께 실패합니다.
- **`baseline set --from-current`**는 지금 코드와 Git 이력을 검사하고(`pgard scan`과 같은 출력) 그 검사를 씁니다.
- **`baseline show`**는 설정한 시각, 어느 검사와 커밋에서 왔는지, 상태와 범위, 발견 항목 수를 출력합니다. **`baseline clear`**는 기준선을 삭제합니다(저장된 검사는 남습니다).
- 기준선은 저장된 결과처럼 **검증된 저장소별**(GitHub 숫자 저장소 ID)로 보관되므로 이 명령들은 먼저 권한 확인을 실행하고, 검증되지 않은 저장소는 거부합니다(종료 코드 3). 아무것도 업로드하지 않습니다.
- **매칭**은 "Since the last scan"과 똑같은 식별 방식과 일대일 짝짓기(규칙, 경로, 가려진 증거의 형태. 줄 번호는 보지 않음)를 씁니다. 그래서 코드가 옮겨지기만 했으면 여전히 기준선에 있고, 기준선에 있던 항목의 두 번째 복사본은 새 항목입니다. **억제된 발견 항목은 기준선을 설정할 때 제외됩니다**(오래된 기준선에 들어 있어도 무시). 억제는 임시이며, 기준선이 함께 삼킨 항목은 억제가 풀리거나 만료된 뒤에도 숨은 채로 남기 때문입니다. 제외되었으므로 그때 새 항목으로 돌아옵니다(`baseline set`이 몇 개를 제외했는지 알려 줍니다). 억제되었고 기준선에도 있는 항목은 억제됨으로 나열됩니다.
- **검사가 보여 주는 것.** 발견 항목 위에 `Baseline (set 2026-10-20): 6 in baseline (1 critical, 5 high), 3 new`(JSON의 `matched`와 `new`는 억제된 항목을 빼며, 억제된 항목은 `suppressions`에서 셉니다. `new`는 `New findings` 제목이 빼는 테스트·vendored 항목도 셉니다), 제목은 새 항목만 세는 `New findings by severity`, 새 항목은 `New findings since the baseline (N)` 아래(대시보드와 보고서에서는 `NEW` 표시), 나머지는 `In baseline (N)` 아래에 기본으로 규칙·심각도별 요약, `--all-findings`로 전체 나열. 기준선의 치명적 항목은 항상 전체 내용으로 나열됩니다. `!` 안내는 새 항목이 기준선이 충분히 다루지 못한 영역에 있을 때(`newInUncertainAreas`), 또는 기준선 설정 뒤 PGARD가 업데이트되었을 때 알려 줍니다.
- **JSON.** `baseline: { setAt, scanId, revision, total, matched, new, newInUncertainAreas, toolVersionChanged }`와 맞는 발견 항목의 `inBaseline: true`. 저장된 결과에도 들어갑니다.
- **저장.** 결과 저장소의 `repos/<저장소 id>/baseline.json`이며 저장된 결과와 같은 규칙을 따릅니다. macOS·Linux에서 디렉터리 `0700`, 파일 `0600`, 심볼릭 링크 거부(파일 자리의 링크는 따라가거나 통해 쓰거나 읽지 않음), 원자적 쓰기, 크기 상한, 더 새로운 PGARD가 쓴 파일은 덮어쓰지 않음, 로컬 경로가 든 결과는 저장하지 않음. 민감정보를 가린 검사 사본을 담고, 20회·90일 보관 정책의 대상이 아니며, `readScanResult`로 읽습니다. 파일에는 기준선을 설정한 저장소 ID가 기록되며, 다른 저장소의 기준선이나 다른 사용자가 쓸 수 있는 파일(macOS·Linux에서 그룹 또는 전체 쓰기 비트)은 경고와 함께 거부합니다. 손상된 기준선은 오류입니다(`pgard scan`은 경고하고 아무것도 적용하지 않고 모든 항목을 보여 줍니다). 조용히 "기준선 없음"이 되지 않습니다.
- **끄기.** `pgard scan --no-store`와 `PGARD_NO_STORE=1`은 기준선을 읽지도 적용하지도 않습니다(모든 발견 항목이 평소처럼 나열됩니다). `PGARD_NO_STORE=1`이면 `baseline` 명령은 실행을 거부합니다(종료 코드 2). 대시보드 검사는 저장소를 읽지 않으므로 대시보드는 기준선을 적용하지 않습니다.
- **`pgard history clear`는 기준선도 삭제합니다**(`--all`, `--repo owner/name`. 메시지에 몇 개인지 나옵니다). 기준선은 저장된 검사 데이터이며, 남겨 두면 전부 지우라고 한 뒤에도 발견 항목을 계속 묶게 됩니다.

### 수정 제안

두 규칙에 한해 PGARD는 발견 항목을 어떻게 고칠 수 있는지 코드 diff로 보여 줍니다. **diff를 적용하지 않으며 사용자의 파일에 쓰지 않습니다.** 검토용 제안이며, 컴파일되는지, 코드의 동작이 유지되는지, 문제 전체가 해결되는지는 PGARD가 확인하지 **않았습니다**(예를 들어 Secure 쿠키는 평문 HTTP로는 전송되지 않으므로 로컬 개발에 영향이 있습니다). 판단은 사람이 합니다.

- **어디에 나오나.** 텍스트: `pgard scan --fixes`(발견 항목 아래 diff). JSON: `Finding.fix`(스키마 1.6, [docs/RESULT_SCHEMA.ko.md](docs/RESULT_SCHEMA.ko.md) 참고). SARIF: `results[].fixes`(SARIF 2.1.0 스키마에 맞으며, 코드 스캐닝 화면이 무시할 수도 있습니다). 대시보드: 발견 항목 상세에 diff를 읽기 전용으로 보여 주고 복사 버튼이 있습니다. diff는 직접 적용하세요. 예: `git apply --unidiff-zero fix.diff`.
- **어떤 규칙(`fixable`).** 고치는 방법이 그 맥락에서 의미를 그대로 유지하는 기계적인 한 줄 교체일 때만 수정 가능한 규칙으로 선언합니다. 현재:
  - `PG-COOKIE-001`: `.properties`나 YAML의 Spring `server.servlet.session.cookie.secure`/`http-only`(`server.reactive...`, `server.session...`, `httponly` 포함)가 명시적인 꺼짐 값이면 `true`로 바꿉니다(dev, local, test 설정은 일부러 그렇게 했을 가능성이 커서 신뢰도를 낮춥니다). 한 줄로 쓴 Express `res.cookie("name", value[, { 평평한 옵션 }])` 호출에는 빠진 `httpOnly: true`, `secure: true`, `sameSite: "lax"`를 추가합니다. 실제 쿠키 옵션 이름만 받고, `sameSite`와 짧은 `path` 외의 문자열 값은 받지 않으며, 줄 끝은 그대로 둡니다. 다음 줄로 이어지는 호출(`.status(200)`)은 안내만 합니다. 이 플래그가 하는 일을 검토하세요. `secure`는 평문 HTTP로 쿠키를 보내지 않게 하므로 로컬 개발에 영향이 있고, `sameSite: "lax"`는 다른 사이트에서 오는 POST와 iframe(OAuth `form_post`, 임베드)에서 쿠키를 빼며, `httpOnly`는 `document.cookie`를 읽는 클라이언트 코드에서 쿠키를 숨깁니다.
  - `PG-CRYPTO-003`: Java 파일에 `import java.util.Random;`이 있고 줄 전체가 `[Random name = ]new Random();` 또는 `new Random().nextBytes(name);`(그 밖의 `next*` 메서드 포함)이거나, Kotlin에서 `val`과 `java.util.Random()`으로 된 같은 형태이면 `new java.security.SecureRandom()`으로 바꿉니다(하위 클래스라 타입과 호출이 그대로 유효하며 import는 추가하지 않습니다). 와일드카드 import, 시드, 익명 하위 클래스, `var`, 다른 줄에서 만든 생성기, 줄에 다른 내용이 있는 경우는 안내만 합니다. 상속된 멤버 타입 `Random`은 배제할 수 없으므로 Java 수정의 신뢰도는 medium입니다.
  - 그 밖의 규칙은 안내(권장 조치)만 합니다. 일부러 안내로 남긴 예: 약한 비밀번호 해시(알고리즘, 저장된 해시, 로그인 흐름이 함께 바뀜), Go `exec.Command("sh", "-c", ...)` 등 명령 실행 규칙, SQL·XSS 규칙(무엇이 값이고 무엇이 식별자나 HTML인지에 따라 수정이 달라짐), `Math.random()` 토큰(토큰 형식과 길이가 바뀜), 암호 모드(모드를 바꾸면 IV와 키 계획이 필요함), `yaml.load`(PGARD에 해당 규칙 없음).
- **diff가 없을 때.** 표시된 줄이 위 교체 중 하나와 정확히 일치하지 않으면 수정 가능한 규칙도 `reason`이 붙은 `kind: "guidance"`를 줍니다. 줄에 주석이나 두 번째 문장이 있음, 리터럴 옵션 객체 대신 변수, 스프레드, 이미 다른 값으로 설정된 옵션, 시드가 있는 생성기, 다른 줄에서 만든 생성기, 스캔 이후 바뀐 파일, 400자를 넘는 줄 등입니다.
- **비밀 없음, 크기 제한, 결정적.** diff에는 지운 줄 하나와 추가한 줄 하나만 있고 문맥 줄이 없어 수정 주변의 소스 텍스트는 복사되지 않습니다. 각 수정기는 표시된 줄 전체를 엄격한 패턴에 맞춰 보고, 패턴이 잡아낸 조각(식별자, 숫자, 쿠키 옵션 이름, 위에 적은 몇 가지 고정 옵션 문자열)으로 새 줄을 만듭니다. 줄의 나머지(16진수나 바이트 배열 키, 문자열, 주석)는 diff에 들어갈 수 없고, 다른 내용이 있는 줄은 안내만 합니다. 두 줄 모두 PGARD의 비밀·경로 가리기를 거쳐도 그대로여야 하며, 아니면 diff를 만들지 않습니다. diff는 최대 2,000자이고, 같은 소스는 같은 diff를 만들며, PGARD는 파일을 읽기 전용으로만 읽습니다(실행하지 않음). `\n`/`\r\n` 외의 줄바꿈(U+2028 등)이 있는 파일은 줄 번호를 믿을 수 없어 안내만 합니다.
- **검증되지 않음.** `Finding.fix.confidence`는 표시된 코드의 의미가 유지된다고 PGARD가 얼마나 확신하는지를 뜻하며 안전을 보장하지 않습니다. 모든 diff를 검토하고 빌드·테스트한 뒤 커밋하세요.

### SARIF 출력

`pgard scan --format sarif > pgard.sarif`는 가려진 결과를 [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) 형식으로 stdout에 출력합니다(진행 상황과 안내는 stderr, 종료 코드는 그대로). 파일로 저장하려면 stdout을 리다이렉트하세요. SARIF용 출력 파일 옵션은 없으며 `--report`/`--output-dir`는 여전히 HTML과 PDF 보고서만 씁니다. **PGARD는 아무것도 업로드하지 않습니다.** 파일을 GitHub이나 IDE로 보내는 것은 사용자의 몫입니다.

**업로드하면 안 되는 경우.** GitHub 코드 스캐닝은 PGARD의 `toolExecutionNotifications`를 표시하지 않으며, 업로드에 없는 기존 알림을 닫습니다. 완전히 실행되지 않은 스캔의 SARIF를 올리면 검사된 적 없는 영역의 알림이 닫힙니다. 종료 코드가 `0`일 때만 업로드하세요. 종료 코드 `3`(blocked), `4`(partial), `5`(failed)이면 업로드하지 마세요. 이때 PGARD는 stderr에 "Do not upload this SARIF"도 출력합니다. 이런 파일은 `executionSuccessful: false`이기도 하며, GitHub가 이를 실패한 실행으로 거부할 것으로 예상되지만 GitHub 문서에는 없으므로 종료 코드가 주된 안전장치입니다. PGARD가 분석하지 않는 ORM이나 쿼리 빌더(TypeORM, Sequelize, Knex, Drizzle, MikroORM, Objection, Kysely, Go의 ent, Bun, XORM, SQLBoiler, go-pg)를 import하는 프로젝트는 항상 partial 결과(종료 코드 4)를 받으므로, 그 SARIF는 설계상 업로드할 수 없습니다. 권한 있는 검사의 CI 워크플로 예시는 없습니다. 권한 확인에 필요한 GitHub 로그인이 현재 CI 러너에는 없어서, 터미널이 없는 러너에서는 로그인을 기다리지 않고 곧바로 종료 코드 3과 blocked 상태의 빈 SARIF가 만들어지기 때문입니다. `pgard scan --code-only --format sarif`는 로그인이 필요 없어 CI에서도 동작하며, 그 결과는 별도의 `pgard/code-only/` 카테고리에 남고 권한을 확인하지 않았다고 표시됩니다. 로컬 흐름 예시:

```sh
pgard scan --format sarif > pgard.sarif && \
  gzip -c pgard.sarif | base64 | tr -d '\n' > pgard.sarif.b64 && \
  gh api -X POST repos/OWNER/REPO/code-scanning/sarifs \
    -f commit_sha="$(git rev-parse HEAD)" -f ref="$(git symbolic-ref HEAD)" \
    -F sarif=@pgard.sarif.b64
```

(`&&` 덕분에 종료 코드 0일 때만 업로드합니다. 커밋이 이미 push되어 있어야 하고, HEAD가 detached 상태이면 안 되며, 토큰에 `security_events` 권한이 필요합니다(`gh auth refresh -s security_events`). 큰 보고서가 인수 길이 제한에 걸리지 않도록 `-F sarif=@file`로 파일을 넘깁니다. 대신 `github/codeql-action/upload-sarif`를 쓰면 결과마다 지문 불일치 경고가 한 번씩 로그에 남지만 정상입니다.)

**카테고리.** 각 실행에는 `automationDetails.id` `pgard/<범위>/`가 들어 있습니다(기본 스캔은 `pgard/code+history/`, 권한 있는 `scan code`는 `pgard/code/`). GitHub는 id마다 별도 카테고리로 취급하고 같은 종류의 스캔을 다시 업로드할 때만 알림을 닫으므로, `scan code`를 올려도 기본 `scan`의 알림은 닫히지 않습니다. 코드 전용 결과(JSON 1.7 `scanBasis.mode: "code_only"`)는 `pgard/code-only/`를 쓰며, 권한을 확인하지 않았다는 경고 알림이 들어 있습니다. `github/codeql-action/upload-sarif`에 넘긴 `category`는 이를 바꾸지 않습니다. 이 액션은 id가 없는 실행에만 값을 채웁니다.

매핑 방식:

- **규칙.** 실행되었거나 발견 항목을 만든 규칙마다 `tool.driver.rules`에 항목이 하나씩 있습니다. 짧은 설명(제목), 전체 설명(근거), `help.text`(해결 방법), `helpUri`(공식 CWE 페이지, 없으면 첫 번째 표준 링크), `properties.tags`(`security`, `CWE-n`, `external/cwe/cwe-n`, `OWASP-A0x:2025`)가 들어 있습니다.
- **심각도.** `level`: critical과 high는 `error`, medium은 `warning`, low와 info는 `note`입니다. `security-severity`는 숫자 문자열입니다. critical `9.5`, high `8.0`, medium `5.5`, low `3.0`, info `1.0`. GitHub는 규칙에 있는 값만 읽으며, PGARD는 이번 실행에서 그 규칙의 발견 항목 중 가장 높은 심각도를 규칙에 넣습니다. 따라서 GitHub가 낮은 심각도 결과를 규칙의 더 높은 심각도로 보여 줄 수 있습니다. 다른 도구를 위해 각 결과에도 자체 값이 들어 있습니다.
- **위치.** 저장소 파일 경로가 있는 발견 항목만 파일에 들어갑니다(물리적 위치가 없는 결과는 GitHub가 거부함). 각 항목은 저장소 기준 상대 경로 `artifactLocation.uri`(`uriBaseId` `%SRCROOT%`)와 시작·끝 줄이 있는 region을 가집니다(줄이 없으면 region도 없음). 이력 발견 항목은 커밋도 `properties.pgard.commit`에 담습니다. **웹 발견 항목은 제외됩니다**(파일이 없고 PGARD는 경로를 지어내지 않습니다). 몇 건이 어떤 규칙에서 제외되었는지는 `error` 알림과 `runs[0].properties.pgard.omittedFindings`에 기록되고, CLI는 stderr에 경고를 출력합니다. 해당 항목은 텍스트나 JSON 출력, 또는 보고서로 확인하세요.
- **지문.** `partialFingerprints["pgardFindingIdentity/v1"]`는 기준선과 스캔 비교가 쓰는 줄 번호와 무관한 식별자와 같으므로, 위치만 옮겨진 발견 항목은 지문이 유지됩니다. GitHub가 쓰는 유일한 지문인 `primaryLocationLineHash`는 이 식별자 뒤에 `:n`을 붙인 값이며, n은 파일 안에서 같은 식별자를 가진 결과의 순번이라 서로 다른 줄의 동일한 발견 항목이 충돌하지 않습니다. 이력의 발견 항목은 파일이 나중에 삭제되어도 식별자가 안정적으로 유지됩니다.
- **숨김 처리된 항목과 기준선.** `pgard.config.json`에서 숨김 처리한 발견 항목은 `suppressions: [{kind: "external", justification}]`와 함께 파일에 그대로 남아 집계됩니다. 기준선이 있으면 `baselineState`는 기준선에 있는 항목에 `unchanged`, 나머지에 `new`입니다. 숨김 처리된 항목에는 `baselineState`가 없습니다. 기준선이 없으면 설정하지 않습니다.
- **실행되지 않은 영역.** `partial` 또는 `not_tested` 영역마다 `runs[0].invocations[0].toolExecutionNotifications`에 `warning`이 하나씩 들어갑니다. `executionSuccessful`은 스캔이 blocked나 failed이거나 요청한 영역 중 하나라도 `partial` 또는 `not_tested`이면(예: 확인된 대상 없이 `scan web`) `false`이며, 이때 `error` 알림도 추가됩니다. GitHub는 `executionSuccessful: false`인 파일을 거부할 것으로 예상됩니다(GitHub 문서에는 없으며, 종료 코드가 주된 안전장치입니다). 선택하지 않은 영역은 나열하지 않습니다. 다른 도구는 이 알림을 보여 줄 수 있지만 GitHub는 보여 주지 않습니다.
- **가림 처리.** 텍스트는 JSON 출력과 똑같이 가려지며 비밀 값은 나타나지 않습니다.

### 저장된 결과

`pgard scan`은 이후 작업에서 검사를 비교할 수 있도록 끝난 결과를 보관합니다. 아무것도 남기지 않던 MVP와 달라진 점입니다. 지금은 CLI 검사만 저장합니다. 대시보드는 결과를 여전히 메모리에만 두고 종료하면 버리며, `project verify`는 저장하지 않습니다.

- **위치.** 프로젝트가 아니라 사용자별 앱 데이터 폴더입니다. macOS는 `~/Library/Application Support/pgard`, Linux는 `$XDG_DATA_HOME/pgard`(기본 `~/.local/share/pgard`), Windows는 `%LOCALAPPDATA%\pgard`입니다.
- **내용.** 검사 한 번에 파일 하나로, 그 실행의 권한 확인에서 얻은 숫자 GitHub 저장소 id 아래에 저장합니다(경로에 저장소 이름은 없음). 파일은 민감정보를 가린 검사 결과이며 [`docs/RESULT_SCHEMA.ko.md`](docs/RESULT_SCHEMA.ko.md)의 JSON과 같습니다. 검사 id와 시각, PGARD 버전, 요청한 범위, 전체 상태, `owner/name`, HEAD 커밋 SHA(웹 검사는 `127.0.0.1` origin), 권한 확인 결정과 다섯 가지 확인의 사유(로그인한 GitHub 계정, owner 계정 또는 조직, 사용자의 역할 이름이 나옴), 영역별 coverage, 그리고 각 발견 항목의 규칙·심각도·저장소 기준 상대 경로와 줄(또는 로컬 URL, 커밋)·가려 처리한 증거 일부·영향·조치 안내가 들어갑니다. 절대 경로, 프로젝트 루트, 토큰, 소스 파일 전체는 들어 있지 않으며, 읽어서 권한을 판단하는 데 쓰지도 않습니다. 다섯 가지 확인은 검사마다 계속 실행됩니다. 이번 실행에서 게이트가 허용했고 `blocked`나 `failed`로 끝나지 않은 검사만 저장합니다.
- **보관 기간.** 저장소마다 최근 20회, 그리고 90일을 넘지 않은 것만 남깁니다. 저장할 때마다 정리합니다(`@pgard/result-store`의 상수 `RETENTION_MAX_SCANS_PER_REPO`, `RETENTION_MAX_AGE_DAYS`).
- **보호.** macOS와 Linux에서 디렉터리는 `0700`, 파일은 `0600`이며 쓴 뒤에 확인합니다. 저장 폴더와 그 안의 파일은 심볼릭 링크를 따라가지 않습니다. 같은 폴더의 임시 파일에 쓴 뒤 이름을 바꾸므로 동시에 실행한 검사도 중간 상태의 파일을 보지 않습니다. Windows에서는 모드 비트가 적용되지 않습니다. 폴더는 `%LOCALAPPDATA%` 프로필 폴더의 접근 규칙을 상속하며 PGARD는 이를 바꾸거나 확인하지 않습니다.
- **다시 읽기.** 항상 파일 크기 상한(8 MiB)을 확인한 뒤 `readScanResult`로 읽습니다. 손상되었거나 너무 크거나 지원하지 않는 파일은 경고와 함께 건너뛰며, 더 새로운 PGARD가 쓴 파일(더 높은 `schemaVersion` minor)은 절대 덮어쓰지 않습니다.
- **지난 검사와 비교.** 검사를 저장한 뒤 PGARD는 같은 저장소에서 가장 최근에 저장된 이전 결과와 비교해 한 줄(현지 시각)을 출력합니다. 예: `Since the last scan (2026-10-25 14:02): 2 new (1 in areas not fully compared: history:commits), 1 no longer reported, 9 unchanged (3 moved)`. 첫 검사와 `--no-store`에서는 출력하지 않습니다. `--format json`에서는 이 줄이 stderr로 가고 stdout은 JSON 문서 하나로 유지됩니다. 이전 검사가 다른 커밋의 것이면 줄에 그 짧은 커밋이 표시됩니다(`, at abc1234`).
  - **매칭.** 발견 항목은 줄 번호가 아니라 규칙, 파일 경로, 가려 처리한 증거의 형태로 맞춥니다. 그래서 위치만 옮겨진 코드는 "사라짐 + 새로 생김"이 아니라 "unchanged (moved)"입니다. 웹 발견 항목은 규칙, 쿼리를 뺀 URL, 버전처럼 보이는 값을 뺀 증거(헤더 이름과 쿠키 이름은 포함)를 쓰고, 히스토리 항목은 규칙, 경로, 커밋, 증거를 씁니다. 식별이 같은 항목이 둘 이상이면 가장 가까운 줄끼리 짝짓습니다. 따라서 한 파일 안의 같은 형태 항목 둘은, 하나가 사라지고 같은 파일의 다른 곳에 하나가 생겨도 옮겨진 항목 하나로 취급됩니다. 심각도나 상태가 바뀐 짝은 따로 셉니다("1 changed severity or status").
  - **"no longer reported"는 "fixed"가 아닙니다.** 코드가 건너뛰어졌거나 이름이 바뀌었거나 삭제되었을 수도 있습니다. 이전 항목은 두 검사 모두에서 그 위치가 완전히 분석된 경우에만 "no longer reported"로 셉니다. 다음의 경우에는 세지 않고 줄에서 이유를 알립니다(`Some findings could not be compared because history:commits was only partially scanned`). 해당 영역이 partial이거나 테스트되지 않았거나 한쪽 검사에서만 실행된 경우, 해당 범위에서 파일이 건너뛰어졌거나(1 MiB 초과, 지원하지 않는 ORM, 의존성 디렉터리, 파일이든 디렉터리든 모든 심볼릭 링크, 읽을 수 없는 디렉터리) 건너뛴 대상의 집합이 달라진 경우(PGARD는 경로 자체가 아니라 건너뛴 경로들의 짧은 해시를 비교합니다), 웹 주소가 다른 경우, 두 검사 사이에 PGARD가 업데이트된 경우(이때 줄에 그렇게 표시됨)입니다.
  - **새 발견 항목은 숨기지 않습니다.** 이전 검사에 없던 모든 발견 항목은 new로 셉니다. 이전에 그 영역이 일부만 검사되었거나 지난 검사 범위에 없었다면 이미 있었을 수 있으므로 `(N in areas not fully compared: <영역>)` 표기로 따로 알립니다.
  - **항상 partial인 영역.** 1 MiB를 넘는 소스 파일, PGARD가 분석할 수 없는 `source:orm:*` 패키지, 1 MiB를 넘는 히스토리 blob처럼 늘 partial인 영역이 있는 저장소에서는 그 영역이 막는 발견 항목이 "no longer reported"로 잡히는 일이 드물거나 없습니다. 의도된 동작입니다. 그런 검사는 해당 위치가 분석되었음을 증명하지 못하므로 항목이 없다는 것이 건너뛰었다는 뜻일 수 있습니다. 두 검사 모두에 있는 항목은 그대로 짝지어집니다.
  - **저장.** 비교를 위해 따로 저장하는 것은 없습니다. 저장된 두 결과로 계산하며, 위와 같은 크기 상한과 `readScanResult`로 읽습니다(읽을 수 있는 가장 최근 파일을 쓰고, 손상되었거나 더 새로운 스키마인 파일은 경고와 함께 건너뜀). 전체 비교 화면은 아직 CLI에 없습니다.
- **처음 실행.** 결과를 처음 저장할 때 PGARD는 결과가 어디에 저장되는지, 어떻게 끄거나 지우는지 stderr에 안내합니다. 한 번만 보여 주며 저장 폴더의 `.notice-shown` 파일이 이를 기록합니다.
- **프로젝트 선택기의 파일은 "경로 없음"의 유일한 예외입니다.** `pgard web`은 결과 옆의 `web/` 폴더에 작은 파일 두 개를 둡니다(소유자 전용 `0700` 폴더, `0600` 파일, 심볼릭 링크를 따라가지 않음, 임시 파일에 쓴 뒤 이름 변경). `settings.json`(`pgard web`이 검색하는 폴더이며 터미널에서만 바꿈)과 `recent-projects.json`(확인한 프로젝트 최대 20개, 90일)입니다. 검사 결과와 달리 **절대 경로**가 들어 있습니다. 로컬 전용이며 업로드되지 않고, `--no-store`나 `PGARD_NO_STORE=1`이면 쓰지 않으며(최근 목록은 비어 있음), `pgard history clear --all`이 지웁니다(`--repo`는 지우지 않음). [프로젝트 고르기: pgard web](#프로젝트-고르기-pgard-web) 참고.
- **끄기와 삭제.** `--no-store`나 `PGARD_NO_STORE=1`이면 아무것도 저장하지 않습니다([기준선](#기준선baseline)도 무시합니다). `pgard history clear --all`은 기준선과 프로젝트 선택기의 `web/` 폴더를 포함해 전부(`--repo owner/name`은 한 저장소)를 삭제합니다. 직접 지우려면 저장 폴더 전체가 아니라 그 안의 `repos` 폴더(`pgard/repos`)를 지우세요. 전체 `pgard` 폴더는 PGARD의 다른 데이터와 함께 쓸 수 있습니다.
- **advisory 데이터는 별도입니다.** `pgard advisories update`는 공개 OSV 취약점 데이터를 같은 앱 데이터 폴더의 `advisories/osv/`에 저장합니다(약 5 MB. 검사 결과가 아니며 `pgard history clear`로 지워지지 않고 `--no-store`의 영향도 받지 않습니다). 사용자가 직접 실행하는 이 명령만 기록하며, OSV 내보내기 호스트에서 내려받을 뿐 아무것도 업로드하지 않습니다. [개인정보와 네트워크 통신](#개인정보와-네트워크-통신) 참고.

### 증분 검사

기본적으로 `pgard scan`은 이 저장소에 마지막으로 저장된 검사를 바탕으로 하므로, 큰 저장소의 두 번째 검사는 바뀐 부분만 봅니다. 무슨 일이 있었는지는 결과가 알려 줍니다(스키마 1.2의 `incremental` 필드와 요약의 한 줄: **증분 검사: 파일 3개 다시 검사, 1997개 재사용 (검사 1a2b3c4d 기준)** 또는 **전체 검사: <사유>**). `pgard scan --full`은 모든 것을 다시 검사합니다. 웹 검사는 증분이 아니며 항상 실시간으로 실행합니다.

- **무엇을 재사용하나.** 코드: 저장된 검사가 분석했을 때와 SHA-256이 같은 소스 파일의 발견 항목(모든 파일의 내용을 비교하므로 커밋하지 않은 파일, 추적하지 않는 파일, Git이 무시하는 파일도 포함되고 `exclude`도 그대로 적용됩니다). 바뀐 파일, 새 파일, 이름이 바뀐 파일, 되돌린 파일은 다시 분석하고 삭제된 파일의 발견 항목은 버립니다. 이력: `저장된HEAD..HEAD`의 커밋만 읽고, 새 커밋이 이전 커밋의 발견 항목을 그대로 참으로 둔다는 것이 확실할 때만 이를 이어받습니다. 그렇지 않으면 이력 전체를 검사하며 요약에 `이력 전체 검사`가 표시됩니다.
- **파일 하나를 넘어 보는 규칙은 복사하지 않습니다.** 모든 규칙은 `packages/scan-core/src/rule-locality.ts`에 분류되어 있습니다(분류되지 않은 규칙이 있으면 테스트가 실패하고, 그 상태의 검사는 전체 검사가 됩니다). `PG-CSRF-001`과 `PG-BRUTE-001`은 프로젝트 전체 규칙입니다. 모든 파일의 세션, CORS, 라이브러리 정보와 패키지 매니페스트를 읽으므로, 바뀌지 않은 파일에 저장된 정보와 바뀐 파일의 새 정보로 매 검사마다 다시 평가합니다. 그래서 CSRF 라이브러리를 import하는 새 파일이나 바뀐 `package.json`은 다른 파일이 바뀌지 않았어도 그 발견 항목을 바꿉니다.
- **전체 검사가 되는 경우.** 같은 저장소와 범위의 저장된 이전 검사가 없음(또는 저장이 꺼져 있음, `--no-store`), `--full`, PGARD 버전·규칙 메타데이터·advisory 데이터·grammar 해시·분석 코드 자체(분석기 소스의 해시, `npm run build`가 다시 만듦)가 바뀜, `pgard.config.json`이 바뀜, 저장된 검사가 손상되었거나 90일이 지났거나 저장된 데이터가 없음(이전 PGARD가 저장했거나 너무 커서 보관하지 못한 경우), 저장된 커밋이 `HEAD`의 조상이 아님(리베이스, 수정한 커밋, 강제 푸시, 다른 복제본), 규칙을 실행한 저장된 영역이 부분 완료이거나 미검사였음(지원하지 않는 언어처럼 탐색 중 발견한 사실만 적는 영역은 규칙을 실행하지 않으므로 해당하지 않습니다), Git이 변경 목록을 내지 못함. 사유는 `incremental.reason`에 있습니다.
- **이력 이어받기.** 이전 커밋의 발견 항목은 발견 항목이 있던 추적 파일이 바뀌지 않았고, 새 커밋이 비밀정보도 환경 파일도 추가하지 않았고, 읽지 못한 파일이 없을 때만 이어받습니다. shallow clone과 잘린 이력은 항상 전체를 검사합니다. 읽은 이력 blob 수는 증분 검사에서 다시 세지 않으며(규칙 통계가 `reason`으로 알립니다), 커밋과 파일 수는 재사용한 것을 포함해 셉니다.
- **coverage는 정직하게 유지합니다.** coverage 설명은 어느 검사에서 파일이나 커밋 몇 개를 재사용했는지 알려 줍니다. 재사용한 발견 항목은 저장된 검사가 알던 내용 그대로이며, 오래된 값이 될 수 있는 변경을 넘어서는 재사용하지 않습니다.
- **무엇을 저장하나.** 결과와 같은 파일에, 분석한 각 소스 파일의 SHA-256, 가려진 발견 항목(결과가 이미 담는 문구), 프로젝트 전체 검사에 필요한 몇 가지 정보(import, 라우트 줄)를 함께 보관합니다. 소스 텍스트, 비밀정보 값, 절대 경로는 없습니다. 이 데이터는 작업을 건너뛰는 데만 쓰이고 검사할 때마다 실제 파일과 대조합니다. 파일이 너무 커지거나(8 MiB, 소스 파일 약 18,000개) 결과와 같은 검사를 통과하지 못하면 결과만 저장하고, 다음 검사는 전체 검사가 됩니다.
- **측정.** TypeScript 파일 2,000개와 커밋 301개가 있는 저장소에서 파일 하나가 바뀐 경우 증분 검사 약 0.36초, 전체 검사 약 2.3초입니다(방법은 풀 리퀘스트 참고).

### 테스트·fixture 코드의 발견 항목

테스트·fixture 코드의 발견 항목은 다른 발견 항목 뒤에 별도 그룹(**In test or fixture code (N)**)으로 표시됩니다. 규칙, 심각도, 근거는 그대로이지만 신뢰도(confidence)는 최대 `low`로 제한됩니다. 상단 개수와 심각도 차트는 일반 코드만 셉니다(예: `Findings by severity (3 total) - plus 2 in test or fixture code`). 테스트에 커밋된 실제 비밀정보도 노출된 것이므로 이 항목들은 버리지 않습니다. 대시보드와 HTML/PDF 보고서는 모두 이 그룹에 나열합니다. 터미널 화면도 나열하지만, 5개를 넘으면 medium·low·info 항목은 요약으로 대체되고 critical·high 항목은 계속 나열됩니다([그룹화와 접기](#그룹화와-접기) 참고).

분류는 파일 내용이 아니라 경로로만 합니다. 다음에 해당하면 테스트·fixture 코드입니다.

- 파일 이름이 `*.test.*`, `*.spec.*`, `*_test.go`와 일치하거나,
- `__tests__/`, `__mocks__/`, `__fixtures__/`, `fixtures/`, `testdata/` 디렉터리 아래에 있거나,
- `test/` 또는 `tests/` 디렉터리 아래에 있는 경우. **단** 설정 파일(`.env*`, `.npmrc`, `Dockerfile*`, `settings.py`, `*_settings.py`, `config.py`, 또는 `.yml`, `.yaml`, `.tf`, `.tfvars`, `.properties`, `.ini`, `.toml`, `.json`, `.conf`, `.cfg`, `.xml` 파일)은 제외합니다. 이런 파일은 실제로 배포된 테스트 환경을 설정할 수 있으므로 일반 코드로 봅니다.

디렉터리 이름은 대소문자를 구분하지 않습니다. 이 규칙은 모든 범위의 발견 항목에 적용되므로, `fixtures/` 아래의 `.env`는 테스트 항목이지만 `deploy/test/.env`는 아닙니다.

### 서드파티·vendored 코드의 제안

저장소에 커밋된 서드파티 의존성 코드의 발견 항목은 일반 발견 항목이 아니라 제안으로 표시됩니다. 사용자가 소유한 코드가 아니고 그 자리에서 고칠 수도 없기 때문입니다. 이 항목들은 테스트·fixture 그룹 뒤, 맨 마지막에 **Suggestions: in third-party/vendored code (N)** 그룹으로 표시되며 "This code is a committed dependency, not your code. Review it if it's unexpected; otherwise consider removing it from Git."(커밋된 의존성 코드이며 사용자의 코드가 아님. 예상치 못한 것이면 검토하고, 아니면 Git에서 제거를 고려) 안내가 붙습니다. 규칙, 심각도, 근거는 그대로이지만 신뢰도(confidence)는 최대 `low`로 제한됩니다. 상단 개수와 심각도 차트에는 포함되지 않습니다(예: `Findings by severity (3 total) - plus 2 in test or fixture code, 5 suggestions in vendored code (1 high)`. 제안 중 critical·high 항목은 합계에 묻히지 않도록 괄호 안에 개수를 보여 줍니다). `node_modules/`에 커밋된 실제 비밀정보도 노출된 것이므로 이 항목들은 버리지 않습니다. coverage, 전체 상태, 종료 코드는 바뀌지 않습니다. 대시보드(같은 필터 적용)와 HTML/PDF 보고서는 모두 이 그룹에 나열하고, 터미널 화면은 테스트·fixture·vendored 코드의 발견 항목이 5개를 넘으면 심각도가 낮은 항목을 요약합니다([그룹화와 접기](#그룹화와-접기) 참고), `PG-HYGIENE-001` 제안([Git 이력 검사](#git-이력-검사) 참고)도 같은 그룹에 표시됩니다.

분류는 파일 내용이 아니라 경로로만 합니다. 경로의 디렉터리가 다음에 해당하면 vendored 코드입니다.

- 경로 어디에 있든 정확히 `node_modules`, `bower_components`, `jspm_packages`, `Pods`인 경우, 또는
- 정확히 `vendor` 또는 `third_party`인 경우. **단** 그 앞의 디렉터리 중에 `src`, `app`, `lib`가 있으면(대소문자 무관, 따라서 `Src/vendor/`도 사용자의 코드) 제외합니다. 이 이름들은 직접 만든 모듈 이름으로도 흔하므로(`nest g module vendor`는 `src/vendor/`를 만듦) `src/vendor/vendor.service.ts`, `packages/web/src/third_party/a.ts`, `app/vendor/client.rb`는 사용자의 코드로 봅니다.

그 밖에:

- 디렉터리 이름 전체가 일치해야 합니다. vendored 이름은 대소문자를 구분합니다. 패키지 관리자는 정확히 그 이름으로 만들고, 소문자 `pods/`는 Kubernetes 설정인 경우가 많기 때문입니다. `src/vendored.ts`, `my_node_modules_x/index.js`, `Vendor/`, `k8s/pods/`는 vendored가 아닙니다.
- 프로젝트나 패키지 최상위에 있는 Go와 PHP(Composer)의 `vendor/` 디렉터리(`vendor/`, `api/vendor/`)는 둘 다 의존성 사본이므로 모두 해당합니다.
- `dist/`, `build/` 같은 빌드 결과물은 사용자 자신의 산출물이므로 vendored가 아닙니다.
- vendored이면서 테스트 코드이기도 한 경로(`node_modules/pkg/test/a.js`)는 vendored로 봅니다.

HTML·PDF 보고서는 같은 가려진 결과로 만듭니다. HTML 보고서는 스크립트가 없고 엄격한 CSP를 쓰는 단일 파일입니다. 보고서는 사용자가 지정한 디렉터리에만 저장되고, 기존 파일을 덮어쓰지 않으며, 권한 `0600`으로 만들어집니다(Windows에서는 불가능합니다. [요구 사항](#요구-사항) 참고). 실수로 커밋되지 않도록 보고서는 저장소 밖에 보관하세요.

## 대시보드

`pgard dashboard`는 현재 디렉터리의 Git 루트를 찾아 보여 주고 `Start the dashboard for this project? [y/N]`을 묻습니다. 대화형 터미널이 필요하며, 없으면 종료 코드 2로 끝납니다. 확인하면 로컬 웹 앱을 시작하고 기본 브라우저로 엽니다. 터미널에는 한 번만 쓰는 토큰을 가린 링크가 나옵니다.

```text
PGARD dashboard is running on 127.0.0.1 only.
Opened in your browser: http://127.0.0.1:<port>/#token=••••
Run again with --print-url to see the full link.
To open it elsewhere, stop and rerun the command.
The link works once, in one tab, within 10 minutes. Do not share it.
Press Ctrl+C to stop; results and the session are discarded when pgard dashboard stops.
```

CI, 출력이 터미널이 아닐 때, SSH 접속(모든 시스템), 디스플레이(`DISPLAY` 또는 `WAYLAND_DISPLAY`)가 없는 Linux, `--no-open`(또는 `--no-browser`)에서는 브라우저를 열지 않고 전체 링크를 대신 출력합니다. 브라우저를 시작하지 못했을 때도 전체 링크를 출력합니다. `--print-url`을 주면 연 뒤에도 전체 링크를 출력합니다. 페이지가 연결되면 터미널에 `Browser connected at HH:MM:SS.`가 출력됩니다.

대시보드는 CLI가 저장한 결과를 읽거나 쓰지 않고 직접 검사하며, 그 검사는 저장되지 않습니다. `pgard.config.json`의 `suppressions`는 CLI처럼 보여 줍니다(제목의 개수, 치명적·와일드카드·넓은·만료된 항목에 대한 경고, 접힌 `Suppressed (N)` 구역). 기준선은 CLI의 결과 저장소에 있으므로 대시보드는 기준선을 적용하지 않습니다. 권한 확인 결과와 GitHub device 코드를 보여 주고, 로컬 서비스 선택·확인, 범위 선택, 진행 상황 확인, 발견 항목 필터(테스트·fixture 항목과 vendored 코드의 제안은 각각 별도 그룹), HTML/PDF 보고서를 브라우저 다운로드로 받는 기능(CLI가 저장하는 것과 같은, 가려진 보고서이며 대시보드는 사용자가 입력한 경로에 파일을 쓰지 않음)을 제공합니다. OS 키체인에 저장된 GitHub 로그인은 서버 쪽에서 다시 사용하며, 토큰은 브라우저로 보내지 않습니다. 로그아웃 버튼은 두 가지입니다. **End dashboard session (keep keychain sign-in)** 버튼은 이 대시보드의 세션만 끝내고 다음 확인 때 키체인 로그인을 다시 사용합니다. **Sign out and remove from OS keychain**은 저장된 로그인도 지웁니다(CLI에서도 지워짐). 대시보드가 실행되는 동안 `pgard login`으로 다른 GitHub 계정으로 바꾸면 대시보드는 마지막 확인 결과를 버리므로, 로컬 서비스 탐색과 probe에는 새 확인이 필요합니다. Ctrl+C로 종료하면 대시보드의 GitHub 세션이 끝나고(키체인 로그인은 유지) 모든 결과를 버립니다.

device 코드가 필요하면 대시보드는 **Open the GitHub sign-in page** 버튼을 보여 주고, `pgard dashboard --no-browser`가 아니면 페이지를 직접 엽니다. 권한 확인 패널이 이 저장소에 PGARD GitHub App이 설치되지 않았다는 이유로만 차단되었고 본인이 승인할 수 있으면(또는 GitHub가 아직 조직 역할을 보여 주지 못하면. 문구는 CLI와 같음) **Install the PGARD GitHub App** 버튼(새 탭에서 열림)을 보여 주고, 최대 10분 동안 5초마다 owner 승인을 다시 확인한 뒤 전체 확인을 자동으로 다시 실행합니다. 두 제한은 서버가 강제합니다. 재확인은 5초에 한 번까지, 확인이 끝난 때부터 10분 안에만 허용되므로 패널을 새로 고쳐도 기다리는 시간이 늘어나지 않습니다. 그렇지 않으면 CLI와 같은 `Ask an owner of <account> ...` 링크를 보여 줍니다.

포트 탐지, 서비스 정체 확인 요청, 대상 확인은 이 프로젝트에 대한 대시보드의 가장 최근 권한 확인이 통과한 뒤에만, 그리고 그 확인이 끝난 뒤 30분 동안만 허용됩니다. 대시보드는 이 시간이 언제 끝나는지 보여 주며, 그 뒤에는(또는 시스템 시계가 뒤로 가면) 다시 확인해야 로컬 서비스에 접근합니다. 새 확인이나 로그아웃은 즉시 이 시간을 끝내고 진행 중인 요청을 중단하며, 페이지는 이전 확인 때의 포트 목록과 확인 결과를 버립니다. 이 시간과 관계없이 모든 검사는 권한 확인 전체를 다시 실행합니다.

대시보드는 한국어와 영어를 지원합니다. 브라우저 언어를 따르며(한국어 설정이면 한국어, 그 외에는 영어) 헤더의 **한국어 / English** 토글로 바꿀 수 있고, 선택은 브라우저에 기억됩니다. 발견 항목 상세의 규칙 문구(제목, 영향, 조치, 표준, 예시)와 표준·규칙 통계 패널은 같은 토글을 따르고, 그 밖에 검사 결과에서 오는 문구(근거, 권한 확인 이유, coverage 설명)는 아직 영어로 표시됩니다.

### 프로젝트 고르기: pgard web

`pgard dashboard`는 현재 디렉터리의 프로젝트에 고정됩니다. `pgard web`은 **프로젝트 없이** 로컬 페이지를 시작하고 브라우저에서 폴더를 고르게 합니다. 터미널에서는 아무것도 묻지 않습니다. macOS와 Linux에서만 동작하며, Windows에서는 사용법 오류(2)로 끝나고 `pgard dashboard`를 안내합니다.

**간단한 화면**(`pgard web`이 여는 화면):

1. **폴더 선택.** **폴더 선택**은 시스템의 폴더 선택 창을 엽니다(macOS는 `osascript`, Linux는 `zenity` 또는 `kdialog`. 서버가 고정된 안내 문구로 실행하고 취소하면 종료합니다). 폴더 경로를 붙여 넣어도 됩니다(`~/`는 홈 폴더로 바뀝니다). 경로는 아래와 같은 자식 프로세스에서 확인합니다. 홈 폴더, 시스템 폴더, `/`는 너무 넓어서 거부하고, Git 데이터 폴더(`.git`과 그 안, bare 저장소)와 다른 사용자의 것이거나 다른 사용자가 바꿀 수 있는 폴더도 거부합니다. 저장소 안의 폴더를 고르면 그 저장소(최상위 폴더)를 확인하고 검사하며, 페이지에 그렇게 표시합니다. 거부할 때는 이유와 해결 방법을 한 줄로 보여 줍니다.
2. **검사.** 권한 확인이 먼저 `pgard scan`과 똑같이 실행됩니다(같은 다섯 가지 확인, GitHub 요청마다 최대 10초). 이미 있는 GitHub 로그인을 쓰며, 페이지가 스스로 로그인을 시작하지 않습니다. 통과하면 코드 검사가 실행되고 찾은 문제가 나옵니다(심각도, `file:line`, 짧은 제목).
3. **승인이 통과하지 않으면** 이유를 한 줄로 보여 주고(이 폴더에 대한 GitHub App 승인 없음, 로그인하지 않음, GitHub 원격 저장소 없음, Git 저장소 아님, 승인을 확인하지 못함) **코드만 검사 (권한 미확인)**와 **승인 방법 보기**를 보여 줍니다. 코드만 검사는 그 버튼을 눌렀을 때만 실행됩니다. 현재 파일만 읽고(Git 기록과 웹 검사 없음) 페이지와 내보낸 보고서의 모든 페이지에 "권한 미확인"이 표시되며, 저장하지 않습니다. 로그인하지 않았으면 눈에 띄지 않는 **로그인하고 승인 확인** 링크로 원할 때만 GitHub 로그인을 시작합니다.

coverage, 표준, 규칙, 내보내기, **전체 대시보드**(Git 기록, 로컬 웹 검사, 추이, 검색 선택기)는 **더보기**에 있습니다. 대시보드의 추이 제목 옆에는 동그라미 「?」 버튼이 있어(키보드로 사용 가능: Enter 또는 Space로 열고 닫고, Esc로 닫습니다) 같은 짧은 설명을 보여 주며, 추이가 비어 있으면(저장 꺼짐, 0건 또는 1건) 대시보드 기준의 흔한 이유를 나열합니다(대시보드에서 실행한 검사나 코드 전용 검사는 저장되지 않음, `PGARD_NO_STORE=1` 또는 `pgard web --no-store`로 저장 끔).

**검색 선택기**(전체 대시보드, 더보기 안)는 터미널에서 `pgard web scope list | add <folder> | remove <folder>`로 추가한 폴더만 검색합니다. 추가한 폴더가 없으면 복사할 명령을 보여 줍니다. `add`는 실제 경로를 보여 주고 확인을 묻습니다(홈 폴더 전체를 추가하면 macOS 권한 요청과 iCloud 다운로드에 대한 경고를 보여 줍니다). 폴더는 본인 소유이고 그룹·다른 사용자가 쓸 수 없어야 하며 최소 두 단계 깊이여야 합니다. 브라우저는 세션 동안 폴더를 끌 수 있지만 추가하거나 바꿀 수는 없습니다.

2. **브라우저는 이름만 보냅니다.** 폴더 이름(2자 이상, 경로 한 단계)을 입력하거나 프로젝트 폴더를 페이지에 놓으세요. 이름만 읽으며 아무것도 업로드하지 않고, 경로나 파일 내용이 페이지나 서버에 도달하는 일은 없습니다. 서버가 자기 폴더를 검색해(심볼릭 링크를 따라가지 않고, 다른 파일 시스템으로 넘어가지 않고, 최대 4단계 깊이, 고정된 한도와 시간 예산) 각 일치 항목의 **실제 경로**와 **`owner/name`**(github.com 원격 저장소)을 보여 줍니다. 탐색, Git 호출, 검사는 별도 자식 프로세스에서 실행되며 시간 초과, 취소, 종료 시 프로세스 그룹 전체가 종료됩니다.
3. **경로와 원격 저장소를 확인합니다.** 확인하기 전에는 아무것도 선택되지 않습니다. 확인하면 서버가 폴더를 다시 살펴보고 바뀌지 않았을 때만 선택합니다. Git 루트가 아니거나, 커밋이 없거나, alternates·replace ref를 쓰거나, github.com 원격 저장소가 없거나(다른 호스트나 여러 저장소 포함), linked worktree·서브모듈이거나, 다른 사용자의 것이거나, 그룹·다른 사용자가 바꿀 수 있는 폴더는 이유와 해결 방법과 함께 차단됩니다(검색 폴더부터 아래 모든 디렉터리, `.git`, `.git/config`. 메시지가 모든 경로와 `chmod go-w ...` 명령 하나를 보여 주며, 이 엄격한 규칙은 비공개 그룹을 쓰는 시스템에서도 완화하지 않습니다).
4. **그다음 같은 다섯 가지 확인.** 기존 권한 확인 패널이 CLI와 똑같이 실행됩니다(저장소, GitHub 신원, 소유자 승인, 현재 접근 권한, 기여). 잘못된 폴더가 곧바로 검사로 이어지는 일은 없습니다. 확인과 검사 전에 서버가 신원과 소유권 확인을 반복하고, 폴더가 확인한 저장소가 아니면 게이트가 막습니다. App 설치 밖의 비공개 저장소는 설치 안내와 함께 평소의 `current_access` 차단 상태로 끝납니다. **프로젝트 변경**은 검사나 확인이 실행 중이면 비활성이고, **확인 취소**는 실행 중인 확인(GitHub 로그인 대기 포함)을 멈춥니다.

`pgard web`은 `--no-store`(`PGARD_NO_STORE=1`도 같음. 선택기의 파일을 읽지도 쓰지도 않으므로 최근 목록과 저장된 검색 폴더가 없으며, 설정되어 있는 동안 `pgard web scope add`와 `remove`는 거부됨), `--no-browser`, `--no-open`, `--print-url`을 받습니다([대시보드](#대시보드)처럼 페이지를 브라우저로 열고 터미널에는 한 번만 쓰는 링크를 가려서 보여 줍니다). 페이지는 127.0.0.1에서만 열리고, 폴더 선택 창, 붙여 넣은 경로, 코드만 검사를 포함한 모든 경로에 같은 세션 비밀값, `Host`, `Origin`, 교차 사이트 확인과 엄격한 콘텐츠 보안 정책이 적용됩니다. 브라우저는 찾은 문제만 받으며 짧게 가린 코드 조각 외의 파일 내용은 받지 않습니다. `pgard dashboard`는 모든 `/api/picker/*` 요청에 `409 fixed_project`로 답합니다. 설계와 위협 모델은 [`docs/WEB_PROJECT_PICKER_DESIGN.ko.md`](docs/WEB_PROJECT_PICKER_DESIGN.ko.md)에 있습니다.

### 대시보드 보호 방식

- `127.0.0.1`의 빈 포트에만 바인딩합니다.
- 브라우저는 개인 리디렉트 파일로 엽니다(소유자만 쓸 수 있는 새 임시 폴더, 페이지가 연결된 뒤나 링크가 만료될 때, PGARD를 멈출 때 지움). 그래서 링크가 컴퓨터의 다른 사용자가 볼 수 있는 명령줄에 나타나지 않습니다.
- 32바이트 임의 토큰을 URL **fragment**로 전달하므로 브라우저가 요청이나 `Referer` 헤더에 싣지 않습니다. 페이지는 주소창에서 토큰을 바로 지웁니다. 링크를 공유하지 마세요.
- **링크는 한 번만 쓸 수 있습니다.** 페이지는 토큰을 탭별 세션 비밀값으로 바꿉니다(`POST /api/session/exchange`, 32바이트 임의 값, 서버는 메모리에 해시로만 보관하고 상수 시간으로 비교). 탭은 비밀값을 `sessionStorage`에 보관하므로 그 탭을 새로고침해도 계속 쓸 수 있습니다. 같은 링크를 다시 열면(다른 탭, 복사한 링크, 방문 기록) "이미 사용한 링크입니다"와 함께 할 일을 보여 줍니다. 이미 열려 있는 탭을 쓰거나 명령을 다시 실행하세요. 직접 연 것이 아니라면 서버를 멈추고(Ctrl+C) 명령을 다시 실행하세요. 쓰지 않은 링크는 10분 뒤 만료되고, 세션은 30분 동안 쓰지 않으면 끝납니다(열려 있는 페이지의 자동 갱신도 사용으로 칩니다).
- 모든 API 호출은 `x-pgard-session` 헤더에 세션 비밀값이 있어야 합니다. URL 토큰은 한 번의 교환 외에는 어떤 경로에서도 받지 않습니다. `Host` 헤더는 정확히 `127.0.0.1:<port>`여야 합니다(DNS rebinding 방어). 다른 `Origin`에서 온 요청과 cross-site 요청은 거부하며, CORS 헤더는 보내지 않습니다.
- 모든 응답에 `Cache-Control: no-store`, 엄격한 Content-Security-Policy, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`를 적용합니다.
- 브라우저는 프로젝트 파일을 읽을 수 없습니다. `pgard dashboard`에서는 프로젝트 루트가 대시보드를 시작할 때 고정되고 브라우저는 경로를 전혀 지정하지 않습니다. `pgard web`에서는 브라우저가 폴더 이름이나, 시스템 선택 창에서 고르거나 붙여 넣은 경로를 보내고, 서버가 직접 경로를 확인합니다. 이를 위해 파일 내용은 읽지 않습니다([프로젝트 고르기](#프로젝트-고르기-pgard-web) 참고). 보고서도 경로가 필요 없습니다. 보고서는 서버가 가려진 결과로 만들어 일반 브라우저 다운로드(세션 비밀값이 필요한 `GET /api/reports/html` 또는 `/pdf`)로 보내므로 대시보드는 디스크에 아무것도 쓰지 않습니다. 브라우저는 가려진 발견 항목(짧게 가려진 코드 조각 포함)만 받고, 전체 소스 파일이나 GitHub 토큰은 받지 않습니다.

## 개인정보와 네트워크 통신

- 코드, Git 이력, 검사 결과는 사용자 컴퓨터에서 처리되며 어디에도 업로드되지 않습니다. `pgard scan`의 결과는 `--no-store`나 `PGARD_NO_STORE=1`로 끄지 않는 한 앱 데이터 폴더에 보관되고 `pgard history clear --all`로 삭제합니다([저장된 결과](#저장된-결과) 참고). `pgard web`은 검색 폴더와 최근 프로젝트 목록도 절대 경로로 그곳에 두며, 로컬 전용이고 같은 명령으로 지워집니다. 대시보드의 결과는 메모리에만 있고 대시보드가 끝나면 버려집니다. 내보낸 보고서는 사용자가 고른 위치에 저장됩니다.
- GitHub 로그인은 파일이 아닌 OS 키체인에 저장되며 브라우저로 보내지 않습니다. 키체인이 없으면 메모리에만 보관합니다. [저장된 로그인](#저장된-로그인os-키체인) 참고.
- 검사(의존성 검사 포함), `pgard sbom`, 그리고 `pgard advisories update`를 제외한 모든 명령이 연결하는 곳은 GitHub뿐이며, 코드·lockfile 내용·결과는 누구에게도 보내지 않습니다. device flow 로그인(및 저장된 로그인 갱신)과, 권한 확인에 필요한 메타데이터(저장소의 GitHub remote 소유자/이름, 사용자 신원, App 설치, 조직 멤버십(조직 저장소인 경우), 접근 권한, 기여)를 읽는 GitHub API 호출입니다. 기여를 확인하기 위해 로컬 커밋의 SHA를 GitHub에 보냅니다(검증된 owner일 때는 로컬 이력이 기본 브랜치와 커밋을 공유하는지 확인하는 데만 사용). `pgard doctor`는 `api.github.com` 연결 가능 여부도 확인합니다(토큰도 저장소 데이터도 없는 인증 없는 `HEAD` 요청).
- 권한 확인을 통과한 뒤, PGARD는 서비스의 정체를 보여 주기 위해 `127.0.0.1`에서 발견한 각 열린 포트에 `GET /`를 한 번 보냅니다. 이후 웹 검사는 사용자가 확인한 서비스에만 요청을 보냅니다.
- 그 밖의 유일한 대상은 OSV 내보내기 호스트 `osv-vulnerabilities.storage.googleapis.com`([osv.dev](https://osv.dev/)의 공식 버킷)이며, 사용자가 `pgard advisories update`를 직접 실행할 때만 연결합니다. https 일반 `GET` 요청으로 공개 취약점 데이터를 내려받습니다(작성 시점 기준 npm 약 220 MB, Go 약 13 MB). 아무것도 업로드하지 않습니다. 패키지 이름, lockfile 내용, 프로젝트·사용자 데이터, GitHub 로그인을 보내지 않습니다. 호스트는 고정되어 있어 다른 호스트, 평문 http, 그 호스트에서 벗어나는 리디렉션은 거부하며, 크기와 시간 제한이 있습니다. 검사는 이 다운로드를 시작하지 않고 패키지별로 OSV를 조회하지도 않으며, `pgard doctor`와 대시보드는 로컬 사본의 상태(있음 또는 없음, 나이, 오래됨 여부, 데이터 버전, 저장 위치)만 읽습니다. 데이터는 사용자 데이터 디렉터리(macOS `~/Library/Application Support/pgard`, Linux `$XDG_DATA_HOME/pgard` 또는 `~/.local/share/pgard`, Windows `%LOCALAPPDATA%\pgard`)의 `advisories/osv/`에 저장되며, 그 폴더를 지우면 제거됩니다. 업데이트하는 동안 저장 위치 옆에 약 220 MB의 임시 공간이 필요하며(업데이트가 끝나면 삭제됨), 저장되는 결과는 약 5 MB입니다.
- OSV 다운로드에는 대조할 공식 체크섬이 없습니다. PGARD는 압축 파일의 SHA-256, 크기, 출처 URL, 시각을 기록하지만, 무결성은 고정된 호스트에 대한 HTTPS 신뢰(처음 받을 때 신뢰)에 의존합니다. zip과 레코드별 CRC-32 검사는 손상·잘림을 찾을 뿐 변조나 진위를 확인하지는 않습니다. 버킷은 Google이 운영하므로, 다른 다운로드와 마찬가지로 요청한 IP 주소와 요청 시각을 알 수 있습니다.
- PGARD는 취약점 데이터베이스를 포함하지 않습니다. 검사는 npm과 Go lockfile 버전을, 사용자가 내려받은 OSV 데이터와 이 컴퓨터에서 오프라인으로 대조합니다. 그 데이터가 없으면 의존성 영역은 검사하지 않음으로 보고됩니다. 검사 뒤 대시보드의 Coverage 화면에는 `pgard doctor`와 같은 advisory 데이터 상태가 표시되며(저장 폴더는 홈 디렉터리를 `~`로 표시), 대시보드는 아무것도 내려받지 않습니다.

## 범위 밖

- 데이터베이스 직접 접속
- Docker·컨테이너 설정
- 성능·부하 테스트
- 원격(loopback이 아닌) 서비스 검사
- 공격 요청, 폼 제출 등 상태를 바꾸는 요청
- 로그인한 상태의 웹 탐색(#45). `web:authenticated` 영역은 항상 `not_selected`이며, PGARD는 애플리케이션 비밀번호를 묻지 않습니다.
- 의존성 권고 대조는 npm과 Go만, 버전 범위로만 합니다. 도달 가능성과 악용 가능성은 분석하지 않습니다. Maven, PyPI, Packagist(및 다른 생태계)는 아직 읽지 않습니다. CVSS v4 점수는 계산하지 않습니다.

## 정확도

각 규칙은 [`tests/corpus/`](tests/corpus/)의 라벨이 붙은 코퍼스로 측정합니다. 소스 규칙에는 취약한 샘플(`positive`)과 안전한 샘플(`negative`)을, 이력 규칙에는 생성한 Git 저장소를, 웹 규칙에는 루프백 서버를 사용합니다. `npm run build && npm run corpus`는(실행기는 빌드된 패키지를 사용합니다) 이를 모두 검사하고 규칙별 true positive, false positive, false negative, 정밀도(precision), 재현율(recall)을 출력하며, 표를 [`tests/corpus/RESULTS.md`](tests/corpus/RESULTS.md)에 씁니다. CI는 규칙이 기록된 임계값 아래로 떨어지거나, 예상 실패 목록을 갱신하지 않은 채 샘플의 결과가 바뀌거나, `RESULTS.md`가 최신이 아니면 실패합니다.

숫자는 조심해서 읽으세요. 코퍼스는 작고(규칙마다 샘플이 열 개 안팎) PGARD 작성자들이 직접 만들었으므로, 우리가 떠올린 경우에서 규칙이 어떻게 동작하는지를 보여 줄 뿐 여러분의 코드에서 얼마나 자주 맞는지를 뜻하지 않습니다. 규칙이 놓치거나 잘못 보고하는 어려운 사례도 일부러 넣었으며, 이런 사례는 코퍼스에서 지우지 않고 이유와 함께 `RESULTS.md`에 남깁니다. 여기서 점수가 높다고 프로젝트가 안전한 것은 아닙니다.

가드는 신뢰도를 낮출 뿐, 결과를 숨기지 않습니다. 인젝션 규칙(SQL, 명령, 경로, SSRF)은 값이 식 자체로 고정되어 있을 때만 결과를 완전히 억제합니다. 리터럴, `Number(x)` 같은 숫자 변환, 리터럴로 설정된 모듈 수준 상수, `shell-quote`의 `quote()`가 여기에 해당합니다. 안전하다는 근거가 PGARD가 추론만 한 것(`startsWith(ROOT + sep)` 검사, 호스트 허용 목록, 조회 테이블, 별칭, 지역 상수)이면 결과는 남고, 신뢰도는 낮음, 심각도는 최대 중간으로 제한되며 어떤 점을 인식했는지 메모가 붙어 직접 확인할 수 있습니다. 코퍼스에서는 이런 추론으로만 안전한 샘플의 헤더에 `expect=low`가 붙으며, 이는 해당 규칙이 그 샘플에서 낮은 신뢰도로 제한된 결과를 반드시 내야 한다는 뜻입니다(결과가 없어도 검사가 실패합니다). `RESULTS.md`는 중간 이상 신뢰도의 결과만 센 정밀도도 함께 보여 줍니다.

## 알려진 제한 사항

- `pgard precommit`은 알려진 바이너리 서명과 함께 처음 8 KB 안의 NUL 또는 압축된 것처럼 보이는 내용이 있는 파일을 설계상 건너뜁니다. 이런 파일 안에 텍스트로 숨긴 비밀정보는 찾지 못합니다. 이런 건너뜀은 실행할 때마다 화면에 이름이 나오지만 검사하지 못한 것으로 세지는 않습니다. 알려진 서명 없이 처음 8 KB와 마지막 8 KB가 모두 바이너리 데이터처럼 보이는 파일도 읽지 않으며, 매번 경고로 이름을 적지만 커밋을 막지는 않습니다. 형식 서명만으로는(`%PDF-`로 시작하는 텍스트 파일) 바이너리로 보지 않습니다.
- PDF 보고서에는 Noto Sans KR 서브셋이 포함되어 한국어와 영어가 모두 표시됩니다. 폰트에 없는 문자(한자, 이모지, 다른 문자 체계)는 `?`로 바뀌고 PDF에 그 사실이 표시됩니다. 전체 텍스트는 HTML 보고서에 있습니다. 포함된 폰트를 불러오지 못하면 PDF는 내장 Latin-1 폰트로 대체되어 규칙 문구까지 전부 영어로 만들어지고(한국어가 `?`로 바뀌지 않으며, 검사 데이터에 있는 Latin-1 밖 문자만 `?`가 됩니다), PDF 안에 이를 알리며 CLI도 경고를 출력합니다.
- [#45](https://github.com/JadenMeister/pgard/issues/45) 로그인한 상태의 웹 탐색은 지원하지 않습니다. 범위 밖입니다([범위 밖](#범위-밖) 참고).
- 검증된 owner가 아닌 사용자의 기여는 보수적으로 확인합니다. co-author trailer와 서명 없는 직접 push는 기여로 인정하지 않으므로, 커밋을 공동 작성만 했거나 서명 없이 push한 협력자는 본인의 pull request가 merge되거나 서명된 커밋을 push할 때까지 기여에서 차단됩니다.
- 대시보드의 규칙 문구는 한국어와 영어를 지원합니다. 검사에서 오는 근거, 권한 확인 이유, coverage 설명은 영어로만 표시되며 내보낸 보고서의 제목과 안내문도 영어입니다.
- 탐지는 완전하지 않습니다. 발견 항목이 없다고 프로젝트가 안전한 것은 아닙니다.
- 포트 탐지는 불완전하거나 사용할 수 없을 수 있습니다. 그럴 때는 포트를 직접 입력하세요.
- 패널 화면의 Windows 터미널 동작(대체 화면, 키 입력, 크기 변경, Ctrl+C, 커서 복원)은 GitHub Actions 워크플로(`windows-tty-smoke`)가 실제 ConPTY에서 자동으로 확인합니다. 이 워크플로는 수동으로 실행하며, 스모크 파일을 바꾸는 pull request에서도 실행됩니다. 레거시 conhost(예전 콘솔 창)와 시각적 표시(글꼴, 색, 글리프)는 사용자가 확인하지 않았습니다. SIGTERM(종료 코드 143)은 ConPTY로 보낼 수 없어 macOS와 Linux에서만 확인합니다.

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
| `tests/corpus`             | 정확도 코퍼스, 실행기, 임계값                             |

```sh
npm ci
npm run build         # 모든 패키지와 대시보드 UI 빌드
npm run typecheck     # 타입 검사만
npm test              # Vitest 테스트 실행
npm run format        # Prettier로 포맷
npm run format:check  # 포맷 확인
npm run check         # typecheck + format:check + test
npm run corpus        # 정확도 코퍼스를 실행하고 tests/corpus/RESULTS.md를 다시 씀
```

CI는 pull request와 `main` push마다 `npm ci`, `npm run build`, `npm run format:check`, `npm test`, `npm run corpus:check`를 실행합니다.

### `docs/`의 문서

[`docs/README.ko.md`](docs/README.ko.md)는 [`docs/`](docs/)의 문서를 안내하며, 어느 문서가 현재 정책이고 어느 문서가 과거 기록인지 알려 줍니다. PGARD는 MVP 기획 기록인 한국어 기획 문서 세 개를 바탕으로 구현했습니다.

- [`PGARD_AGENT_BRIEF_KO.md`](docs/PGARD_AGENT_BRIEF_KO.md): 구현 브리프입니다. 제품 범위, 권한 게이트, 검사 경계, 완료 조건을 정했습니다.
- [`PGARD_CLI_AND_STRUCTURE_KO.md`](docs/PGARD_CLI_AND_STRUCTURE_KO.md): CLI 명령 체계와 앱·패키지 구조를 정했습니다.
- [`PGARD_DEVELOPMENT_CONVENTIONS_KO.md`](docs/PGARD_DEVELOPMENT_CONVENTIONS_KO.md): 커밋 단위, 메시지, 네이밍, 검증, PR 규칙과 현행 이슈·보드·리뷰 운영을 정했습니다.

현재 동작을 설명하는 문서가 하나 더 있습니다(기준은 영문판입니다). [`RESULT_SCHEMA.ko.md`](docs/RESULT_SCHEMA.ko.md)는 검사 결과 스키마의 버전 규칙과, 다른 버전을 읽을 때의 동작을 정했습니다.

구현하면서 나중에 바뀐 결정이 있어서, 기획 문서와 README가 다르면 README와 코드가 맞습니다.

## 라이선스

[MIT](LICENSE)

PDF 보고서에는 SIL Open Font License 1.1로 배포되는 Noto Sans KR 서브셋이 포함됩니다. [NOTICE](NOTICE.md)와 `packages/report/fonts/OFL.txt`를 참고하세요.

PGARD는 참조 목록(OWASP Top 10 2025, CWE Top 25 2025, SEI CERT Java의 규칙 id와 제목)도 포함합니다. 이 데이터는 각각의 라이선스(CC BY-SA 4.0, MITRE CWE 이용 약관, CC BY 4.0)를 따르는 제3자 데이터이며 MIT 라이선스의 적용 대상이 아닙니다. [NOTICE](NOTICE.md)를 참고하세요.
