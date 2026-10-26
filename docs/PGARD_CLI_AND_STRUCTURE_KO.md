# PGARD CLI·저장소 구조 상세 명세

> **참고:** 이 문서는 MVP 기획 기록입니다. 현재 동작은 [README.ko.md](../README.ko.md)([English](../README.md))가 설명하며, 내용이 다르면 README가 맞습니다. 이 문서의 영어 번역: [PGARD_CLI_AND_STRUCTURE_EN.md](PGARD_CLI_AND_STRUCTURE_EN.md).

이 문서는 PGARD 통합 브리프의 상세 부속 문서다. `pgard` 제품명, 로컬 실행, owner 승인·현재 접근·실제 반영 기여의 권한 게이트, 일회성 결과 처리는 확정된 제품 조건이다. 구현 언어 TypeScript/Node.js/React와 아래 폴더 구조는 추천안이다.

## 1. CLI 명령 계층

| 명령                                                     | 역할                                                                                                                |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `pgard`                                                  | 방향키 TUI 메인 메뉴. 프로젝트 확인, 범위별 검사, 대시보드, 규칙, 진단을 선택                                       |
| `pgard project verify`                                   | 현재 Git 저장소·GitHub remote·owner 승인·현재 접근·실제 반영 기여를 항목별로 확인하고 통과/거절/확인 불가 이유 표시 |
| `pgard scan`                                             | 기본 범위: 현재 코드·설정·의존성 + Git 이력                                                                         |
| `pgard scan code`                                        | 현재 코드·설정·의존성만 검사. 기여 확인용 Git 조회는 수행                                                           |
| `pgard scan history`                                     | Git의 과거 커밋과 추적 파일의 비밀정보·위험 파일만 검사                                                             |
| `pgard scan web [--port N]`                              | 승인된 프로젝트에 연결된 로컬 HTTP 서비스의 응답·헤더·허용된 페이지 검사                                            |
| `pgard scan all [--port N]`                              | code + history + web을 같은 검사 ID로 합친 종합 스캔                                                                |
| `pgard dashboard [--target-port N]`                      | 별도 로컬 웹 앱 시작. 웹 화면에서 새 검사를 실행하고 그 세션의 결과 표시                                            |
| `pgard rules list [--language js\|ts\|react\|vue\|go]`   | 지원 규칙, 판정 기준 버전, 취약점 데이터 버전과 미지원 범위 표시                                                    |
| `pgard doctor`                                           | Git·실행 환경·GitHub 연결·로컬 포트 탐지 가능성 진단. 검사/권한 승인 아님                                           |
| `pgard --help`, `pgard <명령> --help`, `pgard --version` | 사용법·버전                                                                                                         |

`scan` 변형과 대시보드의 새 검사는 **매번** 같은 권한 게이트를 다시 통과한다. 앞서 실행한 `project verify`의 통과 결과는 이후 명령에 저장·재사용하지 않는다. `rules list`와 `doctor`는 프로젝트 밖에서도 실행할 수 있다. GitHub 토큰과 검사 결과는 명령 사이에 저장하지 않으므로 별도 영구 로그인·지난 결과 조회 명령은 두지 않는다.

### 옵션과 경계

- `--port`는 `scan web`·`scan all`에서만 허용한다. `--target-port`는 `dashboard`에서만 허용하며 **검사 대상 서비스 포트**다. 대시보드 자체는 별도 가용 loopback 포트에 바인딩한다. 포트는 1~65535의 숫자만 허용하고 실제 접속은 `127.0.0.1`로 고정한다.
- 포트가 생략되면 열린 로컬 HTTP 후보와 `Other port`를 보여준다. 지정된 포트도 URL·응답 상태·`<title>`·추정 기술을 보여준 뒤 `현재 프로젝트의 서비스입니까? [y/N]`에서 명시적 `Y`를 받아야 한다. `N`이면 다른 포트 선택 또는 취소다. Y/N은 동일성 증명이 아닌 사용자 대상 선택이다.
- 모든 `scan` 변형은 `--report html|pdf|both --output-dir <경로>`를 받을 수 있다. 둘 중 하나만 쓰면 사용법 오류다. 저장은 사용자가 지정한 위치에만 하고 기존 파일을 덮어쓰지 않는다. Git 저장소 안 경로면 추적·커밋 위험을 경고하고 명시적 확인을 받는다. 기본은 터미널 결과만 표시한다.
- 알 수 없는 명령/옵션, 잘못된 값, 맞지 않는 옵션 조합은 인증·검사·네트워크 호출 전에 거부한다. `--path`, `--host`, `--url`, `--force`, `--skip-auth`는 MVP에 없다. CLI 검사 대상은 현재 디렉터리의 Git 루트다.

### TUI와 결과

메인 메뉴 → 프로젝트 확인 → GitHub 인증·권한·기여 확인 → 검사 범위 → 웹 범위면 포트·서비스 확인 → 실행 진행 → 결과·보고서 선택 순서다. 하위 명령은 메인 메뉴를 건너뛰고 해당 흐름으로 들어간다. 방향키 이동, Enter 선택, Esc 이전 단계(실행 중에는 취소 확인), `?` 도움말, Ctrl+C 취소 확인으로 통일한다. CLI는 서비스 로그인 비밀번호를 입력받지 않으며, 로그인 뒤 페이지는 사용자가 임시 브라우저 세션에서 직접 로그인할 때만 살핀다.

결과는 심각도별 막대 차트, 확정/의심, 파일:줄 또는 URL, 가려진 근거·가이드, coverage 순서다. 단독 검사가 선택하지 않은 영역은 `not_selected`, 선택했지만 실행하지 못한 영역은 `not_tested`, 일부만 끝난 영역은 `partial`로 표기한다. `발견 없음`과 `검사 실패`는 다르다.

`scan all`은 지원하는 code/history/web 범위를 함께 실행한다는 뜻이다. 웹 포트가 없거나 확인되지 않으면 종합 스캔을 완료로 표시하지 않는다. 사용자가 원하면 code/history 결과를 부분 완료로 받고 웹을 `not_tested`로 남긴다. 인증 뒤 탐색은 사용자가 요청한 경우에만 추가하며, 미요청 상태는 `not_selected`다. DB 직접 접속, Docker, 성능, 무차별 대입, 상태 변경 요청은 포함하지 않는다.

종료 코드는 `0` 요청 범위 완료(발견 항목이 있어도), `2` 잘못된 명령·옵션, `3` 저장소/권한/기여 게이트 실패, `4` 일부 검사 또는 보고서 저장 실패, `5` 내부 오류, `130` 사용자 취소다. 부분 실패 시 확보한 결과는 보여준다.

`dashboard`는 CLI 지난 결과를 자동으로 읽지 않는다. 독립 로컬 웹 앱을 **명시적으로** 시작하고 현재 프로젝트를 런처에서 확인하며, 웹 화면에서 새 검사를 실행한다. 결과·토큰·임시 브라우저 세션은 종료 시 폐기하고 사용자가 내보낸 HTML/PDF만 남는다.

## 2. 추천 저장소·파일 구조

```text
apps/
  cli/
    package.json
    src/
      bin/pgard.ts              # 프로세스 진입점
      app.ts                    # 명령 해석·TUI 실행 연결
      options.ts                # 옵션 검증·도움말
      commands/
        project/verify.ts
        scan/index.ts           # code + history
        scan/code.ts
        scan/history.ts
        scan/web.ts
        scan/all.ts
        dashboard.ts            # 독립 로컬 웹 실행 파일을 명시적 시작
        rules/list.ts
        doctor.ts
      flows/
        authenticate.ts
        select-project.ts
        select-local-port.ts
        run-scan.ts
        export-report.ts
      ui/
        screens/               # AuthScreen, ProjectScreen, ScopeScreen,
                               # PortScreen, ScanScreen, ResultsScreen
        components/            # ChoiceList, ConfirmPrompt, ProgressView,
                               # FindingRow, SeverityBars
        formatters/            # 심각도·경로·시간 표시
      state/session.ts          # 메모리 전용 실행 상태
      adapters/                # 터미널·브라우저·파일 선택 경계
  local-web/
    package.json
    src/
      server/
        index.ts                # 127.0.0.1 시작·종료
        create-server.ts
        launcher.ts             # 현재 프로젝트 폴더 확인
        middleware/
          local-origin.ts       # Host/Origin/CORS
          session-token.ts      # 로컬 API 세션
          csrf.ts
          no-store.ts
        routes/                 # auth, project, ports, scans, reports
        session/                # 메모리 store, project-grant
      client/
        main.tsx
        app/                    # App, providers
        api/client.ts           # 로컬 서버 호출
        features/
          onboarding/          # 권한·프로젝트
          target/              # 포트·서비스 확인
          scan/                # 진행·coverage
          findings/            # 필터·상세
          reports/             # HTML/PDF
          legal/               # 이용약관·개인정보 안내
        components/
          ui/                  # Button, Modal, Card, Badge, EmptyState
          findings/            # FindingCard, SeverityBadge, LocationLink
          charts/              # SeverityBarChart, SeverityDonutChart
          layout/              # PageShell, Navigation, StatusNotice
        hooks/
        styles/tokens.css
packages/
  scan-core/                   # 검사 범위·진행·공통 결과 조정
  policy/                      # 권한 게이트·대상 제한
  github-auth/                 # GitHub 로그인·승인 확인
  git-history/                 # remote/SHA/기여·비밀정보 이력
  source-analysis/             # JS/TS/React/Vue/Go 규칙
  http-local/                  # 제한된 loopback HTTP
  advisory/                    # 로컬 취약점 데이터 대조
  findings/                    # 결과 스키마·가림·차트 집계
  report/                      # HTML/PDF 렌더링
```

`apps/cli`와 `apps/local-web`은 서로의 소스를 import하지 않는다. `dashboard.ts`는 설치된 로컬 웹 실행 파일을 셸 문자열 없이 시작한다. `scan-core`와 `findings`가 두 앱에 공통인 결과·검사 의미를 제공한다. 한 화면만 쓰는 컴포넌트는 feature/screen 옆에, 여러 화면에서 쓰는 컴포넌트는 각 앱의 `components/`에 둔다. React 컴포넌트를 CLI TUI와 공유하지 않으며, 데이터 타입·가림·집계 함수만 공유한다. 브라우저 번들에 GitHub 토큰, Node 파일 API, 검사 엔진을 포함하지 않는다.

## 3. 코드 검사의 용어

- **SQL 어댑터:** `pg`, Prisma, GORM처럼 서로 다른 SQL 라이브러리의 쿼리 호출법을 알아보는 검사 모듈이다. DB 연결 기능이 아니다.
- **AST(추상 구문 트리):** 코드를 글자 검색보다 구조적으로 읽어 변수·함수 호출·문자열 결합을 파악한 형태다.
- **데이터 흐름 분석:** 사용자 입력이 검증·매개변수 바인딩을 거쳤는지 보며 SQL 실행 함수까지 이동하는 경로를 추적한다. 예를 들어 요청값을 SQL 문자열에 그대로 결합하면 검토 대상으로 잡고, 근거가 부족하면 확정 대신 `의심` 또는 `미검사`로 표시한다.

첫 SQL 라이브러리 후보는 `pg`, `mysql2`, Prisma raw query, Go `database/sql`, GORM이다. 이 목록은 추천안이며 미지원 ORM을 안전하다고 판정하지 않는다.
