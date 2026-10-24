# ===== 한국어 =====

## 설치와 빌드

요구 사항: Node.js 22.12 이상, Git.

```sh
git clone https://github.com/JadenMeister/pgard.git
cd pgard
npm ci
npm run build          # TypeScript + 대시보드 UI(Vite)
npm link -w @pgard/cli # 선택: PATH에 `pgard` 등록
```

`npm link` 없이 실행하려면 `node apps/cli/dist/bin/pgard.js <명령>`을 사용합니다.

PGARD는 등록된 PGARD GitHub App으로 GitHub 신원을 확인합니다. 검사 전에 client id를 설정하세요.

```sh
export PGARD_GITHUB_APP_CLIENT_ID=<PGARD GitHub App의 client id>
```

> 제한(#42): 아직 공개 PGARD GitHub App이 등록되지 않았습니다. 설정되기 전까지 GitHub 신원 확인은 "확인 불가"이며 **모든 검사가 차단**됩니다(종료 코드 3). `pgard doctor`가 이를 알려 줍니다.

## 명령

검사 대상은 항상 **현재 디렉터리의 Git 루트**입니다. 모든 검사는 권한 게이트(owner 승인 + 현재 접근 권한 + 실제 반영된 기여)를 매번 다시 통과해야 하며, 앞선 `project verify` 결과를 재사용하지 않습니다.

| 명령                                                     | 역할                                                                                                                                     |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `pgard`                                                  | 방향키 메인 메뉴(확인, 검사, 대시보드, 규칙, 진단, 종료)                                                                                 |
| `pgard project verify`                                   | 권한 게이트를 실행하고 항목별(저장소, GitHub 신원, owner 승인, 현재 접근, 기여) 통과/실패/확인 불가와 이유 표시                          |
| `pgard scan`                                             | 코드·설정·의존성 + Git 이력                                                                                                              |
| `pgard scan code`                                        | 현재 코드·설정·의존성                                                                                                                    |
| `pgard scan history`                                     | Git 이력과 추적 파일(비밀정보, 위험 파일)                                                                                                |
| `pgard scan web [--port N]`                              | 사용자가 확인한 로컬 HTTP 서비스의 비로그인·읽기 전용 검사                                                                               |
| `pgard scan all [--port N]`                              | code + history + web                                                                                                                     |
| `pgard dashboard [--target-port N]`                      | 로컬 웹 대시보드 시작                                                                                                                    |
| `pgard rules list [--language js\|ts\|react\|vue\|go]`   | 지원 규칙, 판정 기준·취약점 데이터 버전, 미지원 범위(프로젝트 밖에서도 실행)                                                             |
| `pgard doctor`                                           | Node.js, Git, GitHub 연결, 포트 탐지, `PGARD_GITHUB_APP_CLIENT_ID`, advisory DB 진단. 진단일 뿐 권한 승인이 아님(프로젝트 밖에서도 실행) |
| `pgard --help`, `pgard <명령> --help`, `pgard --version` | 사용법·버전                                                                                                                              |

옵션:

- `--port N`(`scan web`/`scan all` 전용): 로컬 서비스 포트, 1~65535 정수. 지정해도 `y` 확인이 필요합니다.
- `--target-port N`(`dashboard` 전용): 대시보드에서 검사할 서비스를 미리 선택(대시보드에서 다시 확인). 대시보드 자체는 별도의 빈 포트를 사용합니다.
- `--report html|pdf|both --output-dir <경로>`(모든 `scan`): 반드시 함께 사용합니다. 디렉터리는 이미 존재해야 하며 기존 파일을 덮어쓰지 않습니다. Git 저장소 안의 경로는 명시적 `y`가 필요합니다(터미널이 없으면 거부). 기본은 터미널 결과만 표시합니다.
- 알 수 없는 명령·옵션, 잘못된 값과 조합은 Git·GitHub·네트워크 작업 **전에** 거부됩니다. `--path`, `--host`, `--url`, `--force`, `--skip-auth`는 없습니다.

종료 코드:

| 코드 | 의미                                                                   |
| ---- | ---------------------------------------------------------------------- |
| 0    | 요청 범위 완료(발견 항목이 있어도), `doctor`는 진단 완료               |
| 2    | 잘못된 명령·옵션·값·조합                                               |
| 3    | 저장소/권한/기여 게이트 실패(또는 Git 저장소 밖)                       |
| 4    | 일부 검사 미실행(예: 웹 대상 미확인 ⇒ 부분 완료) 또는 보고서 저장 실패 |
| 5    | 내부 오류(세부 내용 숨김, `PGARD_DEBUG=1`이면 정리된 메시지 표시)      |
| 130  | 사용자 취소                                                            |

## 대화형 키

방향키(또는 j/k) 이동, Enter 선택, Esc 이전 단계(메뉴 안의 하위 단계에서 Esc는 메뉴로 복귀), `?` 도움말, Ctrl+C는 "Cancel and exit? [y/N]" 확인. 검사나 GitHub 로그인이 진행 중일 때는 5초 안에 Ctrl+C를 두 번 누르면 취소됩니다(종료 코드 130). 검사 중 미리 입력한 키는 다음 질문에 답하지 않도록 버립니다.

## GitHub 로그인

필요할 때 GitHub device flow 주소(`https://github.com/login/device`)와 짧은 사용자 코드를 보여 줍니다. 액세스 토큰은 현재 프로세스의 메모리에만 있고 화면·로그·파일에 남기지 않습니다.

## 로컬 웹 대상 확인

`scan web`, `scan all`, 대시보드 공통:

1. 포트에 접근하기 전에 권한을 먼저 확인합니다.
2. `127.0.0.1`에서 HTTP로 응답하는 열린 포트를 보여 줍니다(macOS는 `lsof`, Linux는 `/proc/net/tcp*`). 목록은 불완전할 수 있으므로 **Other port**를 항상 제공합니다. 포트 번호만으로 어떤 프로젝트인지 알 수 없습니다.
3. 서비스 정보를 보여 줍니다: URL, HTTP 상태, `<title>`, 추정 기술(헤더·마크업 기반 추정이며 검증 아님).
4. **"Is this the current project's service? [y/N]"**에 답합니다. 명시적 `y`만 확인으로 인정하고, Enter·`n`·Esc는 아니오입니다(다른 포트 선택 또는 웹 검사 없이 계속). `--port`도 이 확인을 거칩니다.
5. 대화형 터미널이 없으면 대상을 확인할 수 없어 웹은 **not tested**, 검사는 **partial**(종료 코드 4)로 기록됩니다.

웹 검사는 `127.0.0.1:<포트>`에만 비로그인 GET/HEAD 요청을 보냅니다. 같은 loopback origin 안의 리다이렉트만 따라가고, 로그아웃·삭제·초기화처럼 보이는 링크는 건너뜁니다. 한도는 20페이지, 깊이 2, 요청당 5초, 전체 60초, 본문 1MB이며 쿼리 문자열은 결과에 남기지 않습니다. 검사 항목: 보안 헤더(CSP, 프레임 보호, nosniff, Referrer-Policy; HSTS는 평문 http loopback에서 해당 없음), 쿠키 속성, 자격 증명과 함께 쓰인 CORS 와일드카드/반사, 서버 버전 노출, 디렉터리 목록, `/.env`·`/.git/HEAD` 노출(존재 여부만, 값은 저장 안 함). 헤더 하나가 없다는 사실은 정보성 항목이며 취약점의 증거가 아닙니다. 잘못 구현된 앱에서는 GET도 상태를 바꿀 수 있으므로 무변경을 보장하지 않습니다.

## 결과와 보고서

터미널 결과는 심각도 막대 차트, 확정/의심/정보 항목과 `파일:줄` 또는 URL, 가려진 근거와 가이드, coverage(`completed`, `partial`, `not_tested`, `not_selected`)를 보여 줍니다. "발견 없음"을 "안전"으로 표시하지 않습니다.

HTML·PDF 보고서는 같은 가려진 결과에서 만듭니다. HTML은 단일 파일(스크립트 없음, 엄격한 CSP, 모든 값 이스케이프)입니다. 파일은 사용자가 지정한 디렉터리에만 배타적 생성(덮어쓰기 없음, 권한 0600)으로 저장됩니다. 보고서는 저장소 밖에 보관하세요.

> 제한(#44): PDF는 내장 라틴 글꼴을 사용하므로 한국어 등 비라틴 문자는 `?`로 바뀌며 PDF에 그 사실이 표시됩니다. 전체 텍스트는 HTML 보고서를 사용하세요.

## 대시보드(`pgard dashboard`)

`pgard dashboard`는 터미널에서 프로젝트(현재 디렉터리의 Git 루트)를 확인한 뒤 로컬 웹 앱을 시작하고 개인 세션 URL을 출력합니다.

```
PGARD dashboard is running on 127.0.0.1 only.
Open this private session URL in your browser (valid until you stop the dashboard): http://127.0.0.1:<port>/#token=<random>
```

대시보드는 CLI 결과를 읽지 않고 직접 검사합니다: 항목별 이유와 GitHub device 코드가 있는 권한 상태, 서비스 정보 확인과 명시적 확인을 거치는 로컬 서비스 선택, 범위 선택·진행·취소·coverage, 심각도 막대·도넛 차트와 필터가 있는 발견 항목, HTML/PDF 내보내기(존재하는 절대 경로, 저장소 내부 경고·확인, 덮어쓰기 없음). Ctrl+C로 종료하면 GitHub 세션을 로그아웃하고 모든 결과를 폐기합니다.

보안 모델:

- `127.0.0.1`의 빈 포트에만 바인딩합니다.
- 32바이트 임의 세션 토큰은 URL **fragment**로 전달되어 요청·Referer에 실리지 않습니다. 페이지는 주소창에서 토큰을 지우고 메모리에만 보관합니다. URL을 공유하지 마세요.
- 모든 API 호출은 사용자 정의 헤더(`x-pgard-token`)의 토큰이 필요하며 이것이 CSRF도 막습니다. 정확한 `Host: 127.0.0.1:<port>`가 필요하고(DNS rebinding 방어), 다른 `Origin`·cross-site 요청은 거부하며, CORS 헤더는 보내지 않습니다.
- 모든 응답에 `Cache-Control: no-store`, 엄격한 Content-Security-Policy(인라인 스크립트 없음), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`를 적용합니다.
- 브라우저는 파일·폴더를 고를 수 없습니다. 프로젝트 루트는 런처가 고정하고, 파일 읽기 API가 없으며, 빌드된 UI 파일만 제공합니다. 브라우저는 가려진 발견 항목만 받으며 소스 코드, GitHub 토큰, 검사 엔진은 받지 않습니다.

개인정보 안내(대시보드에서 처음 한 번 표시): 검사 데이터는 사용자 컴퓨터에서 일회성으로 처리됩니다. PGARD는 로그인과 저장소 메타데이터 조회를 위해 GitHub에 접속하고, 사용자가 시작한 advisory 업데이트에 네트워크를 사용합니다. 결과·토큰·로그인은 종료 시 폐기되고, 사용자가 내보낸 보고서만 남으며 그 관리 책임은 사용자에게 있습니다. 일부 앱에서는 GET 요청도 부작용이 있을 수 있습니다.

## 제한 사항

- #42 PGARD GitHub App 미등록 ⇒ GitHub 신원 확인 불가, 모든 검사 차단.
- #45 이번 MVP는 로그인 후 탐색을 지원하지 않으며 `web:authenticated`는 항상 `not_selected`입니다. PGARD는 앱 비밀번호를 묻지 않습니다.
- #44 PDF 보고서는 비라틴 문자를 대체합니다. 전체 텍스트는 HTML을 사용하세요.
- 포트 탐지는 불완전하거나 사용할 수 없을 수 있습니다(예: `lsof`가 멈추면 5초 후 포기). 포트를 직접 입력하세요.
- 범위 밖: DB 직접 접속, Docker, 성능 검사, 원격(loopback 외) 서비스, 폼 제출·상태 변경 요청.
