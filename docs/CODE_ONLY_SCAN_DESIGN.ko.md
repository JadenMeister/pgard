# 보안 설계: GitHub 승인 없는 코드 전용 검사와 한 화면 웹 흐름

> **참고:** 이 문서는 [`CODE_ONLY_SCAN_DESIGN.md`](CODE_ONLY_SCAN_DESIGN.md)(영문)의 한국어 번역입니다. 기준 문서는 영문판이며, 내용이 다르면 영문판이 맞습니다. 프로젝트 [README](../README.ko.md)([English](../README.md))와 [문서 목록](README.ko.md)도 참고하세요.

> **상태: 2026-10-29 소유자가 승인했습니다([#414](https://github.com/JadenMeister/pgard/issues/414), [#419](https://github.com/JadenMeister/pgard/issues/419)).** 단계별로 배포합니다(9절).
>
> - **1단계인 결과 표시가 들어갔습니다.** JSON 1.7 `scanBasis`, SARIF, 보고서 배너, 코드 전용 비밀값 문구입니다. CLI는 2단계까지 바뀌지 않으며, `PGARD_WEB_PROTOTYPE=code-only`를 설정하지 않으면 `pgard web`도 바뀌지 않습니다(4단계에서 프로토타입을 대체합니다). 현재 동작의 기준은 README입니다.
> - **결정 사항**은 **[Owner decision Dn]**으로 표시했으며, 모두 2026-10-29 권장안대로 결정되었습니다(11절).

[README](../README.ko.md)와 [문서 목록](README.ko.md)으로 돌아가기.

## 1. 왜 바꾸는가

지금 PGARD는 다섯 가지 권한 확인을 모두 통과해야 분석을 시작합니다(README, [권한 확인 모델](../README.ko.md#권한-확인-모델)). 2026-10-29에 소유자가 준 피드백은 다음과 같았습니다.

- 웹 버전에 탭과 패널이 너무 많다.
- 사용법이 분명하지 않다.
- GitHub App에 너무 많이 의존한다.

소유자가 원한 것: 폴더를 고르면, GitHub App이 설치되어 있지 않아도 Git 기록 없이 취약점을 찾는 것.

소유자는 다음 정책을 정했습니다.

| 영역                                                                | 승인 없음                              | 승인 있음 (다섯 확인 모두 통과) |
| ------------------------------------------------------------------- | -------------------------------------- | ------------------------------- |
| 디스크의 현재 파일: 소스 규칙, 파일 속 비밀값, 의존성(오프라인 OSV) | **실행**, "권한 미확인"으로 표시       | 실행 (현재 동작)                |
| Git 기록 (커밋, Git 객체에서 읽는 추적 파일)                        | 막힘                                   | 실행                            |
| 로컬 웹 서비스 검사 (`scan web`)                                    | 막힘                                   | 실행                            |
| 결과 저장 (추이, 기준선, `report`, 증분 상태)                       | 막힘: 코드 전용 결과는 절대 저장 안 함 | 실행                            |

## 2. 코드 전용 검사란

### 2.1 무엇을 읽는가

- **이 컴퓨터에서 고른 폴더의 파일.** 로컬 린터가 읽는 방식 그대로, 사용자 본인의 파일 권한으로 읽습니다.
- 사용자가 이미 편집기로 열 수 있는 것만 읽습니다.
- 현재 `code` 범위와 같은 소스 규칙을 실행합니다(JavaScript, TypeScript, Vue, Go, Java, Kotlin, Python, PHP).
- **이미 디스크에 있는 OSV 데이터**(`pgard advisories update`)로 의존성을 확인합니다. 검사 중에는 내려받지 않습니다.
- **디스크의 파일에 대한 새 비밀값 검사**(`secrets:working-tree`, 2.3절)를 실행합니다.

### 2.2 절대 하지 않는 것

- **Git 객체를 읽지 않습니다.** 커밋, 추적 파일 blob, 인덱스 모두 읽지 않습니다. `.git`이 없어도 되고, 폴더의 기록에 `git`을 실행하지도 않습니다.
- **네트워크 연결을 만들지 않습니다.**
  - GitHub API 호출, 로그인, 디바이스 플로, 검사 자체를 위한 키체인 읽기가 없습니다.
  - 대상에 아무것도 보내지 않고, 로컬 포트도 탐색하지 않습니다.
  - 외부 데이터는 이미 디스크에 있는 OSV 데이터뿐입니다.
- **아무것도 저장하지 않습니다.** 저장소에 결과를 넣지 않고, 증분 상태도, 추이도 없으며, 폴더 선택기가 이미 보관하는 것 외에 최근 항목도 남기지 않습니다.
- 프로젝트의 **아무것도 실행하지 않습니다**(기존 규칙 그대로, 분석기는 읽기 전용입니다).
- 스스로 권한이 확인된 결과로 **올라가지 않으며**, 이전의 권한 확인을 재사용하지도 않습니다.

### 2.3 현재 파일 속 비밀값: 새로운 영역

지금 비밀값 규칙(`PG-SECRET-001` `.env` 파일, `PG-SECRET-002` 자격 증명)은 **기록 범위에서만** 실행됩니다. 이 범위는 Git 객체에서 추적 파일과 커밋을 읽습니다. 그래서 코드 전용 검사에는 별도의 검사 단계가 필요합니다.

- 프로토타입은 `scanWorkingTreeSecrets`를 추가합니다(`packages/scan-core/src/working-tree-secrets.ts`).
  - `pgard precommit`과 같은 탐지를 씁니다(`scanStagedSecrets`, 모든 줄을 새 줄로 간주).
  - 심볼릭 링크를 따라가지 않습니다.
  - `.git`과 `node_modules`는 건너뜁니다.
  - 1 MiB까지의 파일을 읽고, 바이너리 파일은 건너뜁니다.
  - 파일 수와 깊이에 한도가 있으며, 한도에 닿으면 해당 영역은 `partial`이 됩니다.
  - 발견 항목에 값을 넣지 않습니다.
- **제품화 후속 작업:** 규칙 제목이 "추적 파일 속 비밀값"과 "Git에 커밋된 환경 파일"입니다. 코드 전용 발견 항목에는 맞지 않습니다. 제품 버전에는 코드 전용 문구가 필요하며, 새 규칙 ID 두 개나 제목 변형으로 해결합니다. 프로토타입 스크린샷에는 예전 제목이 보입니다.

## 3. 위협 모델

### 3.1 자산과 행위자

- **자산.**
  - 다른 사람의 비공개 코드와 비밀값.
  - 실행 중인 서비스. 접근 가능한 포트에 있는 남의 웹 앱도 포함합니다.
  - PGARD 결과의 신뢰성("PGARD가 이 저장소는 깨끗하다고 했고, 나는 검사해도 되는 사람이었다").
- **행위자.**
  - 정직한 소유자나 기여자(흔한 경우).
  - 권리 없는 코드 사본을 가진 사람.
  - PGARD 결과를 권한 있는 감사처럼 보이게 하려는 사람.

### 3.2 `.git`, remote, 로그인에 기대는 규칙이 여기서 아무것도 지키지 못하는 이유

소유자는 처음에 "`.git` 폴더가 있으면 먼저 GitHub 로그인을 요구한다"를 생각했습니다. 그 뒤 소유자가 결함을 발견했습니다. **이 설계는 그 변형을 채택하지 않습니다(3.5절).** 일반적으로 다음과 같습니다.

- **`.git`, remote, GitHub 로그인에 거는 조건은 몇 초 만에 우회됩니다.**
  - 코드를 zip으로 내려받으면 `.git`이 없습니다.
  - `.git`을 지우거나 remote를 지우거나 바꿉니다.
  - 파일을 다른 폴더로 복사합니다.
  - 코드는 같고, PGARD가 확인할 수 있던 메타데이터만 사라집니다.
- **그래서 그런 규칙은 정직한 사용자만 벌줍니다.** 예를 들어 App 설치가 보류 중인 사람은 검사를 받으려고 `.git`을 지워야 하는데, 막아야 할 사람은 막히지 않습니다.

### 3.3 로컬 파일의 코드 전용 검사를 허용해도 되는 이유

- **공개된 도구 이상의 것을 공격자에게 주지 않습니다.**
  - 이미 가진 파일의 정적 분석은 `grep`, ESLint, semgrep, gitleaks, trufflehog(파일 시스템 모드), trivy(파일 시스템 모드), CodeQL CLI가 하는 일입니다.
  - 이 도구들은 어느 것도 허락을 구하지 않으며, PGARD의 규칙은 README와 `rules list`에 공개되어 있습니다.
  - PGARD 코드 전용 검사는 로컬 린터와 같습니다.
- **다른 사람의 시스템이나 계정 데이터에 닿지 않습니다.**
  - 사용자가 이미 읽을 수 있는 바이트를 읽고, 어디로도 보내지 않습니다.
  - 누군가 훔친 코드를 가지고 있다면, 피해(보유하고 읽는 것)는 이미 일어난 것입니다. 린터를 돌린다고 새로운 접근이 생기지 않습니다.
- **비밀값 검사는 디스크에 있는 것만 읽습니다.**
  - `grep -r AKIA`가 찾는 문자열과 같은 것을 찾습니다.
  - 비밀값 자체는 보여 주지 않습니다. 발견 항목에는 가린 설명과 위치만 담깁니다.

### 3.4 계속 막아 두는 것과 그 이유

권한 확인은 **사용자 눈앞의 파일을 넘어서는** 동작이나 **저장소에 대해 주장을 하는** 동작을 위해 있습니다.

- **Git 기록.**
  - 기록에는 더 이상 보이지 않는 것이 있습니다. 삭제된 비밀값, 오래된 커밋, 다른 사람의 작업입니다.
  - 기록을 검사하는 것은 "저장소를 파헤치는" 일이므로 소유자 승인이 있어야 합니다.
  - 지금도 GitHub에서 확인된 저장소가 필요합니다. 분석 대상이 권한 있는 저장소와 이어지게 하기 위해서입니다.
  - 바뀌지 않습니다.
- **로컬 웹 서비스 검사.**
  - 실행 중인 서비스에 HTTP 요청을 보냅니다.
  - 사용자의 것이 아닐 수도 있는 실제 시스템에 행동하는 일입니다.
  - 바뀌지 않습니다. 권한 확인과, 사용자가 확인한 `127.0.0.1` 대상이 필요합니다.
- **결과 저장**, 그리고 그 위에 만들어진 모든 것(추이, 기준선, `pgard report`, 증분 재사용).
  - 저장된 결과의 키는 GitHub의 숫자 저장소 ID이며, 이는 권한 확인만이 증명합니다.
  - 권한 없는 결과를 저장하면 나중에 감사를 거친 결과로 오해할 수 있고, 서로 다른 코드의 결과가 한 키에 섞입니다.
  - 코드 전용 결과는 절대 저장하지 않습니다(서버와 CLI가 거부하고, 결과 저장소도 이중 방어로 `code_only`로 표시된 결과를 거부합니다).

### 3.5 채택하지 않은 대안

| 대안                                                   | 채택하지 않은 이유                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "`.git`이 있으면 먼저 GitHub 로그인을 요구"            | zip 내려받기나 `rm -rf .git`으로 우회됩니다(3.2절). 정직한 사용자에게만 네트워크 의존과 로그인을 더하고, 아무도 막지 못합니다.                                                                                                                                                                            |
| "GitHub remote가 없는 폴더만 코드 전용"                | 같은 방식으로 우회됩니다. 소유자가 말한 주된 경우, 곧 아직 App을 설치하지 않은 GitHub 저장소도 벌줍니다.                                                                                                                                                                                                  |
| "코드 전용은 소유자 승인 없이 로그인만 요구"           | 로그인은 신원을 증명할 뿐, 이 코드에 대한 권리를 증명하지 않습니다. 디바이스 플로와 네트워크 접근만 늘고 공격자가 할 수 있는 일은 그대로입니다.                                                                                                                                                           |
| "전부 막아 두기" (현재)                                | 소유자가 거부했습니다. 가장 단순하고 안전한 사용을 막기 때문입니다.                                                                                                                                                                                                                                       |
| "먼저 권한 확인을 하고, 막히면 코드 전용으로 되돌리기" | 코드 전용 검사가 느려지고 온라인이 됩니다(GitHub 호출, 최대 15초 제한). 로그인도 시작됩니다. 권한 확인은 사용자가 권한 있는 검사를 요청한 곳(`scan history`, `scan web`, `scan all`, `--require-authorization`, 전체 대시보드)에서만 실행되고, 거기서 막히면 알려 줄 뿐 코드 전용 결과로 바꾸지 않습니다. |

**권장안: 코드 전용 검사는 `.git`, remote, 로그인이 있든 없든 모든 로컬 폴더에서 동작합니다.** 강한 반론은 찾지 못했습니다.

### 3.6 남는 위험과 알맞은 완화책

| 남는 위험                                                                      | 완화책 (정직한 사용자에게 부담을 주는 것은 없음)                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 코드 전용 결과를 권한 있는 감사("PGARD 확인됨")처럼 내보임.                    | **어디서나 분명하게 표시**: UI 배지, 터미널 줄, JSON/SARIF 필드(4절), 모든 보고서 페이지의 배너. 코드 전용 결과에는 **"확인됨" 문구나 배지가 절대 나오지 않습니다.** `authorization.decision`은 `allowed`가 되지 않습니다.                                                                                                                                                                          |
| 권한 없는 결과가 권한 있는 결과 옆에 쌓임.                                     | 코드 전용 결과는 **저장하지 않으며**(3.4절) 저장소가 거부합니다.                                                                                                                                                                                                                                                                                                                                    |
| 래퍼나 CI 단계가 코드 전용 실행의 종료 코드 0을 "권한 있고 깨끗함"으로 취급함. | JSON과 SARIF의 `scanBasis.authorization: "not_verified"`, 그리고 종료 코드 3을 되살리는 `--require-authorization`(5절).                                                                                                                                                                                                                                                                             |
| 권리 없는 코드를 검사함.                                                       | 받아들입니다. 사용자가 이미 가진 파일에 무료 린터를 돌리는 것과 같고(3.3절), PGARD가 접근을 더하지 않습니다. 처음 사용할 때의 법적 고지가 이미 허용된 것만 검사하라고 안내합니다.                                                                                                                                                                                                                   |
| 디스크에서 찾은 비밀값이 화면에 보임.                                          | 기존 규칙 그대로입니다. 값은 절대 보여 주지 않고 종류와 위치만 보여 줍니다.                                                                                                                                                                                                                                                                                                                         |
| 악의적인 폴더(거대한 트리, 심볼릭 링크 순환, 거대한 파일)가 검사를 느리게 함.  | `code` 범위와 같은 한도에 비밀값 검사 한도(2.3절)를 더합니다. 이 단계는 링크를 따라가지 않습니다. 한도에 닿으면 해당 영역은 `partial`이 되며 "깨끗함"이 되지 않습니다.                                                                                                                                                                                                                              |
| 웹 서버가 임의의 폴더를 읽는 통로가 됨.                                        | 폴더는 토큰으로 보호된 페이지에서 사용자가 OS 폴더 선택 창으로 고르거나 붙여 넣습니다. 서버는 inspector 자식 프로세스에서 realpath로 풀고 폴더 체인 전체의 소유권과 쓰기 비트를 확인합니다. 홈 폴더, 그 상위 폴더, 최상위 폴더는 거부합니다. 검사는 검사 전마다 다시 실행하고, 발견 항목은 가려지며 경로는 저장소 기준 상대 경로입니다. 토큰, Host, Origin 검사가 있고 `127.0.0.1`만 씁니다(6.1절). |

## 4. 결과 표시 방식

### 4.1 JSON 결과: `schemaVersion` 1.7 (마이너 올림)

최상위에 선택 필드 `scanBasis`를 새로 둡니다.

```json
"scanBasis": {
  "mode": "code_only",
  "authorization": "not_verified",
  "reason": "no_approval"
}
```

- **`mode`.**
  - `"authorized"`: 권한 확인을 실행했습니다(`authorization`이 통과 여부를 알려 줍니다. `verified`, 또는 `reason: "no_approval"`과 함께 `not_verified`).
  - `"code_only"`: 권한 확인을 하지 않았습니다.
  - 1.6 이하의 결과에는 이 필드가 없으며, 읽는 쪽은 없으면 `"authorized"`로 봅니다. 이전 PGARD는 권한 확인을 통과한 뒤에만 결과를 썼기 때문입니다.
- **`authorization`.** `"verified"` 또는 `"not_verified"`. 조정자(coordinator)의 `authorization: "not_verified"`입니다. 기존 `authorization` 객체의 타입을 바꾸면 메이저 변경이 되므로 새 객체에 둡니다.
- **`reason`.** `authorization`이 `verified`일 때만 `null`이며, 그 밖에는 열려 있는 코드 값입니다.
  - `no_approval` (권한 확인을 통과하지 못함),
  - `not_checked` (사용자가 코드 전용을 요청함),
  - `no_github_remote`,
  - `not_a_git_repository`,
  - `offline`.
- **닫힌 enum에 값을 추가하지 않습니다.**
  - `authorization.decision`은 `blocked`로 남습니다. 권한 확인이 이 검사를 허용하지 않았으므로 사실과 맞습니다.
  - 모든 확인은 `unverifiable`이며, 이유는 고정 문구 "Not checked: this was a code-only scan of the files on this computer. No authorization was proven."입니다.
  - `requestedScopes`는 `["code"]`입니다.
- **`overallStatus`.**
  - 코드 범위의 결과만으로 정해지며(`completed`, `partial`, `failed`), 분석이 실제로 실행되었으므로 `blocked`가 되지 않습니다.
  - 이전 버전의 읽는 쪽은 `decision: "blocked"`를 보고 안전한 쪽으로 처리합니다. `decision === "allowed"`를 확인하는 코드는 이 결과를 권한 있는 것으로 보지 않습니다.
  - `overallStatus`를 "분석이 실행되었는가"의 뜻으로 쓰는 이전 버전의 읽는 쪽도 계속 올바르게 동작합니다.
- **버전 기록 노트**(`RESULT_SCHEMA.md`)에 필드 간 규칙을 적습니다. 1.7에서 `decision: "blocked"`이면서 상태가 `blocked`가 아니면 `code_only`라는 뜻입니다.

### 4.2 SARIF

- `runs[0].properties.pgard.scanBasis`에 같은 객체를 담습니다.
- `runs[0].invocations[0].toolExecutionNotifications[]`에 `warning` 하나를 담습니다. "Code-only scan: authorization was not verified. Git history and web checks did not run."
- 알림을 보여 주는 업로더(GitHub code scanning 등)는 결과 옆에 이를 표시합니다.

### 4.3 텍스트, 보고서, 대시보드

- **터미널.** 결과의 첫 줄은 `! Code-only scan: authorization not verified (current files only; no Git history, no web checks, not saved).`이고, 이어서 권한 있는 검사를 받는 방법을 한 줄로 안내합니다.
- **HTML과 PDF 보고서.** 모든 페이지에 배너가 있고, 표지에 "Not authorized: code-only scan"이 적힙니다. "확인됨" 문구는 없습니다. 1단계에 구현되었습니다(`packages/report/src/code-only-text.ts`). HTML 배너는 인쇄한 모든 페이지에 반복되고(`@media print`의 고정 요소), PDF 배너는 모든 페이지에 그려지며, 이유(`scanBasis.reason`)가 담긴 표지 블록이 있습니다.
- **웹.**
  - 결과 카드는 항상 **"Not authorized · code only" / "권한 미확인 · 코드만"** 라벨과 짧은 설명으로 시작합니다.
  - 결과가 화면에 있는 동안 라벨은 닫을 수 없습니다.
  - 스크린샷: `*-6-not-authorized-label.png`.

## 5. CLI 동작

**[Owner decision D1] 승인 없이 `pgard scan`이 하는 일.**

**결정(2026-10-29):** `code` 범위는 기본적으로 코드 전용으로 실행하고 분명한 안내를 붙입니다. 엄격 모드는 직접 선택합니다. "그냥 동작"하면서도 증명했다는 인상을 주지 않습니다.

| 명령                                      | 현재                                     | 제안                                                                                                                                                                                                                                                                                                                            |
| ----------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pgard scan code`                         | 권한 확인, 막히면 종료 코드 3, 분석 없음 | 어떤 폴더에서든 **코드 전용으로 실행**(Git도 GitHub도 필요 없음), 로그인하지 않고, 코드 전용 줄을 출력. 종료 코드 0 / 4는 코드 범위 결과에서 나옵니다. 권한 있는 코드 검사는 `--require-authorization`으로 요청합니다(다음 행).                                                                                                 |
| `pgard scan code --require-authorization` | 해당 없음                                | 현재 동작: 먼저 권한 확인을 실행하고, 허용되면 권한 있는 검사(현재처럼 저장), 막히면 종료 코드 3과 분석 없음. 증명이 필요한 사람과 래퍼를 위한 것입니다.                                                                                                                                                                        |
| `pgard scan history`, `scan web`          | 권한 확인                                | **바뀌지 않음**(막히면 종료 코드 3). 막힘 메시지에 한 줄 추가: "`pgard scan code` checks the current files without approval."                                                                                                                                                                                                   |
| `pgard scan all`                          | 권한 확인                                | **[Owner decision D2]** 결정(2026-10-29): **바뀌지 않음**(권한 확인, 막히면 종료 코드 3, 같은 안내 추가). 대안: `code`는 코드 전용으로 실행하고 `history`와 `web`은 `not_tested`("needs owner approval")로 표시, 종료 코드 4. 앞의 안은 "all"의 의미를 정직하게 지키고, 뒤의 안은 더 친절하지만 막힘을 부분 결과 뒤에 숨깁니다. |
| 대화형 메뉴 (`pgard`)                     | 안내형 로그인과 App 설치                 | 첫 선택지가 "Scan the current files (code only)"가 됩니다. 로그인과 App 설치는 그 뒤에 "Also scan Git history"로 안내합니다.                                                                                                                                                                                                    |
| `pgard project verify`                    | 권한 확인만                              | 바뀌지 않음. 막힐 때 한 줄 추가: "Without approval, `pgard scan code` runs a code-only scan of the current files."                                                                                                                                                                                                              |
| `pgard doctor`                            | —                                        | `[info]` 행 하나: "Scans without owner approval run code-only (current files, not saved)."                                                                                                                                                                                                                                      |
| `pgard report`, `baseline`, `sbom`, 추이  | 막힘                                     | **바뀌지 않음**(저장된 결과를 읽거나 저장소에 대해 주장하기 때문). `sbom`은 코드 전용 의존성 확인처럼 잠금 파일만 읽으므로 나중에 같은 규칙을 따를 수 있습니다. 이번 범위 밖입니다.                                                                                                                                             |

- **종료 코드.** 새 코드는 없습니다.
  - 코드 전용 검사는 다른 검사처럼 0(완료, 발견 항목이 있을 수 있음) 또는 4(부분)로 끝납니다.
  - 종료 코드 3은 계속 "권한 확인에서 막힘"이며, 사용자가 권한 확인을 요청했을 때(`--require-authorization`, `history`, `web`, `all`)만 나타납니다.
- **`--format json|sarif`.** `scanBasis`가 담긴 코드 전용 결과를 출력합니다(4절). 표준 출력에는 여전히 문서 하나만 나옵니다.
- **플래그.** 새 플래그는 `--require-authorization` 하나입니다(`code`만 해당, 다른 범위는 항상 요구함). 코드 전용이 `code`의 기본값이므로 `--code-only`는 필요 없습니다.

### 5.1 `pgard precommit` (M10-1, #408)

- `pgard precommit`은 **스테이징된 변경만** 검사하며 기록은 절대 보지 않습니다.
- 이미 인덱스만 읽습니다. 인덱스에는 사용자가 곧 커밋할 본인의 내용이 들어 있습니다.
- 지금은 전체 권한 확인을 실행하므로, 저장된 로그인이 없으면 "권한 확인이 막고 아무것도 검사하지 않습니다"(README).

**[Owner decision D3] 결정(2026-10-29): `pgard precommit`은 항상 코드 전용으로, 권한 확인과 네트워크 없이 실행합니다.**

- **이유.**
  - 스테이징된 내용은 커밋하는 사람 본인의 변경입니다. 같은 바이트가 디스크에 있고 어떤 훅이든 `grep`으로 볼 수 있으므로, 권한 확인은 보호를 더하지 않습니다.
  - 권한 확인은 커밋마다 최대 15초가 들고(`PGARD_PRECOMMIT_TIMEOUT_MS`) 오프라인에서는 실패합니다. GitHub 로그인이 없다는 이유로 커밋을 막는 보안 훅은 소유자가 반대한 바로 그 App 의존입니다.
  - 인덱스를 읽는 것은 precommit 검사 자신의 입력이며, 권한 확인이 막는 뜻의 "Git 기록"이 아닙니다. 비교용인 HEAD의 blob 외에 다른 커밋은 읽지 않습니다.
- **표시.** 요약 줄에 `code-only: authorization not verified`가 나옵니다. 종료 코드는 그대로이며, "권한 없음"이 더는 일어나지 않으므로 precommit에서 종료 코드 3만 사라집니다.
- **대안.**
  - (b) 저장된 로그인이 있을 때만 권한 확인을 하고 없으면 코드 전용으로 되돌립니다. 더 느리고 보호는 같습니다.
  - (c) 바꾸지 않고 엄격하게 유지합니다.
  - 저장소는 `"precommit": { "requireAuthorization": true }`로 엄격 모드를 직접 선택할 수 있습니다. 설정은 검사를 더 엄격하게만 만들므로, 신뢰할 수 없는 저장소에서 읽어도 안전합니다.

## 6. GitHub remote가 없는 경우와 Git이 없는 경우

**[Owner decision D4] 결정(2026-10-29): 둘 다 코드 전용 검사를 받습니다.** 소유자의 의도와 3.2절에 맞습니다. 권한 확인의 증거는 없지만, 코드 전용 검사에는 그 증거가 필요 없습니다.

| 폴더                                                                   | 코드 전용 검사                        | 막힌 부분                                                           |
| ---------------------------------------------------------------------- | ------------------------------------- | ------------------------------------------------------------------- |
| GitHub remote 있음, App 미설치 또는 승인 없음                          | 가능                                  | 안내: "Connect GitHub to also scan Git history"                     |
| GitHub remote 있음, 승인됨                                             | 가능 (선택하면 권한 있는 검사)        | 사용 가능                                                           |
| Git 저장소, remote 없음 또는 GitHub가 아닌 remote(GitLab, 자체 호스팅) | 가능 (`reason: no_github_remote`)     | 사용 불가. 이유를 알려 줍니다. 소유자 승인은 GitHub로만 증명됩니다. |
| Git 저장소가 아님 (zip 내려받기, 새 폴더)                              | 가능 (`reason: not_a_git_repository`) | 사용 불가.                                                          |

웹 폴더 선택기 변경(프로토타입에 구현됨):

- **후보.**
  - 지금 선택기는 GitHub remote가 하나인 Git 저장소 루트만 나열하고, `no_remote`, `remote_not_github`, `remote_ambiguous`, `not_a_git_root`는 막습니다.
  - 이 설계에서는 이 막힘이 **권한 있는** 검사에만 적용됩니다. 단순 화면에서는 코드 전용으로 폴더를 고를 수 있고, 한 줄 안내("Git 저장소가 아닙니다. 파일을 있는 그대로 검사합니다.")가 붙습니다.
  - 폴더 체인 자체에 대한 막힘(`not_owned_by_you`, `group_or_world_writable`, `unsafe_display`)은 여전히 거부합니다.
- **신원.**
  - 코드 전용 폴더의 신원은 기준점(6.1절)에서 이어지는 device/inode 체인입니다. Git 신원은 없습니다(`identity.kind: "folder"`).
  - 같은 소유권과 쓰기 비트 검사를 검사 전마다 다시 실행합니다(새 `folder` 검사: 체인만, Git 호출 없음).
  - 권한 확인을 실행하는 모든 경로(`/api/auth/verify`, 소유자 승인, `POST /api/scan`, 웹 대상)는 폴더 프로젝트를 `409 code_only_project`로 거부합니다. `POST /api/code-scan`만 받습니다. 최근 목록에는 폴더 프로젝트를 저장하지 않습니다.

### 6.1 폴더 고르기: OS 폴더 선택 창 또는 경로 붙여 넣기

소유자는 이름 검색이 헷갈린다고 했습니다("`latent` 입력" → "검색 폴더에 `latent` 폴더가 없습니다 … `pgard web scope add`"). 이제 폴더는 모든 데스크톱 앱이 하는 방식으로 고릅니다.

- **폴더 선택.** 버튼은 토큰으로 보호된 `POST /api/picker/browse`를 보냅니다. **서버**가 운영체제의 폴더 선택 창을 열고, 페이지는 창이 닫힐 때까지 `GET /api/picker/browse`를 폴링합니다(HTTP 요청 제한 시간은 30초이고, 사람은 더 오래 걸릴 수 있습니다).
  - macOS: `/usr/bin/osascript -e activate -e 'POSIX path of (choose folder with prompt "…")'`.
  - Windows: `System.Windows.Forms.FolderBrowserDialog`를 쓰는 `powershell.exe -NoProfile -NonInteractive -STA -Command`.
  - Linux: `/usr/bin/zenity --file-selection --directory`, 없으면 `kdialog --getexistingdirectory`.
  - 쓸 수 있는 도구가 없으면: "이 컴퓨터에는 PGARD가 열 수 있는 폴더 선택 창이 없습니다. 아래에 폴더 경로를 붙여 넣으세요."
- **경로 붙여 넣기.** 버튼 아래의 입력란입니다(`POST /api/picker/path`). `~`와 `~/…`는 홈 폴더로 펼칩니다. `~user`, 상대 경로, NUL, 4096자 초과는 거부합니다(`bad_path`).
- **검색 범위 단계 없음.** 이 경로에는 검색 폴더 목록도, `pgard web scope add`도 없습니다. 이름 검색은 전체 대시보드에만 남습니다.
- **검증(규칙은 그대로, 입구만 새로).** 새 inspector 작업 `resolve`는 서버가 아니라 자식 프로세스에서 실행됩니다.
  - `realpath` 다음 `lstat`: 디렉터리여야 합니다. 심볼릭 링크는 실제 폴더로 풀며, 링크 이름을 믿지 않습니다.
  - 거부: `/`, 최상위 폴더(`/usr`), 홈 폴더와 그 상위 폴더(`too_broad`), 기준점 아래 24단계 초과(`too_deep`), 없음, 파일, 읽을 수 없음.
  - **기준점.** 홈 안이면 홈 폴더입니다. 홈 밖이면 그 위로 올라가며 아직 이 사용자 소유인 가장 높은 폴더입니다. 기준점 바로 위 폴더는 sticky가 아닌 한(`/tmp`처럼) 다른 사용자가 쓸 수 없어야 합니다.
  - 기준점부터 아래로 모든 폴더를 이름으로 `lstat`하며 검색 후보와 같은 `not_owned_by_you` / `group_or_world_writable` 규칙을 적용합니다. 표시 안전성 검사(`unsafe_display`)도 같습니다.
  - 그다음 평소의 `full` 검사로 일반 GitHub 후보인지 코드 전용 후보인지 정합니다(6절).
  - 모든 거부에는 이유와 해결 방법이 영어와 한국어로 붙습니다(예: "홈 폴더나 시스템 폴더이며 프로젝트 폴더가 아닙니다. 프로젝트 자체의 폴더를 선택하세요. 예: ~/code/my-app").
- **선택 창 경로의 보안.**
  - 모든 API 경로와 같은 토큰, Host, Origin 미들웨어. 단순 화면이 켜져 있지 않으면 404입니다.
  - 선택 창은 한 번에 하나(`409 dialog_open`), 제한 시간 5분. 취소, 서버 종료, 시간 초과 때 선택 창 프로세스를 종료합니다.
  - `shell: false`인 `execFile`과 고정된 argv. 인자 안의 텍스트는 PGARD 자체의 현지화된 안내 문구뿐이며 요청 데이터는 절대 들어가지 않습니다.
  - 결과는 서버 세션에 두고 토큰으로 보호된 상태 경로로만, `~`로 줄인 경로를 가진 후보로 돌려줍니다. 원래 문자열은 돌려주지 않습니다.
  - 취소는 오류가 아니라 정상 상태입니다("폴더를 선택하지 않았습니다.").
- **채택하지 않음: 검색 폴더를 쓰는 이름 검색** (현재 선택기, 첫 프로토타입이 쓴 방식). 브라우저가 이름만 보낼 수 있었기 때문에 서버는 "검색 폴더" 목록을 뒤져야 했고, 사용자는 그 목록 밖의 폴더를 찾으려면 먼저 그 목록을 이해하고 늘려야 했습니다(`pgard web scope add`). 선택 창은 그 개념 없이 서버에 같은 것, 곧 사용자가 자기 화면에서 고른 경로를 줍니다. 검색을 안전하게 만들던 경로 검사는 고른 폴더에 그대로 적용됩니다.

## 7. 웹 UX: 한 화면

### 7.1 흐름과 상태

화면은 번호가 붙은 카드 세 장과 접힌 **More**로 이루어진 한 열입니다.

```
pgard  [Prototype]                                         한국어 | English
Scan a project folder
PGARD checks the files in a folder on this computer for leaked secrets, risky code and known-vulnerable dependencies.
(1) Choose a folder   (2) Press Scan   (3) Fix what it finds

┌ 1. Folder ───────────────────────────────────────────────┐
│ [ Choose folder ]                                         │
│ Or paste the folder's path [ ~/code/my-app ________ ] [Check] │
│ Scan this folder?  ~/projects/sample-shop   [Use this folder] │
└──────────────────────────────────────────────────────────┘
┌ 2. Scan ─────────────────────────────────────────────────┐
│ Reads the current files only … nothing is saved.  [ Scan ] │
└──────────────────────────────────────────────────────────┘
┌ 3. Findings ─────────────────────────────── 5 findings ──┐
│ ● Not authorized · code only   Authorization was not checked │
│   … Connect GitHub to also scan Git history (optional)     │
│ severity bar · findings table (rule, file:line, details)  │
└──────────────────────────────────────────────────────────┘
▸ More
```

| 상태             | 사용자가 보는 것                                                                                                                                      | 스크린샷                       |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| 비어 있음        | 제목, 한 문장 안내, 세 단계, 폴더 카드(**폴더 선택**과 경로 입력란), 비활성화된 Scan 카드.                                                            | `*-1-empty.png`                |
| 거부된 경로      | 입력란 아래의 이유와 해결 방법(여기서는 홈 폴더).                                                                                                     | `*-2-refused-home.png`         |
| Git 없는 폴더    | "이 폴더를 검사할까요?", 실제 경로, "Git 저장소가 아닙니다. 파일을 있는 그대로 검사합니다." (D4)                                                      | `*-3-confirm-no-git.png`       |
| GitHub 저장소    | "이 폴더를 검사할까요?", 실제 경로와 GitHub 저장소, **이 폴더 사용**과 **뒤로**.                                                                      | `*-4-confirm-repo.png`         |
| 폴더 선택됨      | "Folder **sample-shop** owner/repo"와 **Change**. Scan이 활성화됩니다.                                                                                | `*-5-folder-chosen.png`        |
| 검사 중          | 스피너, "Scanning the files… N s", **Cancel**. Change는 비활성화됩니다.                                                                               | `*-6-scanning.png`             |
| 결과             | 개수, **권한 미확인** 라벨, 어떤 영역을 실행하지 못했을 때(예: OSV 데이터 없음)의 부분 결과 안내, 심각도 막대(눌러서 필터), 상세가 있는 발견 항목 표. | `*-7-results.png`              |
| 권한 미확인 라벨 | 배지, 한 문장, 선택 사항인 GitHub 연결 링크.                                                                                                          | `*-8-not-authorized-label.png` |
| More 열림        | "What was checked", 표준, 규칙 통계, 그리고 추이와 내보내기(이유와 함께 비활성화), 전체 대시보드.                                                     | `*-9-more.png`                 |
| 선택 창 열림     | "폴더 선택 창을 기다리는 중…"과 **취소**. 고르지 않고 창을 닫으면 "폴더를 선택하지 않았습니다."                                                       | —                              |
| 발견 항목 없음   | "No findings in the checked files." 라벨은 그대로 보입니다. "안전하다"고는 절대 쓰지 않습니다.                                                        | —                              |
| 취소됨 / 실패    | 안내 하나와 다시 검사.                                                                                                                                | —                              |

### 7.2 문구 (EN / KO)

| 키               | English                                                                                                                                                                    | 한국어                                                                                                                                                                           |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Title            | Scan a project folder                                                                                                                                                      | 프로젝트 폴더 검사                                                                                                                                                               |
| Lead             | PGARD checks the files in a folder on this computer for leaked secrets, risky code and known-vulnerable dependencies.                                                      | PGARD는 이 컴퓨터에 있는 폴더의 파일에서 유출된 비밀값, 위험한 코드, 알려진 취약 의존성을 찾습니다.                                                                              |
| Steps            | Choose a folder · Press Scan · Fix what it finds                                                                                                                           | 폴더 선택 · 검사 누르기 · 찾은 문제 고치기                                                                                                                                       |
| Folder hint      | Choose the project's folder, or paste its path.                                                                                                                            | 프로젝트 폴더를 선택하거나 경로를 붙여 넣으세요.                                                                                                                                 |
| Button           | Choose folder                                                                                                                                                              | 폴더 선택                                                                                                                                                                        |
| Paste box        | Or paste the folder's path · Check                                                                                                                                         | 또는 폴더 경로 붙여 넣기 · 확인                                                                                                                                                  |
| No dialog        | This computer has no folder window PGARD can open. Paste the folder's path below instead.                                                                                  | 이 컴퓨터에는 PGARD가 열 수 있는 폴더 선택 창이 없습니다. 아래에 폴더 경로를 붙여 넣으세요.                                                                                      |
| No Git (D4)      | Not a Git repository: the files are scanned as they are.                                                                                                                   | Git 저장소가 아닙니다. 파일을 있는 그대로 검사합니다.                                                                                                                            |
| Refusal example  | This is your home folder or a system folder, not a project. Choose the project's own folder, for example ~/code/my-app.                                                    | 홈 폴더나 시스템 폴더이며 프로젝트 폴더가 아닙니다. 프로젝트 자체의 폴더를 선택하세요. 예: ~/code/my-app                                                                         |
| Scan explanation | Reads the current files only: secrets, risky code patterns and dependencies. No Git history, nothing leaves this computer and nothing is saved.                            | 현재 파일만 읽습니다: 비밀값, 위험한 코드 패턴, 의존성. Git 기록은 읽지 않고, 이 컴퓨터 밖으로 아무것도 보내지 않으며, 아무것도 저장하지 않습니다.                               |
| Badge            | Not authorized · code only                                                                                                                                                 | 권한 미확인 · 코드만                                                                                                                                                             |
| Badge text       | This is a code-only scan of the files on this computer. PGARD did not prove that you may scan this repository, so Git history, local web checks and saved results are off. | 이 결과는 이 컴퓨터에 있는 파일만 검사한 코드 전용 검사입니다. 이 저장소를 검사해도 된다는 권한을 PGARD가 확인하지 않았으므로 Git 기록, 로컬 웹 검사, 결과 저장은 꺼져 있습니다. |
| Upgrade link     | Connect GitHub to also scan Git history. Optional: opens the full dashboard, which asks for GitHub sign-in and owner approval.                                             | GitHub 연결하고 Git 기록도 검사. 선택 사항: GitHub 로그인과 소유자 승인을 요청하는 전체 대시보드를 엽니다.                                                                       |

모든 문구는 `apps/local-web/src/client/features/simple/simple-text.ts`에 있습니다.

### 7.3 "More" 아래로 옮겨지는 것

| 현재 (탭과 패널)                                        | 한 화면 흐름에서                                                                                                  |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Overview (요약 패널, 차트)                              | 없어집니다. 개수, 심각도 막대, 표가 개요를 대신합니다.                                                            |
| Findings (필터, 그룹, 페이지 나누기)                    | **메인 화면**(심각도 필터와 페이지 나누기). 나머지 필터(규칙, 파일, 영역, 분류)는 4단계에서 More 아래로 옮깁니다. |
| Coverage, 활동 로그, advisory 상태                      | More › What was checked                                                                                           |
| Standards (OWASP, CWE)                                  | More › Standards                                                                                                  |
| 규칙 통계                                               | More › Rule statistics                                                                                            |
| Trend                                                   | More › Trend: 권한 있는 검사에서만(저장이 필요). 그 외에는 이유와 함께 비활성화.                                  |
| Export                                                  | More › Export: 권한 있는 결과는 현재처럼, 코드 전용 결과는 보고서 배너가 생긴 뒤(D5).                             |
| 권한 확인 패널, 검사 범위 토글, 웹 대상 패널, 세션 메뉴 | 메인 경로에서 빠집니다. 권한 있는 흐름에서 **Connect GitHub to also scan Git history**를 누른 뒤에 나타납니다.    |
| 법적 고지                                               | 처음 사용할 때 유지(같은 문구). 폴더 카드 위에 표시합니다.                                                        |

**[Owner decision D5] 코드 전용 결과 내보내기.** 결정(2026-10-29): 모든 페이지에 "Not authorized: code-only scan" 배너를 넣어 HTML과 PDF 내보내기를 허용합니다. 이 파일은 `--format json`처럼 사용자 본인의 로컬 출력이기 때문입니다. 대안(채택하지 않음): 승인 없이는 내보내기 없음. 1단계에서 배너를 구현했고, 프로토타입은 배너와 함께 내보냅니다.

### 7.4 승인으로 올리는 것은 막는 장치가 아니라 링크

- 올리는 방법은 두 곳에서 제공합니다. 권한 미확인 라벨과 More › Full dashboard입니다.
- 문구는 **"Connect GitHub to also scan Git history"**입니다. "필수"라고는 절대 쓰지 않습니다.
- 권한 있는 흐름이 열립니다. 로그인, App 설치 안내, 소유자 승인, 그다음 Git 기록과 웹 검사입니다.
- 그 흐름이 `allowed`로 끝나면 권한 있는 검사가 코드 전용 결과를 대체하고, 라벨은 통과한 다섯 확인과 함께 "Authorized"로 바뀝니다.
- 프로토타입에서는 이 링크가 같은 탭에서 현재의 전체 대시보드를 엽니다.

## 8. 이전 방법

- **`pgard web`.**
  - 폴더 선택기를 1단계로 둔 한 화면 흐름이 됩니다.
  - 전체 대시보드는 4단계에서 나머지 부분을 화면에 합칠 때까지 More › Full dashboard("권한 있는 흐름")로 계속 쓸 수 있습니다.
  - `#findings`, `#coverage` 같은 해시는 전체 대시보드 안에서 계속 동작합니다.
- **`pgard dashboard`** (터미널에서 고정 프로젝트로 실행).
  - 1단계가 이미 채워진 같은 한 화면 흐름을 열고, **Change**는 없습니다.
  - 실행기는 지금도 Git 루트를 요구합니다. 4단계에서 코드 전용에 한해 "어떤 폴더든"으로 완화합니다.
- **저장된 결과.**
  - 바뀌지 않습니다. 1.7 이전에 쓴 결과는 권한 있는 결과로 읽습니다(실제로 그랬습니다).
  - 코드 전용 결과는 절대 저장하지 않으므로, 저장소와 추이에는 권한 있는 검사만 들어 있습니다.
- **문서.**
  - README: 정책 줄의 "There is no option to skip them"을 "Git history, web checks and storage need all five checks; `pgard scan code` without approval runs a code-only scan, labelled as not authorized"로 바꿉니다.
  - `SECURITY.md`의 범위를 갱신합니다. 코드 전용 결과를 권한 있는 것처럼 보여 주거나 내보내면 취약점입니다. 로컬 파일의 코드 전용 검사는 권한 확인 우회가 아닙니다.
  - `RESULT_SCHEMA.md`를 1.7에 맞게 갱신합니다.
- **목 서버**(`dev/mock-server.mjs`)에 UI 테스트용으로 현실적인 코드 전용 시나리오(프로젝트 하나, 발견 항목 몇 개)를 추가하고, 소유자를 헷갈리게 한 어수선한 데모 데이터를 대체합니다.

## 9. 단계 나누기 (작은 PR)

단계마다 별도 PR이며, 앞 단계가 리뷰를 통과한 뒤에만 엽니다. 모두 #414를 참조합니다(5단계는 #419도).

1. **설계 기록과 결과 표시 (PR #415).**
   - 2026-10-29 결정을 담은 이 문서.
   - 계약과 읽는 쪽의 JSON 1.7 `scanBasis`. `runCodeOnlyScan`은 `mode: "code_only"`를 쓰고, 권한 있는 검사는 모두 `mode: "authorized"`와 `verified` 또는 `not_verified` / `no_approval`을 씁니다.
   - SARIF: `properties.pgard.scanBasis`, 코드 전용 경고 알림, `pgard/code-only/` 카테고리.
   - HTML·PDF 보고서: 모든 페이지의 배너와 표지 블록(D5). 프로토타입은 배너와 함께 내보냅니다.
   - 결과 저장소는 권한이 확인되지 않은 결과를 거부합니다(심층 방어).
   - 디스크 파일 비밀값 검사는 자체 문구("프로젝트 폴더의 환경 파일", "프로젝트 파일 안의 비밀정보")를 쓰며 "추적되는 파일"이나 "Git에 커밋된"이라고 쓰지 않습니다. 규칙 ID와 지문은 같습니다.
   - 웹 라벨은 권한을 확인하지 않은 이유를 알려 줍니다(GitHub remote 없음, Git 저장소 아님, 확인하지 않음).
   - 1.7을 반영한 `RESULT_SCHEMA.md`.
   - 프로토타입 경로와 화면은 계속 `PGARD_WEB_PROTOTYPE=code-only` 뒤에 둡니다.
2. **CLI (D1, D2, D4).** 기본적으로 코드 전용인 `pgard scan code`, `--require-authorization`, 터미널 안내 줄, 안내를 덧붙이되 바뀌지 않는 `scan all`과 `history`/`web`, `project verify`와 `doctor` 항목, 모든 폴더(Git 없음, remote 없음), README.
3. **Precommit (D3).** 권한 확인과 네트워크 없이 코드 전용으로 실행하는 `pgard precommit`. `"precommit": { "requireAuthorization": true }`로 엄격 모드를 선택합니다.
4. **웹 단순 화면 정식 버전.** OS 폴더 선택 창과 경로 입력란(6.1절)이 있는 한 화면 흐름이 `pgard web`과 `pgard dashboard`의 기본 경로가 됩니다. 프로토타입 플래그와 경로는 없애고, 이전 탭들은 기본 경로에서 빠지며(전체 대시보드는 올리기 링크 뒤의 권한 있는 흐름으로 남습니다), i18n은 카탈로그로 옮깁니다.
5. **세션 URL (#419, 12절).** 브라우저 자동 열기, 가린 토큰, `--print-url`, 한 번만 쓰는 토큰. `pgard web`, `pgard dashboard`, 새 화면에 모두 적용합니다.
6. 배포 전 1~5단계의 **독립 보안 리뷰**.

## 10. PR #415의 프로토타입 (4단계까지 `PGARD_WEB_PROTOTYPE=code-only` 뒤에 둠)

- **실제로 동작하는 것.**
  - OS 폴더 선택 창(macOS `osascript`, Windows PowerShell, Linux `zenity`/`kdialog`)과 경로 입력란. 실제 inspector 자식 프로세스에서 풀고 확인(realpath, 소유권, 쓰기 비트, 표시 안전성)한 뒤 확정하며, 검사 전에 다시 확인합니다.
  - GitHub remote가 없는 폴더와 Git이 없는 폴더도 코드 전용 검사를 받습니다(D4).
  - 실제 폴더에 대한 코드 전용 검사(소스 규칙, 디스크의 OSV 데이터로 확인하는 의존성, 새 비밀값 검사).
  - 값 가리기.
  - 토큰, Host, Origin 검사와 `127.0.0.1`만 사용.
  - 1단계의 결과 표시: 결과의 `scanBasis`(고른 폴더에서 정한 이유 포함), SARIF, 모든 페이지에 배너가 있는 HTML/PDF 내보내기(More › 보고서 내보내기).
- **아직 실제가 아닌 것.**
  - CLI(2단계)와 precommit(3단계)은 아직 코드 전용 검사를 하지 않습니다.
  - 올리기 링크는 현재의 전체 대시보드를 엽니다.
- **절대 하지 않는 것.**
  - 프로토타입 경로는 GitHub를 호출하지 않습니다. 단순 화면이 켜져 있지 않으면 404이며, 고정 모드에서는 단순 화면이 켜지지 않습니다.
  - `POST /api/scan`(권한 확인)은 바뀌지 않습니다.
- **테스트.**
  - `packages/scan-core/src/run-code-only.test.ts`: 권한 확인 없음, 기록 없음, 표시된 결과.
  - `packages/scan-core/src/working-tree-secrets.test.ts`: 디스크의 비밀값, `.env`, 링크를 따라가지 않음, Git 없음, 출력에 값 없음.
  - `apps/local-web/src/server/code-scan-prototype.test.ts`: 꺼져 있으면 404, 고정 모드에서 켜지지 않음, 토큰·Host·Origin 검사, `no_project`, 신원 재확인, 배너가 있는 내보내기.
  - `apps/local-web/src/server/choose-folder-prototype.test.ts`: 선택 창과 붙여 넣기 경로(꺼져 있으면 404, 토큰과 Origin, 선택 창은 한 번에 하나, 취소와 종료 때 선택 창 종료, 도구 없음, 해결 방법이 붙은 거부, `~` 펼치기), Git 없는 폴더는 코드 전용만(verify와 `POST /api/scan`은 `409 code_only_project`), 검사 전 폴더 재확인, 플랫폼별 고정 argv.
  - `apps/local-web/src/server/picker/resolve-folder.test.ts`: 실제 폴더에 대한 `resolve` 작업(GitHub 저장소, Git 없음, 심볼릭 링크, 그룹 쓰기 가능, 홈 밖, 거부되는 경로)과 메시지 검증.
  - `packages/findings/src/scan-basis.test.ts`: `scanBasis` 읽기(없으면 권한 있는 검사, 불가능한 조합 거부, 모르는 이유 코드 유지), SARIF 표시와 카테고리, 작업 트리 비밀값 문구와 한국어 번역.
  - `packages/report/src/code-only-report.test.ts`: HTML 배너와 표지 블록, 인쇄 규칙, 모든 PDF 페이지의 배너.
  - `packages/result-store/src/store.test.ts`: 코드 전용 결과는 절대 저장소에 들어가지 않음.

## 11. 결정 사항 (2026-10-29 결정)

소유자가 2026-10-29 설계를 승인했으며, 모든 결정은 권장안대로입니다.

| #   | 질문                                 | 결정 (2026-10-29)                                                                                                          |
| --- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| D1  | 승인 없는 `pgard scan code`          | 기본적으로 코드 전용이며 분명한 안내 줄을 붙입니다. `--require-authorization`은 종료 코드 3을 되살립니다.                  |
| D2  | 승인 없는 `pgard scan all`           | 바뀌지 않고 엄격합니다(막힘, 종료 코드 3). `scan code`를 실행하라는 안내를 붙입니다.                                       |
| D3  | `pgard precommit`                    | 항상 코드 전용이며 권한 확인과 네트워크가 없습니다. 저장소는 `"precommit": { "requireAuthorization": true }`로 선택합니다. |
| D4  | GitHub remote 없음 / Git 저장소 아님 | 둘 다 코드 전용 검사를 받습니다.                                                                                           |
| D5  | 코드 전용 결과 내보내기              | 모든 페이지에 "권한 미확인" 배너를 넣어 허용합니다.                                                                        |
| D6  | 한 화면 레이아웃과 문구(7절)         | 승인. OS 폴더 선택 창과 경로 붙여 넣기 흐름(6.1절)도 함께 승인되었습니다.                                                  |

## 12. 세션 URL 처리 (#419)

`pgard web`, `pgard dashboard`, 한 화면 흐름에 똑같이 적용합니다(5단계).

### 12.1 지금

- 실행기는 `http://127.0.0.1:<port>/#token=<secret>`을 출력하고 사용자가 복사하거나 클릭합니다.
- 토큰은 URL 조각(fragment)에 든 긴 난수입니다(요청이나 `Referer`로는 보내지지 않습니다). 페이지가 이를 읽어 서버가 멈출 때까지 모든 API 호출에 `x-pgard-token`으로 보냅니다.
- 그래서 비밀값 전체가 터미널 스크롤백, 셸 녹화와 화면 공유, 브라우저 기록에 남고, 서버가 멈출 때까지 어느 탭에서든 같은 링크가 다시 동작합니다.

### 12.2 결정

- **브라우저 열기.** 서버가 대기를 시작하면 실행기가 플랫폼의 열기 도구로 URL을 엽니다. `open`(macOS), `xdg-open`(Linux), `rundll32 url.dll,FileProtocolHandler`(Windows)를 고정 argv와 셸 없는 `execFile`로 실행합니다. CI, 터미널 없음, `--no-open`일 때는 열지 않습니다.
- **터미널에서 토큰 가리기.** 터미널에는 `http://127.0.0.1:4317/#token=•••• (opened in your browser)`이 보입니다. 전체 URL은 열기에 실패했거나 건너뛰었을 때(열기 도구 없음, CI, 터미널 없음, `--no-open`) 또는 `--print-url`일 때만 출력합니다. 전체 URL은 로그 파일에 절대 쓰지 않습니다.
- **한 번만 쓰는 URL 토큰.** URL 토큰은 초대장일 뿐입니다.
  1. 처음 열릴 때 페이지는 URL 토큰으로 `POST /api/session/exchange`를 호출합니다(같은 Host, Origin 검사). 서버는 토큰을 사용됨으로 표시하고 새 **세션 비밀값**(32바이트 난수, 서버에는 해시만 보관)을 돌려줍니다.
  2. 페이지는 주소창에서 조각을 지우고(`history.replaceState`), 세션 비밀값을 `sessionStorage`에 두며 이후 `x-pgard-session`으로 보냅니다. URL 토큰은 어떤 API 경로에서도 더는 받지 않습니다.
  3. 같은 URL 토큰으로 두 번째 교환을 하면(다시 쓴 링크, 다른 탭, 복사한 링크, 브라우저 기록) `409 token_used`로 거부하고 페이지에 "이미 사용한 링크입니다. 명령을 다시 실행해 새 링크를 받으세요." / "This link was already used. Run the command again to get a new one."이 나옵니다.
  4. 쓰지 않은 URL 토큰은 10분 뒤 만료되며, 실행기는 새 링크를 받는 방법(명령 다시 실행)을 출력합니다.
- **새로 고침: 그 탭에서만 계속 동작.** 같은 탭을 새로 고치면 `sessionStorage`의 세션 비밀값으로 URL 토큰 없이 이어집니다. 새 탭, 새 창, 탭을 닫은 뒤에는 새 링크가 필요합니다(명령 다시 실행).
  - `sessionStorage`를 고른 이유: **포트까지 포함한** 정확한 출처와 탭에 묶이고, 탭을 닫으면 사라집니다. 새로 고침은 로컬 페이지에서 가장 흔한 동작이므로(개발자는 바꿀 때마다 새로 고칩니다) 새로 고침에 세션을 잃으면 보안상 얻는 것 없이 사용자를 막아 세웁니다. 이 장치가 막는 공격자는 탭의 저장소가 아니라 터미널이나 기록을 읽는 사람입니다.
  - 채택하지 않음, 쿠키: 쿠키는 포트로 격리되지 않아 `127.0.0.1:4317`의 세션 쿠키가 `127.0.0.1`의 다른 모든 로컬 서버(PGARD가 검사하는 개발 서버 포함)에도 보내집니다.
  - 채택하지 않음, `localStorage`: 탭과 브라우저 재시작보다 오래 남고 출처의 모든 탭이 공유하므로, 세션에 필요한 것보다 오래 비밀값을 남깁니다.
  - 채택하지 않음, 메모리에만 보관: 새로 고칠 때마다 세션이 끝납니다.
- **한 번에 한 세션.** 교환 뒤에는 세션 비밀값을 가진 쪽만 API를 쓸 수 있고 두 번째 브라우저는 들어올 수 없습니다. 터미널에는 "브라우저에서 열었습니다. 다른 곳에서 열려면 멈추고 명령을 다시 실행하세요."라고 나옵니다.
- **바뀌지 않는 것.** `127.0.0.1` 전용, 정확한 Host 검사, Origin 검사, CSP, 프로젝트 epoch.

### 12.3 테스트 (5단계)

한 번 교환, 두 번째 교환과 모든 경로의 원래 URL 토큰 거부, 세션 비밀값으로 새로 고침, 쓰지 않은 토큰의 만료, 가린 터미널 출력과 `--print-url`, 플랫폼별 열기 도구 argv와 CI·터미널 없음 대체 동작, 영어와 한국어의 "이미 사용함" 페이지.
