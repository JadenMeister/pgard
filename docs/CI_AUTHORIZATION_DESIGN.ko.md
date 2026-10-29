# 보안 설계: CI(GitHub Actions)에서의 권한 확인

> **참고:** 이 문서는 [`CI_AUTHORIZATION_DESIGN.md`](CI_AUTHORIZATION_DESIGN.md)(영문)의 한국어 번역입니다. 기준 문서는 영문판이며, 내용이 다르면 영문판이 맞습니다. 프로젝트 [README](../README.ko.md)([English](../README.md))와 [문서 목록](README.ko.md)도 참고하세요.

상태: 검토용 설계([#405](https://github.com/JadenMeister/pgard/issues/405), M10-2). 이 문서의 내용은 아직 아무것도 구현되지 않았습니다. 소유자가 승인한 뒤에만 M10-3에서 구현합니다.

"현재"에 대한 설명은 작성 시점의 코드(`packages/policy/src/authorize-project.ts`, `packages/policy/src/checks.ts`, `packages/policy/src/types.ts`, `packages/github-auth`, `packages/git-history`)를 기준으로 합니다. 이 설계가 아직 코드에 없는 것에 기대는 곳에는 **M10-3 요구사항**이라고 표시했습니다. GitHub에 대한 설명은 GitHub 문서에서 가져왔고, 본문에 링크를 달고 [참고 자료](#12-참고-자료)에 모았습니다. 문서가 말하지 않는 부분은 그렇다고 적고, 그 동작에 기대지 않습니다.

## 1. 목표와 비목표

### 목표

1. GitHub Actions 작업(job)에서의 검사도 로컬 검사와 **같은 다섯 가지 확인**(저장소, GitHub 신원, 소유자 승인, 현재 접근, 기여)을 같은 확인 id, 순서, 상태로 증명합니다. 브라우저 로그인은 없습니다.
2. 각 확인은 로컬 증거와 **같거나 더 강한** 증거로 증명합니다. CI가 그런 증거를 만들 수 없으면 그 확인은 이유와 함께 `failed` 또는 `unverifiable`이 되고, 검사는 막힙니다(종료 코드 3).
3. **확인을 건너뛰거나, 완화하거나, 캐시하는 CI 모드는 없습니다.** CI가 바꾸는 것은 `github_identity`의 증거가 어디서 오는지, 그리고 이후 확인을 어느 계정에 대해 평가하는지뿐입니다. `authorizeProject`는 여전히 유일한 게이트이고 `isAuthorizationAllowed`는 바뀌지 않습니다.
4. GitHub Actions 밖에서 "CI인 척" 실행해도 아무것도 허용되지 않습니다. `GITHUB_ACTIONS`, `GITHUB_REPOSITORY`, `GITHUB_ACTOR` 같은 환경 변수는 절대 증거가 아닙니다.
5. 코드, 히스토리, 결과는 러너에 남습니다. 네트워크 통신은 GitHub(`api.github.com`과 Actions 토큰 서비스 `token.actions.githubusercontent.com`)로만 제한됩니다.

### 비목표

- M10-2에서는 구현하지 않고, 로컬 디바이스 플로 경로도 바꾸지 않습니다.
- CI에서 풀 리퀘스트 코드를 검사하지 않습니다([U2](#8-증명할-수-없어-막는-것) 참고). 이를 위해서는 별도 설계가 필요합니다.
- 다른 CI 시스템과 GitHub Enterprise Server는 지원하지 않습니다([9절](#9-범위-밖) 참고).
- 수정된 `pgard` 바이너리는 막지 않습니다. PGARD는 곧 오픈소스가 되며, 누구나 게이트를 뺀 사본을 빌드할 수 있습니다. 이는 지금 노트북에서도 마찬가지입니다. 게이트는 진짜 `pgard`의 사용자와, 그것이 향하는 저장소의 주인을 허가되지 않은 검사로부터 보호합니다. 이 설계는 그 성질을 CI에서도 유지할 뿐, 그 이상을 하려 하지 않습니다.

## 2. 현재의 확인과 로컬 증거

`authorizeProject`는 모든 검사와 `project verify`에서 실행되고, 결과는 절대 캐시되지 않습니다. 다섯 확인이 모두 통과해야만 결정이 `allowed`입니다.

| #   | 확인              | 현재 증명하는 것                                                                                               | 로컬에서 기대는 증거                                                                                                                                                                                                                                                                                                                                                                                             | 네트워크         |
| --- | ----------------- | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| 1   | `repository`      | 프로젝트 폴더가 유효한 히스토리와 모호하지 않은 `github.com` 원격 하나를 가진, 격리된 Git 저장소의 루트입니다. | 로컬 Git만 사용(`verifyRepository`): `.git` 사전 점검(alternates·grafts 없음, 일반 파일인 `shallow`는 허용), 실제 경로가 Git 루트와 같음, replace ref 없음, 유효한 `HEAD`, raw config에서 읽은 `github.com` 원격이 정확히 하나, `url.*.insteadOf` 재작성 없음.                                                                                                                                                   | 없음             |
| 2   | `github_identity` | 실제 GitHub 사용자가 있고, 설정된 PGARD GitHub App을 통해 로그인했습니다.                                      | OAuth 디바이스 플로(사람이 github.com에 코드를 입력)로 받은 사용자-서버 토큰, 또는 OS 키체인에 저장된 같은 토큰. `GET /user`가 성공해야 합니다. 토큰이 사용자와 App을 증명합니다.                                                                                                                                                                                                                                | `api.github.com` |
| 3   | `owner_approval`  | 저장소 소유자가 이 저장소에 대해 PGARD를 승인했습니다.                                                         | 개인 계정: 소유자 계정(`targetType: User`, 계정 id = 소유자 id)에 설정된 App이 설치되어 있고 그 설치에 저장소 id가 포함됨. 사용자 토큰으로 읽음(`GET /user/installations`, `GET /user/installations/{id}/repositories`). 조직: 조직 계정에 같은 설치가 있고 **또한** 로그인한 사용자의 `GET /user/memberships/orgs/{org}`가 `state: active`, `role: admin`. 원격의 조직 이름은 GitHub의 이름과 정확히 같아야 함. | `api.github.com` |
| 4   | `current_access`  | 로그인한 사용자가 지금 저장소를 읽을 수 있습니다.                                                              | 사용자 토큰으로 `GET /repos/{owner}/{repo}`, 그 사용자에 대해 `permissions.pull`(또는 그 이상)이 보고됨. 404는 `failed`.                                                                                                                                                                                                                                                                                         | `api.github.com` |
| 5   | `contribution`    | 사용자가 저장소에 기여했거나(또는 검증된 소유자이고), 로컬 코드가 그 저장소의 것입니다.                        | `HEAD` 조상 커밋 최대 30개. GitHub가 기본 브랜치에 있다고 보여 주고(`compare`), 그 사용자가(id 기준) 작성한 PR이 이 저장소의 기본 브랜치에 병합되었거나, GitHub가 서명을 검증하고 커미터를 그 사용자로 귀속시킨 커밋만 인정. 검증된 소유자(같은 실행의 확인 3에서 나온 소유자 증거, GitHub id로 대조)는 그 커밋들 중 하나가 기본 브랜치에 있기만 하면 됨.                                                        | `api.github.com` |

CI에서 중요한 성질 두 가지:

- 확인 3~5의 **주체**는 로그인한 사람입니다. 이 확인들을 의미 있게 만드는 모든 것(소유자, 조직 소유자, 협업자, 기여자)은 그 사람의 GitHub 계정 id에 대한 진술입니다.
- 확인 3~5에는 GitHub API가 필요합니다. 현재 게이트에서 오프라인으로 증명할 수 있는 것은 확인 1뿐입니다.

## 3. CI에서 바뀌는 것

CI 작업에는 터미널 앞의 사람이 없으므로 디바이스 플로가 없습니다. "로그인한 사람"의 자리를 무언가가 대신해야 하고, 확인 3~5는 같은 규칙으로 그 주체에 대해 평가되어야 합니다.

이 설계는 입력을 두 종류로 나눕니다.

- **신원(identity)**: 주체가 누구인가. GitHub가 서명해야 하고, 이 작업과 이 프로세스에 묶여 있어서 복사, 재사용(replay), GitHub 밖에서의 생성이 불가능해야 합니다.
- **사실(facts)**: 저장소, 설치, 멤버십, 풀 리퀘스트, 커밋에 대해 GitHub가 말하는 것. TLS로 `api.github.com`에서 읽은 사실은, 그 토큰이 애초에 읽을 수 있었다면, 어느 토큰으로 읽었든 참입니다. 따라서 읽기 전용 토큰의 출처는 사실을 *읽을 수 있는지*에만 영향을 주고, 사실이 *무엇을 말하는지*에는 영향을 주지 않습니다.

CI에서 신원을 주는 것은 GitHub가 서명한 OIDC 토큰뿐입니다(4절). 사실만 읽는 토큰은 어디서 왔든 상관없지만, 절대 신원이 아닙니다.

## 4. CI 신원 후보

각 후보마다 각 확인에 어떻게 대응하는지, 어떻게 위조될 수 있는지, 오프라인으로 검증할 수 있는지를 적습니다.

### A. GitHub Actions OIDC 토큰(`id-token: write`)

`permissions: id-token: write`가 있는 작업의 단계(step)는 러너 변수 `ACTIONS_ID_TOKEN_REQUEST_URL`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`과 원하는 `audience` 쿼리 매개변수로 GitHub OIDC 제공자에게 JWT를 요청할 수 있습니다([OIDC 레퍼런스](https://docs.github.com/en/actions/reference/security/oidc), [워크플로 문법: `permissions`](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)). 토큰은 발급자 `https://token.actions.githubusercontent.com`이 RS256으로 서명하며, 키는 [OpenID 설정](https://token.actions.githubusercontent.com/.well-known/openid-configuration)의 `jwks_uri`에 공개됩니다([JWKS](https://token.actions.githubusercontent.com/.well-known/jwks)). 설정에 나열된 클레임: `sub`, `aud`, `exp`, `iat`, `iss`, `jti`, `nbf`, `ref`, `sha`, `repository`, `repository_id`, `repository_owner`, `repository_owner_id`, `enterprise`, `enterprise_id`, `run_id`, `run_number`, `run_attempt`, `actor`, `actor_id`, `workflow`, `workflow_ref`, `workflow_sha`, `head_ref`, `base_ref`, `event_name`, `ref_type`, `ref_protected`, `environment`, `environment_node_id`, `job_workflow_ref`, `job_workflow_sha`, `repository_visibility`, `runner_environment`, `issuer_scope`, `check_run_id`.

관련된 문서상의 의미:

- `actor` / `actor_id`: 실행을 시작한 계정. 재실행의 경우 GitHub [컨텍스트 레퍼런스](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts)는 `github.actor`가 _최초_ 실행의 사용자로 남고, 재실행은 그 사용자의 권한을 쓰며, 재실행을 시작한 사람은 `github.triggering_actor`라고 말합니다. OIDC 클레임 목록에는 `triggering_actor`가 없습니다.
- `job_workflow_ref` / `job_workflow_sha`: 작업이 재사용 워크플로를 쓸 때 있으며, 호출된 워크플로 파일과 그 커밋을 가리킵니다. 다른 클레임(`repository`, `ref`, `workflow` 등)은 **호출자**를 설명합니다([재사용 워크플로와 OIDC](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows)).
- `runner_environment`: `github-hosted` 또는 `self-hosted`.
- `sub`: 형식이 이벤트, 환경(environment), 사용자 지정 템플릿에 따라 달라지고, 2026년 7월 15일 이후에 만들어진(또는 이름이 바뀌거나 이전된) 저장소는 소유자 id와 저장소 id가 들어간 불변 형식을 씁니다([OIDC 레퍼런스](https://docs.github.com/en/actions/reference/security/oidc)). 그래서 이 설계는 **`sub`를 절대 해석하지 않고** 개별 클레임을 확인합니다.
- 수명: 토큰은 "단일 작업 동안만 유효"합니다([OIDC 개념](https://docs.github.com/en/actions/concepts/security/openid-connect)). GitHub는 고정 수명을 문서화하지 않으므로, 설계는 `exp`를 읽고 자체 신선도 한도를 더합니다.

| 확인              | 대응                                                                                                                                                                                             | 위조 방법                                                                                                                                                                                                                                                                                                                   | 오프라인?                                      |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| `repository`      | 작업을 `repository` / `repository_id`와 커밋 `sha`에 묶습니다. 로컬 확인은 그대로 실행하고, 추가로 원격이 같은 저장소를 가리키고 `HEAD`가 `sha`와 같아야 합니다.                                 | 다른 저장소에서 발급된 토큰은 다른 `repository_id`를 가집니다(거부). `sha`가 아닌 코드를 체크아웃한 작업은 `HEAD` 비교에서 실패합니다.                                                                                                                                                                                      | 예(알려진 키로 서명 검증, 클레임 비교)         |
| `github_identity` | GitHub가 서명한 `actor_id` / `actor`: 실행을 시작한 계정.                                                                                                                                        | 저장소에서 워크플로를 시작할 수 있는 사람은 누구나 actor가 됩니다(그래서 확인 3~5가 여전히 실행됨). 재실행: actor는 이번 시도를 일으킨 사람이 아닙니다. 같은 작업의 어떤 단계든 아무 audience로 토큰을 발급받아 중계할 수 있으므로 작업의 단계가 고정되어야 합니다(7.2절). 셀프 호스티드 러너의 운영자는 기계를 통제합니다. | 서명과 클레임은 예. "User 계정인가"는 API 필요 |
| `owner_approval`  | 제공하지 않음. OIDC는 App 설치에 대해 아무것도 말하지 않습니다. `actor_id == repository_owner_id`는 개인 소유자가 실행을 시작했음을 보여 주지만, PGARD(App)가 승인되었음을 보여 주지는 않습니다. | 해당 없음                                                                                                                                                                                                                                                                                                                   | 아니요                                         |
| `current_access`  | 직접 제공하지 않음. `actor_id == repository_owner_id`이면 개인 소유자의 접근이 함축되지만, 그 외의 사람에 대해서는 아무것도 말하지 않습니다.                                                     | 해당 없음                                                                                                                                                                                                                                                                                                                   | 일부(소유자인 경우만)                          |
| `contribution`    | 제공하지 않음. 기존 규칙의 주체(`actor_id`)를 줍니다.                                                                                                                                            | 해당 없음                                                                                                                                                                                                                                                                                                                   | 아니요                                         |

### B. `GITHUB_TOKEN`

"`GITHUB_TOKEN` 시크릿은 GitHub App 설치 액세스 토큰"이며, 작업마다 만들어지고, 워크플로가 들어 있는 저장소로 제한되며, 작업이 끝나거나 GitHub 호스티드 러너에서 최대 6시간(셀프 호스티드는 24시간) 후에 만료됩니다([`GITHUB_TOKEN`](https://docs.github.com/en/actions/concepts/security/github_token)). 권한은 `permissions:`로 정합니다. 포크에서 온 풀 리퀘스트 이벤트(`pull_request_target` 제외)에서는 저장소가 쓰기 토큰 보내기를 켜지 않는 한 쓰기 권한이 읽기 전용으로 바뀌고, `pull_request_target`은 공개 포크에서 와도 읽기/쓰기를 받습니다([워크플로 문법: `permissions`](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)).

| 확인              | 대응                                                                                                                                | 위조 방법                                                                                                                                               | 오프라인?             |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| `repository`      | 이 저장소의 `GET /repos/{owner}/{repo}`(id, 소유자 id와 유형, 기본 브랜치)를 읽을 수 있음: 사실이지 묶음(binding)이 아님.           | 환경 변수에 든 불투명한 문자열입니다. 개인 액세스 토큰, 다른 저장소의 `GITHUB_TOKEN`, 그 밖의 어떤 토큰이든 GitHub 밖에서 같은 변수에 넣을 수 있습니다. | 아니요(불투명한 토큰) |
| `github_identity` | 없음. 사람이 아니라 GitHub Actions App 설치를 나타내며, 누가 실행을 시작했는지 말하지 않습니다.                                     | 해당 없음                                                                                                                                               | 아니요                |
| `owner_approval`  | 없음. 다른 App의 설치를 나열하거나 조직 멤버십을 읽을 수 없습니다(`members`는 `GITHUB_TOKEN`의 권한 범위가 아님).                   | 해당 없음                                                                                                                                               | 아니요                |
| `current_access`  | 사람에 대해서는 없음: `GET /repos`의 `permissions`는 actor가 아니라 토큰을 설명합니다.                                              | 해당 없음                                                                                                                                               | 아니요                |
| `contribution`    | `contents: read`, `pull-requests: read`로 이 저장소에 대해 기존 규칙에 필요한 사실(`compare`, 커밋의 PR, 커밋 검증)을 읽을 수 있음. | 사실일 뿐(3절). 읽을 수 있는 토큰이면 무엇으로 읽어도 안전합니다.                                                                                       | 아니요                |

결론: 이 저장소의 **사실을 읽는 용도**로만 쓸 수 있고, 신원이나 승인으로는 절대 쓰지 않습니다.

### C. `pgard`에 건네는 GitHub App 설치 토큰

설치 토큰은 App의 JWT로 `POST /app/installations/{installation_id}/access_tokens`를 호출해 만들고, "1시간 후 만료"되며, App의 행위로 기록되고, 설치가 이미 가진 저장소와 권한 안에서 좁힐 수 있습니다([설치로 인증하기](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)). `app_id`, `account`, `repository_selection`을 돌려주는 `GET /repos/{owner}/{repo}/installation`은 App의 JWT가 필요하고, 토큰 생성 응답에는 `app_id`나 `account`가 없습니다([Apps REST API](https://docs.github.com/en/rest/apps/apps)).

두 가지 형태:

- **C1. 미리 만들어진 설치 토큰**(예: 작업 앞부분에서 액션이 발급한 것). `pgard`는 어느 App이 발급했는지 알 수 없습니다. 설치 토큰으로 호출할 수 있는 어떤 API도 App id를 돌려주지 않습니다. 소유자 계정(또는 공격자가 통제하는 저장소)에 설치된 아무 App의 토큰이든 똑같아 보입니다. 소유자 승인이 설정된 App에 대한 것임을 보일 수 없습니다. **승인 증거로는 거부**하고, 사실을 읽는 용도로는 허용합니다.
- **C2. `pgard`에 App 자격 증명(App id와 개인 키)을 줌.** `pgard`가 직접 App JWT를 서명하고, `GET /repos/{owner}/{repo}/installation`을 호출해 `app_id`와 설치 계정을 확인한 뒤, 이 저장소만, 읽기 전용 권한으로 짧은 설치 토큰을 발급합니다. 이는 소유자 계정에 **그 App**이 설치되어 있음을 증명하며, 이것이 현재의 소유자 승인 증거입니다.

| 확인              | 대응(C2)                                                                                                                                                                                                                                                                                                         | 위조 방법                                                                                                                                                                                                                                                                                                                                | 오프라인? |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| `repository`      | 사실(`GET /repos`).                                                                                                                                                                                                                                                                                              | 해당 없음                                                                                                                                                                                                                                                                                                                                | 아니요    |
| `github_identity` | 없음: App은 사람이 아닙니다.                                                                                                                                                                                                                                                                                     | 해당 없음                                                                                                                                                                                                                                                                                                                                | 아니요    |
| `owner_approval`  | `GET /repos/{owner}/{repo}/installation`(JWT): `app_id` = 설정된 App, `account.id` = 소유자 id, `target_type` = 소유자 유형, 저장소 포함. 조직이면 추가로 설치 토큰으로 주체의 멤버십 확인(`GET /orgs/{org}/memberships/{username}`, `state`, `role`)([멤버 API](https://docs.github.com/en/rest/orgs/members)). | 개인 키를 가진 사람은 그 App의 모든 설치에 대해 토큰을 발급할 수 있습니다. 저장소 시크릿에 둔 키는 그 시크릿을 읽을 수 있는 모든 워크플로가 읽을 수 있습니다. 공격자가 자기 App을 등록할 수는 있지만, 개인 계정에 설치하려면 그 계정 주인이 필요하고, 조직에서는 멤버십 확인이 여전히 주체가 활성 소유자일 것을 요구합니다(현재와 같음). | 아니요    |
| `current_access`  | 개인 소유자나 조직 소유자: 함축됨. 그 외: `GET /repos/{owner}/{repo}/collaborators/{username}/permission`(`permission`: admin, write, read, none)([협업자 API](https://docs.github.com/en/rest/collaborators/collaborators)). 어떤 App 권한이 필요한지는 문서에 없음(M10-3에서 확인해야 함).                     | 사실.                                                                                                                                                                                                                                                                                                                                    | 아니요    |
| `contribution`    | 설치 토큰으로 읽은 사실.                                                                                                                                                                                                                                                                                         | 사실.                                                                                                                                                                                                                                                                                                                                    | 아니요    |

기본 제공 PGARD App의 개인 키는 그 관리자가 가지고 있으며, 배포하거나 공유하지 않습니다. 따라서 C2는 저장소 소유자가 키를 가진 App, 즉 직접 등록한 App에만 쓸 수 있습니다. 이는 현재의 `PGARD_GITHUB_APP_CLIENT_ID` 재정의와 같은 경우입니다. [열린 질문 Q1](#11-소유자에게-묻는-열린-질문)을 참고하세요.

### D. 저장된 사용자-서버 토큰(디바이스 플로를 한 번 하고 토큰을 CI 시크릿에 저장)

다섯 확인 모두 지금과 똑같이 실행되겠지만:

- 신원은 이번 실행을 일으킨 사람이 아니라 한때 로그인한 계정입니다. 그 시크릿을 읽는 워크플로를 실행할 수 있는 사람은 누구나 _소유자로서_ 검사하게 되므로, 소유자가 본 적 없는 코드에 소유자 승인과 소유자 예외가 주어집니다.
- 토큰의 수명이 깁니다(App 설정에 따라 8시간 액세스 토큰과 6개월 리프레시 토큰, 또는 만료 없음). 갱신하면 새 시크릿을 다시 써야 합니다.
- 토큰을 환경 변수에 절대 넣지 않는다는 현재 규칙과 충돌합니다.
- 오프라인으로 검증할 수 없고 작업에 묶을 수 없습니다.

**거부.** 개인 액세스 토큰은 같거나 더 나쁘므로(PGARD App에 묶이지도 않음) 같은 이유로 **거부**합니다.

### E. 서명되지 않은 작업 메타데이터(`GITHUB_ACTIONS`, `GITHUB_REPOSITORY`, `GITHUB_ACTOR`, `GITHUB_SHA`, 이벤트 페이로드 파일)

누구나 어떤 기계에서든 설정할 수 있습니다. 확인 결과를 바꾸는 힌트로조차 **절대 증거가 아닙니다**.

### 요약

| 후보                        | 신원        | 소유자 승인      | 현재 접근           | 기여 사실 | 작업에 묶임 | 오프라인      | 판정            |
| --------------------------- | ----------- | ---------------- | ------------------- | --------- | ----------- | ------------- | --------------- |
| A. OIDC 토큰                | 예          | 아니요           | 소유자인 경우만     | 아니요    | 예          | 서명과 클레임 | 신원의 출처     |
| B. `GITHUB_TOKEN`           | 아니요      | 아니요           | 아니요              | 예        | 아니요      | 아니요        | 사실 읽기 전용  |
| C1. 설치 토큰               | 아니요      | 아니요(App 불명) | 사실만              | 예        | 아니요      | 아니요        | 사실 읽기 전용  |
| C2. App id + 개인 키        | 아니요      | 예               | 예(A의 주체와 함께) | 예        | 아니요      | 아니요        | 승인의 출처(Q1) |
| D. 저장된 사용자 토큰 / PAT | 잘못된 주체 | 잘못된 주체      | 잘못된 주체         | 예        | 아니요      | 아니요        | 거부            |
| E. 서명되지 않은 메타데이터 | 아니요      | 아니요           | 아니요              | 아니요    | 아니요      | 해당 없음     | 거부            |

## 5. 오프라인 검증과 온라인 검증, 그리고 JWKS

**오프라인으로 검증 가능**(서명 키를 알고 나면 네트워크 없이): JWT 구조, `alg` = `RS256`, `kid`가 가리키는 키로 헤더와 페이로드에 대한 RS256 서명, `iss`, `aud`, `exp`, `nbf`, `iat`, 그리고 로컬 데이터만 필요한 모든 클레임 비교: 검증된 원격과 `repository`, 로컬 `HEAD`와 `sha`, `pgard`에 내장된 값과 `job_workflow_ref` / `job_workflow_sha`, `runner_environment`, `event_name`, `ref_type`, `run_attempt`, `actor_id == repository_owner_id`.

**GitHub API가 필요**: 서명 키 자체(JWKS 가져오기), `repository_id`, `repository_owner_id`, 기본 브랜치가 GitHub가 지금 보고하는 값과 같은지, actor가 `User` 계정인지(`GET /users/{actor}`, id가 `actor_id`와 같아야 함), App 설치(C2), 조직 멤버십, 협업자 권한, 모든 기여 사실. 확인 3~5에는 항상 API가 필요하므로 **오프라인 CI 권한 확인은 절대 `allowed`가 될 수 없습니다**. 오프라인 모드는 없습니다.

**JWKS 가져오기와 고정**(**M10-3 요구사항**):

- 발급자 `https://token.actions.githubusercontent.com`과 JWKS URL `https://token.actions.githubusercontent.com/.well-known/jwks`는 `pgard` 안의 상수입니다. 실행 중에 OpenID 설정 문서를 가져오지 **않으므로**, 바뀌거나 위조된 discovery 문서가 키의 출처를 옮길 수 없습니다. GitHub가 `jwks_uri`를 바꾸면 `pgard` 릴리스가 필요합니다.
- JWKS는 권한 확인마다 한 번, HTTPS로, 리디렉션을 따르지 않고, 짧은 타임아웃과 크기 제한을 두고, GitHub 클라이언트와 같은 강화된 fetch로 가져옵니다. `kty: RSA`, `alg: RS256`(또는 `alg` 없음), `use: sig`(또는 `use` 없음)인 키만 받으며, 모듈러스는 최소 2048비트입니다.
- JWKS는 그 한 번의 권한 확인 동안 메모리에만 두고 디스크에 쓰지 않습니다. 권한 확인 결과는 아니지만, 캐시하면 최신으로 유지해야 할 두 번째 신뢰 저장소가 생기고, 어차피 실행은 온라인입니다.
- 키 스냅샷을 신뢰 기준으로 배포하지 않습니다. 스냅샷은 GitHub가 교체해 없앤 키를 계속 받아들이게 됩니다(테스트 전용으로 두는 것은 괜찮습니다).
- 가져온 뒤에도 `kid`를 모르거나, 가져오기에 실패하거나, JWKS가 잘못된 형식이면 `github_identity`는 이유와 함께 `unverifiable`입니다. 다른 키나 디바이스 플로로 넘어가지 않습니다.

## 6. 위협 모델

자산: 권한 결정, App 개인 키(C2), 작업 실행 중의 OIDC 토큰과 설치 토큰, 러너 위의 검사 대상 코드와 결과.

신뢰 경계: GitHub 토큰 서비스와 API(서명과 사실에 대해 신뢰), 고정된 재사용 워크플로와 그것이 설치하는 `pgard` 빌드(커밋으로 고정되어 신뢰), 검사 대상 저장소의 호출자 워크플로(신뢰하지 않음: 그 브랜치에 쓰기 권한이 있으면 누구나 바꿀 수 있음), 이벤트 페이로드와 모든 환경 변수(신뢰하지 않음), 러너 기계(GitHub 호스티드일 때만 신뢰).

| #   | 위협                                                                                                                                                                                                                                                                                                                                                                        | 대응                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| T1  | **포크 풀 리퀘스트**(`pull_request`): 포크의 신뢰할 수 없는 코드가 `pgard`를 호출하는 워크플로를 실행합니다.                                                                                                                                                                                                                                                                | `event_name`은 `push` 또는 `workflow_dispatch`여야 하며 `pull_request`는 거부합니다. 포크 실행은 보통 쓰기 권한을 받지 못하고 `id-token: write`는 쓰기 권한이지만, GitHub 문서가 `id-token`의 경우를 명시하지 않으므로 설계는 여기에 기대지 않습니다. 검사할 커밋도 기본 브랜치에 있지 않습니다.                                                                                                                                                                                     |
| T2  | **`pull_request_target`**: 공개 포크에서 와도 기본 저장소의 기본 브랜치 컨텍스트에서 읽기/쓰기 `GITHUB_TOKEN`으로 실행되며, 워크플로가 PR head를 체크아웃하는 경우가 많습니다([이벤트](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows), [안전한 사용](https://docs.github.com/en/actions/reference/security/secure-use)). | `event_name`으로 거부합니다. 허용하더라도 `sha`가 기본 브랜치 커밋이므로 PR 코드를 체크아웃하면 `HEAD == sha`에서 실패하고, actor는 검사를 요청한 적 없는 PR 작성자입니다.                                                                                                                                                                                                                                                                                                           |
| T3  | **`workflow_run` 연쇄**: 다른(포크가 시작했을 수도 있는) 워크플로가 시작하는 특권 워크플로로, 앞의 워크플로에 없던 시크릿과 쓰기 토큰에 접근합니다. `sha`는 기본 브랜치 커밋이고, 앞 실행의 아티팩트는 신뢰할 수 없을 수 있습니다.                                                                                                                                          | `event_name`으로 거부합니다. 앞 실행의 출처(누가, 어떤 코드로 시작했는지)는 토큰에 없습니다.                                                                                                                                                                                                                                                                                                                                                                                         |
| T4  | **셀프 호스티드 러너**: 운영자나, 기계에 남아 있는 이전 작업의 코드가 `ACTIONS_ID_TOKEN_REQUEST_TOKEN`을 읽고, `pgard`의 nonce로 토큰을 발급받고, `pgard` 바이너리를 바꾸거나 체크아웃을 바꿀 수 있습니다([안전한 사용](https://docs.github.com/en/actions/reference/security/secure-use)).                                                                                 | `runner_environment`가 `github-hosted`여야 합니다. 이 클레임은 러너가 아니라 GitHub가 설정합니다. 셀프 호스티드는 이유와 함께 막습니다([U4](#8-증명할-수-없어-막는-것)).                                                                                                                                                                                                                                                                                                             |
| T5  | **PR이나 브랜치에서의 악의적 워크플로 수정**: 쓰기 권한이 있는 사람이 호출자 워크플로를 바꿔 `pgard` 앞에 단계를 넣거나, 조작된 입력을 넘기거나, 다른 코드를 체크아웃하거나, 토큰 요청 변수를 내보냅니다.                                                                                                                                                                   | 호출자가 바꿀 수 없는 단계로 이루어진 작업 안에서 토큰이 발급될 때만 단계가 고정됩니다. 검사 작업은 고정된 재사용 워크플로여야 합니다(`job_workflow_ref` / `job_workflow_sha`, 7.2절). 재사용 워크플로의 호출자는 호출된 작업에 단계를 추가할 수 없습니다. 입력은 허용 목록으로 정하고 검증합니다(셸에 닿는 자유 텍스트 없음). 기본 브랜치가 아닌 브랜치는 거부합니다(`ref`). 기본 브랜치에 병합된 변경은 저장소 자신의 결정이며, 그때 주체는 푸시한 사람이고 확인 3~5로 검사합니다. |
| T6  | **토큰 재사용(replay)**: 로그, 아티팩트, 다른 프로세스에서 복사한 OIDC 토큰을 나중의 `pgard` 실행에 제시합니다.                                                                                                                                                                                                                                                             | `pgard`가 같은 프로세스에서 만든 128비트 무작위 nonce로 `aud = "pgard-ci:v1:" + <nonce>`를 지정해 직접 토큰을 요청하고, 그 audience만 받습니다. 다른 프로세스나 다른 호출자를 위해 발급된 토큰은 audience가 다릅니다. 추가로 `iat`가 로컬 시계와 60초 이내이고 `exp`가 미래여야 합니다. 아무것도 저장하지 않으므로 `jti` 목록은 필요 없습니다. 설치 토큰(C2)은 실행마다 이 저장소만, 읽기 전용으로 발급하고, 권한 확인이 끝나면 폐기합니다(`DELETE /installation/token`).            |
| T7  | **GitHub 밖에서 실행**: 노트북이나 다른 CI에서 `GITHUB_ACTIONS=true`와 공격자 서버를 가리키는 가짜 요청 변수로 `pgard`를 실행합니다.                                                                                                                                                                                                                                        | 환경 변수는 증거가 아닙니다. 공격자 서버는 이 프로세스의 nonce를 audience로 하는, GitHub가 서명한 토큰을 돌려줘야 합니다. 즉 7.3절의 모든 클레임(기본 브랜치, 허용된 이벤트, GitHub 호스티드, 토큰을 중계하지 않는 단계로 된 고정 재사용 워크플로)을 만족하는 대상 저장소의 작업 안에서 실시간으로 발급받아야 합니다. 다른 작업에서 나온 토큰은 적어도 하나의 클레임에서 실패합니다.                                                                                                 |
| T8  | **포크 네트워크의 SHA로 고정된 재사용 워크플로**: 포크는 객체를 공유하므로 `uses: JadenMeister/pgard/...@<sha>`가 포크에만 있는 커밋으로 해석될 수 있고, 그래도 `job_workflow_ref`는 `JadenMeister/pgard`를 가리킵니다.                                                                                                                                                     | `pgard`는 정확히 하나의 `job_workflow_sha`, 즉 자기 릴리스를 빌드한 커밋만 받습니다(릴리스 때 내장, **M10-3 요구사항**). `job_workflow_ref`는 `JadenMeister/pgard/.github/workflows/<파일>@<그 sha>`와 같아야 합니다. 포크 커밋, 더 오래되거나 새로운 워크플로, 브랜치나 태그 ref는 거부합니다. 릴리스 파이프라인은 바로 그 커밋으로 npm 패키지를 빌드하고 그에 대한 provenance를 게시해야 합니다.                                                                                   |
| T9  | **다른 사람의 재실행**: `run_attempt > 1`은 첫 시도의 `actor`를 유지하고, 재실행은 그 actor의 권한을 씁니다.                                                                                                                                                                                                                                                                | `run_attempt`는 `1`이어야 합니다. 재실행은 새 실행(push 또는 `workflow_dispatch`)을 시작하라는 이유와 함께 막습니다. Q2 참고.                                                                                                                                                                                                                                                                                                                                                        |
| T10 | **봇이나 App actor**(Dependabot, `github-actions[bot]`, 다른 App)가 실행을 시작합니다.                                                                                                                                                                                                                                                                                      | `GET /users/{actor}`가 `type: User`와 `id == actor_id`를 돌려줘야 합니다. 아니면 `github_identity`가 실패합니다: 평가할 사람이 없습니다.                                                                                                                                                                                                                                                                                                                                             |
| T11 | **App 개인 키 탈취(C2)**: 그 시크릿을 읽을 수 있는 워크플로는 그 App의 모든 설치에 대해 토큰을 발급할 수 있습니다.                                                                                                                                                                                                                                                          | 키는 기본 브랜치로 제한된 **환경(environment)** 시크릿으로 두고, 호출자는 고정된 워크플로에만 넘깁니다. `pgard`는 키를 한 번 읽고 자기 환경에서 지우며, 절대 로그에 남기지 않고, 이 저장소만 읽기 전용 토큰을 발급하고 폐기합니다. 키를 훔쳐도 소유자, 협업자, 기여자가 아닌 주체에 대해 확인을 통과시킬 수는 없습니다. 확인 3~5는 OIDC actor에 대해 평가되기 때문입니다.                                                                                                            |
| T12 | **이름이 바뀌거나 이전된 저장소, 원격의 대소문자 차이**.                                                                                                                                                                                                                                                                                                                    | `repository_id`와 `repository_owner_id`(숫자)를 `GET /repos`와 비교합니다. 이름은 현재처럼 정확히 비교합니다(대소문자만 다른 조직 이름은 `unverifiable`).                                                                                                                                                                                                                                                                                                                            |
| T13 | **체크아웃 후 작업 트리 변경**(앞 단계가 파일을 수정).                                                                                                                                                                                                                                                                                                                      | 검사 작업에는 호출자의 앞 단계가 없습니다(T5). 현재와 마찬가지로 확인은 작업 트리가 `HEAD`와 같음을 증명하지 않으므로, `pgard`는 CI에서 추가로 깨끗한 작업 트리를 요구합니다(`git status --porcelain`이 비어 있음, **M10-3 요구사항**).                                                                                                                                                                                                                                              |
| T14 | **엔터프라이즈 전용 발급자나 GitHub Enterprise Server**: 다른 `iss`, 키, API 호스트.                                                                                                                                                                                                                                                                                        | `iss`는 github.com 발급자와 정확히 같아야 합니다. 그 외는 `unverifiable`입니다([9절](#9-범위-밖), Q8).                                                                                                                                                                                                                                                                                                                                                                               |

## 7. 권장 설계

### 7.1 개요

1. **신원**은 `pgard`가 작업 안에서 새 nonce audience로 직접 요청하고 GitHub JWKS로 검증한 Actions OIDC 토큰에서만 옵니다(후보 A).
2. **작업이 고정**됩니다: 실행 중인 `pgard`를 빌드한 바로 그 커밋으로 고정된 PGARD 자체의 재사용 워크플로를, GitHub 호스티드 러너에서, 기본 브랜치에 대한 `push` 또는 `workflow_dispatch`로, 첫 시도에 실행한 작업의 토큰만 받습니다.
3. 확인 3~5의 **주체**는 OIDC actor(`actor_id`, `User`)입니다. 기존 확인 함수는 로그인한 사용자 대신 그 주체로 그대로 실행됩니다.
4. **소유자 승인**에는 현재와 같은 강도의 App 증거가 필요합니다: 후보 C2(저장소 소유자가 가진, 설정된 App의 App id와 개인 키). 없으면 소유자 승인은 `unverifiable`이고 검사는 막힙니다. 기본 제공 PGARD App은 지금 이 경우입니다(Q1).
5. **사실**은 C2 설치 토큰으로 읽고, C2가 없으면 `GITHUB_TOKEN`(후보 B)으로 읽어 각 확인이 여전히 자기 이유를 보고하게 합니다.
6. CI 증거 제공자는 명시적으로 선택합니다(제안: `--identity github-actions`, Q7). 없으면 아무것도 바뀌지 않습니다: 터미널과 저장된 로그인이 없으면 여전히 "Not signed in"으로 막힙니다. 있으면 키체인이나 디바이스 플로로 넘어가지 않습니다.

### 7.2 워크플로 모양

검사 대상 저장소는 PGARD의 재사용 워크플로를 호출하며, 그 작업에 단계를 추가할 수 없습니다.

```yaml
# 검사 대상 저장소의 .github/workflows/pgard.yml (호출자)
on:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
  id-token: write
jobs:
  scan:
    uses: JadenMeister/pgard/.github/workflows/ci-scan.yml@<40자리 hex 릴리스 커밋>
    with:
      app-id: "123456" # 숫자만; 설정된 App(C2)
    secrets:
      PGARD_APP_PRIVATE_KEY: ${{ secrets.PGARD_APP_PRIVATE_KEY }}
```

재사용 워크플로(이 저장소에 둠, **M10-3 요구사항**): GitHub 호스티드 이미지에서 `runs-on`, SHA로 고정한 `actions/checkout`에 `persist-credentials: false`와 `fetch-depth: 30`(기여 후보에 충분), SHA로 고정한 `actions/setup-node`, 이 커밋에서 빌드한 `pgard` 버전을 무결성과 provenance를 확인해 정확히 설치, `pgard scan --identity github-actions --format sarif`(또는 json) 실행. 어떤 단계도 토큰 요청 변수를 출력하거나 내보내지 않고, 검증되지 않은 입력은 셸에 닿지 않습니다.

### 7.3 OIDC 토큰에 대한 정확한 확인

따로 적지 않으면 모든 비교는 대소문자를 구분하는 정확한 문자열 비교입니다. 클레임이 없거나, JSON 유형이 틀리거나, 중복되면 `github_identity`는 이유에 클레임 이름을 담아 `unverifiable`입니다(값이 민감할 수 있으면 값은 담지 않음). GitHub 토큰에서 숫자 클레임은 10진 문자열이며, 그 외는 거부합니다.

| 클레임 / 필드                                                                                                        | 요구 값                                                                                                                         | 기대 값의 출처               |
| -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| 헤더 `alg`                                                                                                           | `RS256`(`none`, `HS*` 등 그 외는 거부)                                                                                          | 상수                         |
| 헤더 `kid`                                                                                                           | 있어야 하고, 가져온 JWKS의 키 정확히 하나와 일치                                                                                | JWKS(5절)                    |
| 서명                                                                                                                 | 그 키로 `header.payload`에 대해 유효한 RS256                                                                                    | JWKS                         |
| `iss`                                                                                                                | `https://token.actions.githubusercontent.com`                                                                                   | 상수                         |
| `aud`                                                                                                                | `pgard-ci:v1:<nonce>`; 배열이면 원소가 정확히 하나이고 그 값과 같음                                                             | 이 프로세스에서 만든 nonce   |
| `iat`                                                                                                                | 로컬 시계 ±60초 이내                                                                                                            | 시계                         |
| `nbf`                                                                                                                | ≤ 현재 + 60초                                                                                                                   | 시계                         |
| `exp`                                                                                                                | > 현재, 그리고 `exp − iat` ≤ 3600초                                                                                             | 시계                         |
| `runner_environment`                                                                                                 | `github-hosted`                                                                                                                 | 상수                         |
| `event_name`                                                                                                         | `push` 또는 `workflow_dispatch`                                                                                                 | 상수 허용 목록               |
| `ref_type`                                                                                                           | `branch`                                                                                                                        | 상수                         |
| `ref`                                                                                                                | `refs/heads/` + 이번 실행에서 GitHub가 보고한 기본 브랜치                                                                       | `GET /repos`(온라인)         |
| `run_attempt`                                                                                                        | `1`                                                                                                                             | 상수(Q2)                     |
| `repository`                                                                                                         | 검증된 원격의 `owner/name`, 그리고 GitHub의 `full_name`과 같음                                                                  | 로컬 원격, `GET /repos`      |
| `repository_id`                                                                                                      | GitHub의 저장소 `id`와 같음                                                                                                     | `GET /repos`                 |
| `repository_owner` / `repository_owner_id`                                                                           | GitHub의 `owner.login` / `owner.id`와 같음                                                                                      | `GET /repos`                 |
| `sha`                                                                                                                | 40자리 hex, 로컬 `HEAD`와 같음(`HEAD`는 그 커밋의 체크아웃이어야 하고 작업 트리는 깨끗해야 함)                                  | 로컬 Git                     |
| `job_workflow_ref`                                                                                                   | `JadenMeister/pgard/.github/workflows/ci-scan.yml@<BUILD_SHA>`                                                                  | 릴리스에 내장                |
| `job_workflow_sha`                                                                                                   | `<BUILD_SHA>`                                                                                                                   | 릴리스에 내장                |
| `actor_id` / `actor`                                                                                                 | 10진 / 비어 있지 않음; `GET /users/{actor}`가 `type: User`와 `id == actor_id`를 돌려줌                                          | `GET /users/{actor}`(온라인) |
| `sub`, `workflow`, `workflow_ref`, `workflow_sha`, `run_id`, `environment`, `ref_protected`, `repository_visibility` | 결정에 쓰지 않음. 실행을 추적할 수 있도록 `workflow_ref`와 `run_id`는 `github_identity` 이유에 적음. `ref_protected`는 Q4 참고. | 해당 없음                    |

토큰 요청 자체: `pgard`는 `ACTIONS_ID_TOKEN_REQUEST_URL`과 `ACTIONS_ID_TOKEN_REQUEST_TOKEN`을 읽고, URL이 HTTPS여야 하며, `audience=pgard-ci:v1:<nonce>`를 붙이고, 두 변수와 토큰을 절대 로그에 남기지 않습니다. 공격자가 통제하는 요청 URL은 기껏해야 토큰을 돌려줄 수 있을 뿐이며, 그 토큰은 위의 모든 확인을 통과해야 합니다.

### 7.4 CI에서의 다섯 확인

| 확인              | CI에서                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `repository`      | `verifyRepository`는 그대로. 추가로(**M10-3 요구사항**): 작업 트리가 깨끗하고, 원격의 `owner/name`이 OIDC `repository`와 같음. (`HEAD == sha`는 `github_identity`에서 토큰과 함께 확인합니다. 토큰은 로컬 확인이 통과한 뒤에만 요청하여 현재의 순서를 유지하기 때문입니다.)                                                                                                                                                                                                                                                                                                                        |
| `github_identity` | OIDC 토큰을 요청하고 검증(7.3). 통과 이유 예: "GitHub Actions run 123 (attempt 1) of `owner/repo` on `refs/heads/main`, triggered by `alice` (OIDC token verified)." 주체는 `User`로 확인된 `{ id: actor_id, login: actor }`.                                                                                                                                                                                                                                                                                                                                                                      |
| `current_access`  | 사실 토큰으로 저장소를 읽음(`GET /repos`). 404나 읽기 불가는 현재와 같음. 그다음 주체에 대해: 개인 소유자(`actor_id == owner.id`): 통과, 조직 소유자(주체의 활성 `admin` 멤버십, C2 설치 토큰으로 한 번 읽고 같은 실행의 소유자 승인에서 재사용): 통과, 그 외: `GET /repos/{owner}/{repo}/collaborators/{actor}/permission`이 `read`, `write`, `admin` 중 하나여야 함. 쓸 수 있는 어떤 토큰으로도 그 권한을 읽을 수 없으면 `unverifiable`. `GET /repos`의 `permissions` 객체는 주체가 아니라 토큰을 설명하므로 CI에서는 **절대** 쓰지 않음.                                                        |
| `owner_approval`  | C2가 있으면: 설정된 App의 JWT로 `GET /repos/{owner}/{repo}/installation`; `app_id` = 설정된 App id, `account.id` = `owner.id`, `target_type` = 소유자 유형; 이 저장소로 제한한 읽기 전용 설치 토큰 발급; 저장소 포함. 조직이면 추가로 `GET /orgs/{org}/memberships/{actor}`가 `state: active`, `role: admin`, `user.id == actor_id`, `organization.id == owner.id`. 같은 `OwnerEvidence`를 만듦(`userId = actor_id`). C2가 없으면: `unverifiable`, "CI cannot prove that the repository owner approved PGARD: provide the App id and private key of the configured GitHub App (see the CI guide)." |
| `contribution`    | `verifyContribution`을 그대로, `user = 주체`, 로컬 후보(`fetch-depth: 30`으로 최대 30개), 사실 토큰, 이번 실행의 소유자 승인에서만 나온 `ownerEvidence`로 실행.                                                                                                                                                                                                                                                                                                                                                                                                                                    |

게이트 코드는 신원 단계에서만 바뀝니다(**M10-3 요구사항**): `getGitHubSession`이 두 제공자(디바이스 플로 또는 GitHub Actions OIDC) 중 하나가 되어 각각 주체와 사실용 클라이언트를 돌려주고, `verifyCurrentAccess`에 CI용 주체 기반 변형이 생깁니다. `AUTHORIZATION_CHECK_ORDER`, `isAuthorizationAllowed`, "절대 캐시하지 않음" 규칙은 바뀌지 않습니다.

## 8. 증명할 수 없어 막는 것

| #   | 상황                                                                                      | 증명할 수 없는 이유                                                                                         | 결과                                                              |
| --- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| U1  | 기본 제공 PGARD App의 소유자 승인(작업에서 쓸 수 있는 개인 키 없음)                       | 설치가 어느 App의 것인지는 App의 JWT만 알려 줍니다. 키는 관리자의 것이며 공유하지 않습니다.                 | `owner_approval` `unverifiable`(Q1)                               |
| U2  | 풀 리퀘스트 코드(`pull_request`, `pull_request_target`)                                   | 신뢰할 수 없는 코드, 커밋이 기본 브랜치에 없음, 포크 실행은 쓰기 권한 없음, actor가 검사를 요청하지 않았음. | `github_identity` `failed`(허용되지 않은 이벤트)                  |
| U3  | `workflow_run`, `schedule`, `issue_comment`, `repository_dispatch` 등 그 밖의 모든 이벤트 | 토큰에 연쇄의 출처가 없음. `schedule`에서 `actor`의 의미는 토큰 레퍼런스에 문서화되어 있지 않음.            | `github_identity` `failed`(허용되지 않은 이벤트, `schedule`은 Q3) |
| U4  | 셀프 호스티드 러너                                                                        | 러너 운영자가 토큰 요청, 바이너리, 체크아웃을 통제하며, 기계 위의 어떤 것도 그 반대를 증명할 수 없음.       | `github_identity` `failed`                                        |
| U5  | 재실행(`run_attempt > 1`)                                                                 | 재실행을 시작한 사람(`triggering_actor`)이 토큰에 없음.                                                     | `github_identity` `failed`(Q2)                                    |
| U6  | 봇이나 App actor                                                                          | 평가할 사람이 없음.                                                                                         | `github_identity` `failed`                                        |
| U7  | 고정된 재사용 워크플로가 아닌 작업(인라인 단계, 다른 버전)                                | 앞 단계가 토큰을 발급받아 중계하거나 코드를 바꿀 수 있음.                                                   | `github_identity` `failed`                                        |
| U8  | 쓸 수 있는 어떤 토큰도 협업자 권한을 읽을 수 없을 때 협업자의 현재 접근                   | 필요한 권한이 문서에 없음.                                                                                  | `current_access` `unverifiable`                                   |
| U9  | GitHub Enterprise Server, 엔터프라이즈 전용 발급자, 다른 CI 시스템                        | 다른 발급자, 키, API. 범위 밖.                                                                              | `github_identity` `unverifiable`                                  |
| U10 | 작업 트리가 GitHub에 있는 것과 같은지                                                     | 현재와 같이 확인은 모든 파일이 아니라 `HEAD`를 묶습니다. CI는 깨끗한 작업 트리 요구만 더합니다.             | 로컬과 같은, 문서화된 한계                                        |

이들 모두 종료 코드 3과, 해결 방법이 있으면 그것을 담은 이유와 함께 막힙니다.

## 9. 범위 밖

- **다른 CI 시스템**(GitLab CI, Jenkins, CircleCI, Buildkite, Azure Pipelines 등). PGARD의 소유자 승인은 저장소를 소유한 GitHub 계정에 GitHub App을 설치하는 것이며, 이를 증명할 수 있는 것은 GitHub뿐입니다. GitLab CI OIDC 토큰은 GitHub 저장소나 GitHub 사용자가 아니라 GitLab 프로젝트와 파이프라인을 증명하며, 둘을 잇는 것은 없습니다(미러는 어디든 가리킬 수 있음). Jenkins에는 플랫폼이 서명한 작업 신원이 아예 없습니다. 시스템마다 자체 발급자, 클레임, 위협 모델, GitHub 계정과의 대응이 필요하므로 각각 별도 설계가 필요합니다. 그때까지 `--identity`는 `github-actions`만 받고, 이 시스템들은 지금과 같이 터미널과 저장된 로그인 없이는 막힙니다.
- **GitHub Enterprise Server와 엔터프라이즈 전용 발급자**(Q8): 다른 발급자, 키 집합, API 호스트.
- **CI에서 풀 리퀘스트 검사**(U2): 별도 설계가 필요합니다.
- **결과 업로드**(예: SARIF를 code scanning에 올리기): 바뀌지 않습니다. README에 이미 적힌 대로, 막힌 검사도 막힌 결과 문서를 만듭니다.

## 10. M10-3 요구사항과 테스트 계획

이 문서에 나온 요구사항을 한 목록으로: 넘어가기(fallback) 없는 `--identity github-actions` 제공자(이름은 Q7에 따름), 프로세스별 nonce audience를 쓰는 OIDC 요청, 발급자와 JWKS URL을 고정하고 JWKS는 메모리에만 두는 JWT 검증, 7.3절의 정확한 클레임 표, 각 릴리스에 내장한 빌드 커밋(`BUILD_SHA`)과 그 커밋에서 provenance와 함께 패키지를 빌드하는 릴리스 파이프라인, 재사용 워크플로 `ci-scan.yml`, CI의 깨끗한 작업 트리 확인, CI용 주체 기반 `current_access`, C2 소유자 승인(App JWT, 설치 조회, 제한된 읽기 전용 설치 토큰, 폐기, 키 관리), CI에 대한 README와 CLI 도움말(무엇이 왜 막히는지 포함).

테스트(실제 GitHub 호출 없음, 가짜 JWKS로 제공하는 테스트 키로 서명한 토큰):

- 7.3절의 각 행을 하나씩 바꾼 경우(잘못된 `iss`, `aud`, 만료, 미래의 `iat`, `alg: none`, 공개 키를 비밀로 쓴 `HS256`, 모르는 `kid`, `self-hosted`, `pull_request`, `pull_request_target`, `workflow_run`, `run_attempt: "2"`, 다른 브랜치의 `ref`, `sha` ≠ `HEAD`, 다른 커밋의 `job_workflow_sha`, 다른 저장소의 `job_workflow_ref`, 빠진 클레임, 문자열 대신 숫자)는 기대한 이유와 함께 막힘;
- 다른 프로세스의 nonce를 가진 토큰(재사용)은 막힘;
- 요청 변수 없이 `GITHUB_ACTIONS=true`인 경우와, 다른 저장소에 대해 유효하게 서명된 토큰을 돌려주는 서버를 요청 변수가 가리키는 경우 모두 막힘;
- 봇 actor는 막힘. 개인 소유자, 조직 소유자, 기여가 있거나 없는 협업자는 로컬 테스트와 같이 동작;
- C2가 없으면 `owner_approval`은 `unverifiable`이고 나머지는 여전히 자기 이유를 보고;
- JWKS 가져오기 실패, 리디렉션, 너무 큰 본문: `unverifiable`, 넘어가기 없음;
- `isAuthorizationAllowed`와 다섯 확인의 순서는 그대로(기존 테스트가 계속 통과).

## 11. 소유자에게 묻는 열린 질문

1. **Q1. CI의 소유자 승인 증거.** 기본 제공 PGARD App으로는 CI에서 소유자 승인을 증명할 수 없습니다(U1). 선택지: (a) 저장소 소유자가 키를 가진 **직접 등록한 App으로 C2**, 키는 환경 시크릿에 둠(권장. 현재의 `PGARD_GITHUB_APP_CLIENT_ID` 재정의와 같은 신뢰: 어느 App인지는 설정할 수 있고, 소유자 계정에의 설치가 증거); (b) 기본 제공 App의 키를 가진, 관리자가 운영하는 서비스가 OIDC 토큰을 검증하고 설치 여부에 답함. "검사는 GitHub에만 연결한다"를 깨고 운영할 서비스가 생김; (c) 기본 브랜치에 소유자가 서명한 정책 파일 같은 새로운 종류의 증거. 정책 변경이므로 별도 검토가 필요하고, 조직 소유권은 여전히 `GITHUB_TOKEN`으로 읽을 수 없음. (a)를 받아들일 수 있는지, 그리고 (b)나 (c)가 정해질 때까지 기본 제공 App은 CI에서 막힌 채로 둘지?
2. **Q2. 재실행.** 모든 `run_attempt > 1`을 막을지(권장. 재실행한 사람을 모르므로), 아니면 재실행을 받고 주체가 첫 시도의 actor라고 문서화할지?
3. **Q3. `schedule`.** 예약 검사를 허용할지? 토큰 레퍼런스는 예약 실행에서 `actor`가 누구인지 문서화하지 않습니다. 권장: 문서화될 때까지 막음.
4. **Q4. `ref_protected`.** `ref_protected == "true"`(기본 브랜치의 브랜치 보호나 ruleset)를 요구할지? 보호를 요구하지 않는 로컬보다 엄격합니다. 권장: 요구하지 않되 이유에 적음.
5. **Q5. 풀 리퀘스트 검사.** CI에서 PR 코드를 검사하는 별도 설계(포크 처리와 다른 기여 모델 포함)를 계획할지, 아니면 CI는 기본 브랜치로 한정할지?
6. **Q6. 셀프 호스티드 러너.** 영구히 막을지(권장), 아니면 증명할 수 없음을 알면서 소유자가 선언하는 예외를 설계할지?
7. **Q7. CI 선택 방법.** 플래그(`--identity github-actions`), 환경 변수(`PGARD_IDENTITY=github-actions`), 또는 둘 다? 권장: 플래그만, 자동 감지는 절대 하지 않음.
8. **Q8. GitHub Enterprise.** ghe.com이나 GitHub Enterprise Server가 나중에 범위에 들어오는지? 다른 발급자와 API 호스트가 필요합니다.
9. **Q9. 환경 변수의 App 키.** C2는 작업 안에 개인 키가 필요하며, 보통 시크릿에서 온 환경 변수로 받습니다. 사용자 토큰을 절대 환경 변수에 넣지 않는다는 현재 규칙과 나란히 이것을 받아들일 수 있는지(키는 사용자 토큰이 아니라 App 자격 증명), 아니면 `pgard`가 파일 경로에서만 읽어야 하는지?
10. **Q10. 릴리스 결합.** 릴리스마다 정확히 하나의 `job_workflow_sha`만 받을지(권장. 사용자는 버전과 함께 고정 SHA를 갱신해야 함), 아니면 받아들일 SHA의 공개 목록을 둘지(그 자체의 무결성 방안이 필요)?

## 12. 참고 자료

GitHub 문서(이 설계를 위해 2026년 10월에 읽음):

- OpenID Connect 레퍼런스(클레임, 발급자, audience, subject 형식, 토큰 요청): <https://docs.github.com/en/actions/reference/security/oidc>
- OpenID Connect 개념(수명: 단일 작업 동안 유효): <https://docs.github.com/en/actions/concepts/security/openid-connect>
- Actions 발급자의 OpenID 설정과 JWKS: <https://token.actions.githubusercontent.com/.well-known/openid-configuration>, <https://token.actions.githubusercontent.com/.well-known/jwks>
- 재사용 워크플로와 OIDC(`job_workflow_ref`, 호출자 클레임): <https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows>
- 워크플로를 시작하는 이벤트(`pull_request`, `pull_request_target`, `workflow_run`, 이벤트별 `GITHUB_SHA` / `GITHUB_REF`): <https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows>
- 워크플로 문법, `permissions`(`id-token: write`, 포크 동작): <https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions>
- 컨텍스트(`github.actor`, `github.triggering_actor`, `github.run_attempt`): <https://docs.github.com/en/actions/reference/workflows-and-actions/contexts>
- `GITHUB_TOKEN`: <https://docs.github.com/en/actions/concepts/security/github_token>
- 안전한 사용 레퍼런스(셀프 호스티드 러너, 고정, `pull_request_target`과 `workflow_run`): <https://docs.github.com/en/actions/reference/security/secure-use>
- GitHub App 설치로 인증하기: <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation>
- REST API: Apps(`GET /repos/{owner}/{repo}/installation`, 설치 토큰): <https://docs.github.com/en/rest/apps/apps>
- REST API: 협업자(사용자의 권한): <https://docs.github.com/en/rest/collaborators/collaborators>
- REST API: 조직 멤버(멤버십 `state`, `role`): <https://docs.github.com/en/rest/orgs/members>
