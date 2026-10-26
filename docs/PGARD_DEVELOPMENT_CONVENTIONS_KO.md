# PGARD 구현·커밋·코드 컨벤션

> **참고:** 이 문서는 MVP 기획 기록입니다. 현재 동작은 [README.ko.md](../README.ko.md)([English](../README.md))가 설명하며, 내용이 다르면 README가 맞습니다.

**상태:** 구현 착수용 제안. `pgard`라는 제품/CLI 이름과 로컬 실행·권한·검사 범위는 기존 합의 사항이다. TypeScript/Node.js/React는 아직 추천 스택이므로 최종 언어가 바뀌면 문법 관련 규칙만 해당 언어에 맞게 조정한다. 이 문서는 실제 Git 저장소에 코드를 작성하기 전 에이전트들이 공유할 작업 기준이다.

## 1. 커밋 단위

한 커밋은 **독립적으로 설명·검토·되돌릴 수 있는 한 가지 동작 변화**를 담는다. 한 파일에 여러 커밋이 생겨도 되고, 한 동작을 완성하는 코드·필요한 테스트·문서는 같은 커밋에 넣는다. 단순히 파일 수나 작업 시간으로 커밋을 나누지 않는다.

- 권한 게이트와 검사 규칙, CLI 화면, 보고서 렌더링을 한 커밋에 섞지 않는다. 공통 계약을 바꾸는 경우 계약 변경과 모든 호출부 수정은 함께 넣어 저장소가 중간 커밋에서도 빌드되게 한다.
- 새 보안 규칙은 규칙 ID, 탐지 조건, 안전한 반례, 결과 문구, 필요한 검증을 한 단위로 묶는다. 첫 SQL 규칙 전체가 크면 라이브러리나 입력→실행 흐름별로 쪼갠다.
- 수정 커밋은 원인·행동 변화가 분명해야 한다. 단순 포맷팅은 동작 변경과 분리한다. 각 커밋에 다른 사람이 이해할 수 있는 커밋 메시지를 남긴다.
- 커밋 전 staged diff의 대상 파일, 비밀정보, 생성물, 임시 보고서를 확인한다. 소스 코드나 토큰을 커밋 메시지·테스트 출력·스크린샷에 넣지 않는다. 공용 브랜치의 공개된 커밋은 담당자와 조율 없이 재작성하지 않는다.

### 권장 구현 순서와 커밋 예시

아래는 의존성 순서의 예시이며 **커밋 개수를 강제하지 않는다**. 큰 항목은 더 작게 나누되, 권한 게이트가 검증되기 전에 실제 검사를 허용하는 커밋은 만들지 않는다.

| 순서 | 예시 커밋                                                        | 독립적으로 확인할 결과                                                      |
| ---- | ---------------------------------------------------------------- | --------------------------------------------------------------------------- |
| 1    | `chore(repo): scaffold workspace and shared checks`              | 앱/패키지 경계, 공통 타입 검사·포맷 기준                                    |
| 2    | `feat(findings): define scan scope and result contract`          | `code/history/web`, `completed/partial/not_tested/not_selected` 계약        |
| 3    | `feat(policy): reject scans without repository authorization`    | owner 승인·현재 접근·반영된 기여 중 하나라도 없으면 분석 차단               |
| 4    | `feat(cli): add project verification command`                    | `pgard project verify`의 항목별 통과·거절 이유                              |
| 5    | `feat(source-analysis): detect unsafe SQL interpolation`         | 첫 지원 라이브러리의 양성·음성 사례와 의심 판정                             |
| 6    | `feat(git-history): find tracked secret exposure`                | 현재 추적 상태와 과거 이력 구분, 값 가림                                    |
| 7    | `feat(http-local): restrict scans to confirmed loopback targets` | 포트 확인 Y/N, 리다이렉트 제한, 시간·URL 수 상한                            |
| 8    | `feat(cli): add scoped and combined scans`                       | `pgard scan`, `pgard scan code/history/web`, `pgard scan all`의 범위별 결과 |
| 9    | `feat(report): export redacted HTML and PDF`                     | 같은 결과 스키마에서 두 형식 생성, 파일 덮어쓰기 방지                       |
| 10   | `feat(local-web): show ephemeral scan dashboard`                 | `pgard dashboard` 런처, 로컬 API 보호, 종료 시 상태 폐기                    |
| 11   | `docs(repo): add Korean and English usage guides`                | EN/KO README, 로컬 처리·외부 통신·한계 설명                                 |

## 2. 커밋 메시지

형식은 `type(scope): 동사로 시작하는 짧은 요약`이다. 제목은 영어로 작성하고 한 줄 72자 이내를 목표로 한다. 본문이 필요하면 빈 줄 뒤에 **왜 바꾸는지**, **동작·보안 영향**, **검증 결과**를 적는다. 이슈 번호가 있으면 본문에 연결한다. 제목만으로 변경 이유가 모호한 `update`, `fix stuff`, `misc`는 쓰지 않는다.

| type       | 용도                                       |
| ---------- | ------------------------------------------ |
| `feat`     | 사용자 또는 다른 패키지가 사용할 기능 추가 |
| `fix`      | 기존 동작·보안 문제 수정                   |
| `refactor` | 외부 동작을 바꾸지 않는 구조 개선          |
| `test`     | 기존 동작을 위한 검증만 추가·수정          |
| `docs`     | 문서만 변경                                |
| `chore`    | 저장소 관리·설정·생성물 정리               |
| `build`    | 패키징·빌드 체계 변경                      |
| `ci`       | 자동 검사 설정 변경                        |
| `perf`     | 측정 근거가 있는 성능 개선                 |

`scope`는 실제 소유 패키지/앱 이름을 쓴다: `repo`, `cli`, `local-web`, `scan-core`, `policy`, `github-auth`, `git-history`, `source-analysis`, `http-local`, `advisory`, `findings`, `report`. 여러 영역을 바꾸더라도 주된 책임 경계를 하나 고르고, 계약 변경 이유와 영향을 본문에 적는다. 파괴적인 계약 변경은 `feat(findings)!: ...`와 본문의 `BREAKING CHANGE:`로 표시한다. 보안 수정은 별도 모호한 type 대신 `fix(policy): ...`처럼 문제 영역을 scope로 나타낸다.

```text
fix(policy): reject unverified owner approval

An installation alone does not prove owner approval for this repository.
Keep the scan blocked when approval evidence is unavailable.

Verified: policy denial cases and CLI error mapping.
```

## 3. 브랜치·PR 경계

- 브랜치 이름은 `feat/cli-scoped-scans`, `fix/policy-owner-approval`처럼 `type/짧은-kebab-case`를 권장한다. 한 PR은 하나의 하위 시스템 또는 하나의 세로 기능을 검토할 수 있는 크기로 만든다. 여러 패키지가 함께 바뀌어야 하면 공통 계약과 소비자 변경을 PR 설명에서 연결한다.
- 각 PR에는 목적, 범위, 결과 스크린샷 또는 CLI 출력(민감값 가림), 테스트 결과, 미지원/부분 검사 범위, 보안 영향, 되돌리는 방법을 적는다. 리뷰 대기 PR마다 별도 채팅에서 검토하고 발견 문제를 해당 PR에서 해결한 뒤 총괄에게 보고한다.
- 권한 정책·결과 스키마·로컬 웹 보안 경계를 바꾸는 PR은 해당 패키지 담당자의 검토를 받아야 한다. 코드 소유권 변경과 패키지 간 인터페이스 변경은 담당자끼리 직접 협의하고 총괄에게 알린다. main 병합은 요구된 리뷰·CI·보호 규칙이 통과한 뒤 조율한다.

## 4. 코드 구조와 의존성

- `apps/cli`와 `apps/local-web`은 별도 실행 앱이다. 둘은 서로의 소스를 import하지 않고 `packages/scan-core`, `packages/findings`, `packages/report` 등의 공통 계약을 사용한다. `pgard dashboard`는 로컬 웹 앱을 명시적으로 시작하는 런처다.
- 검사는 `scan-core`가 조정하고, 권한은 `policy`가 결정한다. UI나 개별 검사기가 승인 실패를 자체적으로 통과시키지 않는다. 브라우저 번들에는 파일 시스템 접근, GitHub 토큰, 스캔 엔진 코드를 넣지 않는다.
- 화면 한 곳에서만 쓰는 컴포넌트는 해당 기능 폴더에 둔다. 두 화면 이상에서 쓰면 CLI의 `ui/components/` 또는 웹의 `client/components/`로 옮긴다. CLI와 웹의 렌더링 컴포넌트는 공유하지 않으며, 결과 타입·집계·가림 함수만 공통 패키지에서 재사용한다.
- 외부 입력(CLI 인자, API 요청, Git 출력, 파일 내용)은 경계에서 검증한다. 프로젝트 파일은 읽기 전용으로 다루고 프로젝트 스크립트·빌드·의존성 설치를 실행하지 않는다. 비밀정보는 로깅·예외·보고서에 원문을 남기지 않는다.

## 5. 이름 규칙 (추천 TypeScript 스택 기준)

| 대상                    | 규칙                                        | 예시                                                         |
| ----------------------- | ------------------------------------------- | ------------------------------------------------------------ |
| 일반 파일·폴더          | `kebab-case`                                | `verify-repository-access.ts`, `git-history/`                |
| React/TUI 화면·컴포넌트 | `PascalCase.tsx` 또는 TUI 구현에 따른 `.ts` | `FindingsPage.tsx`, `ChoiceList.ts`                          |
| 변수·매개변수           | 의미 있는 `camelCase`; 컬렉션은 복수형      | `targetPort`, `findings`, `approvedRepos`                    |
| 불리언                  | `is/has/can/should`로 시작                  | `isLoopback`, `hasOwnerApproval`, `canScan`                  |
| 함수                    | 행동을 나타내는 `camelCase` 동사 + 목적어   | `verifyRepositoryAccess`, `scanGitHistory`, `redactEvidence` |
| 타입·인터페이스·클래스  | `PascalCase`; `I` 접두어 금지               | `ScanRequest`, `Finding`, `OwnerApprovalEvidence`            |
| 모듈 수준 상수          | 고정된 설정값만 `UPPER_SNAKE_CASE`          | `MAX_WEB_PAGES`, `DEFAULT_TIMEOUT_MS`                        |
| JSON/API 필드           | `camelCase`, 기존 공통 스키마와 일치        | `overallStatus`, `ruleId`, `webOrigin`                       |
| CLI 명령·옵션           | 소문자 단어와 `kebab-case` 플래그           | `project verify`, `--target-port`                            |
| 환경변수                | `PGARD_` 접두어 + `UPPER_SNAKE_CASE`        | `PGARD_LOG_LEVEL`                                            |
| 검사 규칙 ID            | `PG-영역-세 자리 숫자`                      | `PG-SQL-001`, `PG-SECRET-001`                                |

`data`, `result`, `item`, `handleThing`, `checkSecurity`, `isSafe`처럼 의미가 넓은 이름은 구체화한다. 예를 들어 `isSafe` 대신 `hasConfirmedOwnerApproval`, `checkSecurity` 대신 `verifyRepositoryAccess`를 쓴다. 함수가 파일·네트워크·보고서에 쓰는 부작용을 가지면 `read`, `fetch`, `write`, `save` 같은 동사를 이름에 드러낸다. 파싱·정규화·집계처럼 순수 계산이면 `parse`, `normalize`, `summarize`를 쓴다.

## 6. 작성·검증 기준

- TypeScript를 최종 선택하면 `strict` 모드를 켜고 공개 함수의 입력·출력 타입을 명시한다. 외부 데이터는 `unknown`으로 받은 뒤 검증한다. 경계 검증을 건너뛰는 `any`와 임의의 non-null 단언은 피한다. 오류는 문자열 비교 대신 구분 가능한 코드와 원인을 갖도록 만든다.
- `ScanRequest`·`ScanResult`·`Finding`·`Coverage`는 공통 패키지에서 한 번 정의한다. 요청한 범위와 실행하지 못한 범위를 구분한다. `not_selected`는 사용자가 선택하지 않음, `not_tested`는 선택했지만 실행하지 못함, `partial`은 일부만 실행됨을 뜻한다.
- 보안 규칙은 위험 사례와 안전한 반례를 함께 확인한다. 권한 게이트는 owner 승인 없음, 접근 권한 없음, 기여 증빙 없음, 모호한 remote, 위조된 작성자 이메일을 각각 거부하는지 확인한다. 로컬 HTTP는 loopback 밖 리다이렉트를 막는지 확인한다.
- 변경마다 관련 타입 검사·린트·의미 있는 테스트를 실행하고 결과를 PR에 기록한다. 보안/권한/데이터 가림 변경은 실패 사례 검증이 필수다. 단순 문서·포맷 변경에 구현을 그대로 따라 쓰는 형식적 테스트를 만들지 않는다.
- 검사 범위·규칙·명령 동작이 바뀌면 한국어·영어 README와 CLI 도움말을 함께 갱신한다. 사용자에게 `모든 취약점 발견` 또는 `완전한 무변경 HTTP 검사`를 약속하지 않는다.

## 7. 구현 담당 에이전트의 완료 보고 형식

각 담당자는 자신이 소유한 경계에서 **무엇을 바꿨는지**, **어떤 커밋으로 나눴는지**, **검증 명령과 결과**, **남은 제한·차단 사유**, **다른 담당에게 필요한 계약 변경**을 총괄에게 전달한다. 범위·파일 소유권을 바꾸기 전에는 상대 담당과 직접 협의하고 총괄에게 알린다. 총괄은 PR별 독립 리뷰 결과를 취합하고 main 병합 전 필수 검증 상태를 확인한다.
