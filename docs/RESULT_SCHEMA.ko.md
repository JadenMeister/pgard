# 검사 결과 스키마와 버전 관리

> **참고:** 이 문서는 [`RESULT_SCHEMA.md`](RESULT_SCHEMA.md)(영문)의 한국어 번역입니다. 기준 문서는 영문판이며, 내용이 다르면 영문판이 맞습니다. 프로젝트 [README](../README.ko.md)([English](../README.md))도 참고하세요.

검사 결과(`packages/findings/src/contract.ts`의 `ScanResult`)에는 `major.minor` 형식의 `schemaVersion`이 들어 있습니다. 현재 버전은 `1.1`입니다. 이 문서는 그 버전이 언제 바뀌는지, 그리고 자신이 쓰지 않은 버전을 읽을 때 읽는 쪽이 무엇을 해야 하는지 설명합니다.

## 버전 규칙

**Minor**(`1.0`에서 `1.1`): 추가이면서 선택적인 변경만 해당합니다.

- 새 선택 필드, 또는 이전 버전의 읽는 쪽이 무시해도 되는 새 필드.
- 값의 범위가 열려 있는 문자열 필드의 새 값(예: 새 규칙 id).

**Major**(`1.x`에서 `2.0`): 그 밖의 모든 변경입니다.

- 필드 제거, 이름 변경, 타입 변경.
- 기존 필드의 의미 변경.
- 닫힌 enum(severity, status, category, scope 등)의 새 값. 이전 버전의 읽는 쪽이 해석할 수 없기 때문입니다.
- `Finding.id`를 만드는 방식의 변경(아래 참고).

폐기 예정으로 표시된 필드(예: `advisoryDb`)는 다음 major 버전까지 형태를 유지합니다.

## 읽기 규칙

읽는 쪽은 모르는 필드를 무시합니다. 결과를 다시 읽는 모든 것(저장된 결과, CI 도구, 보고서·SARIF 변환기)은 `@pgard/findings`의 `readScanResult`를 거칩니다. 이 함수는 형태를 엄격하게 검증하고, 예외를 던지지 않으며, 타입이 있는 결과 또는 타입이 있는 오류를 반환합니다.

| 입력 버전                  | 동작                                                                                                                  |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| 같음(`1.1`)                | 받아들입니다.                                                                                                         |
| 같은 major의 더 낮은 minor | 받아들입니다. 나중에 추가된 필드는 없지만 형태는 유효합니다.                                                          |
| 같은 major의 더 높은 minor | 받아들입니다. 모르는 필드는 무시합니다(읽는 쪽이 버립니다). `sourceVersion`은 파일에 있던 버전을 알려 줍니다.         |
| 다른 major                 | `version_unsupported_major`와 해당 버전을 알리는 메시지로 거부합니다. 읽는 쪽은 변환하거나 추측하려 하지 않습니다.    |
| 없음 또는 잘못됨           | `version_missing` 또는 `version_malformed`로 거부합니다. 유효한 버전은 앞에 0이 없는, 점으로 구분된 정수 두 개입니다. |

버전 문법은 `major.minor`이며, 각 부분은 앞에 0이 없는 6자리 이하의 음이 아닌 정수입니다.

받아들인 버전이라도 전체 형태를 다시 검사합니다. 잘못된 enum 값, 빠진 필수 필드, 비어 있는 배열 칸, 중복된 `Finding.id`, 1보다 작은 줄 번호, 너무 큰 배열은 버전이 무엇이라고 하든 `invalid_shape` 또는 `too_large`로 거부합니다. 읽는 쪽은 자기 소유의 데이터 속성만 읽고(getter는 실행하지 않음), 배열 크기, 문자열 길이, 배열 항목의 총 개수를 제한(`READ_LIMITS`)하므로, 악의적인 파일이 파싱 후에 무제한 작업을 시킬 수 없습니다. 호출하는 쪽은 `JSON.parse` 전에 파일 크기를 제한해야 하며, 읽는 쪽은 이를 대신할 수 없습니다.

문자열은 길이만 제한할 뿐 정제하지 않습니다. 근거, 제목, 메모에는 어떤 문자든 들어 있을 수 있으며, HTML, 터미널, SARIF에 맞게 이스케이프하는 일은 그것을 렌더링하는 쪽의 몫입니다.

**다시 쓰기.** 읽는 쪽은 아는 필드만 반환하고 나머지는 버립니다. `sourceVersion`이 `SCHEMA_VERSION`보다 높을 때는 읽는 쪽의 출력을 원본 파일에 다시 쓰지 마세요. 더 새로운 필드가 조용히 사라집니다. 다른 이름으로 사본을 저장하거나 거부하세요.

## 버전 이력

**`1.1`**(추가만 있음. `1.0` 결과도 새 필드가 없는 상태로 계속 읽습니다):

- `Finding.suppression?: { reason: string; expires?: string; source: "pgard.config.json" }`: `pgard.config.json`의 활성 억제 항목이 해당 발견 항목에 맞았을 때만 있습니다. 발견 항목은 결과에 그대로 남습니다.
- `Finding.inBaseline?: true`: 저장소의 기준선(`pgard baseline set`)에 그 발견 항목이 있을 때만(검사 비교와 같은 식별 방식) 있습니다. `false`는 없고, 필드가 없으면 기준선에 없거나 기준선이 없다는 뜻입니다.
- `ScanResult.suppressions?: { source; suppressed; critical; bySeverity; entries: { ruleId; path; reason; expires?; state: "active" | "expired"; matched; wildcard; farExpiry }[]; incomplete }`: 설정에 억제 항목이 하나 이상 있을 때 있습니다. `suppressed`는 `suppression`이 붙은 발견 항목 수, `critical`은 그중 치명적인 수, `bySeverity`는 심각도별 수(합이 `suppressed`), `farExpiry`는 `expires`가 366일을 넘게 남았는지, `matched`는 항목이 맞는 발견 항목 수(만료된 항목은 0), `wildcard`는 항목의 경로가 모든 파일에 맞는지, `incomplete`는 매칭 작업량 한도를 넘었는지(그 뒤 발견 항목은 억제되지 않음)를 뜻합니다.
- `ScanResult.baseline?: { setAt; scanId; revision; total; matched; new; newInUncertainAreas; toolVersionChanged }`: 기준선이 적용되었을 때 있습니다. `matched`는 `inBaseline`이 붙었고 억제되지 않은 발견 항목 수("In baseline" 그룹의 크기), `new`는 기준선에도 없고 억제되지도 않은 발견 항목 수(테스트·vendored 항목 포함), `total`은 기준선 검사의 발견 항목 수입니다. 억제된 발견 항목은 저장되는 기준선에서 제외됩니다.

새 최상위 객체 둘은 모두 선택적이며 다른 새 필드와 독립적입니다. 닫힌 값이 새로 생긴 것은 `SuppressionState`와 `source` 리터럴뿐이며, 여기에 새 값을 더하면 major 변경입니다. 억제나 기준선은 `overallStatus`, 어떤 coverage 영역의 상태, `authorization`도 바꾸지 않습니다. 상태는 coverage에서만 나옵니다. 억제를 언급하는 coverage 문구는 개수를 세는 `source:config` 영역의 `note`뿐입니다.

## 버전이 들어가는 출력

- 검사의 모든 JSON 출력. 계획된 CLI JSON 출력을 포함합니다(최상위의 `schemaVersion`).
- 저장된 결과(같은 객체를 그대로 기록한 것).
- 결과로 만든 보고서(HTML과 PDF). 보고서에는 읽는 쪽이 정규화한 `schemaVersion`(이 PGARD가 구현한 버전)이 표시되며, 원본 파일에 있던 버전과 반드시 같지는 않습니다.

## Finding.id는 지문입니다

`Finding.id`는 규칙, 위치, 원인으로 만든 안정적인 지문입니다. 저장된 결과는 이 id로 이후 검사와 비교되므로, 타입이 `string`일 뿐이어도 계약의 일부입니다. 만드는 방식을 바꾸면 이전 결과의 id가 더 이상 맞지 않으므로, 그런 변경은 **major** 버전 변경입니다. 타입이나 비밀정보를 절대 포함하지 않는다는 규칙도 같은 major 안에서는 바꿀 수 없습니다.

## 버전 바꾸기

버전 상수 `SCHEMA_VERSION`은 형태를 바꾸는 같은 pull request에서 올리며, 여기에 메모를 남기고 새 호환성 사례의 테스트를 함께 추가합니다. 읽는 쪽이 받아들이는 major는 이 상수에서 가져옵니다.
