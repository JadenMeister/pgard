# 규칙 매핑 정책

> 이 문서는 [English](RULE_MAPPING.md) 원문의 번역입니다. 기준은 영문 문서입니다.

PGARD의 모든 규칙은 메타데이터(`packages/findings/src/rule-metadata.ts`의 `standards`)에 표준 매핑을 담고 있습니다. OWASP Top 10:2025 범주, CWE 번호, SEI CERT Java 규칙입니다. 이 매핑은 발견 항목의 참조와 표준 화면에 그대로 보이므로 정확해야 합니다. 이 문서는 매핑을 고르는 기준을 설명합니다. 규칙이 정책을 어기면 테스트가 실패하므로 정책이 어긋나지 않습니다.

## 1. CWE 구체성

규칙이 탐지하는 약점을 이름으로 가리키는 CWE를 고릅니다.

- **Base**와 **Variant** 항목을 우선합니다. MITRE는 이 수준을 "취약점의 근본 원인에 매핑하기에 선호되는 추상화 수준"이라고 설명합니다.
- cwe.mitre.org(CWE 4.20)에서 항목의 **Vulnerability Mapping Notes**를 확인합니다. 사용 구분은 `ALLOWED`, `ALLOWED-WITH-REVIEW`, `DISCOURAGED`입니다.
- **Pillar**나 **Class** 항목은 피하고, `DISCOURAGED`로 표시된 항목은 더 구체적인 항목이 없을 때만 쓰며, 그때는 이유를 `standards.mappingNote`에 적습니다.
- Base나 Variant에 맞추려고 하위 항목을 억지로 고르지 않습니다. MITRE도 같은 입장입니다.
- 규칙이 서로 다른 두 번째 약점을 탐지할 때만 CWE를 하나 더 추가합니다(예: 하드코딩된 키는 CWE-321이면서 CWE-798입니다).

규칙이 쓰는 모든 CWE는 `CWE_MAPPING_USAGE`에 항목(MITRE에서 읽은 추상화 수준과 사용 구분)이 있어야 합니다. 규칙에 CWE를 추가하려면 먼저 그 항목의 매핑 노트를 읽어야 합니다.

## 2. OWASP 범주

규칙의 `standards.owasp`는 **규칙의 CWE에서 도출**합니다. 규칙의 CWE 중 하나가 "List of Mapped CWEs"에 들어 있는 OWASP Top 10:2025 범주의 집합입니다. 그 목록은 `packages/findings/src/standards/owasp-mapped-cwes.ts`에 번호만 담아 포함되어 있습니다.

- 범주의 설명문이 아니라 목록을 따릅니다. 설명문은 해석의 여지가 있지만 목록은 그렇지 않기 때문입니다. 예를 들어 `X-Frame-Options` 헤더 누락은 설정 오류처럼 읽히지만, CWE-1021이 A06 Insecure Design 목록에 있으므로 이 규칙은 A06에 매핑합니다.
- CWE가 서로 다른 두 범주에 걸리면 두 범주를 모두 적습니다. 각 OWASP 범주는 규칙의 CWE 중 하나에 대한 실제 매핑입니다.
- 이 기준에서 벗어나는 규칙(CWE가 매핑되지 않는 범주를 쓰거나 매핑되는 범주를 빼는 경우)은 이유를 `standards.mappingNote`에 적어야 합니다. 현재 벗어나는 규칙은 없습니다.
- OWASP 목록 어디에도 없는 CWE는 범주를 만들지 않습니다.

## 3. CERT Java `via-cwe` 링크

SEI CERT Java에는 웹 규칙 매핑이 따로 없으므로, PGARD는 CWE를 거쳐 규칙을 CERT 규칙에 연결합니다(`kind: "via-cwe"`). 다음 두 조건이 모두 맞을 때만 링크를 유지합니다.

1. SEI의 "MITRE CWE" 관련 지침 표가 해당 CERT 규칙에 그 CWE를 나열합니다(`CERT_JAVA_RULES`). SEI는 이 표가 "외부 기여자가 제공했으며 SEI CERT가 검증하지 않았다"고 밝힙니다.
2. CERT 규칙이 PGARD 규칙이 탐지하는 내용과 **주제상 관련**이 있습니다.

출처가 있어도 관련이 없는 링크는 제거합니다. MSC02-J("강력한 난수를 생성하라")는 CWE-327을 나열하지만 PG-CRYPTO-003은 약한 난수가 아니라 깨졌거나 폐기된 암호를 탐지하므로 이 링크를 제거했습니다.

`kind: "direct"`는 CERT 규칙이 규칙의 약점 자체를 다룰 때만 씁니다.

표시 방식(커버리지 화면과 UI): `via-cwe`는 "관련(CWE-xxx 경유)"이라는 보조 그룹으로 보여 주고 "매핑됨"으로 보여 주지 않습니다. 연결에 쓴 CWE를 항상 밝히고 SEI가 CWE 표를 검증하지 않았다는 점을 덧붙이며, CERT 커버리지에는 절대 포함하지 않습니다.

## 4. `mappingNote`

`standards.mappingNote`는 선택 사항이며 기존 필드를 바꾸지 않고 추가된 필드입니다(영어와 한국어 문장). 다음 두 경우에만 필수이고 그 밖에는 허용하지 않으므로, 노트는 언제나 실제 예외를 뜻합니다.

- 규칙의 OWASP 범주가 규칙의 CWE가 매핑되는 범주와 다릅니다.
- 규칙이 MITRE가 `DISCOURAGED`로 표시한 CWE를 유지합니다.

CWE-693(Pillar, `DISCOURAGED`)을 유지하는 두 규칙에는 노트가 있습니다. PG-WEB-001(Content-Security-Policy)과 PG-WEB-003(`nosniff`)입니다. 이런 헤더 누락을 정확히 설명하는 CWE가 없습니다.

## 5. 검증

- 테스트가 쓰는 `validateRuleMetadata`는 CWE와 맞지 않는 OWASP 범주(`mappingNote` 없음), 노트 없는 `DISCOURAGED` CWE, 불필요한 노트, 매핑 사용 구분이 기록되지 않은 CWE를 보고합니다.
- `apps/cli/src/rule-standards.test.ts`는 예외를 고정합니다. 어떤 규칙에 노트가 있는지, 어떤 Pillar·Class CWE를 쓰는지, 어떤 CERT 링크가 있는지입니다.
- `packages/findings/src/standards/standards.test.ts`는 포함된 목록을 확인합니다. 목록은 `packages/findings/scripts/generate-owasp-mapped-cwes.mjs`로 다시 만들고 차이를 검토하세요.

## 출처

- OWASP Top 10:2025 범주 페이지의 "List of Mapped CWEs": https://top10.owasp.org/2025/ (문서 자체의 라이선스 절 기준 CC BY-SA 4.0).
- CWE 정의와 Vulnerability Mapping Notes: https://cwe.mitre.org/ (MITRE CWE 이용 약관).
- SEI CERT Oracle Coding Standard for Java와 "MITRE CWE" 표: https://cmu-sei.github.io/secure-coding-standards/ (CC BY 4.0).

번호, 추상화 수준, 사용 구분만 포함합니다. 라이선스와 저작자 표시는 [NOTICE.md](../NOTICE.md)를 참고하세요.
