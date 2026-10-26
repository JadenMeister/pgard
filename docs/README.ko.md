# `docs/`의 문서

프로젝트 [README](../README.ko.md)([English](../README.md))로 돌아가기. 영문 색인: [README.md](README.md).

README와 `RESULT_SCHEMA.ko.md`는 PGARD가 지금 하는 일을 설명합니다. 기획 문서 세 개는 구현 전에 한국어로 쓴 MVP 기획 기록입니다. 영어 번역을 함께 제공하지만 기준은 한국어 원본입니다. 기획 문서가 README와 다르면(예를 들어 기획 문서에는 advisory 데이터베이스가 나오지만 PGARD에는 없습니다) README와 코드가 맞습니다.

| 문서            | 역할                                                                 | 한국어                                                                            | English                                                                           | 상태                                                 |
| --------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ---------------------------------------------------- |
| 결과 스키마     | 검사 결과 스키마의 버전 규칙과 다른 버전을 읽을 때의 동작            | [RESULT_SCHEMA.ko.md](RESULT_SCHEMA.ko.md) (번역)                                 | [RESULT_SCHEMA.md](RESULT_SCHEMA.md) (기준)                                       | 현재 정책                                            |
| 규칙 매핑       | 규칙의 CWE·OWASP·CERT 매핑을 고르는 기준과 예외에 이유가 필요한 경우 | [RULE_MAPPING.ko.md](RULE_MAPPING.ko.md) (번역)                                   | [RULE_MAPPING.md](RULE_MAPPING.md) (기준)                                         | 현재 정책                                            |
| 구현 브리프     | 제품 범위, 권한 게이트, 검사 경계, 완료 조건                         | [PGARD_AGENT_BRIEF_KO.md](PGARD_AGENT_BRIEF_KO.md) (원본)                         | [PGARD_AGENT_BRIEF_EN.md](PGARD_AGENT_BRIEF_EN.md) (번역)                         | MVP 기획 기록(과거 문서)                             |
| CLI·저장소 구조 | 명령 체계와 앱·패키지 구조                                           | [PGARD_CLI_AND_STRUCTURE_KO.md](PGARD_CLI_AND_STRUCTURE_KO.md) (원본)             | [PGARD_CLI_AND_STRUCTURE_EN.md](PGARD_CLI_AND_STRUCTURE_EN.md) (번역)             | MVP 기획 기록(과거 문서)                             |
| 개발 컨벤션     | 커밋 단위, 메시지, 네이밍, 검증, PR 규칙, 이슈·보드·리뷰(8절)        | [PGARD_DEVELOPMENT_CONVENTIONS_KO.md](PGARD_DEVELOPMENT_CONVENTIONS_KO.md) (원본) | [PGARD_DEVELOPMENT_CONVENTIONS_EN.md](PGARD_DEVELOPMENT_CONVENTIONS_EN.md) (번역) | MVP 기획 기록(과거 문서). 8절(이슈·보드·리뷰)은 현행 |

정책 자체(권한 확인, 개인정보, 자격 증명, 민감정보 가림, 대시보드 보안, 웹 검사, 범위 밖)는 README의 [정책](../README.ko.md#정책)을 참고하세요.
