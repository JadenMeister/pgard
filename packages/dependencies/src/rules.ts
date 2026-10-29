import { defineRule, type RuleDefinition, type RuleDescriptor } from "@pgard/findings";

/**
 * `PG-DEP-001` belongs to the `code` scope and the `deps:<ecosystem>` coverage areas. Category:
 * `misconfiguration` (the same closed-enum value `PG-HYGIENE-001` uses for dependency problems;
 * a new category would be a major schema change).
 */
const DEPENDENCY_RULE_DEFINITIONS = [
  {
    id: "PG-DEP-001",
    title: "Dependency version is in a known advisory's affected range",
    category: "misconfiguration",
    defaultSeverity: "medium",
    scope: "code",
    languages: ["any"],
    standards: {
      owasp: ["A03:2025"],
      cwe: ["CWE-1395"],
      cert: [],
    },
    rationale: {
      en: "The version of this package that the lockfile pins is inside the affected version range of a published vulnerability advisory (OSV). That is a match on the version only: PGARD did not check whether your code calls the vulnerable function, whether the vulnerable code is reachable, or whether it can be exploited in your setup. A development-only dependency is usually not part of what you ship.",
      ko: "lockfile이 고정한 이 패키지 버전이 공개된 취약점 권고(OSV)의 영향 받는 버전 범위 안에 있습니다. 버전만 비교한 결과입니다. 코드가 취약한 함수를 호출하는지, 취약한 코드에 도달할 수 있는지, 사용자 환경에서 악용할 수 있는지는 확인하지 않았습니다. 개발 전용 의존성은 보통 배포물에 포함되지 않습니다.",
    },
    remediation: {
      en: "Check the advisory for what it affects, and update the package to a fixed version if one is listed (change the version in the manifest if needed, then regenerate the lockfile with your package manager). If no fixed version exists, or the fix is a major update, decide whether you use the affected feature, and consider replacing the package or a documented mitigation. Run `pgard advisories update` regularly so new advisories are included.",
      ko: "권고문에서 영향 범위를 확인하고, 수정된 버전이 표시되어 있으면 그 버전으로 패키지를 업데이트하세요(필요하면 매니페스트의 버전을 바꾸고 패키지 관리자로 lockfile을 다시 생성). 수정된 버전이 없거나 메이저 업데이트가 필요하면, 영향 받는 기능을 쓰는지 판단하고 패키지 교체나 권고문에 적힌 완화 방법을 검토하세요. 새 권고가 반영되도록 `pgard advisories update`를 주기적으로 실행하세요.",
    },
  },
] as const satisfies readonly RuleDefinition[];

export const DEPENDENCY_RULE_ID = "PG-DEP-001" as const;

export function listDependencyRules(): RuleDescriptor[] {
  return DEPENDENCY_RULE_DEFINITIONS.map(defineRule);
}
