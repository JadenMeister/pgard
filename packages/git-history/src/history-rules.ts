import {
  defineRule,
  type LocalizedText,
  type RuleDefinition,
  type RuleDescriptor,
} from "@pgard/findings";

const ROTATE: LocalizedText = {
  en: "Treat the value as compromised: revoke or rotate it, then remove it from the repository (and from history with a history rewrite if the repository is shared), and load secrets from the environment or a secret manager.",
  ko: "해당 값이 유출된 것으로 간주하세요. 폐기하거나 교체(rotate)한 뒤 저장소에서 제거하고(저장소를 공유한다면 이력 재작성으로 이력에서도 제거), 비밀은 환경 변수나 비밀 관리자에서 불러오세요.",
};

const HISTORY_RULE_DEFINITIONS = [
  {
    id: "PG-SECRET-001",
    title: "Environment file committed to Git",
    category: "secret_exposure",
    defaultSeverity: "high",
    scope: "history",
    languages: ["any"],
    standards: {
      owasp: ["A07:2025"],
      cwe: ["CWE-538", "CWE-798"],
      cert: [{ kind: "via-cwe", id: "MSC03-J", cwe: "CWE-798" }],
    },
    rationale: {
      en: "Anyone with repository access (now or later) can read the environment values.",
      ko: "저장소에 접근할 수 있는 사람은 (지금이든 나중이든) 환경 값을 읽을 수 있습니다.",
    },
    remediation: {
      en: `${ROTATE.en} Add the file to .gitignore and commit an example file without values.`,
      ko: `${ROTATE.ko} 이 파일을 .gitignore에 추가하고, 값이 없는 예시 파일을 커밋하세요.`,
    },
  },
  {
    id: "PG-SECRET-002",
    title: "Secret in a tracked file",
    category: "secret_exposure",
    defaultSeverity: "high",
    scope: "history",
    languages: ["any"],
    standards: {
      owasp: ["A07:2025"],
      cwe: ["CWE-798"],
      cert: [{ kind: "via-cwe", id: "MSC03-J", cwe: "CWE-798" }],
    },
    rationale: {
      en: "Anyone with repository access can use the credential.",
      ko: "저장소에 접근할 수 있는 사람은 누구나 이 자격 증명을 사용할 수 있습니다.",
    },
    remediation: ROTATE,
  },
  {
    id: "PG-SECRET-003",
    title: "Secret in Git history (no longer in the current files)",
    category: "secret_exposure",
    defaultSeverity: "high",
    scope: "history",
    languages: ["any"],
    standards: {
      owasp: ["A07:2025"],
      cwe: ["CWE-798", "CWE-540"],
      cert: [{ kind: "via-cwe", id: "MSC03-J", cwe: "CWE-798" }],
    },
    rationale: {
      en: "Deleting the file does not remove the value: it stays readable in every clone's history.",
      ko: "파일을 지워도 값은 사라지지 않습니다. 모든 clone의 이력에 그대로 읽을 수 있게 남아 있습니다.",
    },
    remediation: ROTATE,
  },
  {
    id: "PG-HYGIENE-001",
    title: "Dependency directory committed to Git",
    category: "misconfiguration",
    defaultSeverity: "info",
    scope: "history",
    languages: ["any"],
    standards: { owasp: ["A03:2025"], cwe: ["CWE-1104"], cert: [] },
    rationale: {
      en: "Committed third-party code (node_modules/, vendor/, bower_components/, jspm_packages/, Pods/) is not your code, is not updated by the package manager, bloats every clone, and its matches show up as suggestions in every scan.",
      ko: "커밋된 서드파티 코드(node_modules/, vendor/, bower_components/, jspm_packages/, Pods/)는 내 코드가 아니고, 패키지 관리자가 갱신하지 않으며, 모든 clone을 무겁게 만들고, 그 안에서 찾은 항목이 매번 검사 결과의 제안으로 나타납니다.",
    },
    remediation: {
      en: "Remove the directory from the Git index without deleting the local copy (for example git rm -r --cached node_modules), add it to .gitignore and commit; let the package manager restore dependencies instead.",
      ko: "로컬 사본은 지우지 않고 Git 인덱스에서 디렉터리를 제거한 뒤(예: git rm -r --cached node_modules), .gitignore에 추가하고 커밋하세요. 의존성은 패키지 관리자가 복원하게 하세요.",
    },
  },
] as const satisfies readonly RuleDefinition[];

export type HistoryRuleId = (typeof HISTORY_RULE_DEFINITIONS)[number]["id"];

export const HISTORY_RULES: readonly RuleDescriptor[] = HISTORY_RULE_DEFINITIONS.map(defineRule);

export function listHistoryRules(): RuleDescriptor[] {
  return HISTORY_RULE_DEFINITIONS.map(defineRule);
}
