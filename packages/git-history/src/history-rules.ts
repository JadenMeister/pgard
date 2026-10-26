import { defineRule, type RuleDefinition, type RuleDescriptor } from "@pgard/findings";

const HISTORY_RULE_DEFINITIONS = [
  {
    id: "PG-SECRET-001",
    title: "Environment file committed to Git",
    category: "secret_exposure",
    defaultSeverity: "high",
    scope: "history",
    languages: ["any"],
    standards: {
      owasp: ["A01:2025", "A07:2025"],
      cwe: ["CWE-538", "CWE-798"],
      cert: [{ kind: "via-cwe", id: "MSC03-J", cwe: "CWE-798" }],
    },
    rationale: {
      en: "A committed `.env` file usually holds API keys, database passwords and signing secrets. Everyone with read access to the repository can use them, now or after a later leak, a fork or a CI log, and deleting the file later does not remove it from history.",
      ko: "커밋된 `.env` 파일에는 보통 API 키, 데이터베이스 비밀번호, 서명 비밀정보가 들어 있습니다. 저장소를 읽을 수 있는 사람은 누구나(지금이든, 이후의 유출·포크·CI 로그를 통해서든) 이를 사용할 수 있고, 나중에 파일을 지워도 이력에서는 사라지지 않습니다.",
    },
    remediation: {
      en: "Treat the value as compromised, even if the repository is private. Revoke or rotate it at the provider first, because it stays in history and in every clone. Then remove it from the files, load it from the environment or a secret manager, and, if the repository is shared, rewrite history (for example with `git filter-repo`) and ask collaborators to re-clone. Rotation matters more than removal. Add .env to .gitignore and commit a .env.example that lists the variable names without values.",
      ko: "저장소가 비공개여도 해당 값이 유출된 것으로 간주하세요. 이력과 모든 복제본(clone)에 남아 있으므로 먼저 발급처에서 폐기하거나 교체(rotate)하세요. 그다음 파일에서 제거하고, 환경 변수나 비밀정보 관리 도구(secret manager)에서 불러오세요. 저장소를 공유한다면 `git filter-repo` 같은 도구로 이력을 재작성하고 협업자에게 다시 복제(clone)하도록 안내하세요. 제거보다 교체가 더 중요합니다. .env를 .gitignore에 추가하고, 값 없이 변수 이름만 적은 .env.example을 커밋하세요.",
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
      en: "A credential committed in a file lets anyone who can read the repository authenticate as its owner, with whatever access it grants to a cloud account, database or API. Automated scanners find keys pushed to public hosts within minutes.",
      ko: "파일에 커밋된 자격 증명이 있으면 저장소를 읽을 수 있는 누구나 그 소유자로 인증해, 자격 증명이 허용하는 클라우드 계정, 데이터베이스, API에 접근할 수 있습니다. 공개 호스트에 올라간 키는 자동 스캐너가 몇 분 안에 찾아냅니다.",
    },
    remediation: {
      en: "Treat the value as compromised, even if the repository is private. Revoke or rotate it at the provider first, because it stays in history and in every clone. Then remove it from the files, load it from the environment or a secret manager, and, if the repository is shared, rewrite history (for example with `git filter-repo`) and ask collaborators to re-clone. Rotation matters more than removal.",
      ko: "저장소가 비공개여도 해당 값이 유출된 것으로 간주하세요. 이력과 모든 복제본(clone)에 남아 있으므로 먼저 발급처에서 폐기하거나 교체(rotate)하세요. 그다음 파일에서 제거하고, 환경 변수나 비밀정보 관리 도구(secret manager)에서 불러오세요. 저장소를 공유한다면 `git filter-repo` 같은 도구로 이력을 재작성하고 협업자에게 다시 복제(clone)하도록 안내하세요. 제거보다 교체가 더 중요합니다.",
    },
  },
  {
    id: "PG-SECRET-003",
    title: "Secret in Git history (no longer in the current files)",
    category: "secret_exposure",
    defaultSeverity: "high",
    scope: "history",
    languages: ["any"],
    standards: {
      owasp: ["A01:2025", "A07:2025"],
      cwe: ["CWE-798", "CWE-540"],
      cert: [{ kind: "via-cwe", id: "MSC03-J", cwe: "CWE-798" }],
    },
    rationale: {
      en: "Deleting the file in a later commit does not remove the value. It stays readable in every clone and fork through `git log -p` or the old commit hash, so the credential counts as exposed until it is rotated.",
      ko: "이후 커밋에서 파일을 지워도 값은 사라지지 않습니다. 모든 복제본(clone)과 포크에서 `git log -p`나 이전 커밋 해시로 계속 읽을 수 있으므로, 교체(rotate)하기 전까지는 자격 증명이 노출된 것으로 봐야 합니다.",
    },
    remediation: {
      en: "Treat the value as compromised, even if the repository is private. Revoke or rotate it at the provider first, because it stays in history and in every clone. The current files no longer contain it, so the remaining work is the history: if the repository is shared, rewrite it (for example with `git filter-repo`) and ask collaborators to re-clone. Rotation matters more than removal.",
      ko: "저장소가 비공개여도 해당 값이 유출된 것으로 간주하세요. 이력과 모든 복제본(clone)에 남아 있으므로 먼저 발급처에서 폐기하거나 교체(rotate)하세요. 현재 파일에는 이미 없으므로 남은 작업은 이력입니다. 저장소를 공유한다면 `git filter-repo` 같은 도구로 이력을 재작성하고 협업자에게 다시 복제(clone)하도록 안내하세요. 제거보다 교체가 더 중요합니다.",
    },
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
      en: "Committed dependency folders (node_modules/, vendor/, bower_components/, jspm_packages/, Pods/) are third-party code. The package manager does not update or verify them, modified or malicious files can hide among thousands of others, and they make every clone larger. Their contents also add many low-value matches to scans.",
      ko: "커밋된 의존성 폴더(node_modules/, vendor/, bower_components/, jspm_packages/, Pods/)는 서드파티 코드입니다. 패키지 관리자가 갱신하거나 검증하지 않고, 수정되었거나 악성인 파일이 수많은 파일 속에 숨을 수 있으며, 모든 복제본(clone)을 크게 만듭니다. 그 내용 때문에 검사에서 가치가 낮은 항목도 많이 늘어납니다.",
    },
    remediation: {
      en: "Remove the directory from the Git index without deleting your local copy (`git rm -r --cached node_modules`), add it to `.gitignore` and commit. Let the package manager restore dependencies from the lockfile (`npm ci`).",
      ko: "로컬 사본은 지우지 않고 Git 인덱스에서 디렉터리를 제거한 뒤(`git rm -r --cached node_modules`), `.gitignore`에 추가하고 커밋하세요. 의존성은 패키지 관리자가 lockfile로 복원하게 하세요(`npm ci`).",
    },
  },
] as const satisfies readonly RuleDefinition[];

export type HistoryRuleId = (typeof HISTORY_RULE_DEFINITIONS)[number]["id"];

export const HISTORY_RULES: readonly RuleDescriptor[] = HISTORY_RULE_DEFINITIONS.map(defineRule);

export function listHistoryRules(): RuleDescriptor[] {
  return HISTORY_RULE_DEFINITIONS.map(defineRule);
}
