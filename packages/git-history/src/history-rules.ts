import type { RuleDescriptor } from "@pgard/findings";

const ROTATE =
  "Treat the value as compromised: revoke or rotate it, then remove it from the repository (and from history with a history rewrite if the repository is shared), and load secrets from the environment or a secret manager.";

export const HISTORY_RULES = [
  {
    id: "PG-SECRET-001",
    title: "Environment file committed to Git",
    category: "secret_exposure",
    defaultSeverity: "high",
    scope: "history",
    languages: ["any"],
    cwe: ["CWE-538", "CWE-798"],
    owasp: ["A07:2025"],
    impact: "Anyone with repository access (now or later) can read the environment values.",
    recommendation: `${ROTATE} Add the file to .gitignore and commit an example file without values.`,
  },
  {
    id: "PG-SECRET-002",
    title: "Secret in a tracked file",
    category: "secret_exposure",
    defaultSeverity: "high",
    scope: "history",
    languages: ["any"],
    cwe: ["CWE-798"],
    owasp: ["A07:2025"],
    impact: "Anyone with repository access can use the credential.",
    recommendation: ROTATE,
  },
  {
    id: "PG-SECRET-003",
    title: "Secret in Git history (no longer in the current files)",
    category: "secret_exposure",
    defaultSeverity: "high",
    scope: "history",
    languages: ["any"],
    cwe: ["CWE-798", "CWE-540"],
    owasp: ["A07:2025"],
    impact:
      "Deleting the file does not remove the value: it stays readable in every clone's history.",
    recommendation: ROTATE,
  },
  {
    id: "PG-HYGIENE-001",
    title: "Dependency directory committed to Git",
    category: "misconfiguration",
    defaultSeverity: "info",
    scope: "history",
    languages: ["any"],
    cwe: ["CWE-1104"],
    owasp: ["A03:2025"],
    impact:
      "Committed third-party code (node_modules/, vendor/, bower_components/, jspm_packages/, Pods/) is not your code, is not updated by the package manager, bloats every clone, and its matches show up as suggestions in every scan.",
    recommendation:
      "Remove the directory from the Git index without deleting the local copy (for example git rm -r --cached node_modules), add it to .gitignore and commit; let the package manager restore dependencies instead.",
  },
] as const satisfies readonly RuleDescriptor[];

export type HistoryRuleId = (typeof HISTORY_RULES)[number]["id"];

export function listHistoryRules(): RuleDescriptor[] {
  return HISTORY_RULES.map((rule) => ({
    ...rule,
    languages: [...rule.languages],
    cwe: [...rule.cwe],
    owasp: [...rule.owasp],
  }));
}
