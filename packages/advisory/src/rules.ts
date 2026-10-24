import type { RuleDescriptor } from "@pgard/findings";

export const DEPENDENCY_RULE = {
  id: "PG-DEP-001",
  title: "Dependency version with a known advisory",
  category: "vulnerable_dependency",
  defaultSeverity: "high",
  scope: "code",
  languages: ["javascript", "typescript", "go"],
  cwe: ["CWE-1395"],
  owasp: ["A03:2025"],
  impact:
    "A dependency version with a published vulnerability is resolved; impact depends on whether the vulnerable code is used.",
  recommendation:
    "Upgrade to a fixed version (or apply the advisory's workaround) and re-run the scan with current advisory data.",
} as const satisfies RuleDescriptor;

export function listAdvisoryRules(): RuleDescriptor[] {
  return [
    {
      ...DEPENDENCY_RULE,
      languages: [...DEPENDENCY_RULE.languages],
      cwe: [...DEPENDENCY_RULE.cwe],
      owasp: [...DEPENDENCY_RULE.owasp],
    },
  ];
}
