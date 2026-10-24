import type { FindingCategory, ScanScope, Severity } from "./contract.js";

export type RuleLanguage = "javascript" | "typescript" | "react" | "vue" | "go" | "any";

/** Catalog entry for a rule, shared by every analyzer and shown by `pgard rules list`. */
export interface RuleDescriptor {
  id: string;
  title: string;
  category: FindingCategory;
  /** Severity when the strongest evidence is present; weaker evidence lowers it. */
  defaultSeverity: Severity;
  scope: ScanScope;
  languages: RuleLanguage[];
  cwe: string[];
  owasp: string[];
  impact: string;
  recommendation: string;
}
