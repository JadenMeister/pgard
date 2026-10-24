import type { RuleDescriptor } from "@pgard/findings";
import { listHistoryRules } from "@pgard/git-history";
import { listSourceRules } from "@pgard/source-analysis";

export type { RuleDescriptor, RuleLanguage } from "@pgard/findings";

/**
 * Rules implemented by the local analyzers, for `pgard rules list`. Web rules live in
 * http-local and are merged by the launcher.
 */
export function listSupportedRules(): RuleDescriptor[] {
  return [...listSourceRules(), ...listHistoryRules()];
}
