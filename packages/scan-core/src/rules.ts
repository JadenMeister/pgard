import { listSourceRules, type RuleDescriptor } from "@pgard/source-analysis";

export type { RuleDescriptor, RuleLanguage } from "@pgard/source-analysis";

/**
 * Rules implemented by the local analyzers, for `pgard rules list`. Web rules live in
 * http-local and are merged by the launcher.
 */
export function listSupportedRules(): RuleDescriptor[] {
  return listSourceRules();
}
