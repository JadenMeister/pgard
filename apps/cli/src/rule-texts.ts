import { buildRuleTextCatalog, type RuleTextCatalog } from "@pgard/findings";
import { WEB_RULE_LIST } from "@pgard/http-local";
import { listSupportedRules } from "@pgard/scan-core";

let catalog: RuleTextCatalog | undefined;

/** Titles, impact and fix texts of every rule (code, history and web), in each language. */
export function getRuleTextCatalog(): RuleTextCatalog {
  catalog ??= buildRuleTextCatalog([...listSupportedRules(), ...WEB_RULE_LIST]);
  return catalog;
}
