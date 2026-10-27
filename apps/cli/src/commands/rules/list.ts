import { localizedRuleTitle } from "@pgard/findings";
import { WEB_RULE_LIST } from "@pgard/http-local";
import {
  PGARD_VERSION,
  listSupportedRules,
  type RuleDescriptor,
  type RuleLanguage as CatalogLanguage,
} from "@pgard/scan-core";
import { out, type CommandContext } from "../../context.js";
import { EXIT_CODES, type ExitCode } from "../../exit-codes.js";
import type { RuleLanguage } from "../../options.js";
import { UNSUPPORTED_AREAS_EN } from "../../ui/i18n/command-text.js";
import { cliText, type CliText } from "../../ui/i18n/cli-text.js";

export const UNSUPPORTED_AREAS = UNSUPPORTED_AREAS_EN;

/**
 * Version of the detection criteria shown to users. Bump when rule ids, conditions or severities
 * change.
 */
export const RULE_CRITERIA_VERSION = "2026.10-mvp.4";

/**
 * `--language` value -> catalog languages it selects. Rules tagged "any" always match. React and
 * Vue projects are JavaScript/TypeScript projects too, so they also get the JS/TS rules.
 */
export const LANGUAGE_FILTER: Readonly<Record<RuleLanguage, readonly CatalogLanguage[]>> = {
  js: ["javascript"],
  ts: ["typescript"],
  react: ["react", "javascript", "typescript"],
  vue: ["vue", "javascript", "typescript"],
  go: ["go"],
  java: ["java"],
  kotlin: ["kotlin"],
};

/** The filter line under the header, naming every catalog language the filter includes. */
export function describeLanguageFilter(language: RuleLanguage, t: CliText = cliText("en")): string {
  return t.commands.rulesList.languageFilter(language, LANGUAGE_FILTER[language].slice(1));
}

const EN_HEADINGS = cliText("en").commands.rulesList.headings;

const SCOPE_HEADINGS: ReadonlyArray<{ scope: "code" | "history"; heading: string }> = [
  { scope: "code", heading: EN_HEADINGS.code },
  { scope: "history", heading: EN_HEADINGS.history },
];

/** Heading for catalog rules whose scope has no heading above, so no rule is ever hidden. */
export const OTHER_RULES_HEADING = EN_HEADINGS.other;

export interface RuleGroup {
  /** English heading; the screen translates it through `scope`. */
  heading: string;
  scope: "code" | "history" | "other";
  rules: RuleDescriptor[];
}

/**
 * Groups rules under the scope headings, sorted by id. Rules of any other scope (for example a
 * future catalog rule with scope "web") go into a final "Other rules" group, shown only when it
 * has rules. The output does not depend on the input order.
 */
export function groupRulesByScope(rules: readonly RuleDescriptor[]): RuleGroup[] {
  const byId = (a: RuleDescriptor, b: RuleDescriptor): number => a.id.localeCompare(b.id, "en");
  const known = new Set<string>(SCOPE_HEADINGS.map(({ scope }) => scope));
  const groups: RuleGroup[] = SCOPE_HEADINGS.map(({ scope, heading }) => ({
    heading,
    scope,
    rules: rules.filter((rule) => rule.scope === scope).sort(byId),
  }));
  const other = rules.filter((rule) => !known.has(rule.scope)).sort(byId);
  if (other.length > 0) groups.push({ heading: OTHER_RULES_HEADING, scope: "other", rules: other });
  return groups;
}

export function filterRulesByLanguage(
  rules: readonly RuleDescriptor[],
  language: RuleLanguage | null,
): RuleDescriptor[] {
  if (language === null) return [...rules];
  const wanted = LANGUAGE_FILTER[language];
  return rules.filter(
    (rule) =>
      rule.languages.includes("any") || rule.languages.some((entry) => wanted.includes(entry)),
  );
}

function formatRule(rule: RuleDescriptor, title: string): string {
  return `  ${rule.id.padEnd(14)} ${rule.defaultSeverity.padEnd(8)} ${title} [${rule.languages.join(", ")}]`;
}

/** `pgard rules list`: works outside a project; never touches GitHub or the network. */
export async function runRulesList(
  context: CommandContext,
  language: RuleLanguage | null,
): Promise<ExitCode> {
  const { style } = context;
  const t = cliText(context.ruleLocale);
  const text = t.commands.rulesList;
  const titleOf = (id: string, fallback: string): string =>
    context.ruleTexts === undefined
      ? fallback
      : localizedRuleTitle(context.ruleTexts, id, context.ruleLocale ?? "en", fallback);
  out(context, style.bold(text.header(PGARD_VERSION, RULE_CRITERIA_VERSION)));
  if (language !== null) {
    out(context, style.dim(describeLanguageFilter(language, t)));
  }
  const rules = filterRulesByLanguage(listSupportedRules(), language);
  for (const group of groupRulesByScope(rules)) {
    out(context, "");
    out(context, style.bold(text.headings[group.scope]));
    if (group.rules.length === 0) out(context, style.dim(text.noRules));
    for (const rule of group.rules) out(context, formatRule(rule, titleOf(rule.id, rule.title)));
  }
  out(context, "");
  out(context, style.bold(text.httpHeading));
  for (const rule of WEB_RULE_LIST) {
    out(
      context,
      `  ${rule.id.padEnd(14)} ${rule.severity.padEnd(8)} ${titleOf(rule.id, rule.title)}`,
    );
  }
  out(context, "");
  out(context, style.bold(text.notCoveredHeading));
  for (const area of text.unsupportedAreas) out(context, `  - ${area}`);
  return EXIT_CODES.ok;
}
