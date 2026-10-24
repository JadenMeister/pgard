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
import {
  formatAdvisoryStatus,
  isAdvisoryStatusOk,
  readAdvisoryStatusSafely,
} from "../../ui/formatters/advisory.js";

export const UNSUPPORTED_AREAS = [
  "Direct database connections",
  "Docker / container configuration",
  "Performance and load testing",
  "Remote (non-loopback) web services",
  "Authenticated (logged-in) web browsing",
  "Form submission and other state-changing requests",
];

/**
 * Version of the detection criteria shown to users. Bump when rule ids, conditions or severities
 * change.
 */
export const RULE_CRITERIA_VERSION = "2026.10-mvp";

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
};

/** The filter line under the header, naming every catalog language the filter includes. */
export function describeLanguageFilter(language: RuleLanguage): string {
  const extra = LANGUAGE_FILTER[language].slice(1);
  const included = extra.length > 0 ? `${extra.join("/")} rules and ` : "";
  return `Language filter: ${language} (${included}rules for any language are included)`;
}

const SCOPE_HEADINGS: ReadonlyArray<{ scope: RuleDescriptor["scope"]; heading: string }> = [
  { scope: "code", heading: "Code rules (current files)" },
  { scope: "history", heading: "Git history rules" },
];

/** Heading for catalog rules whose scope has no heading above, so no rule is ever hidden. */
export const OTHER_RULES_HEADING = "Other rules";

export interface RuleGroup {
  heading: string;
  rules: RuleDescriptor[];
}

/**
 * Groups rules under the scope headings, sorted by id. Rules of any other scope (for example a
 * future catalog rule with scope "web") go into a final "Other rules" group, shown only when it
 * has rules. The output does not depend on the input order.
 */
export function groupRulesByScope(rules: readonly RuleDescriptor[]): RuleGroup[] {
  const byId = (a: RuleDescriptor, b: RuleDescriptor): number => a.id.localeCompare(b.id, "en");
  const known = new Set(SCOPE_HEADINGS.map(({ scope }) => scope));
  const groups: RuleGroup[] = SCOPE_HEADINGS.map(({ scope, heading }) => ({
    heading,
    rules: rules.filter((rule) => rule.scope === scope).sort(byId),
  }));
  const other = rules.filter((rule) => !known.has(rule.scope)).sort(byId);
  if (other.length > 0) groups.push({ heading: OTHER_RULES_HEADING, rules: other });
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

function formatRule(rule: RuleDescriptor): string {
  return `  ${rule.id.padEnd(13)} ${rule.defaultSeverity.padEnd(8)} ${rule.title} [${rule.languages.join(", ")}]`;
}

/** `pgard rules list`: works outside a project; never touches GitHub or the network. */
export async function runRulesList(
  context: CommandContext,
  language: RuleLanguage | null,
): Promise<ExitCode> {
  const { deps, io, style } = context;
  const advisory = await readAdvisoryStatusSafely(deps, io.env);
  out(context, style.bold(`pgard ${PGARD_VERSION} - detection criteria ${RULE_CRITERIA_VERSION}`));
  if (language !== null) {
    out(context, style.dim(describeLanguageFilter(language)));
  }
  const rules = filterRulesByLanguage(listSupportedRules(), language);
  for (const group of groupRulesByScope(rules)) {
    out(context, "");
    out(context, style.bold(group.heading));
    if (group.rules.length === 0) out(context, style.dim("  No rules for this language."));
    for (const rule of group.rules) out(context, formatRule(rule));
  }
  out(context, "");
  out(context, style.bold("Local HTTP rules (anonymous GET, any language)"));
  for (const rule of WEB_RULE_LIST) {
    out(context, `  ${rule.id.padEnd(13)} ${rule.severity.padEnd(8)} ${rule.title}`);
  }
  out(context, "");
  out(context, style.bold("Advisory data"));
  const advisoryLine = `  Advisory database status: ${formatAdvisoryStatus(advisory)}`;
  out(context, isAdvisoryStatusOk(advisory) ? advisoryLine : style.yellow(advisoryLine));
  out(context, "");
  out(context, style.bold("Not covered in this version"));
  for (const area of UNSUPPORTED_AREAS) out(context, `  - ${area}`);
  return EXIT_CODES.ok;
}
