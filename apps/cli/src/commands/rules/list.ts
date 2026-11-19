import { isJvmRuleLanguages, localizedRuleTitle, pickText, type RuleLocale } from "@pgard/findings";
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
import { fitLines } from "../../ui/formatters/fit-lines.js";
import { wrapWidth } from "../../ui/i18n/display-width.js";
import { terminalWidth } from "../../ui/formatters/style.js";

export const UNSUPPORTED_AREAS = UNSUPPORTED_AREAS_EN;

/**
 * Version of the detection criteria shown to users. Bump when rule ids, conditions or severities
 * change.
 */
// Also shown in site/index.html and site/ko/index.html; checked by scripts/check-site-version.mjs.
export const RULE_CRITERIA_VERSION = "2026.10-mvp.6";

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
  php: ["php"],
  python: ["python"],
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

/** Columns before the title: indent, id, severity. */
const RULE_PREFIX_WIDTH = 2 + 14 + 1 + 8 + 1;
/** Below this width a row is left to the terminal (a hanging indent would leave no room). */
const MIN_WRAP_WIDTH = 50;

/**
 * A rule row. With a width (a terminal), a long title wraps under itself instead of under the id;
 * without one (a pipe), the row stays on one line so `rules list | grep` keeps working.
 */
function ruleRow(id: string, severity: string, body: string, width: number | null): string[] {
  const prefix = `  ${id.padEnd(14)} ${severity.padEnd(8)} `;
  if (width === null || width < MIN_WRAP_WIDTH) return [`${prefix}${body}`];
  return wrapWidth(body, width - RULE_PREFIX_WIDTH).map((piece, index) =>
    index === 0 ? `${prefix}${piece}` : `${" ".repeat(RULE_PREFIX_WIDTH)}${piece}`,
  );
}

/**
 * The SEI CERT Java lines under a rule. A direct link is for Java and Kotlin files only, a Java or
 * Kotlin rule without one says so (with its reason), and a link through a CWE is labelled indirect.
 */
export function certLines(rule: RuleDescriptor, locale: RuleLocale, t: CliText): string[] {
  const { standards } = rule.metadata;
  const text = t.commands.rulesList;
  const direct = standards.cert.flatMap((ref) =>
    ref.kind === "direct"
      ? [ref.cause === undefined ? ref.id : `${ref.id} (${text.certCause[ref.cause]})`]
      : [],
  );
  const indirect = standards.cert.flatMap((ref) =>
    ref.kind === "via-cwe" ? [`${ref.id} via ${ref.cwe}`] : [],
  );
  const lines: string[] = [];
  if (direct.length > 0) lines.push(text.certDirect(direct.join(", ")));
  else if (standards.noDirectCert !== undefined && isJvmRuleLanguages(rule.languages)) {
    lines.push(text.certNone(pickText(standards.noDirectCert, locale)));
  }
  if (standards.noDirectCertOther !== undefined && direct.length > 0) {
    lines.push(text.certNoneOther(pickText(standards.noDirectCertOther, locale)));
  }
  if (indirect.length > 0) lines.push(text.certIndirect(indirect.join(", ")));
  return lines;
}

/** `pgard rules list`: works outside a project; never touches GitHub or the network. */
export async function runRulesList(
  context: CommandContext,
  language: RuleLanguage | null,
): Promise<ExitCode> {
  const { style } = context;
  const t = cliText(context.ruleLocale);
  const text = t.commands.rulesList;
  // On a terminal long rows and notes wrap; a pipe keeps one line each (`rules list | grep`).
  const width =
    context.io.stdout.isTTY === true ? terminalWidth(context.io.stdout, context.io.env) : null;
  const fit = (line: string): string[] => (width === null ? [line] : fitLines(line, width));
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
    for (const rule of group.rules) {
      const body = `${titleOf(rule.id, rule.title)} [${rule.languages.join(", ")}]`;
      for (const line of ruleRow(rule.id, rule.defaultSeverity, body, width)) out(context, line);
      for (const line of certLines(rule, context.ruleLocale ?? "en", t)) {
        for (const piece of fit(`      ${line}`)) out(context, style.dim(piece));
      }
    }
  }
  out(context, "");
  out(context, style.bold(text.httpHeading));
  for (const rule of WEB_RULE_LIST) {
    for (const line of ruleRow(rule.id, rule.severity, titleOf(rule.id, rule.title), width)) {
      out(context, line);
    }
  }
  out(context, "");
  for (const piece of fit(text.severityNote)) out(context, style.dim(piece));
  for (const piece of fit(text.certNote)) out(context, style.dim(piece));
  out(context, "");
  out(context, style.bold(text.notCoveredHeading));
  for (const area of text.unsupportedAreas) {
    for (const piece of fit(`  - ${area}`)) out(context, piece);
  }
  return EXIT_CODES.ok;
}
