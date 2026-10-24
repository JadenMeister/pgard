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
import { formatAdvisoryStatus, readAdvisoryStatusSafely } from "../../ui/formatters/advisory.js";

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

/** `--language` value -> catalog language. Rules tagged "any" always match. */
export const LANGUAGE_FILTER: Readonly<Record<RuleLanguage, CatalogLanguage>> = {
  js: "javascript",
  ts: "typescript",
  react: "react",
  vue: "vue",
  go: "go",
};

const SCOPE_HEADINGS: ReadonlyArray<{ scope: RuleDescriptor["scope"]; heading: string }> = [
  { scope: "code", heading: "Code rules (current files)" },
  { scope: "history", heading: "Git history rules" },
];

export function filterRulesByLanguage(
  rules: readonly RuleDescriptor[],
  language: RuleLanguage | null,
): RuleDescriptor[] {
  if (language === null) return [...rules];
  const wanted = LANGUAGE_FILTER[language];
  return rules.filter((rule) => rule.languages.includes(wanted) || rule.languages.includes("any"));
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
    out(context, style.dim(`Language filter: ${language} (rules for any language are included)`));
  }
  const rules = filterRulesByLanguage(listSupportedRules(), language);
  for (const { scope, heading } of SCOPE_HEADINGS) {
    out(context, "");
    out(context, style.bold(heading));
    const scoped = rules
      .filter((rule) => rule.scope === scope)
      .sort((a, b) => a.id.localeCompare(b.id, "en"));
    if (scoped.length === 0) out(context, style.dim("  No rules for this language."));
    for (const rule of scoped) out(context, formatRule(rule));
  }
  out(context, "");
  out(context, style.bold("Local HTTP rules (anonymous GET, any language)"));
  for (const rule of WEB_RULE_LIST) {
    out(context, `  ${rule.id.padEnd(13)} ${rule.severity.padEnd(8)} ${rule.title}`);
  }
  out(context, "");
  out(context, style.bold("Advisory data"));
  const advisoryLine = `  Advisory database status: ${formatAdvisoryStatus(advisory)}`;
  out(context, advisory.status === "ok" ? advisoryLine : style.yellow(advisoryLine));
  out(context, "");
  out(context, style.bold("Not covered in this version"));
  for (const area of UNSUPPORTED_AREAS) out(context, `  - ${area}`);
  return EXIT_CODES.ok;
}
