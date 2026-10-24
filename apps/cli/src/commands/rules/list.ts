import { WEB_RULE_LIST } from "@pgard/http-local";
import { PGARD_VERSION } from "@pgard/scan-core";
import { out, type CommandContext } from "../../context.js";
import { EXIT_CODES, type ExitCode } from "../../exit-codes.js";
import type { RuleLanguage } from "../../options.js";

export const UNSUPPORTED_AREAS = [
  "Direct database connections",
  "Docker / container configuration",
  "Performance and load testing",
  "Remote (non-loopback) web services",
  "Authenticated (logged-in) web browsing",
  "Form submission and other state-changing requests",
];

/**
 * Version of the detection criteria shown to users. Placeholder until source-analysis publishes
 * its catalog version; bump when rule ids, conditions or severities change.
 */
export const RULE_CRITERIA_VERSION = "2026.10-mvp";

/** Advisory DB status line. Placeholder until the advisory package exposes its status. */
export const ADVISORY_STATUS_TEXT =
  "status: missing - no local advisory database is configured; dependency advisories are reported as not tested";

/** `pgard rules list`: works outside a project; never touches GitHub or the network. */
export function runRulesList(context: CommandContext, language: RuleLanguage | null): ExitCode {
  const { style } = context;
  out(context, style.bold(`pgard ${PGARD_VERSION} - detection criteria ${RULE_CRITERIA_VERSION}`));
  out(context, "");
  out(context, style.bold("Code and history rules"));
  out(
    context,
    style.dim(
      `  The source-analysis rule catalog is not included in this build yet${language === null ? "" : ` (filter: ${language})`}.`,
    ),
  );
  out(context, "");
  out(context, style.bold("Local HTTP rules (anonymous GET, any language)"));
  for (const rule of WEB_RULE_LIST) {
    out(context, `  ${rule.id}  ${rule.severity.padEnd(6)} ${rule.title}`);
  }
  out(context, "");
  out(context, style.bold("Advisory data"));
  out(
    context,
    style.dim(`  Advisory database ${ADVISORY_STATUS_TEXT} (version: none, updated: never).`),
  );
  out(context, "");
  out(context, style.bold("Not covered in this version"));
  for (const area of UNSUPPORTED_AREAS) out(context, `  - ${area}`);
  return EXIT_CODES.ok;
}
