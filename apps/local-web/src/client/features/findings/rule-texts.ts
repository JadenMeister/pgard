import type { Finding } from "@pgard/findings";
import type { RuleTextsResponse } from "../../../shared/api-types";
import type { Language } from "../../i18n/types";

/**
 * Finding with its title, impact and recommendation in the UI language. A field is replaced only
 * while it still equals the rule's English default, so a finding that carries its own text keeps
 * it. Same rule as `localizeFinding` in `@pgard/findings` (not imported: that package also holds
 * Node-only code that must stay out of the browser bundle).
 */
export function localizeFindingText(
  finding: Finding,
  texts: RuleTextsResponse | null,
  language: Language,
): Finding {
  const entry = texts?.[finding.ruleId];
  if (language === "en" || entry === undefined) return finding;
  return {
    ...finding,
    title: finding.title === entry.title.en ? entry.title[language] : finding.title,
    impact: finding.impact === entry.impact.en ? entry.impact[language] : finding.impact,
    recommendation:
      finding.recommendation === entry.recommendation.en
        ? entry.recommendation[language]
        : finding.recommendation,
  };
}
