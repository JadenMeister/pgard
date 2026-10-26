import {
  CERT_JAVA_ID_PATTERN,
  CWE_ID_PATTERN,
  getCertJavaRule,
  getOwaspCategory,
  OWASP_ID_PATTERN,
  type OwaspId,
} from "./standards/index.js";

/** Languages a rule's explanatory text is written in. English is the default. */
export const RULE_LOCALES = ["en", "ko"] as const;
export type RuleLocale = (typeof RULE_LOCALES)[number];
export const DEFAULT_RULE_LOCALE: RuleLocale = "en";

/**
 * Prose in every supported language. Both keys are required, so a rule with a missing
 * translation does not typecheck (the same approach as the dashboard catalogs: `ko: Messages`).
 */
export type LocalizedText = Record<RuleLocale, string>;

/** A CERT Java rule that applies to the rule's weakness itself. */
export interface DirectCertReference {
  kind: "direct";
  /** CERT Java rule id such as `IDS00-J`. */
  id: string;
}

/** A CERT Java rule that lists one of the rule's CWE ids in its related-guidelines table. */
export interface ViaCweCertReference {
  kind: "via-cwe";
  id: string;
  /** The CWE id that links the rule to the CERT rule. */
  cwe: string;
}

export type CertReference = DirectCertReference | ViaCweCertReference;

export interface RuleStandards {
  /** OWASP Top 10 2025 ids, for example `A05:2025`. */
  owasp: readonly OwaspId[];
  /** CWE ids, for example `CWE-89`. */
  cwe: readonly string[];
  cert: readonly CertReference[];
}

/** A vulnerable and a safe snippet. The code is not translated; the optional note is. */
export interface RuleExample {
  language: string;
  vulnerable: string;
  safe: string;
  note?: LocalizedText;
}

/** Everything that explains a rule beyond its identity: standards, why it matters, how to fix it. */
export interface RuleMetadata {
  standards: RuleStandards;
  /** Short "why it is dangerous". */
  rationale: LocalizedText;
  remediation: LocalizedText;
  examples?: readonly RuleExample[];
}

export function pickText(text: LocalizedText, locale: RuleLocale = DEFAULT_RULE_LOCALE): string {
  return text[locale];
}

const HANGUL = /[ㄱ-ㆎ가-힣]/;

/**
 * Checks a rule's metadata against the bundled standards data and the translation rules.
 * Returns human-readable problems; an empty list means the metadata is valid.
 */
export function validateRuleMetadata(rule: { id: string; metadata: RuleMetadata }): string[] {
  const problems: string[] = [];
  const { standards, rationale, remediation, examples } = rule.metadata;
  const fail = (message: string): void => {
    problems.push(`${rule.id}: ${message}`);
  };

  for (const id of standards.owasp) {
    if (!OWASP_ID_PATTERN.test(id)) fail(`OWASP id ${id} is not an OWASP Top 10 2025 id`);
    else if (getOwaspCategory(id) === undefined) fail(`OWASP id ${id} is not in the 2025 list`);
  }
  for (const id of standards.cwe) {
    if (!CWE_ID_PATTERN.test(id)) fail(`CWE id ${id} is malformed`);
  }
  if (new Set(standards.cwe).size !== standards.cwe.length) fail("duplicate CWE ids");

  for (const ref of standards.cert) {
    if (!CERT_JAVA_ID_PATTERN.test(ref.id)) {
      fail(`CERT id ${ref.id} is malformed`);
      continue;
    }
    const certRule = getCertJavaRule(ref.id);
    if (certRule === undefined) {
      fail(`CERT rule ${ref.id} is not in the CERT Java data`);
    } else if (ref.kind === "via-cwe") {
      if (!standards.cwe.includes(ref.cwe))
        fail(`CERT ${ref.id} via ${ref.cwe}: rule has no such CWE`);
      if (!certRule.cwe.includes(ref.cwe)) fail(`CERT ${ref.id} does not list ${ref.cwe}`);
    }
  }
  const certKeys = standards.cert.map((ref) => `${ref.kind}:${ref.id}`);
  if (new Set(certKeys).size !== certKeys.length) fail("duplicate CERT references");

  const prose: Array<[string, LocalizedText]> = [
    ["rationale", rationale],
    ["remediation", remediation],
    ...(examples ?? []).flatMap((example, index): Array<[string, LocalizedText]> =>
      example.note === undefined ? [] : [[`examples[${index}].note`, example.note]],
    ),
  ];
  for (const [name, text] of prose) {
    for (const locale of RULE_LOCALES) {
      if (typeof text[locale] !== "string" || text[locale].trim() === "") {
        fail(`${name}.${locale} is empty`);
      }
    }
    if (typeof text.ko === "string" && !HANGUL.test(text.ko)) fail(`${name}.ko contains no Korean`);
  }
  return problems;
}
