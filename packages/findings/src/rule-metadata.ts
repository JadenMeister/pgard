import {
  CERT_JAVA_ID_PATTERN,
  CWE_ID_PATTERN,
  cweMappingEntry,
  getCertJavaRule,
  getOwaspCategory,
  OWASP_ID_PATTERN,
  owaspCategoryForCwe,
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
  /**
   * Why the rule departs from the mapping policy (docs/RULE_MAPPING.md): its OWASP categories
   * differ from the ones its CWEs map to, or it keeps a CWE that MITRE marks DISCOURAGED. Required
   * in exactly those cases and absent otherwise.
   */
  mappingNote?: LocalizedText;
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
    else if (cweMappingEntry(id) === undefined) {
      fail(`${id} has no recorded MITRE mapping usage; read its Vulnerability Mapping Notes`);
    }
  }
  if (new Set(standards.cwe).size !== standards.cwe.length) fail("duplicate CWE ids");

  const derived = new Set(
    standards.cwe.flatMap((id) => {
      const category = owaspCategoryForCwe(id);
      return category === undefined ? [] : [category];
    }),
  );
  // Ids that are not in the 2025 list were reported above; they do not also count as a mismatch.
  const listed = new Set(standards.owasp.filter((id) => getOwaspCategory(id) !== undefined));
  const sameCategories = derived.size === listed.size && [...listed].every((id) => derived.has(id));
  const discouraged = standards.cwe.filter((id) => cweMappingEntry(id)?.usage === "DISCOURAGED");
  const needsNote = !sameCategories || discouraged.length > 0;
  if (!sameCategories && standards.mappingNote === undefined) {
    fail(
      `OWASP ${standards.owasp.join(", ") || "(none)"} does not match the categories of its CWEs (${[...derived].join(", ") || "none"}); fix the mapping or add standards.mappingNote`,
    );
  }
  if (discouraged.length > 0 && standards.mappingNote === undefined) {
    fail(
      `${discouraged.join(", ")} is DISCOURAGED by MITRE; use a specific CWE or add standards.mappingNote`,
    );
  }
  if (!needsNote && standards.mappingNote !== undefined) {
    fail("standards.mappingNote is set but the rule follows the mapping policy");
  }

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
    ...(standards.mappingNote === undefined
      ? []
      : ([["standards.mappingNote", standards.mappingNote]] as Array<[string, LocalizedText]>)),
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
