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

/**
 * The cause of a finding that a direct CERT reference can be scoped to, when the CERT rule covers
 * only part of what the PGARD rule reports. The analyzer decides it from the evidence it builds
 * (`certCausesOf` in source-analysis).
 * - `weak-random`: a non-cryptographic random source used as a key, IV, salt or token.
 * - `archive-entry`: the path comes from an archive entry name (zip slip).
 * - `other-than-archive-entry`: any other path finding of the same rule.
 */
export type CertCause = "weak-random" | "archive-entry" | "other-than-archive-entry";

/** A CERT Java rule that applies to the rule's weakness itself. */
export interface DirectCertReference {
  kind: "direct";
  /** When set, the reference holds only for findings of this cause; otherwise for every finding. */
  cause?: CertCause;
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

/**
 * Why a rule departs from the mapping policy (docs/RULE_MAPPING.md). Each field covers exactly one
 * kind of departure, so a note for one cannot excuse the other.
 */
export interface RuleMappingNote {
  /** Required when the rule keeps a CWE that MITRE marks DISCOURAGED. */
  discouragedCwe?: LocalizedText;
  /** Required when the OWASP categories differ from the ones the rule's CWEs map to. */
  owaspDeparture?: LocalizedText;
}

export interface RuleStandards {
  /** OWASP Top 10 2025 ids, for example `A05:2025`. */
  owasp: readonly OwaspId[];
  /** CWE ids, for example `CWE-89`. */
  cwe: readonly string[];
  cert: readonly CertReference[];
  /**
   * The explicit "no direct CERT rule" marker of a rule that applies to Java or Kotlin: why no
   * SEI CERT Oracle Java rule is about this weakness. A JVM rule has either a `direct` CERT
   * reference or this marker, never both and never neither; other rules have neither.
   */
  noDirectCert?: LocalizedText;
  /**
   * For a rule whose direct references are scoped to a cause: why the findings of the other
   * causes have no direct CERT rule. Shown only on Java and Kotlin findings without a
   * `references.cert`. Allowed only next to a scoped direct reference.
   */
  noDirectCertOther?: LocalizedText;
  /** Reasons for departures from the mapping policy. Each field is required in exactly its case. */
  mappingNote?: RuleMappingNote;
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

/** True when a rule's language list includes Java or Kotlin (the languages CERT Java applies to). */
export function isJvmRuleLanguages(languages: readonly string[]): boolean {
  return languages.some((language) => language === "java" || language === "kotlin");
}

const HANGUL = /[ㄱ-ㆎ가-힣]/;

/**
 * Checks a rule's metadata against the bundled standards data and the translation rules.
 * Returns human-readable problems; an empty list means the metadata is valid.
 */
export function validateRuleMetadata(rule: {
  id: string;
  metadata: RuleMetadata;
  /** When given, the direct-CERT policy for JVM rules is checked too. */
  languages?: readonly string[];
}): string[] {
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
  if (new Set(standards.owasp).size !== standards.owasp.length) fail("duplicate OWASP ids");
  const sameCategories = derived.size === listed.size && [...listed].every((id) => derived.has(id));
  const discouraged = standards.cwe.filter((id) => cweMappingEntry(id)?.usage === "DISCOURAGED");
  const note = standards.mappingNote;
  if (!sameCategories && note?.owaspDeparture === undefined) {
    fail(
      `OWASP ${standards.owasp.join(", ") || "(none)"} does not match the categories of its CWEs (${[...derived].join(", ") || "none"}); fix the mapping or add standards.mappingNote.owaspDeparture`,
    );
  }
  if (sameCategories && note?.owaspDeparture !== undefined) {
    fail("standards.mappingNote.owaspDeparture is set but the OWASP categories follow the CWEs");
  }
  if (discouraged.length > 0 && note?.discouragedCwe === undefined) {
    fail(
      `${discouraged.join(", ")} is DISCOURAGED by MITRE; use a specific CWE or add standards.mappingNote.discouragedCwe`,
    );
  }
  if (discouraged.length === 0 && note?.discouragedCwe !== undefined) {
    fail("standards.mappingNote.discouragedCwe is set but the rule has no DISCOURAGED CWE");
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

  if (rule.languages !== undefined) {
    const jvm = isJvmRuleLanguages(rule.languages);
    const direct = standards.cert.some((ref) => ref.kind === "direct");
    const marker = standards.noDirectCert !== undefined;
    if (jvm && !direct && !marker) {
      fail("applies to Java or Kotlin but has no direct CERT reference and no noDirectCert marker");
    }
    if (direct && marker) fail("has both a direct CERT reference and a noDirectCert marker");
    if (!jvm && direct) fail("has a direct CERT reference but does not apply to Java or Kotlin");
    if (!jvm && marker) fail("has a noDirectCert marker but does not apply to Java or Kotlin");
    if (
      standards.noDirectCertOther !== undefined &&
      !standards.cert.some((ref) => ref.kind === "direct" && ref.cause !== undefined)
    ) {
      fail("has a noDirectCertOther marker but no direct CERT reference scoped to a cause");
    }
  }

  const prose: Array<[string, LocalizedText]> = [
    ["rationale", rationale],
    ...(standards.noDirectCertOther === undefined
      ? []
      : ([["standards.noDirectCertOther", standards.noDirectCertOther]] as Array<
          [string, LocalizedText]
        >)),
    ...(standards.noDirectCert === undefined
      ? []
      : ([["standards.noDirectCert", standards.noDirectCert]] as Array<[string, LocalizedText]>)),
    ["remediation", remediation],
    ...(Object.entries(standards.mappingNote ?? {}) as Array<[string, LocalizedText]>).map(
      ([kind, text]): [string, LocalizedText] => [`standards.mappingNote.${kind}`, text],
    ),
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
