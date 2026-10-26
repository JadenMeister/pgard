import type { FindingCategory, ScanScope, Severity } from "./contract.js";
import type { RuleMetadata } from "./rule-metadata.js";

export type RuleLanguage = "javascript" | "typescript" | "react" | "vue" | "go" | "any";

/**
 * Catalog entry for a rule, shared by every analyzer and shown by `pgard rules list`.
 * `cwe`, `owasp`, `impact` and `recommendation` are the English values derived from `metadata`
 * by `defineRule`; they feed findings and reports unchanged. `metadata` is the source of truth.
 */
export interface RuleDescriptor {
  id: string;
  title: string;
  category: FindingCategory;
  /** Severity when the strongest evidence is present; weaker evidence lowers it. */
  defaultSeverity: Severity;
  scope: ScanScope;
  languages: RuleLanguage[];
  cwe: string[];
  owasp: string[];
  impact: string;
  recommendation: string;
  metadata: RuleMetadata;
}

/** What a rule author writes: identity fields plus the metadata, flat. */
export type RuleDefinition = Omit<
  RuleDescriptor,
  "cwe" | "owasp" | "impact" | "recommendation" | "metadata" | "languages"
> &
  RuleMetadata & { languages: readonly RuleLanguage[] };

/** Deep copy of rule metadata, so no mutable reference is shared with the definition. */
export function copyRuleMetadata(metadata: RuleMetadata): RuleMetadata {
  const { standards, rationale, remediation, examples } = metadata;
  return {
    standards: {
      owasp: [...standards.owasp],
      cwe: [...standards.cwe],
      cert: standards.cert.map((ref) => ({ ...ref })),
      ...(standards.mappingNote === undefined
        ? {}
        : {
            mappingNote: {
              ...(standards.mappingNote.discouragedCwe === undefined
                ? {}
                : { discouragedCwe: { ...standards.mappingNote.discouragedCwe } }),
              ...(standards.mappingNote.owaspDeparture === undefined
                ? {}
                : { owaspDeparture: { ...standards.mappingNote.owaspDeparture } }),
            },
          }),
    },
    rationale: { ...rationale },
    remediation: { ...remediation },
    ...(examples === undefined
      ? {}
      : {
          examples: examples.map((example) => ({
            ...example,
            ...(example.note === undefined ? {} : { note: { ...example.note } }),
          })),
        }),
  };
}

/** Splits a definition into the descriptor (English flat fields derived from the metadata). */
export function defineRule(definition: RuleDefinition): RuleDescriptor {
  const { standards, rationale, remediation, examples, languages, ...identity } = definition;
  const metadata = copyRuleMetadata({
    standards,
    rationale,
    remediation,
    ...(examples === undefined ? {} : { examples }),
  });
  return {
    ...identity,
    languages: [...languages],
    cwe: [...metadata.standards.cwe],
    owasp: [...metadata.standards.owasp],
    impact: metadata.rationale.en,
    recommendation: metadata.remediation.en,
    metadata,
  };
}
