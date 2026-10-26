import type { LocalizedText, RuleExample, RuleMetadata } from "./rule-metadata.js";
import {
  certJavaUrl,
  cweUrl,
  getCertJavaRule,
  getCweTop25Entry,
  getOwaspCategory,
} from "./standards/index.js";

/** One link to an official page of a standard: ids, titles and URLs only, never its prose. */
export interface StandardLink {
  kind: "owasp" | "cwe" | "cert";
  /** `A05:2025`, `CWE-89` or `IDS00-J`. */
  id: string;
  /** Official title when the bundled data has one (every OWASP and CERT entry, CWE Top 25). */
  title: string | null;
  url: string;
  /** CERT rule linked through this CWE id (`kind: "via-cwe"` in the metadata). */
  viaCwe?: string;
}

/** What a front end shows for a rule beyond its title: the metadata, with links resolved. */
export interface RuleDetails {
  rationale: LocalizedText;
  remediation: LocalizedText;
  standards: StandardLink[];
  examples: RuleExample[];
}

/** Resolves a rule's standards to official links, in the order OWASP, CWE, CERT. */
export function resolveStandardLinks(standards: RuleMetadata["standards"]): StandardLink[] {
  const links: StandardLink[] = [];
  for (const id of standards.owasp) {
    const category = getOwaspCategory(id);
    if (category !== undefined) {
      links.push({ kind: "owasp", id, title: category.title, url: category.url });
    }
  }
  for (const id of standards.cwe) {
    links.push({ kind: "cwe", id, title: getCweTop25Entry(id)?.name ?? null, url: cweUrl(id) });
  }
  for (const reference of standards.cert) {
    const rule = getCertJavaRule(reference.id);
    if (rule === undefined) continue;
    links.push({
      kind: "cert",
      id: rule.id,
      title: rule.title,
      url: certJavaUrl(rule),
      ...(reference.kind === "via-cwe" ? { viaCwe: reference.cwe } : {}),
    });
  }
  return links;
}

/** Plain copy of the metadata with links resolved, safe to serialize to the dashboard. */
export function buildRuleDetails(metadata: RuleMetadata): RuleDetails {
  return {
    rationale: { ...metadata.rationale },
    remediation: { ...metadata.remediation },
    standards: resolveStandardLinks(metadata.standards),
    examples: (metadata.examples ?? []).map((example) => ({
      ...example,
      ...(example.note === undefined ? {} : { note: { ...example.note } }),
    })),
  };
}
