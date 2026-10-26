import { CERT_JAVA_RULES } from "./cert-java.js";
import { CWE_TOP25 } from "./cwe-top25.js";
import { OWASP_TOP10_2025 } from "./owasp-top10-2025.js";
import type { CertJavaRule, CweTop25Entry, OwaspCategory, StandardProvenance } from "./types.js";

export type {
  CertJavaRule,
  CweTop25Entry,
  OwaspCategory,
  OwaspId,
  StandardProvenance,
} from "./types.js";
export { OWASP_IDS } from "./types.js";
export { OWASP_TOP10_2025, OWASP_TOP10_2025_PROVENANCE } from "./owasp-top10-2025.js";
export { CWE_TOP25, CWE_TOP25_PROVENANCE } from "./cwe-top25.js";
export { CERT_JAVA_RULES } from "./cert-java.js";
export {
  CWE_MAPPING_USAGE,
  CWE_MAPPING_USAGE_PROVENANCE,
  OWASP_MAPPED_CWES,
  OWASP_MAPPED_CWES_PROVENANCE,
  cweMappingEntry,
  owaspCategoryForCwe,
} from "./owasp-mapped-cwes.js";
export type { CweAbstraction, CweMappingEntry, CweMappingUsage } from "./owasp-mapped-cwes.js";

const CERT_BASE =
  "https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/";

export const CERT_JAVA_PROVENANCE: StandardProvenance = {
  name: "SEI CERT Oracle Coding Standard for Java",
  edition:
    "Rules and MITRE CWE table as published by SEI (secure-coding-standards commit 72e8a32, 2026-10-23)",
  sourceUrl: CERT_BASE,
  retrievedAt: "2026-10-26",
  license: "Creative Commons Attribution 4.0 (CC BY 4.0)",
  attribution:
    "(c) 2026 Carnegie Mellon University. SEI CERT is a registered trademark of Carnegie Mellon University.",
};

const owaspById = new Map<string, OwaspCategory>(OWASP_TOP10_2025.map((c) => [c.id, c]));
const cweById = new Map(CWE_TOP25.map((c) => [c.id, c]));
const certById = new Map(CERT_JAVA_RULES.map((r) => [r.id, r]));

export const OWASP_ID_PATTERN = /^A(0[1-9]|10):2025$/;
export const CWE_ID_PATTERN = /^CWE-[1-9]\d*$/;
export const CERT_JAVA_ID_PATTERN = /^[A-Z]{3}\d{2}-J$/;

export function getOwaspCategory(id: string): OwaspCategory | undefined {
  return owaspById.get(id);
}

/** Top 25 entry for a CWE id. `undefined` means outside the Top 25 (it can still be a valid CWE). */
export function getCweTop25Entry(id: string): CweTop25Entry | undefined {
  return cweById.get(id);
}

export function isCweTop25(id: string): boolean {
  return cweById.has(id);
}

export function getCertJavaRule(id: string): CertJavaRule | undefined {
  return certById.get(id);
}

/** CERT Java rules whose related-guidelines table lists this CWE id. */
export function certJavaRulesForCwe(cwe: string): CertJavaRule[] {
  return CERT_JAVA_RULES.filter((r) => r.cwe.includes(cwe));
}

export function cweUrl(id: string): string {
  return `https://cwe.mitre.org/data/definitions/${id.replace(/^CWE-/, "")}.html`;
}

export function certJavaUrl(rule: CertJavaRule): string {
  return `${CERT_BASE}${rule.path}`;
}
