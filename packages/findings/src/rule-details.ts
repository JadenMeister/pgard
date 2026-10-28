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
  /**
   * CERT only: the rule itself is about this weakness (`kind: "direct"`). It is valid for
   * findings in Java or Kotlin files only; see `standardsForPath`.
   */
  direct?: true;
}

/** True for a Java or Kotlin source file (`.kts` Gradle scripts are not analysed as Kotlin). */
export function isJvmSourcePath(path: string | null): boolean {
  if (path === null) return false;
  const lower = path.toLowerCase();
  return lower.endsWith(".java") || lower.endsWith(".kt");
}

/**
 * The standards links that hold for a finding in `path`. A direct CERT Java link is kept only for
 * a Java or Kotlin file, so a JS, Go, Python or PHP finding never shows one. On a JVM file a
 * "via CWE" link to a CERT rule that is already linked directly is dropped as redundant; other
 * files keep the indirect link. The input is not mutated.
 */
export function standardsForPath(
  links: readonly StandardLink[],
  path: string | null,
): StandardLink[] {
  const jvm = isJvmSourcePath(path);
  const direct = new Set(
    links.filter((l) => l.kind === "cert" && l.direct === true).map((l) => l.id),
  );
  return links.filter((link) => {
    if (link.kind !== "cert") return true;
    if (link.direct === true) return jvm;
    return !(jvm && direct.has(link.id));
  });
}

/**
 * Links for a group of findings of one rule (a SARIF rule, a grouped terminal entry): a direct
 * CERT link needs a Java or Kotlin finding in the group, and an indirect one stays for the others.
 */
export function standardsForFindings(
  links: readonly StandardLink[],
  findings: readonly { location: { path: string | null } }[],
): StandardLink[] {
  const jvm = findings.some((f) => isJvmSourcePath(f.location.path));
  const other = findings.length === 0 || findings.some((f) => !isJvmSourcePath(f.location.path));
  const keep = new Set<StandardLink>();
  if (jvm) for (const link of standardsForPath(links, "File.java")) keep.add(link);
  if (other) for (const link of standardsForPath(links, null)) keep.add(link);
  return links.filter((link) => keep.has(link));
}

/** Direct CERT Java rule ids a finding in `path` references (empty outside Java and Kotlin). */
export function directCertIdsForPath(
  standards: RuleMetadata["standards"],
  path: string | null,
): string[] {
  if (!isJvmSourcePath(path)) return [];
  return standards.cert.filter((ref) => ref.kind === "direct").map((ref) => ref.id);
}

/** What a front end shows for a rule beyond its title: the metadata, with links resolved. */
export interface RuleDetails {
  rationale: LocalizedText;
  remediation: LocalizedText;
  standards: StandardLink[];
  /** Why no CERT Java rule is about this (Java and Kotlin) rule's weakness; absent otherwise. */
  noDirectCert?: LocalizedText;
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
      ...(reference.kind === "via-cwe" ? { viaCwe: reference.cwe } : { direct: true as const }),
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
    ...(metadata.standards.noDirectCert === undefined
      ? {}
      : { noDirectCert: { ...metadata.standards.noDirectCert } }),
    examples: (metadata.examples ?? []).map((example) => ({
      ...example,
      ...(example.note === undefined ? {} : { note: { ...example.note } }),
    })),
  };
}
