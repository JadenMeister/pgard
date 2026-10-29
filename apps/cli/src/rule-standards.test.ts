import {
  CWE_ID_PATTERN,
  cweMappingEntry,
  getCertJavaRule,
  getOwaspCategory,
  isCweTop25,
  owaspCategoryForCwe,
  redactEvidence,
  validateRuleMetadata,
  type RuleMetadata,
} from "@pgard/findings";
import { WEB_RULE_LIST } from "@pgard/http-local";
import { listSupportedRules } from "@pgard/scan-core";
import { describe, expect, it } from "vitest";

interface Refs {
  id: string;
  metadata: RuleMetadata;
  cwe: readonly string[];
  owasp: readonly string[];
}

const certRefs = (rule: Refs): string[] =>
  rule.metadata.standards.cert.map((ref) =>
    ref.kind === "via-cwe" ? `${ref.id} via ${ref.cwe}` : ref.id,
  );

const allRules = (): Refs[] => [
  ...listSupportedRules(),
  ...WEB_RULE_LIST.map((r) => ({
    id: r.id,
    metadata: r.metadata,
    cwe: r.references.cwe,
    owasp: r.references.owasp,
  })),
];

describe("rule references against bundled standards data", () => {
  it("covers the full rule catalog", () => {
    expect(allRules().length).toBeGreaterThan(30);
  });

  it("uses well-formed CWE ids, and the ones outside the CWE Top 25 are exactly the known set", () => {
    const outside: Record<string, string[]> = {};
    for (const rule of allRules()) {
      for (const cwe of rule.cwe) {
        expect(cwe, rule.id).toMatch(CWE_ID_PATTERN);
        if (!isCweTop25(cwe)) (outside[cwe] ??= []).push(rule.id);
      }
    }
    // Valid CWE ids that are not in the Top 25. A change here is deliberate: update the list.
    expect(outside).toEqual({
      "CWE-916": ["PG-CRYPTO-001"],
      "CWE-328": ["PG-CRYPTO-001"],
      "CWE-321": ["PG-CRYPTO-002"],
      "CWE-1395": ["PG-DEP-001"],
      "CWE-798": ["PG-CRYPTO-002", "PG-SECRET-001", "PG-SECRET-002", "PG-SECRET-003"],
      "CWE-327": ["PG-CRYPTO-003"],
      "CWE-256": ["PG-AUTH-001"],
      "CWE-1004": ["PG-COOKIE-001", "PG-WEB-005"],
      "CWE-614": ["PG-COOKIE-001", "PG-WEB-007"],
      "CWE-1275": ["PG-COOKIE-001", "PG-WEB-006"],
      "CWE-201": ["PG-WEB-004"],
      "CWE-497": ["PG-WEB-010"],
      "CWE-307": ["PG-BRUTE-001"],
      "CWE-538": ["PG-SECRET-001", "PG-WEB-012", "PG-WEB-013"],
      "CWE-527": ["PG-WEB-013"],
      "CWE-540": ["PG-SECRET-003"],
      "CWE-1104": ["PG-HYGIENE-001"],
      "CWE-693": ["PG-WEB-001", "PG-WEB-003"],
      "CWE-1021": ["PG-WEB-002"],
      "CWE-942": ["PG-CONF-001", "PG-WEB-008", "PG-WEB-009"],
      "CWE-548": ["PG-WEB-011"],
    });
  });

  it("only uses OWASP ids that exist in the 2025 list", () => {
    const unknown: string[] = [];
    for (const rule of allRules()) {
      for (const id of rule.owasp) if (!getOwaspCategory(id)) unknown.push(`${rule.id}: ${id}`);
    }
    expect(unknown).toEqual([]);
  });

  it("maps every rule's OWASP categories from its CWEs, unless the rule documents a departure", () => {
    const departures: string[] = [];
    for (const rule of allRules()) {
      const fromCwes = [
        ...new Set(rule.cwe.flatMap((cwe) => owaspCategoryForCwe(cwe) ?? [])),
      ].sort();
      const owasp = [...rule.owasp].sort();
      if (JSON.stringify(owasp) !== JSON.stringify(fromCwes)) {
        expect(
          rule.metadata.standards.mappingNote?.owaspDeparture,
          `${rule.id} departs from its CWEs' categories without a mappingNote.owaspDeparture`,
        ).toBeDefined();
        departures.push(rule.id);
      }
    }
    // A change here is deliberate: a rule that departs from the mapped-CWE lists needs a reason.
    expect(departures).toEqual([]);
  });

  it("uses a discouragedCwe note only for DISCOURAGED CWEs, and every such CWE has one", () => {
    const withNote = allRules()
      .filter((rule) => rule.metadata.standards.mappingNote?.discouragedCwe !== undefined)
      .map((rule) => rule.id);
    const discouraged = allRules()
      .filter((rule) => rule.cwe.some((cwe) => cweMappingEntry(cwe)?.usage === "DISCOURAGED"))
      .map((rule) => rule.id);
    expect(withNote).toEqual(["PG-WEB-001", "PG-WEB-003"]);
    expect(discouraged).toEqual(withNote);
  });

  it("prefers Base and Variant CWEs: the only Pillar or Class CWEs are the documented ones", () => {
    const broad = new Set<string>();
    for (const rule of allRules()) {
      for (const cwe of rule.cwe) {
        const entry = cweMappingEntry(cwe);
        if (entry?.abstraction === "Pillar" || entry?.abstraction === "Class") broad.add(cwe);
      }
    }
    // CWE-693 (Pillar, DISCOURAGED) has a note; CWE-327 (Class, ALLOWED-WITH-REVIEW) is MITRE's
    // entry for a broken cipher and no more specific entry covers "any broken cipher".
    // CWE-862 (Class, ALLOWED-WITH-REVIEW) names the missing authorization of PG-CONF-001 (catch-all permitAll, web.ignoring()); CWE-284 is a DISCOURAGED Pillar.
    expect([...broad].sort()).toEqual(["CWE-327", "CWE-693", "CWE-862"]);
  });

  it("keeps CERT links only where SEI lists the CWE and the topic matches", () => {
    const certs = Object.fromEntries(
      allRules()
        .map((rule): [string, string[]] => [rule.id, certRefs(rule)])
        .filter(([, refs]) => refs.length > 0),
    );
    expect(certs).toEqual({
      "PG-CMD-001": ["IDS07-J via CWE-78"],
      "PG-CMD-002": ["IDS07-J via CWE-78"],
      // IDS07-J and FIO16-J are about Runtime.exec and path canonicalization themselves.
      "PG-CMD-003": ["IDS07-J"],
      // MSC03-J names hard coded encryption keys itself: direct for Java and Kotlin findings, and
      // still the indirect link for the other languages of the rule.
      "PG-CRYPTO-002": ["MSC03-J", "MSC03-J via CWE-798"],
      "PG-CRYPTO-003": ["MSC02-J"],
      "PG-PATH-002": ["FIO16-J", "IDS04-J"],
      "PG-SECRET-001": ["MSC03-J via CWE-798"],
      "PG-SECRET-002": ["MSC03-J via CWE-798"],
      "PG-SECRET-003": ["MSC03-J via CWE-798"],
      // IDS00-J is about SQL injection itself, so the link is direct.
      "PG-SQL-005": ["IDS00-J"],
    });
  });

  it("gives every Java and Kotlin rule a direct CERT entry or the explicit no-direct marker", () => {
    const direct: Record<string, string[]> = {};
    const none: string[] = [];
    for (const rule of listSupportedRules()) {
      const jvm = rule.languages.some((l) => l === "java" || l === "kotlin");
      const { cert, noDirectCert } = rule.metadata.standards;
      const ids = cert.filter((ref) => ref.kind === "direct").map((ref) => ref.id);
      if (!jvm) {
        // Rules for other languages never carry a direct CERT Java entry or the marker.
        expect(ids, rule.id).toEqual([]);
        expect(noDirectCert, rule.id).toBeUndefined();
        continue;
      }
      expect(ids.length > 0 !== (noDirectCert !== undefined), `${rule.id}: one of the two`).toBe(
        true,
      );
      if (ids.length > 0) direct[rule.id] = ids;
      else none.push(rule.id);
    }
    // Direct entries: the CERT rule is about the weakness itself (not merely a related CWE).
    //   PG-SQL-005    IDS00-J  "Prevent SQL injection"
    //   PG-CMD-003    IDS07-J  "Sanitize untrusted data passed to the Runtime.exec() method" (CWE-78)
    //   PG-PATH-002   FIO16-J  "Canonicalize path names before validating them" (path findings other than archive entries)
    //                 IDS04-J  "Safely extract files from ZipInputStream" (archive entry findings: zip slip)
    //   PG-CRYPTO-003 MSC02-J  "Generate strong random numbers" (weak random source findings only; table lists CWE-327)
    //   PG-CRYPTO-002 MSC03-J  "Never hard code sensitive information", names encryption keys (CWE-798)
    expect(direct).toEqual({
      "PG-SQL-005": ["IDS00-J"],
      "PG-CMD-003": ["IDS07-J"],
      "PG-PATH-002": ["FIO16-J", "IDS04-J"],
      "PG-CRYPTO-002": ["MSC03-J"],
      "PG-CRYPTO-003": ["MSC02-J"],
    });
    // Marked "no direct CERT rule": no rule of the SEI CERT Oracle Java standard is about them.
    expect(none.sort()).toEqual([
      "PG-AUTH-001",
      "PG-CONF-001",
      "PG-COOKIE-001",
      "PG-CRYPTO-001",
      "PG-CSRF-001",
      "PG-SSRF-002",
      "PG-XSS-004",
    ]);
  });

  it("agrees direct CERT entries with the bundled CERT table", () => {
    for (const rule of listSupportedRules()) {
      for (const ref of rule.metadata.standards.cert) {
        const certRule = getCertJavaRule(ref.id);
        expect(certRule, `${rule.id} ${ref.id}`).toBeDefined();
        if (ref.kind === "direct") {
          // Where the table lists a CWE of the rule, say so; otherwise the entry is topical
          // (IDS00-J lists CWE-116 only, FIO16-J lists CWE-171 and CWE-647), pinned above.
          const shared = rule.metadata.standards.cwe.filter((cwe) => certRule?.cwe.includes(cwe));
          const topical = ["PG-SQL-005", "PG-PATH-002"];
          expect(shared.length > 0 || topical.includes(rule.id), `${rule.id} ${ref.id}`).toBe(true);
        }
      }
    }
  });

  it("gives every rule concrete guidance in both languages, and examples that differ", () => {
    for (const rule of allRules()) {
      const { rationale, remediation, examples } = rule.metadata;
      for (const text of [rationale, remediation]) {
        expect(text.en.length, `${rule.id} English text is too short`).toBeGreaterThan(80);
        expect(text.ko.length, `${rule.id} Korean text is too short`).toBeGreaterThan(40);
      }
      for (const example of examples ?? []) {
        expect(example.vulnerable, rule.id).not.toBe(example.safe);
        expect(example.vulnerable.length, rule.id).toBeGreaterThan(0);
      }
    }
    expect(allRules().filter((rule) => (rule.metadata.examples ?? []).length > 0).length).toBe(25);
  });

  it("survives output redaction unchanged: findings carry impact and recommendation through redactEvidence", () => {
    for (const rule of allRules()) {
      const { rationale, remediation } = rule.metadata;
      for (const text of [rationale.en, rationale.ko, remediation.en, remediation.ko]) {
        expect(redactEvidence(text, { maxLength: 1000 }), rule.id).toBe(text);
      }
    }
  });

  it("keeps every recommendation within the 500-character limit, in both languages", () => {
    for (const rule of allRules()) {
      expect(rule.metadata.remediation.en.length, `${rule.id} en`).toBeLessThanOrEqual(500);
      expect(rule.metadata.remediation.ko.length, `${rule.id} ko`).toBeLessThanOrEqual(500);
    }
  });

  it("has valid metadata with Korean text for every rule", () => {
    const rules = allRules();
    expect(rules.flatMap((rule) => validateRuleMetadata(rule))).toEqual([]);
    expect(new Set(rules.map((rule) => rule.id)).size).toBe(rules.length);
  });

  it("keeps the flat English fields identical to the metadata", () => {
    for (const rule of listSupportedRules()) {
      expect(rule.impact, rule.id).toBe(rule.metadata.rationale.en);
      expect(rule.recommendation, rule.id).toBe(rule.metadata.remediation.en);
      expect(rule.cwe, rule.id).toEqual([...rule.metadata.standards.cwe]);
      expect(rule.owasp, rule.id).toEqual([...rule.metadata.standards.owasp]);
    }
    for (const rule of WEB_RULE_LIST) {
      expect(rule.impact, rule.id).toBe(rule.metadata.rationale.en);
      expect(rule.recommendation, rule.id).toBe(rule.metadata.remediation.en);
      expect(rule.references.cwe, rule.id).toEqual([...rule.metadata.standards.cwe]);
      expect(rule.references.owasp, rule.id).toEqual([...rule.metadata.standards.owasp]);
      expect(rule.references.cve, rule.id).toEqual([]);
    }
  });

  it("does not share mutable arrays between a web rule's flat fields and its metadata", () => {
    for (const rule of WEB_RULE_LIST) {
      expect(rule.references.cwe, rule.id).not.toBe(rule.metadata.standards.cwe);
      expect(rule.references.owasp, rule.id).not.toBe(rule.metadata.standards.owasp);
    }
  });
});
