import {
  CWE_ID_PATTERN,
  cweMappingEntry,
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
      "CWE-942": ["PG-WEB-008", "PG-WEB-009"],
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
    expect([...broad].sort()).toEqual(["CWE-327", "CWE-693"]);
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
      "PG-CRYPTO-002": ["MSC03-J via CWE-798"],
      "PG-SECRET-001": ["MSC03-J via CWE-798"],
      "PG-SECRET-002": ["MSC03-J via CWE-798"],
      "PG-SECRET-003": ["MSC03-J via CWE-798"],
    });
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
    expect(allRules().filter((rule) => (rule.metadata.examples ?? []).length > 0).length).toBe(16);
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
