import {
  CWE_ID_PATTERN,
  getOwaspCategory,
  isCweTop25,
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
      "CWE-307": ["PG-BRUTE-001"],
      "CWE-538": ["PG-SECRET-001", "PG-WEB-012", "PG-WEB-013"],
      "CWE-540": ["PG-SECRET-003"],
      "CWE-1104": ["PG-HYGIENE-001"],
      "CWE-693": ["PG-WEB-001", "PG-WEB-003"],
      "CWE-1021": ["PG-WEB-002"],
      "CWE-1275": ["PG-WEB-006"],
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
