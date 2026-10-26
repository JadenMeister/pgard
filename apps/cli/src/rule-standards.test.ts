import { CWE_ID_PATTERN, getOwaspCategory, isCweTop25 } from "@pgard/findings";
import { WEB_RULE_LIST } from "@pgard/http-local";
import { listSupportedRules } from "@pgard/scan-core";
import { describe, expect, it } from "vitest";

interface Refs {
  id: string;
  cwe: readonly string[];
  owasp: readonly string[];
}

const allRules = (): Refs[] => [
  ...listSupportedRules(),
  ...WEB_RULE_LIST.map((r) => ({
    id: r.id,
    cwe: r.references.cwe,
    owasp: r.references.owasp,
  })),
];

describe("rule references against bundled standards data", () => {
  it("covers the full rule catalog", () => {
    expect(allRules().length).toBeGreaterThan(30);
  });

  it("uses well-formed CWE ids, and reports those outside the CWE Top 25", () => {
    const outside = new Map<string, string[]>();
    for (const rule of allRules()) {
      for (const cwe of rule.cwe) {
        expect(cwe, rule.id).toMatch(CWE_ID_PATTERN);
        if (!isCweTop25(cwe)) outside.set(cwe, [...(outside.get(cwe) ?? []), rule.id]);
      }
    }
    // Informational: weaknesses valid in CWE but outside the Top 25 (explicitly reported, not an error).
    console.info(
      "CWE ids used by rules but outside the CWE Top 25 (2025):\n" +
        [...outside.entries()].map(([cwe, ids]) => `  ${cwe}: ${ids.join(", ")}`).join("\n"),
    );
    expect(outside.size).toBeGreaterThan(0);
  });

  it("only uses OWASP ids that exist in the 2025 list, and reports the others", () => {
    const unknown = new Map<string, string[]>();
    for (const rule of allRules()) {
      for (const id of rule.owasp) {
        if (!getOwaspCategory(id)) unknown.set(id, [...(unknown.get(id) ?? []), rule.id]);
      }
    }
    console.info(
      "OWASP ids used by rules but not in the 2025 list:\n" +
        ([...unknown.entries()].map(([id, ids]) => `  ${id}: ${ids.join(", ")}`).join("\n") ||
          "  (none)"),
    );
    expect([...unknown.keys()]).toEqual([]);
  });
});
