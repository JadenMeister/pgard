import { describe, expect, it } from "vitest";
import { RULE_LOCALITY, unclassifiedRules } from "./rule-locality.js";
import { listSupportedRules } from "./rules.js";

describe("rule locality for incremental scans", () => {
  it("classifies every supported rule (add the new rule to RULE_LOCALITY)", () => {
    // A rule without an entry makes every scan a full one; this test makes that a build failure
    // instead, so the author decides whether the rule is file-local or project-wide.
    expect(unclassifiedRules()).toEqual([]);
  });

  it("has no entry for a rule that does not exist", () => {
    const ids = new Set(listSupportedRules().map((rule) => rule.id));
    expect(Object.keys(RULE_LOCALITY).filter((id) => !ids.has(id))).toEqual([]);
  });

  it("gives every entry a known class and a reason", () => {
    for (const [id, entry] of Object.entries(RULE_LOCALITY)) {
      expect(["file-local", "project-wide", "history-carried"], id).toContain(entry.locality);
      expect(entry.reason.length, id).toBeGreaterThan(20);
    }
  });

  it("treats the checks that read project facts as project-wide", () => {
    expect(RULE_LOCALITY["PG-CSRF-001"]?.locality).toBe("project-wide");
    expect(RULE_LOCALITY["PG-BRUTE-001"]?.locality).toBe("project-wide");
  });

  it("classifies source rules as file-local only when their analyzers see one file", () => {
    // Every source rule except the two project-wide ones is decided by an analyzer that receives
    // the text and path of a single file (`analyzeJsSource`, `analyzeGoSource`, `analyzeVueSource`).
    const local = Object.entries(RULE_LOCALITY)
      .filter(([, entry]) => entry.locality === "file-local")
      .map(([id]) => id);
    expect(local.every((id) => !id.startsWith("PG-SECRET") && !id.startsWith("PG-HYGIENE"))).toBe(
      true,
    );
    expect(local.length).toBeGreaterThanOrEqual(16);
  });
});
