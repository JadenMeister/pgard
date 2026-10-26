import { describe, expect, it } from "vitest";
import type { Finding } from "./contract.js";
import { buildRuleTextCatalog, localizeFinding, localizeFindings } from "./rule-text.js";
import type { RuleMetadata } from "./rule-metadata.js";

const metadata = {
  standards: { owasp: [], cwe: [], cert: [] },
  rationale: { en: "English impact", ko: "한국어 영향" },
  remediation: { en: "English fix", ko: "한국어 조치" },
} satisfies RuleMetadata;

const catalog = buildRuleTextCatalog([
  { id: "PG-HYGIENE-001", title: "Dependency directory committed to Git", metadata },
]);

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    ruleId: "PG-HYGIENE-001",
    title: "Dependency directory committed to Git",
    category: "hygiene",
    severity: "info",
    status: "informational",
    confidence: "low",
    location: { kind: "file", path: "node_modules/", line: null, url: null, commit: null },
    evidence: "tracked",
    impact: "English impact",
    recommendation: "English fix",
    references: { cwe: [], owasp: [], cve: [] },
    sources: ["history"],
    ...overrides,
  } as Finding;
}

describe("localizeFinding", () => {
  it("returns the same finding for en", () => {
    const input = finding();
    expect(localizeFinding(input, catalog, "en")).toBe(input);
  });

  it("translates title, impact and recommendation for ko without changing the input", () => {
    const input = finding();
    const output = localizeFinding(input, catalog, "ko");
    expect(output.title).toBe("Git에 커밋된 의존성 디렉터리");
    expect(output.impact).toBe("한국어 영향");
    expect(output.recommendation).toBe("한국어 조치");
    expect(input.impact).toBe("English impact");
  });

  it("keeps a recommendation that differs from the rule default (a finding-specific text)", () => {
    const output = localizeFinding(
      finding({ recommendation: "Remove node_modules and add it to .gitignore" }),
      catalog,
      "ko",
    );
    expect(output.recommendation).toBe("Remove node_modules and add it to .gitignore");
    expect(output.impact).toBe("한국어 영향");
  });

  it("leaves findings of unknown rules alone", () => {
    const input = finding({ ruleId: "PG-DEP-OSV" });
    expect(localizeFinding(input, catalog, "ko")).toBe(input);
    expect(localizeFindings([input], catalog, "ko")).toEqual([input]);
  });
});
