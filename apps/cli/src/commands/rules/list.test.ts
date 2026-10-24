import { PGARD_VERSION, listSupportedRules } from "@pgard/scan-core";
import { describe, expect, it } from "vitest";
import { createTestContext, createTestDeps, createTestIo } from "../../test-support.js";
import { RULE_CRITERIA_VERSION, filterRulesByLanguage, runRulesList } from "./list.js";

function runList(language: Parameters<typeof runRulesList>[1]): string {
  const captured = createTestIo();
  expect(runRulesList(createTestContext(captured, createTestDeps()), language)).toBe(0);
  return captured.stdout();
}

describe("runRulesList", () => {
  it("shows the version header, web rules, advisory status and unsupported areas", () => {
    const stdout = runList(null);
    expect(stdout).toContain(
      `pgard ${PGARD_VERSION} - detection criteria ${RULE_CRITERIA_VERSION}`,
    );
    expect(stdout).toContain("PG-WEB-013");
    expect(stdout).toContain("Advisory database status: missing");
    expect(stdout).toContain("Direct database connections");
  });

  it("lists every engine rule grouped by scope", () => {
    const stdout = runList(null);
    for (const rule of listSupportedRules()) expect(stdout).toContain(rule.id);
    const codeHeading = stdout.indexOf("Code rules (current files)");
    const historyHeading = stdout.indexOf("Git history rules");
    const webHeading = stdout.indexOf("Local HTTP rules");
    expect(codeHeading).toBeGreaterThan(-1);
    expect(stdout.indexOf("PG-SQL-001")).toBeGreaterThan(codeHeading);
    expect(stdout.indexOf("PG-SQL-001")).toBeLessThan(historyHeading);
    expect(stdout.indexOf("PG-SECRET-001")).toBeGreaterThan(historyHeading);
    expect(stdout.indexOf("PG-SECRET-001")).toBeLessThan(webHeading);
    expect(stdout).toMatch(/PG-SQL-001\s+high\s+.+\[javascript, typescript\]/);
  });

  it("filters by language and keeps rules for any language", () => {
    const stdout = runList("go");
    expect(stdout).toContain("Language filter: go");
    expect(stdout).toContain("PG-SQL-003");
    expect(stdout).not.toContain("PG-SQL-001");
    expect(stdout).not.toContain("PG-XSS-002");
    expect(stdout).toContain("PG-SECRET-001");
    expect(stdout).toContain("PG-WEB-001");
  });

  it("is deterministic", () => {
    expect(runList("ts")).toBe(runList("ts"));
  });
});

describe("filterRulesByLanguage", () => {
  const rules = listSupportedRules();

  it("maps js/ts to the catalog language names", () => {
    const js = filterRulesByLanguage(rules, "js").map((rule) => rule.id);
    const ts = filterRulesByLanguage(rules, "ts").map((rule) => rule.id);
    expect(js).toContain("PG-SQL-001");
    expect(ts).toContain("PG-SQL-001");
    expect(js).not.toContain("PG-SQL-003");
  });

  it("selects framework rules for react and vue", () => {
    const react = filterRulesByLanguage(rules, "react").map((rule) => rule.id);
    const vue = filterRulesByLanguage(rules, "vue").map((rule) => rule.id);
    expect(react).toContain("PG-XSS-002");
    expect(react).not.toContain("PG-XSS-003");
    expect(vue).toContain("PG-XSS-003");
    expect(vue).toContain("PG-SECRET-002");
  });

  it("returns every rule without a filter", () => {
    expect(filterRulesByLanguage(rules, null)).toHaveLength(rules.length);
  });
});
