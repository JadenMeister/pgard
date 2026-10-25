import { PGARD_VERSION, listSupportedRules, type RuleDescriptor } from "@pgard/scan-core";
import { describe, expect, it } from "vitest";
import type { CliDeps } from "../../deps.js";
import { createTestContext, createTestDeps, createTestIo } from "../../test-support.js";
import {
  OTHER_RULES_HEADING,
  RULE_CRITERIA_VERSION,
  filterRulesByLanguage,
  groupRulesByScope,
  runRulesList,
} from "./list.js";

const DB_PATH = "/home/user/secret-place/osv.json";

async function runList(
  language: Parameters<typeof runRulesList>[1],
  overrides: Partial<CliDeps> = {},
): Promise<string> {
  const captured = createTestIo({ env: { PGARD_ADVISORY_DB: DB_PATH } });
  expect(await runRulesList(createTestContext(captured, createTestDeps(overrides)), language)).toBe(
    0,
  );
  return captured.stdout();
}

describe("runRulesList", () => {
  it("shows the version header, web rules and unsupported areas, with no advisory status", async () => {
    const stdout = await runList(null);
    expect(stdout).toContain(
      `pgard ${PGARD_VERSION} - detection criteria ${RULE_CRITERIA_VERSION}`,
    );
    expect(stdout).toContain("PG-WEB-013");
    expect(stdout).not.toContain("Advisory database status");
    expect(stdout).not.toContain("PG-DEP-001");
    expect(stdout).not.toContain(DB_PATH);
    expect(stdout).toContain("Direct database connections");
    expect(stdout).toContain("PGARD ships no vulnerability database");
  });

  it("lists every engine rule grouped by scope", async () => {
    const stdout = await runList(null);
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
    expect(stdout.indexOf("PG-HYGIENE-001")).toBeGreaterThan(historyHeading);
    expect(stdout.indexOf("PG-HYGIENE-001")).toBeLessThan(webHeading);
    expect(stdout).toContain(
      "  PG-HYGIENE-001 info     Dependency directory committed to Git [any]",
    );
  });

  it("filters by language and keeps rules for any language", async () => {
    const stdout = await runList("go");
    expect(stdout).toContain("Language filter: go");
    expect(stdout).toContain("PG-SQL-003");
    expect(stdout).not.toContain("PG-SQL-001");
    expect(stdout).not.toContain("PG-XSS-002");
    expect(stdout).toContain("PG-SECRET-001");
    expect(stdout).toContain("PG-WEB-001");
  });

  it("says that react and vue include the JavaScript/TypeScript rules", async () => {
    const react = await runList("react");
    expect(react).toContain(
      "Language filter: react (javascript/typescript rules and rules for any language are included)",
    );
    expect(react).toContain("PG-SQL-001");
    expect(react).toContain("PG-XSS-002");
    expect(await runList("go")).toContain(
      "Language filter: go (rules for any language are included)",
    );
  });

  it("is deterministic", async () => {
    expect(await runList("ts")).toBe(await runList("ts"));
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
    expect(vue).not.toContain("PG-XSS-002");
    expect(vue).toContain("PG-SECRET-002");
  });

  it("includes the JavaScript/TypeScript rules for react and vue, but not Go rules", () => {
    const jsTs = new Set([
      ...filterRulesByLanguage(rules, "js").map((rule) => rule.id),
      ...filterRulesByLanguage(rules, "ts").map((rule) => rule.id),
    ]);
    for (const language of ["react", "vue"] as const) {
      const ids = filterRulesByLanguage(rules, language).map((rule) => rule.id);
      for (const id of jsTs) expect(ids).toContain(id);
      expect(ids).toContain("PG-SQL-001");
      expect(ids).not.toContain("PG-SQL-003");
    }
  });

  it("returns every rule without a filter", () => {
    expect(filterRulesByLanguage(rules, null)).toHaveLength(rules.length);
  });
});

describe("groupRulesByScope", () => {
  const rules = listSupportedRules();

  it("puts rules of a scope without a heading into a fallback group", () => {
    const webRule: RuleDescriptor = { ...rules[0]!, id: "PG-WEB-900", scope: "web" };
    const unknownRule = {
      ...rules[0]!,
      id: "PG-NEW-001",
      scope: "deps",
    } as unknown as RuleDescriptor;
    const groups = groupRulesByScope([...rules, unknownRule, webRule]);
    const other = groups.at(-1)!;
    expect(other.heading).toBe(OTHER_RULES_HEADING);
    expect(other.rules.map((rule) => rule.id)).toEqual(["PG-NEW-001", "PG-WEB-900"]);
    const listed = groups.flatMap((group) => group.rules.map((rule) => rule.id)).sort();
    expect(listed).toEqual([...rules.map((rule) => rule.id), "PG-NEW-001", "PG-WEB-900"].sort());
  });

  it("shows no fallback group when every scope has a heading", () => {
    const headings = groupRulesByScope(rules).map((group) => group.heading);
    expect(headings).not.toContain(OTHER_RULES_HEADING);
  });

  it("does not depend on the catalog order", () => {
    const expected = groupRulesByScope(rules);
    let seed = 7;
    for (let round = 0; round < 5; round += 1) {
      const shuffled = [...rules];
      for (let index = shuffled.length - 1; index > 0; index -= 1) {
        seed = (seed * 1103515245 + 12345) % 2147483648;
        const swap = seed % (index + 1);
        [shuffled[index], shuffled[swap]] = [shuffled[swap]!, shuffled[index]!];
      }
      expect(groupRulesByScope(shuffled)).toEqual(expected);
    }
    expect(groupRulesByScope([...rules].reverse())).toEqual(expected);
  });
});
