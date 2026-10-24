import { PGARD_VERSION, listSupportedRules, type AdvisoryDbStatus } from "@pgard/scan-core";
import { describe, expect, it } from "vitest";
import type { CliDeps } from "../../deps.js";
import { createTestContext, createTestDeps, createTestIo } from "../../test-support.js";
import { RULE_CRITERIA_VERSION, filterRulesByLanguage, runRulesList } from "./list.js";

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

function advisoryDeps(status: AdvisoryDbStatus): Partial<CliDeps> {
  return { readAdvisoryDbStatus: async () => status };
}

describe("runRulesList", () => {
  it("shows the version header, web rules, advisory status and unsupported areas", async () => {
    const stdout = await runList(null);
    expect(stdout).toContain(
      `pgard ${PGARD_VERSION} - detection criteria ${RULE_CRITERIA_VERSION}`,
    );
    expect(stdout).toContain("PG-WEB-013");
    expect(stdout).toContain("Advisory database status: missing");
    expect(stdout).toContain("Direct database connections");
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

  it("is deterministic", async () => {
    expect(await runList("ts")).toBe(await runList("ts"));
  });
});

describe("runRulesList advisory status", () => {
  it("shows an ok database with version, update time and note", async () => {
    const stdout = await runList(
      null,
      advisoryDeps({
        status: "ok",
        version: "osv-2026-10-20",
        updatedAt: "2026-10-20T00:00:00.000Z",
        advisoryCount: 12,
        note: "12 advisories, updated 2026-10-20.",
      }),
    );
    expect(stdout).toContain(
      "Advisory database status: ok - version osv-2026-10-20, updated 2026-10-20T00:00:00.000Z - 12 advisories, updated 2026-10-20.",
    );
  });

  it("shows stale and invalid databases without the configured path", async () => {
    const stale = await runList(
      null,
      advisoryDeps({
        status: "stale",
        version: "v1",
        updatedAt: "2026-01-01T00:00:00.000Z",
        advisoryCount: 3,
        note: "Advisory data is stale: last updated 2026-01-01 (more than 30 days ago). Newer advisories are not checked.",
      }),
    );
    expect(stale).toContain("Advisory database status: stale - version v1");
    expect(stale).toContain("Newer advisories are not checked.");
    const invalid = await runList(
      null,
      advisoryDeps({
        status: "invalid",
        version: null,
        updatedAt: null,
        advisoryCount: 0,
        note: "The advisory database contains no advisories.",
      }),
    );
    expect(invalid).toContain(
      "Advisory database status: invalid - version none, updated never - The advisory database contains no advisories.",
    );
    expect(stale).not.toContain(DB_PATH);
    expect(invalid).not.toContain(DB_PATH);
  });

  it("reports a failing status read as invalid without echoing the error", async () => {
    const stdout = await runList(null, {
      readAdvisoryDbStatus: async () => {
        throw new Error(`EACCES: permission denied, open '${DB_PATH}'`);
      },
    });
    expect(stdout).toContain("Advisory database status: invalid - version none, updated never");
    expect(stdout).not.toContain(DB_PATH);
    expect(stdout).not.toContain("EACCES");
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
