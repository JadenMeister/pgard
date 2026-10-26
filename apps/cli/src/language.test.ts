import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RULE_TITLES_KO } from "@pgard/findings";
import { WEB_RULE_LIST } from "@pgard/http-local";
import { listSupportedRules } from "@pgard/scan-core";
import { describe, expect, it } from "vitest";
import { main } from "./app.js";
import { saveReports } from "./flows/export-report.js";
import { runScanCommand } from "./commands/scan/index.js";
import { runRulesList } from "./commands/rules/list.js";
import { resolveLanguage } from "./language.js";
import { parseCommandLine, UsageError } from "./options.js";
import { getRuleTextCatalog } from "./rule-texts.js";
import {
  createTestContext,
  createTestDeps,
  createTestIo,
  noInterrupts,
  testFinding,
  testResult,
} from "./test-support.js";

const HANGUL = /[가-힣]/;

describe("resolveLanguage", () => {
  const none = (): undefined => undefined;

  it("defaults to English", () => {
    expect(resolveLanguage({ flag: null, env: {}, platformLocale: none })).toBe("en");
  });

  it("prefers --lang over PGARD_LANG over the locale", () => {
    const env = { PGARD_LANG: "ko", LANG: "en_US.UTF-8" };
    expect(resolveLanguage({ flag: "en", env, platformLocale: none })).toBe("en");
    expect(resolveLanguage({ flag: null, env, platformLocale: none })).toBe("ko");
    expect(
      resolveLanguage({ flag: null, env: { LANG: "ko_KR.UTF-8" }, platformLocale: none }),
    ).toBe("ko");
    expect(resolveLanguage({ flag: null, env: { PGARD_LANG: "en", LANG: "ko_KR.UTF-8" } })).toBe(
      "en",
    );
  });

  it("reads LC_ALL, then LC_MESSAGES, then LANG; the first non-empty one decides", () => {
    const ko = "ko_KR.UTF-8";
    expect(
      resolveLanguage({ flag: null, env: { LC_ALL: ko, LANG: "en_US" }, platformLocale: none }),
    ).toBe("ko");
    expect(
      resolveLanguage({ flag: null, env: { LC_ALL: "C", LANG: ko }, platformLocale: none }),
    ).toBe("en");
    expect(
      resolveLanguage({ flag: null, env: { LC_ALL: "", LC_MESSAGES: ko }, platformLocale: none }),
    ).toBe("ko");
    expect(resolveLanguage({ flag: null, env: { LANG: "ko" }, platformLocale: none })).toBe("ko");
    expect(resolveLanguage({ flag: null, env: { LANG: "kok_IN" }, platformLocale: none })).toBe(
      "en",
    );
  });

  it("falls back to the platform locale only when no variable is set", () => {
    expect(resolveLanguage({ flag: null, env: {}, platformLocale: () => "ko-KR" })).toBe("ko");
    expect(
      resolveLanguage({ flag: null, env: { LANG: "en_US" }, platformLocale: () => "ko-KR" }),
    ).toBe("en");
  });

  it("accepts PGARD_LANG and --lang values in any letter case", () => {
    expect(resolveLanguage({ flag: null, env: { PGARD_LANG: "KO" } })).toBe("ko");
    expect(resolveLanguage({ flag: null, env: { PGARD_LANG: " En " }, platformLocale: none })).toBe(
      "en",
    );
    expect(parseCommandLine(["rules", "list", "--lang", "KO"])).toMatchObject({ lang: "ko" });
  });

  it("rejects an invalid PGARD_LANG as a usage error", () => {
    expect(() => resolveLanguage({ flag: null, env: { PGARD_LANG: "fr" } })).toThrow(UsageError);
  });
});

describe("language options", () => {
  it("parses --lang and --report-lang", () => {
    expect(
      parseCommandLine([
        "scan",
        "--lang",
        "ko",
        "--report",
        "html",
        "--output-dir",
        "/tmp/x",
        "--report-lang=en",
      ]),
    ).toMatchObject({ kind: "scan", lang: "ko", reportLang: "en" });
    expect(parseCommandLine(["rules", "list", "--lang", "ko"])).toMatchObject({
      kind: "rules-list",
      lang: "ko",
    });
  });

  it("rejects bad values and misplaced options", () => {
    expect(() => parseCommandLine(["scan", "--lang", "fr"])).toThrow("--lang must be one of");
    expect(() => parseCommandLine(["scan", "--report-lang", "ko"])).toThrow(
      "--report-lang needs --report",
    );
    expect(() => parseCommandLine(["doctor", "--lang", "ko"])).toThrow("not available");
  });

  it("exits 2 for an invalid --lang or PGARD_LANG before any work", async () => {
    for (const [argv, env] of [
      [["rules", "list", "--lang", "fr"], {}],
      [["rules", "list"], { PGARD_LANG: "fr" }],
    ] as const) {
      const captured = createTestIo({ env });
      const code = await main(argv, captured.io, {
        deps: createTestDeps(),
        interrupts: noInterrupts,
      });
      expect(code).toBe(2);
      expect(captured.stdout()).toBe("");
      expect(captured.stderr()).toMatch(/must be one of en, ko/);
    }
  });
});

describe("rule titles", () => {
  const rules = [...listSupportedRules(), ...WEB_RULE_LIST];

  it("every rule has a Korean title that differs from the English one", () => {
    expect(rules.length).toBeGreaterThanOrEqual(35);
    for (const rule of rules) {
      const ko = RULE_TITLES_KO[rule.id];
      expect(ko, rule.id).toBeDefined();
      expect(ko, rule.id).toMatch(HANGUL);
      expect(ko, rule.id).not.toBe(rule.title);
    }
  });

  it("has no Korean title for an unknown rule id", () => {
    const ids = new Set(rules.map((rule) => rule.id));
    expect(Object.keys(RULE_TITLES_KO).filter((id) => !ids.has(id))).toEqual([]);
  });

  it("every rule has Korean impact and fix texts in the catalog", () => {
    for (const rule of rules) {
      const texts = getRuleTextCatalog().get(rule.id);
      expect(texts?.impact.ko, rule.id).toMatch(HANGUL);
      expect(texts?.recommendation.ko, rule.id).toMatch(HANGUL);
    }
  });
});

describe("PGARD_LANG scope", () => {
  it("does not stop commands that show no rule text", async () => {
    for (const argv of [["doctor"], ["logout"], ["history", "clear", "--all"]]) {
      const captured = createTestIo({ env: { PGARD_LANG: "fr" } });
      await main(argv, captured.io, { deps: createTestDeps(), interrupts: noInterrupts });
      expect(captured.stderr(), argv.join(" ")).not.toMatch(/PGARD_LANG/);
    }
  });
});

describe("Korean CLI output", () => {
  const sql = listSupportedRules().find((rule) => rule.id === "PG-SQL-001");
  if (sql === undefined) throw new Error("PG-SQL-001 is missing");
  const ruleFinding = (overrides = {}) =>
    testFinding({
      ruleId: sql.id,
      title: sql.title,
      impact: sql.impact,
      recommendation: sql.recommendation,
      ...overrides,
    });

  async function scanOutput(
    locale: "en" | "ko",
    findings: ReturnType<typeof ruleFinding>[],
  ): Promise<string> {
    const captured = createTestIo();
    const context = {
      ...createTestContext(
        captured,
        createTestDeps({ runScan: async () => testResult({ findings }) }),
      ),
      ruleLocale: locale,
      ruleTexts: getRuleTextCatalog(),
    };
    await runScanCommand(context, { variant: "code", port: null, report: null });
    return captured.stdout();
  }

  it("prints the rule title and fix in Korean", async () => {
    const stdout = await scanOutput("ko", [ruleFinding()]);
    expect(stdout).toContain("pg/mysql2 쿼리에 동적 문자열로 만든 SQL");
    expect(stdout).toContain("SQL 문자열은 고정해 두고 값은 바인딩된 매개변수로 전달하세요");
    expect(stdout).not.toContain("Keep the SQL text constant");
  });

  it("keeps English when the language is en", async () => {
    const stdout = await scanOutput("en", [ruleFinding()]);
    expect(stdout).toContain(sql.title);
    expect(stdout).toContain("Keep the SQL text constant");
  });

  it("keeps a finding's own recommendation instead of the rule default", async () => {
    const own = "Remove the directory from Git and add it to .gitignore.";
    const stdout = await scanOutput("ko", [ruleFinding({ recommendation: own })]);
    expect(stdout).toContain(own);
    expect(stdout).not.toContain("SQL 문자열은 고정해 두고");
    expect(stdout).toContain("pg/mysql2 쿼리에 동적 문자열로 만든 SQL");
  });

  it("does not change the JSON output", async () => {
    const captured = createTestIo();
    const context = {
      ...createTestContext(
        captured,
        createTestDeps({ runScan: async () => testResult({ findings: [ruleFinding()] }) }),
      ),
      ruleLocale: "ko" as const,
      ruleTexts: getRuleTextCatalog(),
    };
    await runScanCommand(context, { variant: "code", port: null, report: null, format: "json" });
    const parsed = JSON.parse(captured.stdout()) as { findings: Array<{ title: string }> };
    expect(parsed.findings[0]?.title).toBe(sql.title);
    expect(captured.stdout()).not.toMatch(HANGUL);
  });

  it("lists rule titles in Korean with `rules list --lang ko`", async () => {
    const captured = createTestIo();
    const code = await main(["rules", "list", "--lang", "ko"], captured.io, {
      deps: createTestDeps(),
      interrupts: noInterrupts,
    });
    expect(code).toBe(0);
    expect(captured.stdout()).toContain("PG-SQL-001");
    expect(captured.stdout()).toContain("pg/mysql2 쿼리에 동적 문자열로 만든 SQL");
    expect(captured.stdout()).toContain("HTTP로 제공되는 .env 파일");
    expect(captured.stdout()).not.toContain(sql.title);
  });

  it("follows PGARD_LANG and the system locale when --lang is absent", async () => {
    for (const env of [{ PGARD_LANG: "ko" }, { LANG: "ko_KR.UTF-8" }] as Array<
      Record<string, string>
    >) {
      const captured = createTestIo({ env });
      await main(["rules", "list"], captured.io, {
        deps: createTestDeps(),
        interrupts: noInterrupts,
      });
      expect(captured.stdout()).toContain("pg/mysql2 쿼리에 동적 문자열로 만든 SQL");
    }
    const english = createTestIo();
    await main(["rules", "list"], english.io, { deps: createTestDeps(), interrupts: noInterrupts });
    expect(english.stdout()).toContain(sql.title);
  });

  it("passes the report language and rule texts to the report writer", async () => {
    const calls: Array<{ lang?: string; hasTexts: boolean }> = [];
    const captured = createTestIo();
    const context = {
      ...createTestContext(
        captured,
        createTestDeps({
          writeReports: (async (
            _result: unknown,
            options: { lang?: string; ruleTexts?: unknown },
          ) => {
            calls.push({ lang: options.lang, hasTexts: options.ruleTexts !== undefined });
            return [];
          }) as never,
        }),
      ),
      ruleLocale: "en" as const,
      reportLocale: "ko" as const,
      ruleTexts: getRuleTextCatalog(),
    };
    expect(await saveReports(context, testResult(), "html", "/tmp/out")).toBe(true);
    expect(calls).toEqual([{ lang: "ko", hasTexts: true }]);
  });

  it("writes reports in --report-lang, independent of --lang, end to end through main", async () => {
    const outDir = mkdtempSync(join(tmpdir(), "pgard-lang-"));
    const seen: Array<{ lang?: string }> = [];
    for (const [argv, expected] of [
      [
        ["scan", "--lang", "en", "--report", "html", "--output-dir", outDir, "--report-lang", "ko"],
        "ko",
      ],
      [["scan", "--lang", "ko", "--report", "html", "--output-dir", outDir], "ko"],
      [
        ["scan", "--lang", "ko", "--report", "html", "--output-dir", outDir, "--report-lang", "en"],
        "en",
      ],
    ] as const) {
      const captured = createTestIo();
      await main(argv, captured.io, {
        deps: createTestDeps({
          runScan: async () => testResult(),
          writeReports: (async (_result: unknown, options: { lang?: string }) => {
            seen.push({ lang: options.lang });
            return [];
          }) as never,
        }),
        interrupts: noInterrupts,
      });
      expect(seen.at(-1)?.lang).toBe(expected);
    }
    expect(seen).toHaveLength(3);
    rmSync(outDir, { recursive: true, force: true });
  });

  it("runRulesList stays English without a locale", async () => {
    const captured = createTestIo();
    await runRulesList(createTestContext(captured, createTestDeps()), null);
    expect(captured.stdout()).toContain(sql.title);
  });
});
