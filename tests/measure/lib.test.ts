import { describe, expect, it } from "vitest";
import {
  cacheDirName,
  fixCheck,
  judgeCase,
  matchCase,
  positiveInt,
  renderMarkdown,
  tally,
  validRepo,
  validSha,
} from "./lib.mjs";

const sqlCase = {
  id: "GHSA-test-0001",
  language: "java",
  cwe: ["CWE-89"],
  doubtful: false,
  inScope: true,
  expect: [{ file: "src/Dao.java", startLine: 40, endLine: 44 }],
};
const finding = (ruleId: string, path: string, line: number) => ({ ruleId, path, line });
const area = (name: string, status: string, ruleIds: string[] = []) => ({
  area: name,
  status,
  ruleIds,
});

describe("matchCase", () => {
  it("is a hit for a same-family finding within 5 lines of the range", () => {
    for (const line of [35, 39, 44, 49]) {
      const result = matchCase(sqlCase, [finding("PG-SQL-002", "src/Dao.java", line)]);
      expect(result.status).toBe("hit");
      expect(result.matchedRules).toEqual(["PG-SQL-002"]);
    }
  });

  it("is loose in the right file but outside the window, and counts other findings", () => {
    const result = matchCase(sqlCase, [
      finding("PG-SQL-001", "src/Dao.java", 50),
      finding("PG-XSS-001", "src/Dao.java", 41),
    ]);
    expect(result).toMatchObject({ status: "loose", sameFamilyInFile: 1, anyFindingsInFile: 2 });
  });

  it("is a miss for another family, another file, or no finding", () => {
    expect(matchCase(sqlCase, [finding("PG-XSS-001", "src/Dao.java", 41)]).status).toBe("miss");
    expect(matchCase(sqlCase, [finding("PG-SQL-001", "src/Other.java", 41)]).status).toBe("miss");
    expect(matchCase(sqlCase, []).status).toBe("miss");
  });

  it("maps secrets and crypto CWEs to their rules", () => {
    const secret = { ...sqlCase, cwe: ["CWE-798"] };
    expect(matchCase(secret, [finding("PG-SECRET-001", "src/Dao.java", 42)]).status).toBe("hit");
    const random = { ...sqlCase, cwe: ["CWE-338"] };
    expect(matchCase(random, [finding("PG-CRYPTO-003", "src/Dao.java", 42)]).status).toBe("hit");
    expect(matchCase(random, [finding("PG-CRYPTO-001", "src/Dao.java", 42)]).status).toBe("miss");
    const cookie = { ...sqlCase, cwe: ["CWE-1275"] };
    expect(matchCase(cookie, [finding("PG-COOKIE-001", "src/Dao.java", 42)]).status).toBe("hit");
  });
});

describe("judgeCase", () => {
  const ran = [area("source:java", "completed", ["PG-SQL-005"]), area("history", "not_selected")];

  it("keeps hit and loose, and flags partial scans separately", () => {
    const hit = judgeCase(
      sqlCase,
      [finding("PG-SQL-005", "src/Dao.java", 41)],
      [area("source:java", "partial", ["PG-SQL-005"])],
    );
    expect(hit).toMatchObject({ status: "hit", partial: true, partialAreas: ["source:java"] });
  });

  it("is a plain miss only when the relevant area completed", () => {
    expect(judgeCase(sqlCase, [], ran)).toMatchObject({ status: "miss", partial: false });
  });

  it("does not read a not_tested area as a miss, and not_selected is no gap", () => {
    const result = judgeCase(sqlCase, [], [area("source:java", "not_tested"), ...ran.slice(1)]);
    expect(result).toMatchObject({ status: "not-tested", partial: true });
    expect(judgeCase(sqlCase, [], ran).partial).toBe(false);
  });

  it("is unsupported-language when no analyzer with a family rule ran", () => {
    const result = judgeCase(sqlCase, [], [area("source:go", "completed", ["PG-SQL-003"])]);
    expect(result.status).toBe("miss");
    const none = judgeCase(sqlCase, [], [area("source:javascript", "completed")]);
    expect(none.status).toBe("unsupported-language");
  });

  it("is no-rule when PGARD has no rule for the CWE", () => {
    for (const cwe of ["CWE-287", "CWE-306", "CWE-16", "CWE-1188", "CWE-326", "CWE-611"]) {
      expect(judgeCase({ ...sqlCase, cwe: [cwe] }, [], ran).status).toBe("no-rule");
    }
  });
});

describe("fixCheck", () => {
  const rules = ["PG-SQL-005"];
  it("is gone when no matched-rule finding is near the range at the fix", () => {
    expect(fixCheck(sqlCase, rules, [], true)).toEqual({ fixGone: true, fixNote: null });
    const far = [finding("PG-SQL-005", "src/Dao.java", 200)];
    expect(fixCheck(sqlCase, rules, far, true).fixGone).toBe(true);
  });

  it("is not gone when the finding is still near, even if others disappeared", () => {
    const near = [finding("PG-SQL-005", "src/Dao.java", 43)];
    expect(fixCheck(sqlCase, rules, near, true).fixGone).toBe(false);
  });

  it("is not comparable when the expected file was removed or nothing matched", () => {
    expect(fixCheck(sqlCase, rules, [], false).fixGone).toBeNull();
    expect(fixCheck(sqlCase, [], [], true).fixGone).toBeNull();
  });
});

describe("aggregation", () => {
  const results = [
    { ...sqlCase, status: "hit" },
    { ...sqlCase, id: "b", status: "loose", doubtful: true },
    { ...sqlCase, id: "c", status: "miss", language: "go", cwe: ["CWE-22"] },
    { ...sqlCase, id: "d", status: "no-rule", inScope: false, cwe: ["CWE-611"] },
    { ...sqlCase, id: "e", status: "not-tested", partial: true, language: "go", cwe: ["CWE-22"] },
    { ...sqlCase, id: "f", status: "fetch-error", language: "go", cwe: ["CWE-22"] },
  ];

  it("takes recall over cases with a rule and keeps not-measured ones in the denominator", () => {
    expect(tally(results)).toMatchObject({
      n: 6,
      ruleN: 5,
      hit: 1,
      loose: 1,
      miss: 1,
      notTested: 1,
      noRule: 1,
      unmeasured: 1,
      partial: 1,
      hitPct: "20.0%",
      loosePct: "40.0%",
    });
    expect(tally([]).hitPct).toBe("n/a");
  });

  it("renders per-language and per-family tables for all, non-doubtful and in-scope", () => {
    const markdown = renderMarkdown(results, { date: "2026-01-01", version: "0.0.0", filter: "" });
    expect(markdown).toContain("## all (n=6)");
    expect(markdown).toContain("## non-doubtful (n=5)");
    expect(markdown).toContain("## in-scope (n=5)");
    expect(markdown).toContain("| java | 3 | 2 | 1 | 50.0% | 100.0% | 0 | 0 | 1 | 0 | 0 |");
    expect(markdown).toContain("| go | 3 | 3 | 0 | 0.0% | 0.0% | 1 | 1 | 0 | 1 | 1 |");
    expect(markdown).toContain("| (no rule) | 1 | 0 | 0 | n/a | n/a | 0 | 0 | 1 | 0 | 0 |");
    expect(markdown).toContain("Per-family rows can overlap");
  });
});

describe("input validation", () => {
  it("accepts owner/name and 40-hex shas only", () => {
    expect(validRepo("apache/activemq")).toBe(true);
    for (const bad of ["a", "a/b/c", "../x", "a/..", "a b/c", "-x/y;rm", "a/b\n"]) {
      expect(validRepo(bad), bad).toBe(false);
    }
    expect(validSha("a".repeat(40))).toBe(true);
    for (const bad of ["a".repeat(39), "A".repeat(40), "g".repeat(40), "--upload-pack=x"]) {
      expect(validSha(bad), bad).toBe(false);
    }
  });

  it("makes one safe cache folder name and parses positive integers", () => {
    expect(cacheDirName("a/b")).toBe("a__b.git");
    expect(cacheDirName("a/b").includes("/")).toBe(false);
    expect(positiveInt("5")).toBe(5);
    for (const bad of ["abc", "0", "-1", "1.5", "", "5x"]) expect(positiveInt(bad)).toBeNull();
  });
});
