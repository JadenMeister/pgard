import { describe, expect, it } from "vitest";
import { hasSupportedLanguage, matchCase, renderMarkdown, tally } from "./lib.mjs";

const sqlCase = {
  id: "GHSA-test-0001",
  language: "java",
  cwe: ["CWE-89"],
  doubtful: false,
  inScope: true,
  expect: [{ file: "src/Dao.java", startLine: 40, endLine: 44 }],
};
const finding = (ruleId: string, path: string, line: number) => ({ ruleId, path, line });

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

  it("never hits a CWE without a rule family", () => {
    const result = matchCase({ ...sqlCase, cwe: ["CWE-611"] }, [
      finding("PG-SQL-001", "src/Dao.java", 41),
    ]);
    expect(result.status).toBe("miss");
  });

  it("maps secrets and crypto CWEs to their rule families", () => {
    const secret = { ...sqlCase, cwe: ["CWE-798"] };
    expect(matchCase(secret, [finding("PG-SECRET-001", "src/Dao.java", 42)]).status).toBe("hit");
    const crypto = { ...sqlCase, cwe: ["CWE-338", "CWE-330"] };
    expect(matchCase(crypto, [finding("PG-CRYPTO-002", "src/Dao.java", 42)]).status).toBe("hit");
  });
});

describe("aggregation", () => {
  const results = [
    { ...sqlCase, status: "hit" },
    { ...sqlCase, id: "b", status: "loose", doubtful: true },
    { ...sqlCase, id: "c", status: "miss", language: "go", cwe: ["CWE-22"] },
    { ...sqlCase, id: "d", status: "fetch-error", inScope: false, cwe: ["CWE-611"] },
  ];

  it("counts not-measured cases in n so recall is not inflated", () => {
    expect(tally(results)).toMatchObject({
      n: 4,
      hit: 1,
      loose: 1,
      miss: 1,
      unmeasured: 1,
      hitPct: "25.0%",
      loosePct: "50.0%",
    });
    expect(tally([]).hitPct).toBe("n/a");
  });

  it("renders per-language and per-family tables for all, non-doubtful and in-scope", () => {
    const markdown = renderMarkdown(results, { date: "2026-01-01", version: "0.0.0", filter: "" });
    expect(markdown).toContain("## all (n=4)");
    expect(markdown).toContain("## non-doubtful (n=3)");
    expect(markdown).toContain("## in-scope (n=3)");
    expect(markdown).toContain("| java | 3 | 1 | 33.3% | 66.7% | 0 | 1 |");
    expect(markdown).toContain("| (no rule family) | 1 | 0 | 0.0% | 0.0% | 0 | 1 |");
  });
});

describe("hasSupportedLanguage", () => {
  it("is false when no expected file has an analyzed source extension", () => {
    expect(hasSupportedLanguage(sqlCase)).toBe(true);
    expect(hasSupportedLanguage({ expect: [{ file: "lib/a.rb" }] })).toBe(false);
  });
});
