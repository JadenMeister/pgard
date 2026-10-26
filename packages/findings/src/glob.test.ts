import { describe, expect, it } from "vitest";
import {
  MAX_GLOB_LENGTH,
  MAX_PATH_LENGTH,
  compileGlob,
  compilePathMatcher,
  globMatches,
  globProblem,
  matchesEverything,
} from "./glob.js";

const matches = (pattern: string, filePath: string) => globMatches(compileGlob(pattern), filePath);

describe("glob syntax", () => {
  it.each([
    ["legacy/**", "legacy/a.ts", true],
    ["legacy/**", "legacy", true],
    ["legacy/**", "src/legacy/a.ts", false],
    ["legacy", "legacy/deep/a.ts", true],
    ["legacy/", "legacy/a.ts", true],
    ["legacy", "a/legacy/b.ts", true],
    ["src/legacy", "src/legacy/b.ts", true],
    ["src/legacy", "x/src/legacy/b.ts", false],
    ["*.gen.ts", "a/b/c.gen.ts", true],
    ["*.gen.ts", "c.gen.ts", true],
    ["*.gen.ts", "c.gen.tsx", false],
    ["src/*.ts", "src/a.ts", true],
    ["src/*.ts", "src/x/a.ts", false],
    ["src/**/a.ts", "src/a.ts", true],
    ["src/**/a.ts", "src/x/y/a.ts", true],
    ["a?c.js", "abc.js", true],
    ["a?c.js", "ac.js", false],
    ["a?c.js", "a/c.js", false],
    ["*", "x/y/z.ts", true],
    ["**/*.test.ts", "a/b/c.test.ts", true],
    ["**/*.test.ts", "c.test.ts", true],
    ["**/*.test.ts", "a/c.test.tsx", false],
    ["docs/*/draft", "docs/a/draft/x.md", true],
    ["docs/*/draft", "docs/a/b/draft/x.md", false],
    ["Legacy", "legacy/a.ts", false],
    [".github", ".github/workflows/a.yml", true],
    ["*.ts", ".hidden.ts", true],
  ])("%s vs %s -> %s", (pattern, filePath, expected) => {
    expect(matches(pattern, filePath)).toBe(expected);
  });

  it("matches only whole segments, never a substring of a directory name", () => {
    expect(matches("lib", "library/a.ts")).toBe(false);
    expect(matches("lib", "src/lib/a.ts")).toBe(true);
  });

  it.each([
    ["", "empty"],
    ["/etc/passwd", "absolute"],
    ["C:/x", "absolute"],
    ["../x", ".."],
    ["a/../b", ".."],
    ["a/./b", '"."'],
    ["a//b", "empty path segments"],
    ["a\\b", "backslashes"],
    ["a[0-9]", "[ ]"],
    ["{a,b}", "[ ]"],
    ["!a", "negation"],
    ["a**b", "whole path segment"],
    ["a\nb", "control"],
    ["a\u0000b", "control"],
    ["x".repeat(MAX_GLOB_LENGTH + 1), "at most"],
    [Array.from({ length: 40 }, () => "a").join("/"), "segments"],
  ])("rejects %j", (pattern, fragment) => {
    expect(globProblem(pattern)).toContain(fragment);
    expect(() => compileGlob(pattern)).toThrow();
  });

  it("caps the number of * in one segment", () => {
    expect(globProblem("*a".repeat(10))).toBeNull();
    expect(globProblem("*a".repeat(11))).toContain("at most 10 *");
    expect(globProblem(`${"*a".repeat(11)}/b`)).toContain("at most 10 *");
    // Stars in different segments are counted per segment.
    expect(globProblem(`${"*a".repeat(10)}/${"*a".repeat(10)}`)).toBeNull();
  });

  it("rejects bidirectional controls, zero-width and format characters, lone surrogates", () => {
    for (const bad of [
      "a\u202Eb",
      "a\u202Ab",
      "a\u2066b",
      "a\u2069b",
      "a\u200Bb",
      "a\u200Db",
      "a\uFEFFb",
      "a\u00ADb",
      "a\ud800b",
      "a\udc00b",
    ]) {
      expect(globProblem(bad)).toContain("format characters");
    }
    expect(globProblem("a\ud83d\ude00b")).toBeNull(); // a valid surrogate pair (an emoji)
    expect(globProblem("caf\u00e9")).toBeNull();
  });

  it("the control-character bound is exactly U+001F and U+007F", () => {
    expect(globProblem("a\u001fb")).toContain("control");
    expect(globProblem("a\u007fb")).toContain("control");
    expect(globProblem("a b")).toBeNull(); // U+0020
    expect(globProblem("a\u0080b")).toBeNull();
  });

  it("rejects non-strings", () => {
    for (const value of [1, null, undefined, {}, [], true]) {
      expect(globProblem(value)).toBe("must be a string");
    }
  });

  it("does not match paths over the length limit, so they stay analyzed", () => {
    expect(matches("**", "a/".repeat(MAX_PATH_LENGTH))).toBe(false);
    expect(matches("**", "")).toBe(false);
  });

  it("handles unusual file names without special meaning", () => {
    expect(matches("a.b+c(d)", "a.b+c(d)/x.ts")).toBe(true);
    expect(matches("a.b", "aXb/x.ts")).toBe(false); // `.` is not a regex wildcard
    expect(matches("^a$", "a/x.ts")).toBe(false);
    expect(matches("a|b", "a/x.ts")).toBe(false);
    expect(matches("*", "__proto__/x.ts")).toBe(true);
  });
});

describe("matchesEverything", () => {
  it.each(["**", "*", "**/*", "**/**", "*/**", "**/*/**"])("flags %s", (pattern) => {
    expect(matchesEverything(compileGlob(pattern))).toBe(true);
  });
  it.each(["src", "**/*.ts", "legacy/**", "*.js", "a/**/b"])("does not flag %s", (pattern) => {
    expect(matchesEverything(compileGlob(pattern))).toBe(false);
  });
});

describe("compilePathMatcher", () => {
  it("matches when any pattern matches and never matches null", () => {
    const matcher = compilePathMatcher(["a", "*.gen.ts"]);
    expect(matcher.matches("a/b.ts")).toBe(true);
    expect(matcher.matches("x/y.gen.ts")).toBe(true);
    expect(matcher.matches("x/y.ts")).toBe(false);
    expect(matcher.matches(null)).toBe(false);
    expect(compilePathMatcher([]).matches("a")).toBe(false);
  });
});

describe("glob matching is not exponential", () => {
  const time = (action: () => void): number => {
    const start = performance.now();
    action();
    return performance.now() - start;
  };

  it("survives classic regex-bomb patterns against long non-matching names", () => {
    // `(a*)*b`-style blowups: many stars in one segment, name that almost matches.
    const stars = `*b${"*a".repeat(8)}*b`; // 10 stars, the most allowed; needs two b
    const name = `${"a".repeat(1500)}b`;
    expect(stars.length).toBeLessThanOrEqual(MAX_GLOB_LENGTH);
    const glob = compileGlob(stars);
    let result = true;
    const elapsed = time(() => {
      result = globMatches(glob, `dir/${name}`);
    });
    expect(result).toBe(false);
    expect(elapsed).toBeLessThan(1500);
  });

  it("survives many ** segments against a deep path", () => {
    const pattern = Array.from({ length: 15 }, (_, i) => (i % 2 === 0 ? "**" : "a*")).join("/");
    const glob = compileGlob(`${pattern}/zzz`);
    const deep = `${"a/".repeat(1500)}b`;
    let result = true;
    const elapsed = time(() => {
      result = globMatches(glob, deep);
    });
    expect(result).toBe(false);
    expect(elapsed).toBeLessThan(1500);
  });

  it("does work proportional to the path length for a fixed pattern (counted, not timed)", () => {
    // The matcher's work budget counts table cells, so the number of matches that fit in a fixed
    // budget is inversely proportional to the cost of one match: linear work gives a ratio near 4
    // for a 4x longer path, quadratic work would give about 16.
    const matchesInBudget = (segments: number) => {
      const matcher = compilePathMatcher(["**/a*a*a*a*a/**/c"], 20_000_000);
      const filePath = `${"aaaa/".repeat(segments)}x`;
      let count = 0;
      while (!matcher.exhausted && count < 1_000_000) {
        matcher.matches(filePath);
        count += 1;
      }
      return count;
    };
    const ratio = matchesInBudget(200) / matchesInBudget(800);
    expect(ratio).toBeGreaterThan(2.5);
    expect(ratio).toBeLessThan(6);
  });

  it("200 patterns with 10 stars against 10 000 files stay small", () => {
    const patterns = Array.from({ length: 200 }, (_, i) => `${"*a".repeat(9)}*b${i}`);
    const matcher = compilePathMatcher(patterns);
    const files = Array.from(
      { length: 10_000 },
      (_, i) => `src/pkg${i % 40}/${"a".repeat(30)}${i}.ts`,
    );
    const elapsed = time(() => {
      for (const file of files) matcher.matches(file);
    });
    console.info(
      `glob benchmark: 200 star-heavy patterns x 10000 files = ${Math.round(elapsed)} ms`,
    );
    expect(elapsed).toBeLessThan(20_000);
  }, 60_000);

  it("matches 20 000 files against 200 patterns within a few seconds", () => {
    const patterns = Array.from({ length: 200 }, (_, i) => `module${i}/**/*.gen${i}.ts`);
    const matcher = compilePathMatcher(patterns);
    const files = Array.from({ length: 20_000 }, (_, i) => `src/pkg${i % 50}/dir/file${i}.ts`);
    const elapsed = time(() => {
      for (const file of files) matcher.matches(file);
    });
    expect(elapsed).toBeLessThan(15_000);
  });
});

describe("glob prefilter and work budget", () => {
  it("the length prefilter keeps a*b matching ab and does not let prefix and suffix overlap", () => {
    expect(globMatches(compileGlob("a*b"), "ab")).toBe(true);
    expect(globMatches(compileGlob("a*b"), "axb")).toBe(true);
    expect(globMatches(compileGlob("a*a"), "a")).toBe(false);
    expect(globMatches(compileGlob("ab*ba"), "aba")).toBe(false);
    expect(globMatches(compileGlob("ab*ba"), "abba")).toBe(true);
    expect(globMatches(compileGlob("a?b"), "ab")).toBe(false);
    expect(globMatches(compileGlob("*.ts"), ".ts")).toBe(true);
  });

  it("past the work budget the matcher answers false, even for a pattern that would match", () => {
    const hostile = Array.from({ length: 30 }, (_, i) => `*${"?x".repeat(20)}${"?".repeat(i)}*`);
    const matcher = compilePathMatcher(["secret", ...hostile], 20_000);
    expect(matcher.exhausted).toBe(false);
    expect(matcher.matches("src/secret/a.ts")).toBe(true); // matched by the first pattern, within budget
    for (let i = 0; i < 200; i += 1) matcher.matches(`src/dir${i}/${"y".repeat(60)}.ts`);
    expect(matcher.exhausted).toBe(true);
    // Fail-safe: nothing matches any more, so nothing is excluded or demoted.
    expect(matcher.matches("secret/a.ts")).toBe(false);
    expect(compilePathMatcher(["secret"]).matches("secret/a.ts")).toBe(true);
  });

  it("an ordinary configuration never comes near the default budget", () => {
    const matcher = compilePathMatcher([
      "legacy",
      "*.generated.ts",
      "**/*.gen.*",
      "docs/*/draft",
      "tools/??-old",
    ]);
    for (let i = 0; i < 20_000; i += 1) matcher.matches(`src/pkg${i % 50}/dir/file${i}.ts`);
    expect(matcher.exhausted).toBe(false);
  });

  it("200 hostile ?-pattern globs on 10 000 typical paths stop at the budget in about a second", () => {
    const patterns = Array.from({ length: 200 }, (_, i) => {
      const letter = String.fromCharCode(98 + (i % 25));
      return `*${"?".repeat(Math.floor(i / 25))}${`?${letter}`.repeat(60)}*`;
    });
    const matcher = compilePathMatcher(patterns);
    const start = performance.now();
    for (let i = 0; i < 10_000; i += 1) matcher.matches(`src/p${i % 40}/${"a".repeat(20)}${i % 7}`);
    const elapsed = performance.now() - start;
    console.info(`glob budget: 200 hostile ?-patterns x 10000 paths = ${Math.round(elapsed)} ms`);
    expect(matcher.exhausted).toBe(true);
    expect(elapsed).toBeLessThan(15_000);
  }, 60_000);

  it("identical patterns are matched once", () => {
    const one = compilePathMatcher(["*a*b*"], 10_000);
    const many = compilePathMatcher(
      Array.from({ length: 50 }, () => "*a*b*"),
      10_000,
    );
    for (let i = 0; i < 20; i += 1) {
      one.matches(`dir/zzzzzzzz${i}`);
      many.matches(`dir/zzzzzzzz${i}`);
    }
    expect(many.exhausted).toBe(one.exhausted);
  });
});
