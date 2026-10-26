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

  it("scales about linearly in the path length for a fixed pattern", () => {
    const glob = compileGlob("**/a*a*a*a*a/**/c");
    const run = (segments: number) => {
      const filePath = `${"aaaa/".repeat(segments)}x`;
      const start = performance.now();
      for (let i = 0; i < 40; i += 1) globMatches(glob, filePath);
      return performance.now() - start;
    };
    const best = (segments: number) => Math.min(run(segments), run(segments), run(segments));
    run(100); // warm up
    const small = Math.max(best(200), 0.05);
    const large = best(800); // 4x the path
    // Linear would be about 4x; a quadratic matcher would be 16x and an exponential one far more.
    expect(large / small).toBeLessThan(10);
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
