import { describe, expect, it } from "vitest";
import {
  MAX_EXCLUDE_PATTERNS,
  MAX_PROJECT_CONFIG_BYTES,
  MAX_SUPPRESSIONS,
  MAX_SUPPRESSION_REASON_LENGTH,
  MAX_TEST_DIRECTORIES,
  parseProjectConfig,
} from "./project-config.js";

const ok = (value: unknown) =>
  parseProjectConfig(typeof value === "string" ? value : JSON.stringify(value));
const problems = (value: unknown): string[] => {
  const result = ok(value);
  if (result.ok) throw new Error("expected the config to be rejected");
  return result.problems;
};
const suppression = (overrides: Record<string, unknown> = {}) => ({
  ruleId: "PG-SQL-001",
  path: "scripts/**",
  reason: "Admin-only script, input is not user controlled",
  ...overrides,
});

describe("parseProjectConfig", () => {
  it("accepts the documented shape", () => {
    const result = ok({
      version: 1,
      exclude: ["legacy/**", "*.generated.ts"],
      testDirectories: ["e2e"],
      suppressions: [suppression({ expires: "2027-02-28" }), suppression()],
    });
    expect(result).toEqual({
      ok: true,
      config: {
        version: 1,
        exclude: ["legacy/**", "*.generated.ts"],
        testDirectories: ["e2e"],
        suppressions: [suppression({ expires: "2027-02-28" }), suppression()],
      },
    });
  });

  it("only the version is required", () => {
    expect(ok({ version: 1 })).toEqual({
      ok: true,
      config: { version: 1, exclude: [], testDirectories: [], suppressions: [] },
    });
    expect(problems({})[0]).toContain('missing required key "version"');
  });

  it("accepts a UTF-8 byte order mark", () => {
    expect(ok('\uFEFF{"version":1}').ok).toBe(true);
  });

  it.each([2, 0, "1", true, null, 1.5, [1]])("rejects version %j", (version) => {
    expect(problems({ version }).join()).toContain("version: must be the number 1");
  });

  describe("keys that must not exist", () => {
    const forbidden = [
      "authorization",
      "authorize",
      "allowedHosts",
      "hosts",
      "host",
      "ports",
      "port",
      "network",
      "networkTargets",
      "webTarget",
      "origin",
      "url",
      "token",
      "severity",
      "severities",
      "ruleSeverity",
      "rules",
      "skipAuthorization",
      "policy",
      "$schema",
      "extends",
      "__proto__",
      "constructor",
    ];
    it.each(forbidden)("rejects the top-level key %s", (key) => {
      const text = `{"version":1,${JSON.stringify(key)}:true}`;
      expect(problems(text).join()).toContain("not configurable");
    });

    it("rejects unknown keys inside a suppression, including severity and network keys", () => {
      for (const key of ["severity", "host", "port", "action"]) {
        expect(
          problems({ version: 1, suppressions: [suppression({ [key]: "x" })] }).join(),
        ).toContain("not configurable");
      }
    });
  });

  describe("syntax", () => {
    it.each([
      ["", "invalid JSON"],
      ["{", "invalid JSON"],
      ["[]", "top level must be a JSON object"],
      ['"a"', "top level must be a JSON object"],
      ["null", "top level must be a JSON object"],
      ['{"version":1,}', "invalid JSON"],
      ['{"version":1} x', "invalid JSON"],
      ["{'version':1}", "invalid JSON"],
      ['{"version":1 // c\n}', "invalid JSON"],
      ['{"version":1,"exclude":[,]}', "invalid JSON"],
      ['{"version":01}', "invalid JSON"],
      ['{"version":1,"exclude":["a\u0001"]}', "invalid JSON"],
      ['{"version":1,"exclude":["\\x41"]}', "invalid JSON"],
      ['{"version":1,"exclude":["\\ud83"]}', "invalid JSON"],
      ['{"version":NaN}', "invalid JSON"],
    ])("rejects %j", (text, fragment) => {
      expect(problems(text).join()).toContain(fragment);
    });

    it("rejects duplicate keys, also nested and also when the values agree", () => {
      expect(problems('{"version":1,"version":1}').join()).toContain("duplicate key");
      expect(problems('{"version":1,"exclude":[],"exclude":["a"]}').join()).toContain(
        "duplicate key",
      );
      expect(
        problems(
          '{"version":1,"suppressions":[{"ruleId":"PG-SQL-001","path":"a","reason":"r","reason":"s"}]}',
        ).join(),
      ).toContain("duplicate key");
      // The same key spelled with an escape is still a duplicate.
      expect(problems('{"version":1,"vers\\u0069on":1}').join()).toContain("duplicate key");
    });

    it("rejects nesting that is too deep without overflowing the stack", () => {
      const deep = `{"version":1,"x":${"[".repeat(100_000)}${"]".repeat(100_000)}}`;
      expect(problems(deep.slice(0, MAX_PROJECT_CONFIG_BYTES - 10)).join()).toContain(
        "invalid JSON",
      );
    });

    it("allows nesting up to the depth limit and names the limit when exceeded", () => {
      const nested = (levels: number) =>
        `{"version":1,"x":${"[".repeat(levels)}${"]".repeat(levels)}}`;
      // Eight levels pass the reader (the unknown key "x" is then what fails).
      expect(problems(nested(8)).join()).toContain("not configurable");
      expect(problems(nested(9)).join()).toContain("nesting too deep");
    });

    it("rejects raw control characters in strings, exactly up to U+001F", () => {
      const raw = (code: number) => `{"version":1,"exclude":["a${String.fromCharCode(code)}b"]}`;
      expect(problems(raw(0x1f)).join()).toContain("invalid JSON");
      expect(ok(raw(0x20)).ok).toBe(true);
    });

    it("rejects bidirectional, zero-width and format characters and lone surrogates anywhere", () => {
      const text = (value: string) =>
        `{"version":1,"suppressions":[{"ruleId":"PG-SQL-001","path":"a","reason":"${value}"}]}`;
      for (const bad of ["x\\u202Ey", "x\\u200Bx", "x\\u2066x", "x\\ud83dx", "x\\ude00x"]) {
        expect(problems(text(bad)).join()).toContain("format character");
      }
      // The same inside a key, and as raw characters.
      expect(problems('{"version":1,"a\\u202Eb":1}').join()).toContain("format character");
      expect(problems(text("x\u202Ey")).join()).toContain("format character");
      expect(ok(text("caf\u00e9 \\ud83d\\ude00")).ok).toBe(true); // accents and a valid pair
    });

    it.each([
      ["a C1 control", "x\\u0085y"],
      ["a line separator", "x\\u2028y"],
      ["a paragraph separator", "x\\u2029y"],
      ["a combining grapheme joiner", "x\\u034Fy"],
      ["a Hangul choseong filler", "x\\u115Fy"],
      ["a Hangul jungseong filler", "x\\u1160y"],
      ["a Hangul filler", "x\\u3164y"],
      ["a halfwidth Hangul filler", "x\\uFFA0y"],
    ])("rejects %s in a reason, however it is written", (_name, escaped) => {
      const text = (value: string) =>
        `{"version":1,"suppressions":[{"ruleId":"PG-SQL-001","path":"a","reason":"${value}"}]}`;
      expect(ok(text(escaped)).ok).toBe(false);
      expect(ok(text(JSON.parse(`"${escaped}"`))).ok).toBe(false);
    });

    it("treats __proto__ as an ordinary unknown key (no prototype pollution)", () => {
      const result = ok('{"version":1,"__proto__":{"exclude":["**"]}}');
      expect(result.ok).toBe(false);
      expect(({} as Record<string, unknown>).exclude).toBeUndefined();
    });
  });

  describe("limits", () => {
    it("caps the size", () => {
      const big = `{"version":1,"exclude":["${"a".repeat(MAX_PROJECT_CONFIG_BYTES)}"]}`;
      expect(problems(big)[0]).toContain("larger than");
    });

    it("counts bytes, not characters", () => {
      const text = `{"version":1,"x":"${"\u20ac".repeat(MAX_PROJECT_CONFIG_BYTES / 3)}"}`;
      expect(problems(text)[0]).toContain("larger than");
    });

    it("caps counts: exclude, testDirectories, suppressions", () => {
      const many = (n: number) => Array.from({ length: n }, (_, i) => `d${i}`);
      expect(ok({ version: 1, exclude: many(MAX_EXCLUDE_PATTERNS) }).ok).toBe(true);
      expect(problems({ version: 1, exclude: many(MAX_EXCLUDE_PATTERNS + 1) }).join()).toContain(
        "at most 200",
      );
      expect(ok({ version: 1, testDirectories: many(MAX_TEST_DIRECTORIES) }).ok).toBe(true);
      expect(
        problems({ version: 1, testDirectories: many(MAX_TEST_DIRECTORIES + 1) }).join(),
      ).toContain("at most 100");
      const entries = (n: number) => Array.from({ length: n }, () => suppression());
      expect(ok({ version: 1, suppressions: entries(MAX_SUPPRESSIONS) }).ok).toBe(true);
      expect(
        problems({ version: 1, suppressions: entries(MAX_SUPPRESSIONS + 1) }).join(),
      ).toContain("at most 200");
    });

    it("caps the reason length and requires a reason", () => {
      const reason = (text: unknown) => ({
        version: 1,
        suppressions: [suppression({ reason: text })],
      });
      expect(ok(reason("x".repeat(MAX_SUPPRESSION_REASON_LENGTH))).ok).toBe(true);
      expect(problems(reason("x".repeat(MAX_SUPPRESSION_REASON_LENGTH + 1))).join()).toContain(
        "at most 300",
      );
      for (const bad of ["", "   ", 5, null, ["a"]]) {
        expect(problems(reason(bad)).join()).toContain("reason");
      }
      expect(
        problems({ version: 1, suppressions: [{ ruleId: "PG-SQL-001", path: "a" }] }).join(),
      ).toContain('missing required key "reason"');
      expect(problems(reason("line\nbreak")).join()).toContain("control characters");
    });

    it("limits how many problems are reported", () => {
      const result = problems({ version: 1, exclude: Array.from({ length: 50 }, () => "../x") });
      expect(result).toHaveLength(11);
      expect(result[10]).toBe("and 40 more problem(s)");
    });
  });

  describe("path patterns", () => {
    it.each([
      "/abs",
      "../up",
      "a/../b",
      "C:\\x",
      "a\\b",
      "",
      " ".repeat(0),
      "!neg",
      "a[b]",
      5,
      null,
    ])("rejects exclude entry %j", (entry) => {
      expect(ok({ version: 1, exclude: [entry] }).ok).toBe(false);
      expect(ok({ version: 1, testDirectories: [entry] }).ok).toBe(false);
      expect(ok({ version: 1, suppressions: [suppression({ path: entry })] }).ok).toBe(false);
    });
    it("rejects a non-array", () => {
      for (const key of ["exclude", "testDirectories", "suppressions"]) {
        for (const bad of ["a", {}, null, 1]) {
          expect(ok({ version: 1, [key]: bad }).ok).toBe(false);
        }
      }
    });
    it("reports the position of the bad entry", () => {
      expect(problems({ version: 1, exclude: ["ok", "../bad"] })[0]).toMatch(/^exclude\[1\]:/);
    });
  });

  describe("suppression entries", () => {
    const bad = (overrides: Record<string, unknown>) =>
      problems({ version: 1, suppressions: [suppression(overrides)] }).join();
    it.each(["sql", "PG-SQL-1", "pg-sql-001", "PG-SQL-0001", "PG--001", "PG-SQL-001 ", 7, null])(
      "rejects ruleId %j",
      (ruleId) => {
        expect(bad({ ruleId })).toContain("ruleId");
      },
    );
    it.each([
      "2027-02-30",
      "2027-13-01",
      "2027-1-1",
      "tomorrow",
      "2027-02-28T00:00:00Z",
      2027,
      null,
    ])("rejects expires %j", (expires) => {
      expect(bad({ expires })).toContain("expires");
    });
    it("accepts a leap day only in a leap year", () => {
      expect(ok({ version: 1, suppressions: [suppression({ expires: "2028-02-29" })] }).ok).toBe(
        true,
      );
      expect(bad({ expires: "2027-02-29" })).toContain("expires");
    });
    it("rejects non-objects", () => {
      expect(problems({ version: 1, suppressions: ["x", null, []] })).toHaveLength(3);
    });
  });

  it("never throws on random input (fuzz)", () => {
    let seed = 12345;
    const next = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed;
    };
    const alphabet = '{}[]",:\\/*?-01 tfnu.!\n\u0000\u2028abcPGSQL_';
    for (let i = 0; i < 3000; i += 1) {
      const length = next() % 80;
      let text = "";
      for (let j = 0; j < length; j += 1) text += alphabet.charAt(next() % alphabet.length);
      const result = parseProjectConfig(text);
      expect(typeof result.ok).toBe("boolean");
    }
    // Mutations of a valid document: removing or swapping one character must never throw, and a
    // result that is accepted must still have the exact shape.
    const valid = JSON.stringify({
      version: 1,
      exclude: ["a/**"],
      testDirectories: ["e2e"],
      suppressions: [suppression({ expires: "2027-01-01" })],
    });
    for (let i = 0; i < valid.length; i += 1) {
      for (const mutated of [
        valid.slice(0, i) + valid.slice(i + 1),
        valid.slice(0, i) + valid.charAt((i * 7) % valid.length) + valid.slice(i + 1),
      ]) {
        const result = parseProjectConfig(mutated);
        if (result.ok) {
          expect(Object.keys(result.config).sort()).toEqual([
            "exclude",
            "suppressions",
            "testDirectories",
            "version",
          ]);
        }
      }
    }
  });
});
