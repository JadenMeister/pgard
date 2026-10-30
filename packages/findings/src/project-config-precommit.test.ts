import { describe, expect, it } from "vitest";
import { parseProjectConfig } from "./project-config.js";

const ok = (value: unknown) => parseProjectConfig(JSON.stringify(value));
const problems = (value: unknown): string[] => {
  const result = ok(value);
  if (result.ok) throw new Error("expected the config to be rejected");
  return result.problems;
};

describe("parseProjectConfig precommit", () => {
  it("accepts block and warn for mode and whenNotScanned", () => {
    for (const mode of ["block", "warn"]) {
      for (const whenNotScanned of ["block", "warn"]) {
        const result = ok({ version: 1, precommit: { mode, whenNotScanned } });
        expect(result.ok && result.config.precommit).toEqual({ mode, whenNotScanned });
      }
    }
    const partial = ok({ version: 1, precommit: { mode: "warn" } });
    expect(partial.ok && partial.config.precommit).toEqual({ mode: "warn" });
    const empty = ok({ version: 1, precommit: {} });
    expect(empty.ok && empty.config.precommit).toEqual({});
  });

  it("accepts requireAuthorization true or false, and nothing else", () => {
    for (const requireAuthorization of [true, false]) {
      const result = ok({ version: 1, precommit: { requireAuthorization } });
      expect(result.ok && result.config.precommit).toEqual({ requireAuthorization });
    }
    expect(problems({ version: 1, precommit: { requireAuthorization: "yes" } })).toEqual([
      "precommit.requireAuthorization: must be true or false",
    ]);
    expect(problems({ version: 1, precommit: { requireAuthorization: 1 } })[0]).toContain(
      "true or false",
    );
  });

  it("has no precommit field when the key is absent", () => {
    const result = ok({ version: 1 });
    expect(result.ok && "precommit" in result.config).toBe(false);
  });

  it("rejects any other value, key or shape, and does not partly apply the file", () => {
    expect(problems({ version: 1, precommit: { mode: "off" } })[0]).toContain('"block" or "warn"');
    expect(problems({ version: 1, precommit: { mode: true } })[0]).toContain('"block" or "warn"');
    expect(problems({ version: 1, precommit: { whenNotScanned: "skip" } })[0]).toContain(
      "precommit.whenNotScanned",
    );
    expect(problems({ version: 1, precommit: { authorization: "skip" } })[0]).toContain(
      "unknown key",
    );
    expect(problems({ version: 1, precommit: "warn" })).toEqual(["precommit: must be an object"]);
    expect(problems({ version: 1, precommit: [] })).toEqual(["precommit: must be an object"]);
    expect(problems({ version: 1, precommit: { mode: "warn", extra: 1 } }).length).toBe(1);
  });
});
