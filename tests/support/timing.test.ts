import { describe, expect, it } from "vitest";
import { bestTimeOf, computeTimeFactor, parseTimeFactor } from "./timing.js";

describe("test time factor", () => {
  it("is 1 locally and 3 on CI", () => {
    expect(computeTimeFactor({}, "linux")).toBe(1);
    expect(computeTimeFactor({ CI: "true" }, "linux")).toBe(3);
  });

  it("multiplies by 3 on Windows", () => {
    expect(computeTimeFactor({}, "win32")).toBe(3);
    expect(computeTimeFactor({ CI: "true" }, "win32")).toBe(9);
  });

  it("takes PGARD_TEST_TIME_FACTOR over the CI default", () => {
    expect(computeTimeFactor({ CI: "true", PGARD_TEST_TIME_FACTOR: "5" }, "linux")).toBe(5);
    expect(computeTimeFactor({ PGARD_TEST_TIME_FACTOR: "0.5" }, "linux")).toBe(0.5);
  });

  it.each(["", "  ", "0", "-2", "abc", "NaN", "Infinity"])(
    "ignores the invalid value %j",
    (raw) => {
      expect(parseTimeFactor(raw)).toBeUndefined();
      expect(computeTimeFactor({ CI: "true", PGARD_TEST_TIME_FACTOR: raw }, "linux")).toBe(3);
    },
  );

  it("bestTimeOf returns the fastest run", () => {
    let calls = 0;
    const best = bestTimeOf(3, () => {
      calls += 1;
    });
    expect(calls).toBe(3);
    expect(best).toBeGreaterThanOrEqual(0);
  });
});
