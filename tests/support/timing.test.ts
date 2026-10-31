import { describe, expect, it } from "vitest";
import { bestTimeOf, bestTimeOfAsync, computeTimeFactor, isCi, parseTimeFactor } from "./timing.js";

describe("test time factor", () => {
  it("is 1 locally and 3 on CI", () => {
    expect(computeTimeFactor({}, "linux")).toBe(1);
    expect(computeTimeFactor({ CI: "true" }, "linux")).toBe(3);
  });

  it("treats CI=false and CI=0 as not CI", () => {
    for (const CI of ["false", "FALSE", "0", ""]) {
      expect(isCi({ CI })).toBe(false);
      expect(computeTimeFactor({ CI }, "linux")).toBe(1);
    }
    expect(isCi({ CI: "1" })).toBe(true);
  });

  it("multiplies by 3 on Windows", () => {
    expect(computeTimeFactor({}, "win32")).toBe(3);
    expect(computeTimeFactor({ CI: "true" }, "win32")).toBe(9);
  });

  it("uses PGARD_TEST_TIME_FACTOR as is, also on Windows", () => {
    expect(computeTimeFactor({ CI: "true", PGARD_TEST_TIME_FACTOR: "5" }, "linux")).toBe(5);
    expect(computeTimeFactor({ PGARD_TEST_TIME_FACTOR: "5" }, "win32")).toBe(5);
    expect(computeTimeFactor({ PGARD_TEST_TIME_FACTOR: "0.5" }, "linux")).toBe(0.5);
  });

  it("clamps the override to 0.25 .. 100", () => {
    expect(parseTimeFactor("1e9")).toBe(100);
    expect(parseTimeFactor("1e-9")).toBe(0.25);
    expect(parseTimeFactor("100")).toBe(100);
  });

  it.each(["", "  ", "0", "-1", "-2", "abc", "NaN", "Infinity"])(
    "ignores the invalid value %j",
    (raw) => {
      expect(parseTimeFactor(raw)).toBeUndefined();
      expect(computeTimeFactor({ CI: "true", PGARD_TEST_TIME_FACTOR: raw }, "linux")).toBe(3);
    },
  );

  it("bestTimeOf returns the fastest run", async () => {
    let calls = 0;
    expect(
      bestTimeOf(3, () => {
        calls += 1;
      }),
    ).toBeGreaterThanOrEqual(0);
    expect(calls).toBe(3);
    expect(await bestTimeOfAsync(2, async () => {})).toBeGreaterThanOrEqual(0);
  });
});
