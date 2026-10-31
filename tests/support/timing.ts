/**
 * Shared knobs for wall-clock assertions in tests.
 *
 * A budget measured on an idle laptop fails on a loaded CI runner (the v0.1.0 release verify was
 * blocked once by 5277 ms against a 5000 ms budget). Every test that compares a duration with a
 * number scales that number with TIME_FACTOR. A test about linearity times two input sizes and
 * asserts a ratio, which load does not change (a quadratic blow-up still fails); its absolute
 * ceiling is only a hang guard.
 */
import { it } from "vitest";

export const MIN_TIME_FACTOR = 0.25;
export const MAX_TIME_FACTOR = 100;

/**
 * A positive finite number from PGARD_TEST_TIME_FACTOR clamped to [0.25, 100], or undefined when
 * unset or invalid (empty, zero, negative, not a number).
 */
export function parseTimeFactor(raw: string | undefined): number | undefined {
  if (raw === undefined || raw.trim() === "") return undefined;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) return undefined;
  return Math.min(MAX_TIME_FACTOR, Math.max(MIN_TIME_FACTOR, value));
}

/** `CI=false` and `CI=0` mean "not CI"; any other non-empty value means CI. */
export function isCi(env: NodeJS.ProcessEnv): boolean {
  const raw = env.CI?.trim().toLowerCase();
  return raw !== undefined && raw !== "" && raw !== "false" && raw !== "0";
}

/**
 * PGARD_TEST_TIME_FACTOR when set and valid, used as is (Windows does not multiply it again).
 * Otherwise 1 locally, 3 on CI, and three times that on Windows.
 */
export function computeTimeFactor(env: NodeJS.ProcessEnv, platform: string): number {
  const override = parseTimeFactor(env.PGARD_TEST_TIME_FACTOR);
  if (override !== undefined) return override;
  return (isCi(env) ? 3 : 1) * (platform === "win32" ? 3 : 1);
}

/** Multiply every wall-clock budget by this. */
export const TIME_FACTOR = computeTimeFactor(process.env, process.platform);

/** A budget in milliseconds, scaled for the machine running the tests. */
export const scaled = (ms: number): number => ms * TIME_FACTOR;

/** `it` whose explicit timeout is scaled, so it stays above the scaled budgets inside the test. */
export const itScaled = (name: string, fn: () => unknown, timeoutMs: number) =>
  it(name, fn as () => void | Promise<void>, scaled(timeoutMs));

/** The fastest of `runs` runs of `fn`, in milliseconds. The minimum shrugs off a noisy neighbour. */
export function bestTimeOf(runs: number, fn: () => void): number {
  let best = Infinity;
  for (let i = 0; i < runs; i += 1) {
    const start = performance.now();
    fn();
    best = Math.min(best, performance.now() - start);
  }
  return best;
}

/** `bestTimeOf` for an async function. */
export async function bestTimeOfAsync(runs: number, fn: () => Promise<unknown>): Promise<number> {
  let best = Infinity;
  for (let i = 0; i < runs; i += 1) {
    const start = performance.now();
    await fn();
    best = Math.min(best, performance.now() - start);
  }
  return best;
}
