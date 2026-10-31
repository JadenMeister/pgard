/**
 * Shared knobs for wall-clock assertions in tests.
 *
 * A budget measured on an idle laptop fails on a loaded CI runner (the v0.1.0 release verify was
 * blocked once by 5277 ms against a 5000 ms budget). Every test that compares a duration with a
 * number scales that number with TIME_FACTOR, and prefers a ratio between two sizes (a quadratic
 * blow-up still fails) with a generous absolute ceiling kept only as a hang guard.
 */

/** A positive finite number from PGARD_TEST_TIME_FACTOR, or undefined when unset or invalid. */
export function parseTimeFactor(raw: string | undefined): number | undefined {
  if (raw === undefined || raw.trim() === "") return undefined;
  const value = Number(raw);
  return Number.isFinite(value) && value > 0 ? value : undefined;
}

/** Base factor: the override, else 3 on CI, else 1. Windows runners get three times that. */
export function computeTimeFactor(env: NodeJS.ProcessEnv, platform: string): number {
  const base = parseTimeFactor(env.PGARD_TEST_TIME_FACTOR) ?? (env.CI ? 3 : 1);
  return base * (platform === "win32" ? 3 : 1);
}

/** Multiply every wall-clock budget by this. */
export const TIME_FACTOR = computeTimeFactor(process.env, process.platform);

/** A budget in milliseconds, scaled for the machine running the tests. */
export const scaled = (ms: number): number => ms * TIME_FACTOR;

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
