import { defineConfig } from "vitest/config";
import { TIME_FACTOR } from "./tests/support/timing.js";

/** setTimeout rejects anything above a signed 32-bit integer of milliseconds. */
const MAX_TIMER_MS = 2_147_483_647;

export default defineConfig({
  resolve: {
    conditions: ["source"],
  },
  // Vitest resolves workspace imports ("@pgard/*") in its SSR environment, which needs its own
  // condition list: without it integration tests load a stale `dist` build.
  ssr: {
    resolve: {
      conditions: ["source"],
    },
  },
  test: {
    // Windows spawns processes far slower; git-heavy tests need more than the 5 s default there.
    // Both timeouts scale with the shared time factor (tests/support/timing.ts) so a loaded runner
    // fails on a real hang, not on a slow spawn, and never exceed the 32-bit timer limit.
    // testTimeout: Linux and macOS 5 s locally, 15 s on CI; Windows at least 30 s, 45 s on CI.
    testTimeout: Math.min(
      Math.max(5_000 * TIME_FACTOR, process.platform === "win32" ? 30_000 : 0),
      MAX_TIMER_MS,
    ),
    // A stuck setup or teardown fails with the name of its test instead of stalling the run.
    // Vitest's own default for both is 10 s.
    // hookTimeout: 30 s locally, 90 s on CI; Windows at least 60 s.
    hookTimeout: Math.min(
      Math.max(30_000 * TIME_FACTOR, process.platform === "win32" ? 60_000 : 0),
      MAX_TIMER_MS,
    ),
    teardownTimeout: 30_000,
    // In CI every test is logged as it finishes, so a run that stalls names the last test that
    // started, and the hanging-process reporter lists the handles that keep the run open.
    reporters: process.env.CI ? ["verbose", "hanging-process"] : ["default"],
    include: ["packages/*/src/**/*.test.ts", "apps/*/src/**/*.test.{ts,tsx}", "tests/**/*.test.ts"],
    environment: "node",
  },
});
