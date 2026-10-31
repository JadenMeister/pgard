import { defineConfig } from "vitest/config";
import { TIME_FACTOR } from "./tests/support/timing.js";

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
    // Scaled by the shared time factor (3 on CI; override with PGARD_TEST_TIME_FACTOR) so a loaded
    // runner fails on a real hang, not on a slow spawn. The factor already includes the Windows 3.
    testTimeout: (process.platform === "win32" ? 10_000 : 5_000) * TIME_FACTOR,
    // A stuck setup or teardown fails with the name of its test instead of stalling the run.
    // Vitest's own default for both is 10 s.
    hookTimeout: (process.platform === "win32" ? 20_000 : 30_000) * TIME_FACTOR,
    teardownTimeout: 30_000,
    // In CI every test is logged as it finishes, so a run that stalls names the last test that
    // started, and the hanging-process reporter lists the handles that keep the run open.
    reporters: process.env.CI ? ["verbose", "hanging-process"] : ["default"],
    include: ["packages/*/src/**/*.test.ts", "apps/*/src/**/*.test.{ts,tsx}", "tests/**/*.test.ts"],
    environment: "node",
  },
});
