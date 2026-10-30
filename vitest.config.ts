import { defineConfig } from "vitest/config";

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
    testTimeout: process.platform === "win32" ? 30_000 : 5_000,
    // A stuck setup or teardown fails with the name of its test instead of stalling the run.
    // Vitest's own default for both is 10 s.
    hookTimeout: process.platform === "win32" ? 60_000 : 30_000,
    teardownTimeout: 30_000,
    // In CI every test is logged as it finishes, so a run that stalls names the last test that
    // started, and the hanging-process reporter lists the handles that keep the run open.
    reporters: process.env.CI ? ["verbose", "hanging-process"] : ["default"],
    include: ["packages/*/src/**/*.test.ts", "apps/*/src/**/*.test.{ts,tsx}", "tests/**/*.test.ts"],
    environment: "node",
  },
});
