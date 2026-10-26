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
    include: ["packages/*/src/**/*.test.ts", "apps/*/src/**/*.test.{ts,tsx}", "tests/**/*.test.ts"],
    environment: "node",
  },
});
