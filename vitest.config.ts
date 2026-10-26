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
    include: ["packages/*/src/**/*.test.ts", "apps/*/src/**/*.test.{ts,tsx}", "tests/**/*.test.ts"],
    environment: "node",
  },
});
