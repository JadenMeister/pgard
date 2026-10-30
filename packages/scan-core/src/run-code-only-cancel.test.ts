import { describe, expect, it } from "vitest";
import { runCodeOnlyScan, ScanCancelledError } from "./index.js";

describe("Cancel of a code-only scan (#427)", () => {
  it("returns at once when an analyzer is stuck in a call that never returns", async () => {
    const controller = new AbortController();
    const started = Date.now();
    const running = runCodeOnlyScan(
      { projectRoot: "/work/stuck" },
      {
        signal: controller.signal,
        env: {},
        // A hung network or FUSE mount: the analyzer never settles.
        analyzers: { code: () => new Promise(() => undefined) },
      },
    );
    setTimeout(() => controller.abort(), 30);
    await expect(running).rejects.toBeInstanceOf(ScanCancelledError);
    expect(Date.now() - started).toBeLessThan(3000);
  });
});
