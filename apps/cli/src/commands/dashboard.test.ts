import { describe, expect, it, vi } from "vitest";
import { createTestContext, createTestDeps, createTestIo, scriptedKeys } from "../test-support.js";
import { runDashboard } from "./dashboard.js";

describe("runDashboard", () => {
  it("needs a terminal to confirm the project", async () => {
    const captured = createTestIo();
    expect(await runDashboard(createTestContext(captured, createTestDeps()), null)).toBe(2);
  });

  it("starts the installed launcher with the confirmed project root only after y", async () => {
    const captured = createTestIo();
    const startDashboardProcess = vi.fn(async () => 0);
    const deps = createTestDeps({
      resolveDashboardEntry: () => "/install/local-web/dist/server/index.js",
      startDashboardProcess,
    });
    expect(await runDashboard(createTestContext(captured, deps, scriptedKeys(["n"])), 3000)).toBe(
      130,
    );
    expect(startDashboardProcess).not.toHaveBeenCalled();
    const released = vi.fn();
    const context = {
      ...createTestContext(captured, deps, scriptedKeys(["y"])),
      releaseInterrupts: released,
    };
    expect(await runDashboard(context, 3000)).toBe(0);
    expect(released).toHaveBeenCalledOnce();
    expect(startDashboardProcess).toHaveBeenCalledWith("/install/local-web/dist/server/index.js", [
      "--project-root",
      "/work/repo",
      "--target-port",
      "3000",
    ]);
  });

  it("exits 5 when the dashboard is not installed", async () => {
    const captured = createTestIo();
    expect(
      await runDashboard(createTestContext(captured, createTestDeps(), scriptedKeys([])), null),
    ).toBe(5);
  });

  it("maps unknown exit codes of the dashboard process to 5", async () => {
    const captured = createTestIo();
    const deps = createTestDeps({
      resolveDashboardEntry: () => "/install/local-web/dist/server/index.js",
      startDashboardProcess: async () => 1,
    });
    expect(await runDashboard(createTestContext(captured, deps, scriptedKeys(["y"])), null)).toBe(
      5,
    );
  });
});
