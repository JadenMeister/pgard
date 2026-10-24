import { describe, expect, it, vi } from "vitest";
import { main } from "./app.js";
import { createTestDeps, createTestIo, noInterrupts } from "./test-support.js";

describe("main", () => {
  it("prints help and version with exit 0 without touching dependencies", async () => {
    const throwingDeps = createTestDeps({
      findGitRoot: () => {
        throw new Error("must not be called");
      },
    });
    const help = createTestIo();
    expect(await main(["--help"], help.io, { deps: throwingDeps, interrupts: noInterrupts })).toBe(
      0,
    );
    expect(help.stdout()).toContain("pgard scan all [--port N]");
    const version = createTestIo();
    expect(
      await main(["--version"], version.io, { deps: throwingDeps, interrupts: noInterrupts }),
    ).toBe(0);
    expect(version.stdout()).toMatch(/^pgard \d+\.\d+\.\d+/);
  });

  it("rejects invalid input with exit 2 before any authorization, scan or network call", async () => {
    const findGitRoot = vi.fn();
    const runScan = vi.fn();
    const captured = createTestIo();
    const code = await main(["scan", "web", "--port", "99999"], captured.io, {
      deps: createTestDeps({ findGitRoot, runScan }),
      interrupts: noInterrupts,
    });
    expect(code).toBe(2);
    expect(findGitRoot).not.toHaveBeenCalled();
    expect(runScan).not.toHaveBeenCalled();
    expect(captured.stderr()).toContain("--port must be an integer from 1 to 65535");
  });

  it("strips control characters from echoed invalid input", async () => {
    const captured = createTestIo();
    await main(["\u001b[31mevil"], captured.io, {
      deps: createTestDeps(),
      interrupts: noInterrupts,
    });
    expect(captured.stderr()).not.toContain("\u001b[31m");
  });

  it("refuses the interactive menu without a terminal", async () => {
    const captured = createTestIo();
    expect(await main([], captured.io, { deps: createTestDeps(), interrupts: noInterrupts })).toBe(
      2,
    );
  });

  it("maps unexpected errors to exit 5 without printing details", async () => {
    const captured = createTestIo();
    const code = await main(["scan"], captured.io, {
      deps: createTestDeps({
        runScan: async () => {
          throw new Error("token ghu_SECRET leaked in message");
        },
        createSessionProvider: () => (async () => ({})) as never,
      }),
      interrupts: noInterrupts,
    });
    expect(code).toBe(5);
    expect(captured.stderr()).not.toContain("ghu_SECRET");
  });

  it("runs rules list outside a project", async () => {
    const captured = createTestIo();
    const code = await main(["rules", "list"], captured.io, {
      deps: createTestDeps({ findGitRoot: async () => null }),
      interrupts: noInterrupts,
    });
    expect(code).toBe(0);
    expect(captured.stdout()).toContain("PG-WEB-001");
    expect(captured.stdout()).toContain("Authenticated (logged-in) web browsing");
  });
});
