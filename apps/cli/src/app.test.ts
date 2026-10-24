import { ScanCancelledError } from "@pgard/scan-core";
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

  it("lets Ctrl+C (SIGINT) cancel a running scan after a prompt was used", async () => {
    const captured = createTestIo({ isTTY: true });
    const stdin = captured.io.stdin as typeof captured.io.stdin & {
      setRawMode?: (mode: boolean) => void;
    };
    const rawModes: boolean[] = [];
    stdin.setRawMode = (mode) => {
      rawModes.push(mode);
    };
    let interrupt: (() => void) | null = null;
    const interrupts = {
      on: (_event: "SIGINT", listener: () => void) => {
        interrupt = listener;
      },
      off: () => {
        interrupt = null;
      },
    };
    const deps = createTestDeps({
      createSessionProvider: () => (async () => ({})) as never,
      runScan: async (_request, scanDeps) => {
        // The prompt has been answered; raw mode must be off so Ctrl+C is a SIGINT again.
        expect(rawModes.at(-1)).toBe(false);
        interrupt?.();
        interrupt?.();
        if (scanDeps.signal?.aborted === true) throw new ScanCancelledError();
        throw new Error("signal was not aborted");
      },
    });
    const running = main(["scan", "web", "--port", "3000"], captured.io, { deps, interrupts });
    await new Promise((resolve) => setTimeout(resolve, 20));
    stdin.write("y");
    expect(await running).toBe(130);
  });

  it("exits 0 when the menu is left after a command ended with Esc (130)", async () => {
    const captured = createTestIo({ isTTY: true });
    const stdin = captured.io.stdin as typeof captured.io.stdin & {
      setRawMode?: (mode: boolean) => void;
    };
    stdin.setRawMode = () => undefined;
    const running = main([], captured.io, {
      deps: createTestDeps({ createSessionProvider: () => (async () => ({})) as never }),
      interrupts: noInterrupts,
    });
    const press = async (sequence: string): Promise<void> => {
      await new Promise((resolve) => setTimeout(resolve, 15));
      stdin.write(sequence);
    };
    // Menu: 5th entry "Scan local web service".
    for (let index = 0; index < 4; index += 1) await press("\u001b[B");
    await press("\r");
    // Port list (re-activated after the authorization check): Esc returns with status 130.
    await new Promise((resolve) => setTimeout(resolve, 100));
    // A lone ESC is only recognised after readline's escape timeout (~500 ms).
    await press("\u001b");
    await new Promise((resolve) => setTimeout(resolve, 700));
    await press("x"); // "Press any key to return to the menu"
    await press("\u001b"); // Esc on the menu = quit
    expect(await running).toBe(0);
    expect(captured.stdout()).toContain("(exit status 130)");
  }, 10_000);
});
