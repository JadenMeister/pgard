import { describe, expect, it, vi } from "vitest";
import { main } from "../app.js";
import type { CliDeps } from "../deps.js";
import { createTestDeps, createTestIo, noInterrupts } from "../test-support.js";
import { OPEN_PROMPT } from "./browser.js";

const DEVICE_PAGE = "https://github.com/login/device";

/** A login whose fake sign-in shows the device code, then succeeds. */
function loginDeps(openBrowser: CliDeps["openBrowser"], verificationUri = DEVICE_PAGE): CliDeps {
  return createTestDeps({
    openBrowser,
    signInAndStore: async (options) => {
      await options.onUserCode({ userCode: "WXYZ-1234", verificationUri, expiresIn: 900 });
      return { login: "octo", savedError: null };
    },
  });
}

async function login(
  argv: string[],
  deps: CliDeps,
  options: { stdoutIsTTY: boolean; env?: Record<string, string> },
) {
  const captured = createTestIo(options.env ? { env: options.env } : {});
  // stdout is a terminal, stdin is not: no key reader, but browser opening is allowed.
  (captured.io.stdout as { isTTY?: boolean }).isTTY = options.stdoutIsTTY;
  const exitCode = await main(argv, captured.io, { deps, interrupts: noInterrupts });
  return { exitCode, stdout: captured.stdout(), stderr: captured.stderr() };
}

describe("opening the GitHub device page", () => {
  it("only prints the page when stdout is a TTY but stdin is not (nobody can press Enter)", async () => {
    const openBrowser = vi.fn(async () => true);
    const result = await login(["login"], loginDeps(openBrowser), { stdoutIsTTY: true });
    expect(result.exitCode).toBe(0);
    expect(openBrowser).not.toHaveBeenCalled();
    expect(result.stderr).not.toContain(OPEN_PROMPT);
    expect(result.stderr).toContain(`1. Open ${DEVICE_PAGE}`);
    expect(result.stderr).toContain("Enter the code WXYZ-1234");
  });

  it("does not open anything with --no-browser", async () => {
    const openBrowser = vi.fn(async () => true);
    const result = await login(["login", "--no-browser"], loginDeps(openBrowser), {
      stdoutIsTTY: true,
    });
    expect(result.exitCode).toBe(0);
    expect(openBrowser).not.toHaveBeenCalled();
    expect(result.stderr).toContain(`1. Open ${DEVICE_PAGE}`);
  });

  it("does not open anything when stdout is not a TTY", async () => {
    const openBrowser = vi.fn(async () => true);
    const result = await login(["login"], loginDeps(openBrowser), { stdoutIsTTY: false });
    expect(result.exitCode).toBe(0);
    expect(openBrowser).not.toHaveBeenCalled();
    expect(result.stderr).toContain(`1. Open ${DEVICE_PAGE}`);
  });

  it("never opens a verification URI that is not on https://github.com/", async () => {
    const openBrowser = vi.fn(async () => true);
    const result = await login(
      ["login"],
      loginDeps(openBrowser, "https://evil.test/login/device"),
      { stdoutIsTTY: true },
    );
    expect(result.exitCode).toBe(0);
    expect(openBrowser).not.toHaveBeenCalled();
  });

  it("blocks login on a malformed PGARD_GITHUB_APP_SLUG without signing in", async () => {
    const openBrowser = vi.fn(async () => true);
    const deps = loginDeps(openBrowser);
    const signIn = vi.spyOn(deps, "signInAndStore");
    const result = await login(["login"], deps, {
      stdoutIsTTY: true,
      env: { PGARD_GITHUB_APP_SLUG: "Not A Slug" },
    });
    expect(result.exitCode).toBe(3);
    expect(result.stderr).toContain(
      "PGARD_GITHUB_APP_SLUG is set but is not a valid GitHub App slug",
    );
    expect(result.stderr).not.toContain("Not A Slug");
    expect(signIn).not.toHaveBeenCalled();
    expect(openBrowser).not.toHaveBeenCalled();
  });
});

/** A promise whose resolution the test controls. */
function gate() {
  let open!: () => void;
  const promise = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { promise, open };
}

const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

describe("Enter before opening the GitHub device page (terminal)", () => {
  /** Sign-in that shows the code, then waits for the test to finish it (or for Ctrl+C). */
  function pendingSignIn(openBrowser: CliDeps["openBrowser"], done: Promise<void>) {
    let clock = 0;
    return createTestDeps({
      openBrowser,
      now: () => (clock += 100),
      signInAndStore: async (options) => {
        await options.onUserCode({
          userCode: "WXYZ-1234",
          verificationUri: DEVICE_PAGE,
          expiresIn: 900,
        });
        await Promise.race([
          done,
          new Promise<never>((_, reject) =>
            options.signal?.addEventListener("abort", () => reject(new Error("aborted"))),
          ),
        ]);
        return { login: "octo", savedError: null };
      },
    });
  }

  function run(argv: string[], deps: CliDeps, interrupts = noInterrupts) {
    const captured = createTestIo({ isTTY: true });
    const exit = main(argv, captured.io, { deps, interrupts });
    return { captured, exit };
  }

  it("prints the code first, then the prompt, and opens only after Enter", async () => {
    const openBrowser = vi.fn(async () => true);
    const done = gate();
    const { captured, exit } = run(["login"], pendingSignIn(openBrowser, done.promise));
    await tick();
    const shown = captured.stderr();
    expect(shown).toContain("Enter the code WXYZ-1234");
    expect(shown.indexOf("WXYZ-1234")).toBeLessThan(shown.indexOf(OPEN_PROMPT));
    expect(openBrowser).not.toHaveBeenCalled();
    captured.stdin.write("\n");
    await tick();
    expect(openBrowser).toHaveBeenCalledExactlyOnceWith(DEVICE_PAGE);
    done.open();
    expect(await exit).toBe(0);
  });

  it("ignores keys other than Enter and opens nothing without Enter", async () => {
    const openBrowser = vi.fn(async () => true);
    const done = gate();
    const { captured, exit } = run(["login"], pendingSignIn(openBrowser, done.promise));
    await tick();
    captured.stdin.write("o");
    captured.stdin.write(" ");
    await tick();
    done.open();
    expect(await exit).toBe(0);
    expect(openBrowser).not.toHaveBeenCalled();
  });

  it("does not wait for Enter to start signing in: finishing first abandons the prompt", async () => {
    const openBrowser = vi.fn(async () => true);
    const done = gate();
    const { captured, exit } = run(["login"], pendingSignIn(openBrowser, done.promise));
    await tick();
    const listeners = captured.stdin.listenerCount("data");
    expect(listeners).toBeGreaterThan(0);
    done.open(); // the user opened the page by hand and approved
    expect(await exit).toBe(0);
    expect(captured.stdin.listenerCount("data")).toBeLessThan(listeners);
    expect(captured.stdin.isPaused()).toBe(true);
    captured.stdin.write("\n"); // too late
    await tick();
    expect(openBrowser).not.toHaveBeenCalled();
  });

  it("ignores an Enter that was typed ahead before the prompt", async () => {
    const openBrowser = vi.fn(async () => true);
    const done = gate();
    const deps = pendingSignIn(openBrowser, done.promise);
    deps.now = () => 0; // the clock never moves: every key is "too soon"
    const { captured, exit } = run(["login"], deps);
    await tick();
    captured.stdin.write("\n");
    await tick();
    expect(openBrowser).not.toHaveBeenCalled();
    done.open();
    await exit;
  });

  it("never prompts or opens with --no-browser", async () => {
    const openBrowser = vi.fn(async () => true);
    const done = gate();
    const { captured, exit } = run(
      ["login", "--no-browser"],
      pendingSignIn(openBrowser, done.promise),
    );
    await tick();
    captured.stdin.write("\n");
    await tick();
    done.open();
    expect(await exit).toBe(0);
    expect(openBrowser).not.toHaveBeenCalled();
    expect(captured.stderr()).not.toContain(OPEN_PROMPT);
    expect(captured.stderr()).toContain(`1. Open ${DEVICE_PAGE}`);
  });

  it("never prompts when stdout is not a terminal", async () => {
    const openBrowser = vi.fn(async () => true);
    const done = gate();
    const deps = pendingSignIn(openBrowser, done.promise);
    const captured = createTestIo({ isTTY: true });
    (captured.io.stdout as { isTTY?: boolean }).isTTY = false;
    const exit = main(["login"], captured.io, { deps, interrupts: noInterrupts });
    await tick();
    captured.stdin.write("\n");
    await tick();
    done.open();
    expect(await exit).toBe(0);
    expect(openBrowser).not.toHaveBeenCalled();
    expect(captured.stderr()).not.toContain(OPEN_PROMPT);
  });

  it("does not offer a page outside https://github.com/", async () => {
    const openBrowser = vi.fn(async () => true);
    const done = gate();
    const deps = pendingSignIn(openBrowser, done.promise);
    deps.signInAndStore = async (options) => {
      await options.onUserCode({
        userCode: "WXYZ-1234",
        verificationUri: "https://evil.test/login/device",
        expiresIn: 900,
      });
      await done.promise;
      return { login: "octo", savedError: null };
    };
    const { captured, exit } = run(["login"], deps);
    await tick();
    captured.stdin.write("\n");
    await tick();
    done.open();
    await exit;
    expect(openBrowser).not.toHaveBeenCalled();
    expect(captured.stderr()).not.toContain(OPEN_PROMPT);
  });

  it("reports a browser that fails to open after Enter and keeps signing in", async () => {
    const openBrowser = vi.fn(async () => false);
    const done = gate();
    const { captured, exit } = run(["login"], pendingSignIn(openBrowser, done.promise));
    await tick();
    captured.stdin.write("\n");
    await tick();
    expect(captured.stderr()).toContain("Could not open a browser; open the link above yourself.");
    done.open();
    expect(await exit).toBe(0);
  });

  it("keeps the Ctrl+C-twice cancel (exit 130) while the prompt is shown", async () => {
    const openBrowser = vi.fn(async () => true);
    const done = gate();
    let onSigint: () => void = () => undefined;
    const interrupts = {
      on: (_event: "SIGINT", listener: () => void) => {
        onSigint = listener;
      },
      off: () => undefined,
    };
    const { captured, exit } = run(["login"], pendingSignIn(openBrowser, done.promise), interrupts);
    await tick();
    expect(captured.stderr()).toContain(OPEN_PROMPT);
    onSigint();
    onSigint();
    expect(await exit).toBe(130);
    expect(openBrowser).not.toHaveBeenCalled();
    expect(captured.stdin.isPaused()).toBe(true);
  });
});
