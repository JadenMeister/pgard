import { describe, expect, it, vi } from "vitest";
import { main } from "../app.js";
import type { CliDeps } from "../deps.js";
import { createTestDeps, createTestIo, noInterrupts } from "../test-support.js";

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
  it("opens the verification page when stdout is a TTY, and still prints it", async () => {
    const openBrowser = vi.fn(async () => true);
    const result = await login(["login"], loginDeps(openBrowser), { stdoutIsTTY: true });
    expect(result.exitCode).toBe(0);
    expect(openBrowser).toHaveBeenCalledExactlyOnceWith(DEVICE_PAGE);
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

  it("treats a failed open as harmless and points at the printed link", async () => {
    const openBrowser = vi.fn(async () => false);
    const result = await login(["login"], loginDeps(openBrowser), { stdoutIsTTY: true });
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain("Could not open a browser; open the link above yourself.");
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
