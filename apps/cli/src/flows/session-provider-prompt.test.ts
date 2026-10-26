import { describe, expect, it, vi } from "vitest";
import type { CliDeps } from "../deps.js";
import { createTestContext, createTestDeps, createTestIo } from "../test-support.js";
import { createSessionProvider } from "./authenticate.js";
import { OPEN_PROMPT } from "./browser.js";

const PAGE = "https://github.com/login/device";
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

type Factory = CliDeps["createSessionProvider"];

/** A provider whose sign-in shows a code, then ends when `finish` is called. */
function fakeProvider(): { factory: Factory; finish: () => void } {
  let finish!: () => void;
  const finished = new Promise<void>((resolve) => {
    finish = resolve;
  });
  const factory: Factory = ({ onUserCode }) =>
    Object.assign(
      async () => {
        onUserCode({ userCode: "WXYZ-1234", verificationUri: PAGE, expiresIn: 900 });
        await finished;
        return {} as never;
      },
      { invalidate: () => undefined, signOut: () => undefined, existing: async () => null },
    );
  return { factory, finish };
}

function setup() {
  const captured = createTestIo({ isTTY: true });
  const openBrowser = vi.fn(async () => true);
  const fake = fakeProvider();
  let clock = 0;
  const deps = createTestDeps({
    openBrowser,
    now: () => (clock += 100),
    createSessionProvider: fake.factory,
  });
  const context = { ...createTestContext(captured, deps), canOpenBrowser: true };
  return { captured, openBrowser, fake, provider: createSessionProvider(context) };
}

describe("Enter prompt of the session provider (scan, project verify)", () => {
  it("opens the page after Enter while the sign-in is still running", async () => {
    const { captured, openBrowser, fake, provider } = setup();
    const signIn = provider();
    await tick();
    expect(captured.stderr()).toContain(OPEN_PROMPT);
    expect(openBrowser).not.toHaveBeenCalled();
    captured.stdin.write("\n");
    await tick();
    expect(openBrowser).toHaveBeenCalledExactlyOnceWith(PAGE);
    fake.finish();
    await signIn;
  });

  it("abandons the prompt when the sign-in call ends", async () => {
    const { captured, openBrowser, fake, provider } = setup();
    const signIn = provider();
    await tick();
    fake.finish();
    await signIn;
    expect(captured.stdin.isPaused()).toBe(true);
    captured.stdin.write("\n");
    await tick();
    expect(openBrowser).not.toHaveBeenCalled();
  });

  it("keeps the prompt through a background existing() re-check", async () => {
    const { openBrowser, captured, fake, provider } = setup();
    const signIn = provider();
    await tick();
    await provider.existing();
    captured.stdin.write("\n");
    await tick();
    expect(openBrowser).toHaveBeenCalledExactlyOnceWith(PAGE);
    fake.finish();
    await signIn;
  });
});
