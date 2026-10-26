import type { GitHubSessionProvider } from "@pgard/scan-core";
import { describe, expect, it, vi } from "vitest";
import type { ServerDeps } from "../deps.js";
import { createGitHubSessionManager } from "./github-session.js";

/** A provider whose `existing()` stays pending until the test settles it. */
function fakeProvider(signal: AbortSignal) {
  let settle: (value: null) => void = () => {};
  const existing = vi.fn(
    () =>
      new Promise<null>((resolve) => {
        settle = resolve;
      }),
  );
  const provider = Object.assign(async () => ({}) as never, {
    invalidate: vi.fn(),
    signOut: vi.fn(),
    existing,
  }) as unknown as GitHubSessionProvider;
  return { provider, signal, settle: () => settle(null) };
}

function manager() {
  const created: ReturnType<typeof fakeProvider>[] = [];
  const deps: Pick<ServerDeps, "createSessionProvider"> = {
    createSessionProvider: (options) => {
      const fake = fakeProvider(options.signal);
      created.push(fake);
      return fake.provider;
    },
  };
  const sessions = createGitHubSessionManager(
    deps,
    {},
    () => {},
    () => {},
  );
  return { sessions, created };
}

describe("github session manager", () => {
  it("aborts a refresh started by existing() when a scan is cancelled", async () => {
    const { sessions, created } = manager();
    const rechecking = sessions.getGitHubSession.existing();
    expect(created[0]?.signal.aborted).toBe(false);

    sessions.abortPendingSignIn();
    expect(created[0]?.signal.aborted).toBe(true);
    expect(created[0]?.provider.signOut).toHaveBeenCalled();
    // The next call gets a fresh provider with a live signal.
    expect(created).toHaveLength(2);
    expect(created[1]?.signal.aborted).toBe(false);

    created[0]?.settle();
    await expect(rechecking).resolves.toBeNull();
  });

  it("does not abort anything when no sign-in or refresh is pending", async () => {
    const { sessions, created } = manager();
    const rechecking = sessions.getGitHubSession.existing();
    created[0]?.settle();
    await rechecking;
    sessions.abortPendingSignIn();
    expect(created).toHaveLength(1);
    expect(created[0]?.signal.aborted).toBe(false);
  });

  it("aborts a refresh started by existing() on shutdown", async () => {
    const { sessions, created } = manager();
    const rechecking = sessions.getGitHubSession.existing();
    sessions.dispose();
    expect(created[0]?.signal.aborted).toBe(true);
    created[0]?.settle();
    await rechecking;
    await expect(sessions.getGitHubSession.existing()).rejects.toThrow("shutting down");
  });
});
