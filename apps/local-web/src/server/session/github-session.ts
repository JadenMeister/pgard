import type { DeviceUserCode, GitHubSessionProvider } from "@pgard/scan-core";
import type { ServerDeps } from "../deps.js";

/**
 * Owns the GitHub session for the dashboard's lifetime. Each provider gets its own
 * AbortController so a pending device-flow sign-in can be stopped (scan cancel, sign-out,
 * shutdown) instead of polling GitHub until the code expires.
 */
export interface GitHubSessionManager {
  /** Stable provider handed to verifyProject/runScan; delegates to the current provider. */
  getGitHubSession: GitHubSessionProvider;
  /** Stops a device flow that is still waiting for the user; a signed-in session is kept. */
  abortPendingSignIn: () => void;
  /** Explicit sign-out: drops the session and stops any pending sign-in. */
  signOut: () => void;
  /** Shutdown: like signOut, and no new provider is created. */
  dispose: () => void;
}

export function createGitHubSessionManager(
  deps: Pick<ServerDeps, "createSessionProvider">,
  env: Readonly<Record<string, string | undefined>>,
  onUserCode: (code: DeviceUserCode) => void,
): GitHubSessionManager {
  let controller = new AbortController();
  let provider = deps.createSessionProvider({ env, onUserCode, signal: controller.signal });
  let pendingSignIns = 0;
  let isDisposed = false;

  const reset = (): void => {
    controller.abort();
    provider.signOut();
    pendingSignIns = 0;
    if (isDisposed) return;
    controller = new AbortController();
    provider = deps.createSessionProvider({ env, onUserCode, signal: controller.signal });
  };

  const call = async (): ReturnType<GitHubSessionProvider> => {
    if (isDisposed) throw new Error("The dashboard is shutting down.");
    const current = provider;
    pendingSignIns += 1;
    try {
      return await current();
    } finally {
      if (current === provider) pendingSignIns = Math.max(0, pendingSignIns - 1);
    }
  };

  const getGitHubSession = Object.assign(call, {
    invalidate: () => provider.invalidate(),
    signOut: () => reset(),
  }) as GitHubSessionProvider;

  return {
    getGitHubSession,
    abortPendingSignIn: () => {
      if (pendingSignIns > 0) reset();
    },
    signOut: reset,
    dispose: () => {
      isDisposed = true;
      reset();
    },
  };
}
