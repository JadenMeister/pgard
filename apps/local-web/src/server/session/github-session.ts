import type { DeviceUserCode, GitHubSessionProvider, SignInNotice } from "@pgard/scan-core";
import type { ServerDeps } from "../deps.js";

/**
 * Owns the GitHub session for the dashboard's lifetime. Each provider gets its own
 * AbortController so a pending device-flow sign-in can be stopped (scan cancel, sign-out,
 * shutdown) instead of polling GitHub until the code expires.
 */
export interface GitHubSessionManager {
  /** Stable provider handed to verifyProject/runScan; delegates to the current provider. */
  getGitHubSession: GitHubSessionProvider;
  /**
   * Stops a device flow that is still waiting for the user, or a token refresh a non-interactive
   * re-check (`existing()`) has in flight; a signed-in session is kept.
   */
  abortPendingSignIn: () => void;
  /**
   * Ends this dashboard's GitHub session and stops any pending sign-in. A sign-in saved in the
   * OS keychain is kept (the next check reuses it); removing it is a separate, explicit action.
   */
  signOut: () => void;
  /** Shutdown: like signOut, and no new provider is created. */
  dispose: () => void;
}

export function createGitHubSessionManager(
  deps: Pick<ServerDeps, "createSessionProvider">,
  env: Readonly<Record<string, string | undefined>>,
  onUserCode: (code: DeviceUserCode) => void,
  onNotice: (notice: SignInNotice) => void,
): GitHubSessionManager {
  let controller = new AbortController();
  let provider = deps.createSessionProvider({
    env,
    onUserCode,
    onNotice,
    signal: controller.signal,
  });
  let pendingSignIns = 0;
  let isDisposed = false;

  const reset = (): void => {
    controller.abort();
    provider.signOut();
    pendingSignIns = 0;
    if (isDisposed) return;
    controller = new AbortController();
    provider = deps.createSessionProvider({ env, onUserCode, onNotice, signal: controller.signal });
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
    // Non-interactive (owner-approval re-check): never starts a device flow.
    // Tracked like `call`, so a scan cancel or shutdown aborts a token refresh it started.
    existing: async () => {
      if (isDisposed) throw new Error("The dashboard is shutting down.");
      const current = provider;
      pendingSignIns += 1;
      try {
        return await current.existing();
      } finally {
        if (current === provider) pendingSignIns = Math.max(0, pendingSignIns - 1);
      }
    },
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
