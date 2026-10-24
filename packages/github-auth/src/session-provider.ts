import {
  authenticateWithDeviceFlow,
  type DeviceFlowOptions,
  type DeviceUserCode,
  type GitHubSession,
} from "./device-flow.js";
import { GITHUB_APP_CLIENT_ID_ENV } from "./env.js";
import { GitHubAuthError } from "./errors.js";
import type { FetchLike } from "./fetch.js";

/**
 * Supplies an authenticated session to the authorization gate. Called only after local
 * repository checks pass. Throws `GitHubAuthError` when no session can be obtained.
 */
export type GitHubSessionProvider = () => Promise<GitHubSession>;

export interface DeviceFlowSessionProviderOptions {
  /** From `readGitHubAppClientId(process.env)`; `null` makes every call fail. */
  clientId: string | null;
  onUserCode: (code: DeviceUserCode) => void | Promise<void>;
  fetch?: FetchLike;
  signal?: AbortSignal;
  /** Test hooks forwarded to the device flow. */
  sleep?: DeviceFlowOptions["sleep"];
  now?: DeviceFlowOptions["now"];
}

/**
 * Creates a provider that runs the device flow on first use and keeps the session in memory for
 * the lifetime of the provider (one CLI process or one local-web server). Nothing is persisted.
 * A failed sign-in is not remembered, so the next call starts a new device flow.
 */
export function createDeviceFlowSessionProvider(
  options: DeviceFlowSessionProviderOptions,
): GitHubSessionProvider {
  let pending: Promise<GitHubSession> | null = null;

  return () => {
    const { clientId } = options;
    if (clientId === null) {
      return Promise.reject(
        new GitHubAuthError(
          "missing_client_id",
          `${GITHUB_APP_CLIENT_ID_ENV} is not set. A registered PGARD GitHub App is required to verify GitHub identity.`,
        ),
      );
    }
    if (pending === null) {
      pending = authenticateWithDeviceFlow({
        clientId,
        onUserCode: options.onUserCode,
        ...(options.fetch ? { fetch: options.fetch } : {}),
        ...(options.signal ? { signal: options.signal } : {}),
        ...(options.sleep ? { sleep: options.sleep } : {}),
        ...(options.now ? { now: options.now } : {}),
      });
      pending.catch(() => {
        pending = null;
      });
    }
    return pending;
  };
}
