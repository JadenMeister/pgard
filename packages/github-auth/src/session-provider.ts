import {
  authenticateWithDeviceFlow,
  createGitHubSession,
  type DeviceFlowOptions,
  type DeviceUserCode,
  type GitHubSession,
} from "./device-flow.js";
import { GITHUB_APP_CLIENT_ID_ENV } from "./env.js";
import { GitHubAuthError, isGitHubAuthError } from "./errors.js";
import type { FetchLike } from "./fetch.js";
import type { GitHubClient } from "./github-client.js";

/**
 * Supplies an authenticated session to the authorization gate. Called only after local
 * repository checks pass. Throws `GitHubAuthError` when no session can be obtained.
 *
 * - `invalidate()` forgets the cached session so the next call signs in again.
 * - `signOut()` does the same; it is the explicit user action. The token cannot be revoked on
 *   GitHub without the app's client secret, so it is only dropped from memory.
 */
export type GitHubSessionProvider = (() => Promise<GitHubSession>) & {
  invalidate(): void;
  signOut(): void;
};

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

/** A session is renewed this long before its token expires. */
const EXPIRY_MARGIN_MS = 60_000;

/**
 * Wraps every client method so an `unauthorized` response clears the cached session, and so a
 * session that was invalidated or signed out refuses further calls even if a caller kept it.
 */
function wrapClient(
  client: GitHubClient,
  onUnauthorized: () => void,
  isRevoked: () => boolean,
): GitHubClient {
  const wrapped = {} as Record<string, unknown>;
  for (const key of Object.keys(client) as (keyof GitHubClient)[]) {
    const method = client[key] as (...args: unknown[]) => Promise<unknown>;
    wrapped[key] = async (...args: unknown[]) => {
      if (isRevoked()) {
        throw new GitHubAuthError(
          "unauthorized",
          "This GitHub session was signed out or replaced; sign in again.",
        );
      }
      try {
        return await method(...args);
      } catch (error) {
        if (isGitHubAuthError(error) && error.code === "unauthorized") {
          onUnauthorized();
        }
        throw error;
      }
    };
  }
  return wrapped as unknown as GitHubClient;
}

/**
 * Creates a provider that runs the device flow on first use and keeps the session in memory for
 * the lifetime of the provider (one CLI process or one local-web server). Nothing is persisted.
 * The cached session is dropped when sign-in fails, when the token is about to expire, when
 * GitHub answers 401, or on `invalidate()`/`signOut()`.
 */
export function createDeviceFlowSessionProvider(
  options: DeviceFlowSessionProviderOptions,
): GitHubSessionProvider {
  const now = options.now ?? Date.now;
  let pending: Promise<GitHubSession> | null = null;
  let generation = 0;

  const forget = () => {
    pending = null;
    generation += 1;
  };

  const startSignIn = (clientId: string): Promise<GitHubSession> => {
    const myGeneration = generation;
    const clearIfCurrent = () => {
      if (generation === myGeneration) {
        forget();
      }
    };
    const promise = authenticateWithDeviceFlow({
      clientId,
      onUserCode: options.onUserCode,
      ...(options.fetch ? { fetch: options.fetch } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
      ...(options.sleep ? { sleep: options.sleep } : {}),
      now,
    }).then((session) =>
      createGitHubSession(
        wrapClient(session.client, clearIfCurrent, () => generation !== myGeneration),
        session.expiresAt,
      ),
    );
    promise.catch(clearIfCurrent);
    return promise;
  };

  const provider = async (): Promise<GitHubSession> => {
    const { clientId } = options;
    if (clientId === null) {
      throw new GitHubAuthError(
        "missing_client_id",
        `${GITHUB_APP_CLIENT_ID_ENV} is not set. A registered PGARD GitHub App is required to verify GitHub identity.`,
      );
    }
    if (pending !== null) {
      const current = pending;
      const session = await current.catch(() => null);
      if (
        session !== null &&
        pending === current &&
        (session.expiresAt === null || now() < session.expiresAt - EXPIRY_MARGIN_MS)
      ) {
        return session;
      }
      if (pending === current) {
        forget();
      }
    }
    pending ??= startSignIn(clientId);
    return pending;
  };

  return Object.assign(provider, { invalidate: forget, signOut: forget });
}
