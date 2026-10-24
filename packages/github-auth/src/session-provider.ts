import { isCredentialStoreError, type CredentialStore } from "./credential-store.js";
import {
  createGitHubSession,
  createSessionFromToken,
  defaultSleep,
  refreshUserToken,
  requestDeviceFlowTokens,
  type DeviceFlowOptions,
  type DeviceUserCode,
  type GitHubSession,
  type UserTokenSet,
} from "./device-flow.js";
import { GITHUB_APP_CLIENT_ID_ENV } from "./env.js";
import { GitHubAuthError, isGitHubAuthError } from "./errors.js";
import type { FetchLike } from "./fetch.js";
import type { GitHubClient, GitHubUser } from "./github-client.js";
import {
  githubHostOf,
  loadStoredSignIn,
  saveStoredSignIn,
  signInKey,
  type StoredSignInRecord,
} from "./stored-sign-in.js";

/**
 * Supplies an authenticated session to the authorization gate. Called only after local
 * repository checks pass. Throws `GitHubAuthError` when no session can be obtained.
 *
 * - `invalidate()` forgets the cached session so the next call signs in again.
 * - `signOut()` does the same; it is the explicit user action. It only ends the session held by
 *   this provider: a sign-in stored in the OS keychain is kept (see `removeStoredSignIn`).
 */
export type GitHubSessionProvider = (() => Promise<GitHubSession>) & {
  invalidate(): void;
  signOut(): void;
};

/**
 * Secret-free events about the stored sign-in, for the CLI and dashboard to show. `reason` texts
 * are fixed wording and never contain a token.
 */
export type SignInNotice =
  /** A stored sign-in was reused (after an automatic token refresh when `isRefreshed`). */
  | { kind: "reused"; login: string; isRefreshed: boolean }
  /** A new device-flow sign-in was saved to the OS keychain. */
  | { kind: "saved"; login: string }
  /** The stored sign-in could not be used and was deleted; the device flow runs instead. */
  | { kind: "removed"; reason: "expired" | "revoked" | "refresh_failed" | "malformed" }
  /** No keychain: this provider keeps the sign-in in memory only. */
  | { kind: "memory_only"; reason: string };

export interface DeviceFlowSessionProviderOptions {
  /** From `readGitHubAppClientId(process.env)`; `null` makes every call fail. */
  clientId: string | null;
  onUserCode: (code: DeviceUserCode) => void | Promise<void>;
  /**
   * Where the sign-in is reused from and saved to (the OS keychain in production). Omitted or
   * `null`: memory only, the device flow runs once per provider.
   */
  credentialStore?: CredentialStore | null;
  onNotice?: (notice: SignInNotice) => void;
  fetch?: FetchLike;
  signal?: AbortSignal;
  /** Test hooks forwarded to the device flow. */
  sleep?: DeviceFlowOptions["sleep"];
  now?: DeviceFlowOptions["now"];
}

/** A session is renewed this long before its token expires. */
const EXPIRY_MARGIN_MS = 60_000;
/**
 * After GitHub rejects a refresh token, how long to wait for another PGARD process that may
 * have just refreshed (and rotated) it to save the new tokens, before deleting the entry.
 */
const REFRESH_RACE_WAIT_MS = 1_500;

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

function missingClientIdError(): GitHubAuthError {
  return new GitHubAuthError(
    "missing_client_id",
    `${GITHUB_APP_CLIENT_ID_ENV} is not set. A registered PGARD GitHub App is required to verify GitHub identity.`,
  );
}

function isUnauthorized(error: unknown): boolean {
  return isGitHubAuthError(error) && error.code === "unauthorized";
}

function isRejectedRefresh(error: unknown): boolean {
  return (
    isGitHubAuthError(error) &&
    (error.code === "refresh_failed" || error.code === "incorrect_client_credentials")
  );
}

function toRecord(
  tokens: UserTokenSet,
  user: GitHubUser,
  host: string,
  clientId: string,
  now: number,
): StoredSignInRecord {
  return {
    ...tokens,
    host,
    clientId,
    login: user.login,
    userId: user.id,
    savedAt: now,
  };
}

/** Options shared by the provider and `signInAndStore`. */
type SignInOptions = Omit<DeviceFlowSessionProviderOptions, "clientId"> & { clientId: string };

/**
 * Runs the device flow, looks up the signed-in account and saves the sign-in to the keychain.
 * Used by `pgard login`, which always signs in again (to switch accounts or replace a stale
 * entry). Rejects with `GitHubAuthError` when sign-in fails; a keychain failure is reported in
 * the result, never as a thrown token-bearing error.
 */
export async function signInAndStore(
  options: SignInOptions & { credentialStore: CredentialStore },
): Promise<{ login: string; savedError: string | null }> {
  const now = options.now ?? Date.now;
  const tokens = await requestDeviceFlowTokens(deviceFlowOptions(options, options.clientId));
  const session = createSessionFromToken(tokens.accessToken, tokens.expiresAt, options);
  const user = await session.client.getAuthenticatedUser();
  const savedError = await saveStoredSignIn(
    options.credentialStore,
    toRecord(tokens, user, githubHostOf(), options.clientId, now()),
  );
  return { login: user.login, savedError };
}

function deviceFlowOptions(
  options: Omit<SignInOptions, "clientId">,
  clientId: string,
): DeviceFlowOptions {
  return {
    clientId,
    onUserCode: options.onUserCode,
    ...(options.fetch ? { fetch: options.fetch } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
    ...(options.sleep ? { sleep: options.sleep } : {}),
    ...(options.now ? { now: options.now } : {}),
  };
}

/**
 * Creates a provider for one CLI process or one dashboard server.
 *
 * With a `credentialStore`, the first call reuses the sign-in stored for this GitHub host and App
 * client id: an expired access token is refreshed with the refresh token (no client secret is
 * needed for device-flow tokens), and the token is checked with `GET /user` before it is handed
 * out. When the entry is expired, malformed, revoked (401) or the refresh is rejected, the entry
 * is deleted and the device flow runs instead. A device-flow sign-in is saved to the store. When
 * the store is unavailable, the provider says so once (`memory_only`) and keeps the session in
 * memory, exactly like the provider without a store.
 *
 * The cached session is dropped when sign-in fails, when the token is about to expire, when
 * GitHub answers 401 (which also deletes the stored entry), or on `invalidate()`/`signOut()`.
 */
export function createDeviceFlowSessionProvider(
  options: DeviceFlowSessionProviderOptions,
): GitHubSessionProvider {
  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? defaultSleep;
  const host = githubHostOf();
  const notify = (notice: SignInNotice): void => options.onNotice?.(notice);
  let store: CredentialStore | null = options.credentialStore ?? null;
  let pending: Promise<GitHubSession> | null = null;
  let generation = 0;

  const forget = () => {
    pending = null;
    generation += 1;
  };

  const isFresh = (expiresAt: number | null): boolean =>
    expiresAt === null || now() < expiresAt - EXPIRY_MARGIN_MS;

  const fallBackToMemory = (reason: string): void => {
    if (store === null) return;
    store = null;
    notify({ kind: "memory_only", reason });
  };

  const deleteEntry = async (clientId: string): Promise<void> => {
    const current = store;
    if (current === null) return;
    await current.delete(signInKey(host, clientId)).catch((error: unknown) => {
      if (isCredentialStoreError(error)) fallBackToMemory(error.message);
    });
  };

  /**
   * Deletes the entry only while it still holds `accessToken`. Another process (`pgard login`,
   * or a refresh in a second PGARD process) may have replaced it since this provider read it; a
   * failure of the old token must not delete the newer sign-in.
   */
  const deleteIfStillHolds = async (clientId: string, accessToken: string): Promise<boolean> => {
    const current = store;
    if (current === null) return false;
    const loaded = await loadStoredSignIn(current, host, clientId, { deleteMalformed: false });
    if (loaded.kind !== "found" || loaded.record.accessToken !== accessToken) return false;
    await deleteEntry(clientId);
    return true;
  };

  const drop = async (
    clientId: string,
    reason: Extract<SignInNotice, { kind: "removed" }>["reason"],
  ): Promise<void> => {
    await deleteEntry(clientId);
    notify({ kind: "removed", reason });
  };

  /** Validates (and if needed refreshes) a stored sign-in; `null` means use the device flow. */
  const tryStored = async (
    current: CredentialStore,
    record: StoredSignInRecord,
    isRetry: boolean,
  ): Promise<{ tokens: UserTokenSet; isRefreshed: boolean } | null> => {
    let tokens: UserTokenSet = record;
    let isRefreshed = false;
    if (!isFresh(record.expiresAt)) {
      if (record.refreshToken === null || !isFresh(record.refreshTokenExpiresAt)) {
        await drop(record.clientId, "expired");
        return null;
      }
      try {
        tokens = await refreshUserToken({
          clientId: record.clientId,
          refreshToken: record.refreshToken,
          ...(options.fetch ? { fetch: options.fetch } : {}),
          ...(options.signal ? { signal: options.signal } : {}),
          now,
        });
        isRefreshed = true;
      } catch (error) {
        if (!isRejectedRefresh(error)) throw error;
        // Another PGARD process may have refreshed first (GitHub rotates refresh tokens) and
        // not have saved the new tokens yet. Reload now and once more after a short wait, and
        // reuse what it stored instead of deleting a valid entry.
        const waits = isRetry ? [0] : [0, REFRESH_RACE_WAIT_MS];
        let latest: StoredSignInRecord | null = null;
        for (const wait of waits) {
          if (wait > 0) await sleep(wait, options.signal);
          const reloaded = await loadStoredSignIn(current, host, record.clientId, {
            deleteMalformed: false,
          });
          // Gone (or unreadable): someone else removed it, so there is nothing to delete.
          if (reloaded.kind !== "found") return null;
          latest = reloaded.record;
          if (latest.refreshToken !== record.refreshToken) {
            return isRetry ? null : tryStored(current, latest, true);
          }
        }
        if (latest !== null) await drop(record.clientId, "refresh_failed");
        return null;
      }
    }
    return { tokens, isRefreshed };
  };

  /** Reuses a stored sign-in after checking it with `GET /user`; `null` means use the device flow. */
  const reuseStored = async (
    current: CredentialStore,
    record: StoredSignInRecord,
    myGeneration: number,
    canRetry: boolean,
  ): Promise<GitHubSession | null> => {
    const reused = await tryStored(current, record, false);
    if (reused === null) return null;
    const session = createSessionFromToken(
      reused.tokens.accessToken,
      reused.tokens.expiresAt,
      options,
    );
    let user: GitHubUser;
    try {
      user = await session.client.getAuthenticatedUser();
    } catch (error) {
      if (!isUnauthorized(error)) throw error;
      // Delete only the entry that was rejected; `pgard login` elsewhere may have replaced it.
      const reloaded = await loadStoredSignIn(current, host, record.clientId, {
        deleteMalformed: false,
      });
      if (reloaded.kind === "found" && reloaded.record.accessToken !== record.accessToken) {
        return canRetry ? reuseStored(current, reloaded.record, myGeneration, false) : null;
      }
      if (reloaded.kind === "found") await drop(record.clientId, "revoked");
      return null;
    }
    if (reused.isRefreshed) {
      const failure = await saveStoredSignIn(
        current,
        toRecord(reused.tokens, user, host, record.clientId, now()),
      );
      if (failure !== null) {
        // The old refresh token is spent; do not leave it behind.
        await deleteEntry(record.clientId);
        fallBackToMemory(failure);
      }
    }
    notify({ kind: "reused", login: user.login, isRefreshed: reused.isRefreshed });
    return finish(session, reused.tokens.accessToken, myGeneration);
  };

  const acquire = async (clientId: string, myGeneration: number): Promise<GitHubSession> => {
    let current = store;
    if (current !== null) {
      const loaded = await loadStoredSignIn(current, host, clientId);
      if (loaded.kind === "unavailable") {
        fallBackToMemory(loaded.reason);
      } else if (loaded.kind === "none" && loaded.wasMalformed) {
        notify({ kind: "removed", reason: "malformed" });
      } else if (loaded.kind === "found") {
        const session = await reuseStored(current, loaded.record, myGeneration, true);
        if (session !== null) return session;
      }
    }

    const tokens = await requestDeviceFlowTokens(deviceFlowOptions(options, clientId));
    const session = createSessionFromToken(tokens.accessToken, tokens.expiresAt, options);
    current = store;
    if (current !== null) {
      let user: GitHubUser | null = null;
      try {
        user = await session.client.getAuthenticatedUser();
      } catch {
        // The gate looks the user up again and reports the error; nothing is saved.
      }
      if (user !== null) {
        const failure = await saveStoredSignIn(
          current,
          toRecord(tokens, user, host, clientId, now()),
        );
        if (failure === null) {
          notify({ kind: "saved", login: user.login });
        } else {
          fallBackToMemory(failure);
        }
      }
    }
    return finish(session, tokens.accessToken, myGeneration);
  };

  const finish = (
    session: GitHubSession,
    accessToken: string,
    myGeneration: number,
  ): GitHubSession => {
    const clientId = options.clientId;
    const onUnauthorized = () => {
      if (generation === myGeneration) forget();
      if (clientId !== null && store !== null) {
        void deleteIfStillHolds(clientId, accessToken).then((wasDeleted) => {
          if (wasDeleted) notify({ kind: "removed", reason: "revoked" });
        });
      }
    };
    return createGitHubSession(
      wrapClient(session.client, onUnauthorized, () => generation !== myGeneration),
      session.expiresAt,
    );
  };

  const startSignIn = (clientId: string): Promise<GitHubSession> => {
    const myGeneration = generation;
    const promise = acquire(clientId, myGeneration);
    promise.catch(() => {
      if (generation === myGeneration) forget();
    });
    return promise;
  };

  const provider = async (): Promise<GitHubSession> => {
    const { clientId } = options;
    if (clientId === null) {
      throw missingClientIdError();
    }
    if (pending !== null) {
      const current = pending;
      const session = await current.catch(() => null);
      if (session !== null && pending === current && isFresh(session.expiresAt)) {
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
