import {
  isCredentialStoreError,
  type CredentialKey,
  type CredentialStore,
} from "./credential-store.js";
import { GITHUB_OAUTH_BASE_URL, type UserTokenSet } from "./device-flow.js";
import { asInteger, asRecord, asString } from "./fetch.js";

/** Keychain service name for every PGARD entry. */
export const CREDENTIAL_SERVICE = "pgard";
/** Where a user revokes the PGARD App's access; revoking via the API needs a client secret. */
export const GITHUB_APP_AUTHORIZATIONS_URL = "https://github.com/settings/apps/authorizations";

const RECORD_VERSION = 1;

/**
 * What PGARD keeps in the keychain entry. Internal to this package: it holds tokens, so it is
 * never returned to apps, logged or serialized anywhere but into the keychain itself.
 */
export interface StoredSignInRecord extends UserTokenSet {
  host: string;
  clientId: string;
  login: string;
  userId: number;
  savedAt: number;
}

/** Secret-free description of the stored sign-in, for `doctor`, `logout` and the dashboard. */
export type StoredSignInStatus =
  | { status: "stored"; login: string; expiresAt: number | null; refreshExpiresAt: number | null }
  | { status: "none" }
  | { status: "unavailable"; reason: string };

export function githubHostOf(oauthBaseUrl: string = GITHUB_OAUTH_BASE_URL): string {
  return new URL(oauthBaseUrl).host;
}

/**
 * One entry per GitHub host and App client id, so a token issued to another App (or another
 * GitHub host) is never reused after the client id changes. The built-in PGARD App and an env
 * override with the same id share one entry; a different override id gets its own.
 */
export function signInKey(host: string, clientId: string): CredentialKey {
  return { service: CREDENTIAL_SERVICE, account: `github:${host}:${clientId}` };
}

function parseRecord(text: string, host: string, clientId: string): StoredSignInRecord | null {
  let value: Record<string, unknown> | null;
  try {
    value = asRecord(JSON.parse(text));
  } catch {
    return null;
  }
  if (value === null || value.version !== RECORD_VERSION) return null;
  const accessToken = asString(value.accessToken);
  const login = asString(value.login);
  const userId = asInteger(value.userId);
  // The key already contains host and client id; checking the payload too guards against an
  // entry written under the wrong key by another tool.
  if (
    !accessToken ||
    !login ||
    userId === null ||
    value.host !== host ||
    value.clientId !== clientId
  ) {
    return null;
  }
  const refreshToken = asString(value.refreshToken);
  return {
    host,
    clientId,
    accessToken,
    expiresAt: asInteger(value.expiresAt),
    refreshToken: refreshToken || null,
    refreshTokenExpiresAt: asInteger(value.refreshTokenExpiresAt),
    login,
    userId,
    savedAt: asInteger(value.savedAt) ?? 0,
  };
}

export type LoadResult =
  | { kind: "found"; record: StoredSignInRecord }
  /** No entry, or a malformed one (deleted unless `deleteMalformed` is false). */
  | { kind: "none"; wasMalformed: boolean }
  | { kind: "unavailable"; reason: string };

function unavailableReason(error: unknown): string {
  return isCredentialStoreError(error) ? error.message : "the OS keychain could not be used";
}

export interface LoadStoredSignInOptions {
  /**
   * Delete an entry that cannot be parsed (default `true`). Read-only status paths (`doctor`,
   * the dashboard's session status, the `login` pre-check) pass `false` so that looking at the
   * keychain never changes it.
   */
  deleteMalformed?: boolean;
}

export async function loadStoredSignIn(
  store: CredentialStore,
  host: string,
  clientId: string,
  options: LoadStoredSignInOptions = {},
): Promise<LoadResult> {
  const key = signInKey(host, clientId);
  let text: string | null;
  try {
    text = await store.get(key);
  } catch (error) {
    return { kind: "unavailable", reason: unavailableReason(error) };
  }
  if (text === null) return { kind: "none", wasMalformed: false };
  const record = parseRecord(text, host, clientId);
  if (record === null) {
    if (options.deleteMalformed !== false) await store.delete(key).catch(() => false);
    return { kind: "none", wasMalformed: true };
  }
  return { kind: "found", record };
}

/** Writes the entry; resolves with a reason when the keychain refused it, otherwise `null`. */
export async function saveStoredSignIn(
  store: CredentialStore,
  record: StoredSignInRecord,
): Promise<string | null> {
  const payload = JSON.stringify({
    version: RECORD_VERSION,
    host: record.host,
    clientId: record.clientId,
    accessToken: record.accessToken,
    expiresAt: record.expiresAt,
    refreshToken: record.refreshToken,
    refreshTokenExpiresAt: record.refreshTokenExpiresAt,
    login: record.login,
    userId: record.userId,
    savedAt: record.savedAt,
  });
  try {
    await store.set(signInKey(record.host, record.clientId), payload);
    return null;
  } catch (error) {
    return unavailableReason(error);
  }
}

export type RemoveStoredSignInResult =
  | { status: "removed"; login: string | null }
  | { status: "none" }
  | { status: "unavailable"; reason: string };

/**
 * Deletes the stored sign-in for this host and client id. The token is not revoked at GitHub:
 * GitHub's revoke endpoint needs the App's client secret, which PGARD does not have.
 */
export async function removeStoredSignIn(
  store: CredentialStore,
  clientId: string,
  host: string = githubHostOf(),
): Promise<RemoveStoredSignInResult> {
  const loaded = await loadStoredSignIn(store, host, clientId);
  if (loaded.kind === "unavailable") return { status: "unavailable", reason: loaded.reason };
  try {
    const wasDeleted = await store.delete(signInKey(host, clientId));
    if (loaded.kind === "found") return { status: "removed", login: loaded.record.login };
    return wasDeleted ? { status: "removed", login: null } : { status: "none" };
  } catch (error) {
    return { status: "unavailable", reason: unavailableReason(error) };
  }
}

/**
 * Reads the stored sign-in without contacting GitHub and returns only secret-free fields. It is
 * read-only: a malformed entry is reported as `none` but left in place.
 */
export async function readStoredSignInStatus(
  store: CredentialStore,
  clientId: string,
  host: string = githubHostOf(),
): Promise<StoredSignInStatus> {
  const loaded = await loadStoredSignIn(store, host, clientId, { deleteMalformed: false });
  if (loaded.kind === "unavailable") return { status: "unavailable", reason: loaded.reason };
  if (loaded.kind === "none") return { status: "none" };
  const { login, expiresAt, refreshToken, refreshTokenExpiresAt } = loaded.record;
  return {
    status: "stored",
    login,
    expiresAt,
    refreshExpiresAt: refreshToken === null ? null : refreshTokenExpiresAt,
  };
}
