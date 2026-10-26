import { sanitizeDisplayText } from "@pgard/http-local";
import {
  resolveKeychainClientId,
  readStoredSignInStatus,
  type CredentialStore,
  type SignInNotice,
} from "@pgard/scan-core";
import type { StoredSignInDto } from "../../shared/api-types.js";
import { resetAuthIfAccountChanged, type SessionState } from "./session-state.js";

const REMOVED_REASONS: Record<Extract<SignInNotice, { kind: "removed" }>["reason"], string> = {
  expired: "had expired",
  revoked: "was rejected by GitHub (revoked or expired)",
  refresh_failed: "could not be refreshed",
  malformed: "could not be read",
};

const login = (value: string): string => sanitizeDisplayText(value, 40);

/** Tracks the account the provider adopted; a different account resets the latest check. */
function adoptAccount(state: SessionState, account: { login: string; userId: number }): void {
  state.sessionAccount = { login: account.login, userId: account.userId };
  resetAuthIfAccountChanged(state, state.sessionAccount);
}

/**
 * Re-reads the keychain entry (no GitHub call) and resets the latest check when it now holds a
 * different account than the one that check ran with, e.g. after `pgard login` switched
 * accounts in another terminal. A missing or unreadable entry changes nothing here.
 */
export async function resetAuthIfStoredAccountChanged(
  state: SessionState,
  store: CredentialStore,
  env: Readonly<Record<string, string | undefined>>,
): Promise<void> {
  if (state.authAccount === null) return;
  const { clientId } = resolveKeychainClientId(env);
  if (clientId === null) return;
  let status: Awaited<ReturnType<typeof readStoredSignInStatus>>;
  try {
    status = await readStoredSignInStatus(store, clientId);
  } catch {
    return;
  }
  if (status.status !== "stored") return;
  resetAuthIfAccountChanged(state, { login: status.login, userId: status.userId });
}

/** Records a provider notice as browser-safe state. Notices never contain a token. */
export function applySignInNotice(state: SessionState, notice: SignInNotice): void {
  switch (notice.kind) {
    case "reused":
      state.storedSignIn = { status: "stored", login: login(notice.login) };
      state.signInNotice = `Using the GitHub sign-in for ${login(notice.login)} saved in the OS keychain${notice.isRefreshed ? " (token refreshed)" : ""}.`;
      adoptAccount(state, notice);
      return;
    case "saved":
      state.storedSignIn = { status: "stored", login: login(notice.login) };
      state.signInNotice = `Saved the GitHub sign-in for ${login(notice.login)} in the OS keychain; the CLI and later dashboard sessions reuse it.`;
      adoptAccount(state, notice);
      return;
    case "removed":
      state.storedSignIn = { status: "none" };
      state.signInNotice = `The saved GitHub sign-in ${REMOVED_REASONS[notice.reason]} and was removed from the OS keychain. Sign in again with the code shown.`;
      return;
    case "memory_only": {
      const reason = sanitizeDisplayText(notice.reason, 200);
      state.storedSignIn = { status: "unavailable", reason };
      state.signInNotice = `The GitHub sign-in is kept in memory until the dashboard stops: ${reason}.`;
      return;
    }
  }
}

/** Reads the keychain entry (no GitHub call) and returns the login at most. */
export async function readStoredSignInDto(
  store: CredentialStore,
  env: Readonly<Record<string, string | undefined>>,
): Promise<StoredSignInDto> {
  // The entry is named by the client id alone; a malformed slug override does not hide it.
  const { clientId } = resolveKeychainClientId(env);
  if (clientId === null) return { status: "unknown" };
  try {
    const status = await readStoredSignInStatus(store, clientId);
    if (status.status === "stored") return { status: "stored", login: login(status.login) };
    if (status.status === "unavailable") {
      return { status: "unavailable", reason: sanitizeDisplayText(status.reason, 200) };
    }
    return { status: "none" };
  } catch {
    return { status: "unavailable", reason: "the OS keychain could not be read" };
  }
}
