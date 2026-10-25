import { sanitizeDisplayText } from "@pgard/http-local";
import {
  resolveGitHubAppClientId,
  readStoredSignInStatus,
  type CredentialStore,
  type SignInNotice,
} from "@pgard/scan-core";
import type { StoredSignInDto } from "../../shared/api-types.js";
import type { SessionState } from "./session-state.js";

const REMOVED_REASONS: Record<Extract<SignInNotice, { kind: "removed" }>["reason"], string> = {
  expired: "had expired",
  revoked: "was rejected by GitHub (revoked or expired)",
  refresh_failed: "could not be refreshed",
  malformed: "could not be read",
};

const login = (value: string): string => sanitizeDisplayText(value, 40);

/** Records a provider notice as browser-safe state. Notices never contain a token. */
export function applySignInNotice(state: SessionState, notice: SignInNotice): void {
  switch (notice.kind) {
    case "reused":
      state.storedSignIn = { status: "stored", login: login(notice.login) };
      state.signInNotice = `Using the GitHub sign-in for ${login(notice.login)} saved in the OS keychain${notice.isRefreshed ? " (token refreshed)" : ""}.`;
      return;
    case "saved":
      state.storedSignIn = { status: "stored", login: login(notice.login) };
      state.signInNotice = `Saved the GitHub sign-in for ${login(notice.login)} in the OS keychain; the CLI and later dashboard sessions reuse it.`;
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
  const { clientId } = resolveGitHubAppClientId(env);
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
