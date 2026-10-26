import type { SessionInfo, StoredSignInDto } from "../../../shared/api-types";
import { en } from "../../i18n/en";
import type { Messages } from "../../i18n/types";

/** Two sign-out actions, labelled so it is clear which one touches the OS keychain. */
export function signOutTexts(m: Messages = en): {
  labels: { sessionOnly: string; removeStored: string };
  hints: { sessionOnly: string; removeStored: string };
} {
  return {
    labels: {
      sessionOnly: m.auth.signOut.sessionOnlyLabel,
      removeStored: m.auth.signOut.removeStoredLabel,
    },
    hints: {
      sessionOnly: m.auth.signOut.sessionOnlyHint,
      removeStored: m.auth.signOut.removeStoredHint,
    },
  };
}

/** English texts, kept as constants for callers and tests that do not care about the language. */
export const SIGN_OUT_LABELS = signOutTexts(en).labels;
export const SIGN_OUT_HINTS = signOutTexts(en).hints;

/**
 * One line about the GitHub App: the override in use, or why an invalid override blocks every
 * check. `null` for the built-in PGARD App, which needs no setup and no mention.
 */
export function describeGitHubApp(
  app: SessionInfo["githubApp"],
  m: Messages = en,
): { tone: "info" | "warning"; text: string } | null {
  switch (app.source) {
    case "default":
      return null;
    case "env":
      return {
        tone: "info",
        text: m.auth.githubAppEnv(app.clientId),
      };
    case "invalid":
      return {
        tone: "warning",
        text: m.auth.githubAppInvalid(app.message),
      };
  }
}

/** One line about the GitHub sign-in the server holds. Shows the account login at most. */
export function describeStoredSignIn(
  storedSignIn: StoredSignInDto,
  m: Messages = en,
): string | null {
  switch (storedSignIn.status) {
    case "stored":
      return m.auth.storedSignIn(storedSignIn.login);
    case "none":
      return m.auth.noSignIn;
    case "unavailable":
      return m.auth.keychainUnavailable(storedSignIn.reason);
    case "unknown":
      return null;
  }
}
