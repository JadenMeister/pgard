import type { SessionInfo, StoredSignInDto } from "../../../shared/api-types";

/** Two sign-out actions, labelled so it is clear which one touches the OS keychain. */
export const SIGN_OUT_LABELS = {
  sessionOnly: "End dashboard session (keep keychain sign-in)",
  removeStored: "Sign out and remove from OS keychain",
} as const;

export const SIGN_OUT_HINTS = {
  sessionOnly:
    "Forgets the GitHub session in this dashboard only. The sign-in saved in the OS keychain stays, and the next check reuses it without a code.",
  removeStored:
    "Also deletes the saved sign-in from the OS keychain, for the CLI too. The next check asks for a new device code.",
} as const;

/**
 * One line about the GitHub App: the override in use, or why an invalid override blocks every
 * check. `null` for the built-in PGARD App, which needs no setup and no mention.
 */
export function describeGitHubApp(
  app: SessionInfo["githubApp"],
): { tone: "info" | "warning"; text: string } | null {
  switch (app.source) {
    case "default":
      return null;
    case "env":
      return {
        tone: "info",
        text: `GitHub App: ${app.clientId} from PGARD_GITHUB_APP_CLIENT_ID (override of the built-in PGARD App).`,
      };
    case "invalid":
      return {
        tone: "warning",
        text: `${app.message} Until then GitHub identity is unverifiable and every scan is blocked.`,
      };
  }
}

/** One line about the GitHub sign-in the server holds. Shows the account login at most. */
export function describeStoredSignIn(storedSignIn: StoredSignInDto): string | null {
  switch (storedSignIn.status) {
    case "stored":
      return `GitHub sign-in: ${storedSignIn.login}, saved in the OS keychain and reused for each check. The token stays on this computer and is never sent to the browser.`;
    case "none":
      return "GitHub sign-in: none saved. The next check asks for a device code and saves the sign-in in the OS keychain.";
    case "unavailable":
      return `GitHub sign-in: the OS keychain is unavailable (${storedSignIn.reason}), so the sign-in is kept in memory until the dashboard stops.`;
    case "unknown":
      return null;
  }
}
