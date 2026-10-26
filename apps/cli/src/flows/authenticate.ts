import {
  GITHUB_APP_CLIENT_ID_ENV,
  mixedAppOverrideWarning,
  resolveGitHubAppClientId,
  type DeviceUserCode,
  type GitHubSessionProvider,
  type SignInNotice,
} from "@pgard/scan-core";
import { err, type CommandContext } from "../context.js";
import { offerBrowserOpen, stopBrowserOffers } from "./browser.js";
import { safeText } from "../ui/formatters/style.js";

/**
 * Formats the device-flow instructions. The user code is a short-lived public code the user
 * types on github.com; the access token itself is never shown.
 */
export function formatDeviceCode(code: DeviceUserCode): string {
  const minutes = Math.max(1, Math.round(code.expiresIn / 60));
  return [
    "GitHub sign-in is required to verify your identity and repository access.",
    `  1. Open ${safeText(code.verificationUri, 200)}`,
    `  2. Enter the code ${safeText(code.userCode, 40)} (expires in about ${minutes} min)`,
    "Waiting for approval... (Ctrl+C to cancel)",
  ].join("\n");
}

const REMOVED_REASONS: Record<Extract<SignInNotice, { kind: "removed" }>["reason"], string> = {
  expired: "has expired",
  revoked: "was rejected by GitHub (revoked or expired)",
  refresh_failed: "could not be refreshed",
  malformed: "could not be read",
};

/** One line per sign-in event for stderr. Never contains a token. */
export function formatSignInNotice(notice: SignInNotice): string {
  switch (notice.kind) {
    case "reused":
      return `Using the GitHub sign-in for ${safeText(notice.login, 40)} saved in the OS keychain${notice.isRefreshed ? " (token refreshed)" : ""}.`;
    case "saved":
      return `Saved the GitHub sign-in for ${safeText(notice.login, 40)} in the OS keychain; later runs reuse it. \`pgard logout\` removes it.`;
    case "removed":
      return `The saved GitHub sign-in ${REMOVED_REASONS[notice.reason]} and was removed from the OS keychain. Sign in again below.`;
    case "memory_only":
      return `The GitHub sign-in is kept in memory for this run only: ${safeText(notice.reason, 200)}.`;
  }
}

/** Said once per command when the env override (not the built-in PGARD App) is in use. */
export function formatGitHubAppOverride(clientId: string): string {
  return `Using GitHub App ${clientId} from ${GITHUB_APP_CLIENT_ID_ENV} (override).`;
}

/**
 * Prints the device-flow instructions (always) and, in a terminal, offers to open the
 * verification page after Enter. Returns at once so polling starts right away; the offer ends
 * when the sign-in does (`stopBrowserOffers`). The code is typed by the user; it is never passed
 * to the browser.
 */
export function showDeviceCode(context: CommandContext, code: DeviceUserCode): void {
  err(context, context.errStyle.bold(formatDeviceCode(code)));
  offerBrowserOpen(context, code.verificationUri);
}

/**
 * One provider per CLI process. It reuses the sign-in saved in the OS keychain (or saves a new
 * one); without a keychain the token stays in memory and is dropped on exit.
 */
export function createSessionProvider(context: CommandContext): GitHubSessionProvider {
  const app = resolveGitHubAppClientId(context.io.env);
  if (app.source === "env")
    err(context, context.errStyle.dim(formatGitHubAppOverride(app.clientId)));
  // Once per command: an overridden slug with the built-in client id can never approve PGARD.
  const mixed = mixedAppOverrideWarning(context.io.env);
  if (mixed !== null) err(context, context.errStyle.yellow(mixed));
  const provider = context.deps.createSessionProvider({
    env: context.io.env,
    onUserCode: (code) => showDeviceCode(context, code),
    onNotice: (notice) => {
      const text = formatSignInNotice(notice);
      err(
        context,
        notice.kind === "reused" ? context.errStyle.dim(text) : context.errStyle.yellow(text),
      );
    },
    signal: context.signal,
  });
  // The sign-in call ending (approved, denied, expired, cancelled) ends the Enter prompt.
  // `existing()` is a background re-check and must not touch it.
  return Object.assign(
    async () => {
      try {
        return await provider();
      } finally {
        stopBrowserOffers(context);
      }
    },
    {
      invalidate: () => provider.invalidate(),
      signOut: () => provider.signOut(),
      existing: () => provider.existing(),
    },
  );
}
