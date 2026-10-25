import {
  type DeviceUserCode,
  type GitHubSessionProvider,
  type SignInNotice,
} from "@pgard/scan-core";
import { err, type CommandContext } from "../context.js";
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

/**
 * One provider per CLI process. It reuses the sign-in saved in the OS keychain (or saves a new
 * one); without a keychain the token stays in memory and is dropped on exit.
 */
export function createSessionProvider(context: CommandContext): GitHubSessionProvider {
  return context.deps.createSessionProvider({
    env: context.io.env,
    onUserCode: (code) => err(context, context.errStyle.bold(formatDeviceCode(code))),
    onNotice: (notice) => {
      const text = formatSignInNotice(notice);
      err(
        context,
        notice.kind === "reused" ? context.errStyle.dim(text) : context.errStyle.yellow(text),
      );
    },
    signal: context.signal,
  });
}
