import type { AuthorizationSummary } from "@pgard/findings";
import {
  GITHUB_APP_CLIENT_ID_ENV,
  readGitHubAppClientId,
  type DeviceUserCode,
  type GitHubSessionProvider,
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

/** One provider per CLI process: the token stays in memory and is dropped on exit. */
export function createSessionProvider(context: CommandContext): GitHubSessionProvider {
  return context.deps.createSessionProvider({
    env: context.io.env,
    onUserCode: (code) => err(context, context.errStyle.bold(formatDeviceCode(code))),
    signal: context.signal,
  });
}

/**
 * When the gate was blocked and no GitHub App client id is configured, say so explicitly:
 * without a registered PGARD GitHub App, identity can never be verified.
 */
export function printMissingClientIdHint(
  context: CommandContext,
  summary: AuthorizationSummary,
): void {
  if (summary.decision !== "blocked" || readGitHubAppClientId(context.io.env) !== null) return;
  err(
    context,
    context.errStyle.yellow(
      `Hint: ${GITHUB_APP_CLIENT_ID_ENV} is not set. A registered PGARD GitHub App is required to verify your GitHub identity; until it is configured every scan is blocked.`,
    ),
  );
}
