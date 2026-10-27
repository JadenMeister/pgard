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
import { cliText, type CliText } from "../ui/i18n/cli-text.js";
import { localizeKeychainReason } from "../ui/i18n/command-text.js";
import { safeText } from "../ui/formatters/style.js";

/**
 * Formats the device-flow instructions. The user code is a short-lived public code the user
 * types on github.com; the access token itself is never shown.
 */
export function formatDeviceCode(code: DeviceUserCode, t: CliText = cliText("en")): string {
  const minutes = Math.max(1, Math.round(code.expiresIn / 60));
  return t.commands.signIn.deviceCode(
    safeText(code.verificationUri, 200),
    safeText(code.userCode, 40),
    minutes,
  );
}

/** One line per sign-in event for stderr. Never contains a token. */
export function formatSignInNotice(notice: SignInNotice, t: CliText = cliText("en")): string {
  const text = t.commands.signIn;
  switch (notice.kind) {
    case "reused":
      return text.reused(safeText(notice.login, 40), notice.isRefreshed);
    case "saved":
      return text.saved(safeText(notice.login, 40));
    case "removed":
      return text.removedNotice(text.removedReason[notice.reason]);
    case "memory_only":
      return text.memoryOnly(localizeKeychainReason(safeText(notice.reason, 200), text));
  }
}

/** Said once per command when the env override (not the built-in PGARD App) is in use. */
export function formatGitHubAppOverride(clientId: string, t: CliText = cliText("en")): string {
  return t.commands.signIn.appOverride(clientId, GITHUB_APP_CLIENT_ID_ENV);
}

/**
 * Prints the device-flow instructions (always) and, in a terminal, offers to open the
 * verification page after Enter. Returns at once so polling starts right away; the offer ends
 * when the sign-in does (`stopBrowserOffers`). The code is typed by the user; it is never passed
 * to the browser.
 */
export function showDeviceCode(context: CommandContext, code: DeviceUserCode): void {
  err(context, context.errStyle.bold(formatDeviceCode(code, cliText(context.ruleLocale))));
  offerBrowserOpen(context, code.verificationUri);
}

/**
 * A person can answer a device code only when stdin and stderr (where the code is shown) are
 * terminals. Otherwise a sign-in would wait for nobody: the gate blocks with "not signed in".
 */
export function canSignInInteractively(context: CommandContext): boolean {
  return context.io.stdin.isTTY === true && context.io.stderr.isTTY === true;
}

/**
 * One provider per CLI process. It reuses the sign-in saved in the OS keychain (or saves a new
 * one); without a keychain the token stays in memory and is dropped on exit.
 */
export function createSessionProvider(context: CommandContext): GitHubSessionProvider {
  const app = resolveGitHubAppClientId(context.io.env);
  if (app.source === "env")
    err(
      context,
      context.errStyle.dim(formatGitHubAppOverride(app.clientId, cliText(context.ruleLocale))),
    );
  // Once per command: an overridden slug with the built-in client id can never approve PGARD.
  const mixed = mixedAppOverrideWarning(context.io.env);
  if (mixed !== null) err(context, context.errStyle.yellow(mixed));
  const provider = context.deps.createSessionProvider({
    env: context.io.env,
    onUserCode: (code) => showDeviceCode(context, code),
    onNotice: (notice) => {
      const text = formatSignInNotice(notice, cliText(context.ruleLocale));
      err(
        context,
        notice.kind === "reused" ? context.errStyle.dim(text) : context.errStyle.yellow(text),
      );
    },
    canSignInInteractively: canSignInInteractively(context),
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
