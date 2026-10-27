import {
  GITHUB_APP_AUTHORIZATIONS_URL,
  isGitHubAuthError,
  resolveGitHubAppClientId,
  resolveKeychainClientId,
  readStoredSignInStatus,
  removeStoredSignIn,
} from "@pgard/scan-core";
import { err, out, suspendKeys, throwIfCancelled, type CommandContext } from "../context.js";
import { EXIT_CODES, type ExitCode } from "../exit-codes.js";
import {
  canSignInInteractively,
  formatGitHubAppOverride,
  showDeviceCode,
} from "../flows/authenticate.js";
import { stopBrowserOffers } from "../flows/browser.js";
import { safeText } from "../ui/formatters/style.js";
import { cliText } from "../ui/i18n/cli-text.js";
import { localizeKeychainReason } from "../ui/i18n/command-text.js";

/**
 * `pgard login`: runs the device flow and saves the sign-in in the OS keychain so later scans
 * and the dashboard reuse it. It always signs in again, which also switches accounts. Only the
 * sign-in is reused: every scan still runs all five authorization checks against GitHub.
 */
export async function runLogin(context: CommandContext): Promise<ExitCode> {
  const { deps, errStyle } = context;
  const text = cliText(context.ruleLocale).commands.signIn;
  // Nobody could type the code: refuse before anything is requested (a usage error, exit 2).
  if (!canSignInInteractively(context)) {
    err(context, errStyle.red(text.loginNeedsTerminal));
    return EXIT_CODES.usage;
  }
  const app = resolveGitHubAppClientId(context.io.env);
  if (app.source === "invalid") {
    err(context, errStyle.red(app.message));
    return EXIT_CODES.blocked;
  }
  const { clientId } = app;
  if (app.source === "env")
    out(context, formatGitHubAppOverride(clientId, cliText(context.ruleLocale)));
  // Check the keychain before asking the user to type a code that could not be saved.
  const status = await readStoredSignInStatus(deps.credentialStore, clientId);
  if (status.status === "unavailable") {
    err(
      context,
      errStyle.yellow(
        text.keychainUnavailableOnLogin(localizeKeychainReason(safeText(status.reason, 200), text)),
      ),
    );
    return EXIT_CODES.partial;
  }
  suspendKeys(context);
  let result: Awaited<ReturnType<typeof deps.signInAndStore>>;
  try {
    result = await deps.signInAndStore({
      clientId,
      credentialStore: deps.credentialStore,
      onUserCode: (code) => showDeviceCode(context, code),
      signal: context.signal,
    });
  } catch (error) {
    stopBrowserOffers(context);
    throwIfCancelled(context);
    // GitHubAuthError messages are fixed text without tokens; anything else stays generic.
    const reason = isGitHubAuthError(error) ? safeText(error.message, 200) : text.unexpectedError;
    err(context, errStyle.red(text.failed(reason)));
    return EXIT_CODES.blocked;
  }
  stopBrowserOffers(context);
  const login = safeText(result.login, 40);
  if (result.savedError !== null) {
    err(
      context,
      errStyle.yellow(
        text.signedInNotSaved(
          login,
          localizeKeychainReason(safeText(result.savedError, 200), text),
        ),
      ),
    );
    return EXIT_CODES.partial;
  }
  out(context, context.style.green(text.signedIn(login)));
  out(context, text.signedInHint);
  return EXIT_CODES.ok;
}

/** `pgard logout`: deletes the stored sign-in from the OS keychain. */
export async function runLogout(context: CommandContext): Promise<ExitCode> {
  const { deps, errStyle } = context;
  const text = cliText(context.ruleLocale).commands.signIn;
  // Only the client id names the entry, so a malformed slug override does not block removal.
  const app = resolveKeychainClientId(context.io.env);
  // Never fall back to the built-in App's entry: the operator asked for another App.
  if (app.clientId === null) {
    err(context, errStyle.red(app.message));
    return EXIT_CODES.blocked;
  }
  const result = await removeStoredSignIn(deps.credentialStore, app.clientId);
  switch (result.status) {
    case "unavailable":
      err(
        context,
        errStyle.yellow(
          text.keychainUnavailableOnLogout(
            localizeKeychainReason(safeText(result.reason, 200), text),
          ),
        ),
      );
      return EXIT_CODES.partial;
    case "none":
      out(context, text.noneSaved);
      return EXIT_CODES.ok;
    case "removed":
      out(
        context,
        result.login === null ? text.removedAnonymous : text.removed(safeText(result.login, 40)),
      );
      out(context, context.style.dim(text.revokeHint(GITHUB_APP_AUTHORIZATIONS_URL)));
      return EXIT_CODES.ok;
  }
}
