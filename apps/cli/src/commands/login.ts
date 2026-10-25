import {
  GITHUB_APP_AUTHORIZATIONS_URL,
  isGitHubAuthError,
  resolveGitHubAppClientId,
  readStoredSignInStatus,
  removeStoredSignIn,
} from "@pgard/scan-core";
import { err, out, suspendKeys, throwIfCancelled, type CommandContext } from "../context.js";
import { EXIT_CODES, type ExitCode } from "../exit-codes.js";
import { formatDeviceCode, formatGitHubAppOverride } from "../flows/authenticate.js";
import { safeText } from "../ui/formatters/style.js";

export const REVOKE_HINT = `PGARD cannot revoke the token at GitHub (that needs the App's client secret, which PGARD does not have). It stays valid until it expires; to revoke it now, open ${GITHUB_APP_AUTHORIZATIONS_URL} and revoke the PGARD app.`;

/**
 * `pgard login`: runs the device flow and saves the sign-in in the OS keychain so later scans
 * and the dashboard reuse it. It always signs in again, which also switches accounts. Only the
 * sign-in is reused: every scan still runs all five authorization checks against GitHub.
 */
export async function runLogin(context: CommandContext): Promise<ExitCode> {
  const { deps, errStyle } = context;
  const app = resolveGitHubAppClientId(context.io.env);
  if (app.source === "invalid") {
    err(context, errStyle.red(app.message));
    return EXIT_CODES.blocked;
  }
  const { clientId } = app;
  if (app.source === "env") out(context, formatGitHubAppOverride(clientId));
  // Check the keychain before asking the user to type a code that could not be saved.
  const status = await readStoredSignInStatus(deps.credentialStore, clientId);
  if (status.status === "unavailable") {
    err(
      context,
      errStyle.yellow(
        `No OS keychain is available: ${safeText(status.reason, 200)}. Nothing was saved; scans and the dashboard ask for a device code on each run.`,
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
      onUserCode: (code) => err(context, errStyle.bold(formatDeviceCode(code))),
      signal: context.signal,
    });
  } catch (error) {
    throwIfCancelled(context);
    // GitHubAuthError messages are fixed text without tokens; anything else stays generic.
    const reason = isGitHubAuthError(error) ? safeText(error.message, 200) : "unexpected error";
    err(context, errStyle.red(`GitHub sign-in failed: ${reason}`));
    return EXIT_CODES.blocked;
  }
  const login = safeText(result.login, 40);
  if (result.savedError !== null) {
    err(
      context,
      errStyle.yellow(
        `Signed in to GitHub as ${login}, but the OS keychain did not save it: ${safeText(result.savedError, 200)}. Nothing was saved.`,
      ),
    );
    return EXIT_CODES.partial;
  }
  out(context, context.style.green(`Signed in to GitHub as ${login}.`));
  out(
    context,
    "The sign-in is saved in the OS keychain and reused by `pgard scan`, `pgard project verify` and `pgard dashboard`. Owner approval, current access and a merged contribution are still checked on every scan. `pgard logout` removes it.",
  );
  return EXIT_CODES.ok;
}

/** `pgard logout`: deletes the stored sign-in from the OS keychain. */
export async function runLogout(context: CommandContext): Promise<ExitCode> {
  const { deps, errStyle } = context;
  const app = resolveGitHubAppClientId(context.io.env);
  // Never fall back to the built-in App's entry: the operator asked for another App.
  if (app.source === "invalid") {
    err(context, errStyle.red(app.message));
    return EXIT_CODES.blocked;
  }
  const result = await removeStoredSignIn(deps.credentialStore, app.clientId);
  switch (result.status) {
    case "unavailable":
      err(
        context,
        errStyle.yellow(
          `No OS keychain is available: ${safeText(result.reason, 200)}. Nothing was removed.`,
        ),
      );
      return EXIT_CODES.partial;
    case "none":
      out(context, "No GitHub sign-in is saved in the OS keychain for this GitHub App.");
      return EXIT_CODES.ok;
    case "removed":
      out(
        context,
        result.login === null
          ? "Removed the saved GitHub sign-in from the OS keychain."
          : `Removed the GitHub sign-in for ${safeText(result.login, 40)} from the OS keychain.`,
      );
      out(context, context.style.dim(REVOKE_HINT));
      return EXIT_CODES.ok;
  }
}
