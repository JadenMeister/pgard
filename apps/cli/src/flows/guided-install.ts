import {
  guidedInstallRemedy,
  resolveGitHubAppClientId,
  type AuthorizationDependencies,
  type AuthorizationOutcome,
  type GitHubSessionProvider,
} from "@pgard/scan-core";
import { err, type CommandContext } from "../context.js";
import { safeText } from "../ui/formatters/style.js";
import { openInBrowser } from "./browser.js";

/** How often owner approval is checked again while the user installs the App. */
export const INSTALL_POLL_INTERVAL_MS = 5_000;
/** How long PGARD waits for the installation before blocking. */
export const INSTALL_WAIT_LIMIT_MS = 10 * 60_000;

export const WAITING_FOR_INSTALL_MESSAGE =
  "Waiting for the PGARD GitHub App to be installed... (Ctrl+C to cancel)";

/**
 * - `not_offered`: no guided install applies; the caller reports the outcome as before.
 * - `blocked`: shown the reason/link, but nothing to wait for (or the wait timed out).
 * - `cancelled`: the user cancelled the wait (the caller exits 130).
 * - `reauthorize`: owner approval changed; the caller MUST run the full authorization again
 *   (a fresh `verifyProject` or `runScan`) before doing anything else.
 */
export type GuidedInstallResult = "not_offered" | "blocked" | "cancelled" | "reauthorize";

/** Authorization deps for this command: the session provider plus the configured App slug. */
export function authorizationDepsFor(
  context: CommandContext,
  getGitHubSession: GitHubSessionProvider,
): AuthorizationDependencies {
  return { getGitHubSession, appSlug: resolveGitHubAppClientId(context.io.env).slug };
}

/** "Ask an owner" line for a user who cannot install the App; the link is safe to share. */
export function formatAskOwner(accountLogin: string, url: string): string {
  return `Ask an owner of ${safeText(accountLogin, 100)} to install the PGARD GitHub App: ${url}`;
}

function formatInstallSteps(accountLogin: string, repo: string | null, url: string): string {
  const target = repo === null ? "this repository" : safeText(repo, 120);
  return [
    `Owner approval: install the PGARD GitHub App on ${safeText(accountLogin, 100)} to approve PGARD for ${target}.`,
    `  1. Open ${url}`,
    `  2. Choose "Only select repositories" (${target}) or "All repositories", then click Install.`,
    "Installing the App is the owner approval; PGARD cannot install it for you.",
  ].join("\n");
}

/**
 * Called after a blocked authorization. When owner approval failed only because the PGARD GitHub
 * App is not installed for this repository:
 *
 * - no install link (client id override without a slug): prints why;
 * - the signed-in user cannot install it (not the personal owner / not an organization owner):
 *   prints "Ask an owner of <account> ..." with the link; no browser, no waiting;
 * - the user can install it: prints the steps, opens the install page (when allowed) and, on a
 *   terminal, re-checks owner approval every 5 s for up to 10 minutes.
 *
 * Detecting the installation is never a pass by itself: `reauthorize` tells the caller to run the
 * complete authorization again from scratch. Nothing is cached and no check is skipped.
 */
export async function offerGuidedInstall(
  context: CommandContext,
  outcome: AuthorizationOutcome,
  projectRoot: string,
  authorization: AuthorizationDependencies,
): Promise<GuidedInstallResult> {
  const remedy = guidedInstallRemedy(outcome);
  if (remedy === null) return "not_offered";
  const { errStyle } = context;
  if (remedy.url === null) {
    err(context, errStyle.yellow(remedy.unavailableReason ?? "No install link is available."));
    return "blocked";
  }
  if (!remedy.canApprove) {
    err(context, errStyle.yellow(formatAskOwner(remedy.account.login, remedy.url)));
    return "blocked";
  }
  err(context, errStyle.bold(formatInstallSteps(remedy.account.login, outcome.repo, remedy.url)));
  if (context.io.stdout.isTTY !== true) {
    err(
      context,
      errStyle.dim(
        "Not a terminal, so PGARD does not wait for the installation. Run the command again after installing.",
      ),
    );
    return "blocked";
  }
  await openInBrowser(context, remedy.url);
  err(context, errStyle.dim(WAITING_FOR_INSTALL_MESSAGE));

  const deadline = context.deps.now() + INSTALL_WAIT_LIMIT_MS;
  for (;;) {
    try {
      await context.deps.sleep(INSTALL_POLL_INTERVAL_MS, context.signal);
    } catch {
      // Only an abort ends the sleep early.
    }
    if (context.signal.aborted) {
      err(context, errStyle.yellow("Stopped waiting for the PGARD GitHub App installation."));
      return "cancelled";
    }
    let recheck;
    try {
      recheck = await context.deps.recheckOwnerApproval(projectRoot, authorization);
    } catch {
      recheck = null;
    }
    if (context.signal.aborted) {
      err(context, errStyle.yellow("Stopped waiting for the PGARD GitHub App installation."));
      return "cancelled";
    }
    if (recheck === null) {
      err(context, errStyle.red("Owner approval could not be checked again."));
      return "blocked";
    }
    if (recheck.status === "passed") {
      err(
        context,
        errStyle.green(
          "The PGARD GitHub App installation was found. Running the full authorization again...",
        ),
      );
      return "reauthorize";
    }
    if (recheck.remedy === null) {
      // Owner approval now fails for another reason (e.g. the installation exists but the
      // membership cannot be read). The full authorization reports the current reasons.
      err(
        context,
        errStyle.yellow("Owner approval changed. Running the full authorization again..."),
      );
      return "reauthorize";
    }
    if (context.deps.now() >= deadline) {
      err(
        context,
        errStyle.red(
          `Stopped waiting after ${INSTALL_WAIT_LIMIT_MS / 60_000} minutes. ${safeText(recheck.reason, 300)}`,
        ),
      );
      return "blocked";
    }
  }
}
