import {
  guidedInstallRemedy,
  resolveGitHubAppClientId,
  type AuthorizationDependencies,
  type AuthorizationOutcome,
  type GitHubSessionProvider,
} from "@pgard/scan-core";
import { err, type CommandContext } from "../context.js";
import { safeText } from "../ui/formatters/style.js";
import { offerBrowserOpen } from "./browser.js";

/** How often owner approval is checked again while the user installs the App. */
export const INSTALL_POLL_INTERVAL_MS = 5_000;
/** How long PGARD waits for the installation before blocking. */
export const INSTALL_WAIT_LIMIT_MS = 10 * 60_000;

export const WAITING_FOR_INSTALL_MESSAGE =
  "Waiting for the PGARD GitHub App to be installed... (press Ctrl+C twice to cancel)";

/** The waiting line: for a repository to be added to an existing installation, or an install. */
export function waitingMessage(missing: string, repo: string | null): string {
  if (missing !== "repository_access") return WAITING_FOR_INSTALL_MESSAGE;
  const target = repo === null ? "this repository" : safeText(repo, 120);
  return `Waiting for ${target} to be added to the PGARD GitHub App's repository access... (press Ctrl+C twice to cancel)`;
}

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

/**
 * Said when GitHub would not show the organization membership (expected before the App is
 * installed there): an owner installs it on the install page, anyone else asks an owner. It names
 * "the install page" plus the link, since with `--no-browser` (or in the dashboard) nothing opened.
 */
export function formatOwnerOrAsk(accountLogin: string, url: string): string {
  const account = safeText(accountLogin, 100);
  return `If you are an owner of ${account}, install the App on the install page; otherwise ask an owner to install it there: ${url}`;
}

type MissingKind = "installation" | "repository" | "access" | "repository_access";

/** "Ask an owner" line when the repository must be added to an existing installation. */
export function formatAskOwnerToAddRepository(
  accountLogin: string,
  repo: string | null,
  url: string,
): string {
  const target = repo === null ? "this repository" : safeText(repo, 120);
  return `Ask an owner of ${safeText(accountLogin, 100)} to add ${target} to the PGARD GitHub App's repository access: ${url}`;
}

function formatInstallSteps(
  accountLogin: string,
  repo: string | null,
  url: string,
  canApprove: "yes" | "unknown",
  missing: MissingKind = "installation",
): string {
  const target = repo === null ? "this repository" : safeText(repo, 120);
  const account = safeText(accountLogin, 100);
  if (missing === "repository_access") {
    return [
      `GitHub shows no access to ${target}. The PGARD GitHub App is already installed on ${account}, but its repository access does not include this repository (or your account has no access to it).`,
      canApprove === "yes"
        ? `Owner approval: add ${target} to the PGARD GitHub App's repository access.`
        : `If you are an owner of ${account}, add ${target} to the PGARD GitHub App's repository access on its settings page; otherwise ask an owner to do it there: ${url}`,
      `  1. Open ${url}`,
      `  2. Under "Repository access", choose "Only select repositories", add ${target}, then click Save.`,
      "Changing the App's repository access is the owner approval; PGARD cannot change it for you.",
    ].join("\n");
  }
  return [
    ...(missing === "access"
      ? [
          `GitHub shows no access to ${target}. If it is private, the PGARD GitHub App must be installed for it (PGARD cannot tell this from missing account access).`,
        ]
      : []),
    canApprove === "yes"
      ? `Owner approval: install the PGARD GitHub App on ${account} to approve PGARD for ${target}.`
      : formatOwnerOrAsk(accountLogin, url),
    `  1. Open ${url}`,
    missing === "access"
      ? `  2. The page pre-selects "All repositories". To limit PGARD to this repository, choose "Only select repositories" and pick ${target}, then click Install.`
      : `  2. Choose "Only select repositories" (${target}) or "All repositories", then click Install.`,
    "Installing the App is the owner approval; PGARD cannot install it for you.",
  ].join("\n");
}

/**
 * Called after a blocked authorization. When owner approval failed only because the PGARD GitHub
 * App is not installed for this repository:
 *
 * - no install link (client id override without a slug): prints why;
 * - GitHub shows the signed-in user cannot install it (not the personal owner, or a non-owner /
 *   pending organization membership): prints "Ask an owner of <account> ..." with the link; no
 *   browser, no waiting;
 * - the user can install it, or the organization membership could not be read yet: prints the
 *   steps, opens the install page (when allowed) and, on a terminal, re-checks owner approval
 *   every 5 s for up to 10 minutes. The re-check uses only the existing sign-in
 *   (`getGitHubSession.existing()`), never a new device flow; without one it ends the wait and the
 *   caller's full authorization signs in as usual.
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
  if (remedy.canApprove === "no") {
    err(
      context,
      errStyle.yellow(
        remedy.missing === "repository_access"
          ? formatAskOwnerToAddRepository(remedy.account.login, outcome.repo, remedy.url)
          : formatAskOwner(remedy.account.login, remedy.url),
      ),
    );
    return "blocked";
  }
  // `unknown` (the organization membership could not be read yet) is guided like `yes`: only a
  // real owner can complete the install, and the full authorization runs again afterwards.
  err(
    context,
    errStyle.bold(
      formatInstallSteps(
        remedy.account.login,
        outcome.repo,
        remedy.url,
        remedy.canApprove,
        remedy.missing,
      ),
    ),
  );
  if (context.io.stdout.isTTY !== true) {
    err(
      context,
      errStyle.dim(
        remedy.missing === "repository_access"
          ? "Not a terminal, so PGARD does not wait. Run the command again after adding the repository to the App's repository access."
          : "Not a terminal, so PGARD does not wait for the installation. Run the command again after installing.",
      ),
    );
    return "blocked";
  }
  const stopOffer = offerBrowserOpen(context, remedy.url);
  err(context, errStyle.dim(waitingMessage(remedy.missing, outcome.repo)));

  const deadline = context.deps.now() + INSTALL_WAIT_LIMIT_MS;
  try {
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
        // membership cannot be read), or could not be evaluated (rate limit, API error, sign-in
        // gone). The full authorization reports the current reasons.
        err(
          context,
          errStyle.yellow(
            recheck.status === "unverifiable"
              ? "Owner approval could not be confirmed. Running the full authorization again..."
              : "Owner approval changed. Running the full authorization again...",
          ),
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
  } finally {
    // Whatever ended the poll, the Enter prompt is no longer wanted.
    stopOffer();
  }
}
