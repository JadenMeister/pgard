import {
  guidedInstallRemedy,
  resolveGitHubAppClientId,
  type AuthorizationDependencies,
  type AuthorizationOutcome,
  type GitHubSessionProvider,
} from "@pgard/scan-core";
import { err, type CommandContext } from "../context.js";
import { safeText } from "../ui/formatters/style.js";
import { cliText, type CliText } from "../ui/i18n/cli-text.js";
import { offerBrowserOpen } from "./browser.js";

/** How often owner approval is checked again while the user installs the App. */
export const INSTALL_POLL_INTERVAL_MS = 5_000;
/** How long PGARD waits for the installation before blocking. */
export const INSTALL_WAIT_LIMIT_MS = 10 * 60_000;

export const WAITING_FOR_INSTALL_MESSAGE = cliText("en").commands.install.waitingInstall;

/** The waiting line: for a repository to be added to an existing installation, or an install. */
export function waitingMessage(
  missing: string,
  repo: string | null,
  t: CliText = cliText("en"),
): string {
  const text = t.commands.install;
  if (missing !== "repository_access") return text.waitingInstall;
  return text.waitingRepositoryAccess(repo === null ? text.thisRepository : safeText(repo, 120));
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
export function formatAskOwner(
  accountLogin: string,
  url: string,
  t: CliText = cliText("en"),
): string {
  return t.commands.install.askOwner(safeText(accountLogin, 100), url);
}

/**
 * Said when GitHub would not show the organization membership (expected before the App is
 * installed there): an owner installs it on the install page, anyone else asks an owner. It names
 * "the install page" plus the link, since with `--no-browser` (or in the dashboard) nothing opened.
 */
export function formatOwnerOrAsk(
  accountLogin: string,
  url: string,
  t: CliText = cliText("en"),
): string {
  return t.commands.install.ownerOrAsk(safeText(accountLogin, 100), url);
}

export type MissingKind = "installation" | "repository" | "access" | "repository_access";

/** "Ask an owner" line when the repository must be added to an existing installation. */
export function formatAskOwnerToAddRepository(
  accountLogin: string,
  repo: string | null,
  url: string,
  t: CliText = cliText("en"),
): string {
  const text = t.commands.install;
  const target = repo === null ? text.thisRepository : safeText(repo, 120);
  return text.askOwnerToAdd(safeText(accountLogin, 100), target, url);
}

export function formatInstallSteps(
  accountLogin: string,
  repo: string | null,
  url: string,
  canApprove: "yes" | "unknown",
  missing: MissingKind = "installation",
  t: CliText = cliText("en"),
): string {
  const text = t.commands.install;
  const target = repo === null ? text.thisRepository : safeText(repo, 120);
  const account = safeText(accountLogin, 100);
  if (missing === "repository_access") {
    return [
      text.repositoryAccessIntro(target, account),
      canApprove === "yes"
        ? text.ownerApprovalAdd(target)
        : text.ownerOrAskToAdd(account, target, url),
      text.open(url),
      text.repositoryAccessStep(target),
      text.repositoryAccessFooter,
    ].join("\n");
  }
  return [
    ...(missing === "access" ? [text.accessIntro(target)] : []),
    canApprove === "yes"
      ? text.ownerApprovalInstall(account, target)
      : formatOwnerOrAsk(accountLogin, url, t),
    text.open(url),
    missing === "access" ? text.accessStep(target) : text.installStep(target),
    text.installFooter,
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
 *   steps, offers to open the install page after Enter (when allowed) and, on a terminal,
 *   re-checks owner approval every 5 s for up to 10 minutes. The re-check uses only the existing
 *   sign-in (`getGitHubSession.existing()`), never a new device flow; without one it ends the
 *   wait and the caller's full authorization signs in as usual.
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
  const t = cliText(context.ruleLocale);
  const text = t.commands.install;
  if (remedy.url === null) {
    err(context, errStyle.yellow(remedy.unavailableReason ?? text.noInstallLink));
    return "blocked";
  }
  if (remedy.canApprove === "no") {
    err(
      context,
      errStyle.yellow(
        remedy.missing === "repository_access"
          ? formatAskOwnerToAddRepository(remedy.account.login, outcome.repo, remedy.url, t)
          : formatAskOwner(remedy.account.login, remedy.url, t),
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
        t,
      ),
    ),
  );
  if (context.io.stdout.isTTY !== true) {
    err(
      context,
      errStyle.dim(
        remedy.missing === "repository_access"
          ? text.notTerminalRepository
          : text.notTerminalInstall,
      ),
    );
    return "blocked";
  }
  const stopOffer = offerBrowserOpen(context, remedy.url);
  err(context, errStyle.dim(waitingMessage(remedy.missing, outcome.repo, t)));

  const deadline = context.deps.now() + INSTALL_WAIT_LIMIT_MS;
  try {
    for (;;) {
      try {
        await context.deps.sleep(INSTALL_POLL_INTERVAL_MS, context.signal);
      } catch {
        // Only an abort ends the sleep early.
      }
      if (context.signal.aborted) {
        err(context, errStyle.yellow(text.stoppedWaiting));
        return "cancelled";
      }
      let recheck;
      try {
        recheck = await context.deps.recheckOwnerApproval(projectRoot, authorization);
      } catch {
        recheck = null;
      }
      if (context.signal.aborted) {
        err(context, errStyle.yellow(text.stoppedWaiting));
        return "cancelled";
      }
      if (recheck === null) {
        err(context, errStyle.red(text.recheckFailed));
        return "blocked";
      }
      if (recheck.status === "passed") {
        err(context, errStyle.green(text.found));
        return "reauthorize";
      }
      if (recheck.remedy === null) {
        // Owner approval now fails for another reason (e.g. the installation exists but the
        // membership cannot be read), or could not be evaluated (rate limit, API error, sign-in
        // gone). The full authorization reports the current reasons.
        err(
          context,
          errStyle.yellow(recheck.status === "unverifiable" ? text.unconfirmed : text.changed),
        );
        return "reauthorize";
      }
      if (context.deps.now() >= deadline) {
        err(
          context,
          errStyle.red(
            text.stoppedAfter(INSTALL_WAIT_LIMIT_MS / 60_000, safeText(recheck.reason, 300)),
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
