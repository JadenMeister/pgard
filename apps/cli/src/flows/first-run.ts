import {
  guidedInstallRemedy,
  isAuthorizationAllowed,
  readStoredSignInStatus,
  resolveGitHubAppClientId,
} from "@pgard/scan-core";
import { runLogin } from "../commands/login.js";
import { showOutcome } from "../commands/project/verify.js";
import { runScanCommand } from "../commands/scan/index.js";
import { err, out, suspendKeys, throwIfCancelled, type CommandContext } from "../context.js";
import { EXIT_CODES } from "../exit-codes.js";
import {
  promptConfirmYes,
  promptEnterOrLetter,
  type PromptContext,
} from "../ui/components/prompts.js";
import { cliText } from "../ui/i18n/cli-text.js";
import { canSignInInteractively, createSessionProvider } from "./authenticate.js";
import { openInBrowser } from "./browser.js";
import {
  authorizationDepsFor,
  formatAskOwner,
  formatAskOwnerToAddRepository,
  formatInstallSteps,
} from "./guided-install.js";

/** How many times the whole authorization runs again after "I installed the App". */
export const MAX_INSTALL_RETRIES = 3;

/**
 * The guided first run of the interactive menu. It only adds guidance and retries around the
 * existing authorization gate; the gate itself is untouched:
 *
 * - it starts only when no GitHub sign-in is stored (a first run) in a Git repository;
 * - each verification is a complete `verifyProject` (all five checks, from scratch), including
 *   the ones after "I installed the App"; nothing is cached or skipped;
 * - only a block that the App installation or its repository access can fix gets the install
 *   steps and the retry prompt (at most `MAX_INSTALL_RETRIES` retries). Every other reason is
 *   shown as the blocked result and ends the guidance;
 * - on success the scan runs as the menu does (which runs the gate once more itself).
 *
 * Ctrl+C at any prompt ends as a cancellation (exit 130) through `UserCancelledError`.
 */
export async function runGuidedFirstRun(context: CommandContext): Promise<void> {
  const { keys, errStyle } = context;
  if (keys === null) return;
  // Without a terminal on stdin and stderr nobody can answer a device code: no questions.
  if (!canSignInInteractively(context)) return;
  const projectRoot = await context.deps.findGitRoot(context.io.cwd);
  if (projectRoot === null) return;
  const app = resolveGitHubAppClientId(context.io.env);
  if (app.source === "invalid") return;
  let status;
  try {
    status = await readStoredSignInStatus(context.deps.credentialStore, app.clientId);
  } catch {
    return;
  }
  // A stored sign-in (or a keychain that cannot hold one) is not a first run.
  if (status.status !== "none") return;

  const t = cliText(context.ruleLocale);
  const text = t.commands.firstRun;
  const prompts: PromptContext = {
    keys,
    out: context.io.stdout,
    style: context.style,
    helpText: "",
  };
  out(context, "");
  err(context, errStyle.yellow(text.notSignedIn));
  if (!(await promptConfirmYes(prompts, text.signInQuestion))) {
    err(context, errStyle.dim(text.signInDeclined));
    return;
  }
  // The existing device flow (it asks for Enter before opening the browser).
  const signedIn = await runLogin(context);
  throwIfCancelled(context);
  if (signedIn !== EXIT_CODES.ok) {
    err(context, errStyle.yellow(text.signInFailed));
    return;
  }
  err(context, errStyle.dim(text.signedInVerifying));

  const authorization = authorizationDepsFor(context, createSessionProvider(context));
  err(context, errStyle.dim(text.verifying));
  suspendKeys(context);
  let outcome = await context.deps.verifyProject(projectRoot, authorization);
  throwIfCancelled(context);
  for (let retries = 0; ; retries += 1) {
    out(context, "");
    showOutcome(context, outcome, t);
    if (isAuthorizationAllowed(outcome)) break;
    const remedy = guidedInstallRemedy(outcome);
    if (remedy === null) {
      err(context, errStyle.yellow(text.blockedOther));
      return;
    }
    if (remedy.url === null) {
      err(context, errStyle.yellow(remedy.unavailableReason ?? t.commands.install.noInstallLink));
      return;
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
      return;
    }
    if (retries >= MAX_INSTALL_RETRIES) {
      err(context, errStyle.red(text.stillBlocked(MAX_INSTALL_RETRIES)));
      return;
    }
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
    if (context.canOpenBrowser) {
      const open = await promptEnterOrLetter(prompts, text.openPrompt, "s");
      if (open === "enter") await openInBrowser(context, remedy.url);
    }
    const answer = await promptEnterOrLetter(prompts, text.afterInstallPrompt, "q");
    if (answer === "letter") {
      err(context, errStyle.dim(text.quit));
      return;
    }
    err(context, errStyle.dim(text.rechecking(retries + 1, MAX_INSTALL_RETRIES)));
    suspendKeys(context);
    // The complete gate again, from scratch; the installation alone is never a pass.
    outcome = await context.deps.verifyProject(projectRoot, authorization);
    throwIfCancelled(context);
  }

  err(context, errStyle.green(text.allowed));
  await runScanCommand(context, {
    variant: "default",
    port: null,
    report: null,
    format: "text",
    allFindings: false,
  });
}
