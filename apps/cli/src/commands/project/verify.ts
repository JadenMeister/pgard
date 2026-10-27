import type { AuthorizationOutcome } from "@pgard/scan-core";
import { err, out, suspendKeys, throwIfCancelled, type CommandContext } from "../../context.js";
import { EXIT_CODES, type ExitCode } from "../../exit-codes.js";
import { createSessionProvider } from "../../flows/authenticate.js";
import { authorizationDepsFor, offerGuidedInstall } from "../../flows/guided-install.js";
import { formatAuthorization } from "../../ui/formatters/result-view.js";
import { safeText } from "../../ui/formatters/style.js";

export const NOT_A_REPOSITORY_MESSAGE =
  "The current directory is not inside a Git repository. PGARD always checks the Git root of the current directory.";

export function showOutcome(context: CommandContext, outcome: AuthorizationOutcome): void {
  out(
    context,
    context.style.dim(
      `Repository ${safeText(outcome.repo ?? "unknown", 120)} @ ${safeText((outcome.revision ?? "unknown").slice(0, 12), 20)}`,
    ),
  );
  out(context, formatAuthorization(outcome.summary, context.style));
  out(context, context.style.dim("This result is not stored. Every scan checks again."));
}

/**
 * `pgard project verify`: runs the authorization gate and shows each check's reason.
 * The outcome is display-only; scans run the gate again. When only the PGARD GitHub App
 * installation is missing, it guides the install and then runs the whole gate again.
 */
export async function runProjectVerify(context: CommandContext): Promise<ExitCode> {
  const projectRoot = await context.deps.findGitRoot(context.io.cwd);
  if (projectRoot === null) {
    err(context, context.errStyle.red(NOT_A_REPOSITORY_MESSAGE));
    return EXIT_CODES.blocked;
  }
  suspendKeys(context);
  const authorization = authorizationDepsFor(context, createSessionProvider(context));
  let outcome = await context.deps.verifyProject(projectRoot, authorization);
  throwIfCancelled(context);
  showOutcome(context, outcome);
  if (outcome.summary.decision !== "allowed") {
    const guided = await offerGuidedInstall(context, outcome, projectRoot, authorization);
    throwIfCancelled(context);
    if (guided === "reauthorize") {
      // The installation is the owner's approval, but it is not a pass by itself: all five
      // checks run again from scratch.
      outcome = await context.deps.verifyProject(projectRoot, authorization);
      throwIfCancelled(context);
      out(context, "");
      showOutcome(context, outcome);
    }
  }
  return outcome.summary.decision === "allowed" ? EXIT_CODES.ok : EXIT_CODES.blocked;
}
