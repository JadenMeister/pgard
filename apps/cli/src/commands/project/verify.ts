import { err, out, type CommandContext } from "../../context.js";
import { EXIT_CODES, type ExitCode } from "../../exit-codes.js";
import { createSessionProvider, printMissingClientIdHint } from "../../flows/authenticate.js";
import { formatAuthorization } from "../../ui/formatters/result-view.js";
import { safeText } from "../../ui/formatters/style.js";

export const NOT_A_REPOSITORY_MESSAGE =
  "The current directory is not inside a Git repository. PGARD always checks the Git root of the current directory.";

/**
 * `pgard project verify`: runs the authorization gate and shows each check's reason.
 * The outcome is display-only; scans run the gate again.
 */
export async function runProjectVerify(context: CommandContext): Promise<ExitCode> {
  const projectRoot = await context.deps.findGitRoot(context.io.cwd);
  if (projectRoot === null) {
    err(context, context.errStyle.red(NOT_A_REPOSITORY_MESSAGE));
    return EXIT_CODES.blocked;
  }
  const outcome = await context.deps.verifyProject(projectRoot, {
    getGitHubSession: createSessionProvider(context),
  });
  out(
    context,
    context.style.dim(
      `Repository ${safeText(outcome.repo ?? "unknown", 120)} @ ${safeText((outcome.revision ?? "unknown").slice(0, 12), 20)}`,
    ),
  );
  out(context, formatAuthorization(outcome.summary, context.style));
  printMissingClientIdHint(context, outcome.summary);
  out(context, context.style.dim("This result is not stored. Every scan checks again."));
  return outcome.summary.decision === "allowed" ? EXIT_CODES.ok : EXIT_CODES.blocked;
}
