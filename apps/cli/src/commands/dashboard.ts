import { err, out, promptContextOf, type CommandContext } from "../context.js";
import { EXIT_CODES, toKnownExitCode, type ExitCode } from "../exit-codes.js";
import { promptConfirm } from "../ui/components/prompts.js";
import { safeText } from "../ui/formatters/style.js";
import { NOT_A_REPOSITORY_MESSAGE } from "./project/verify.js";

const DASHBOARD_HELP = `The dashboard runs on 127.0.0.1 only and checks only the project shown here.
The browser cannot choose another folder. Results end when you stop it.`;

/**
 * `pgard dashboard`: confirm the project in the terminal, then start the separately installed
 * local-web launcher with this Node binary (no shell). The web app runs its own scans.
 */
export async function runDashboard(
  context: CommandContext,
  targetPort: number | null,
): Promise<ExitCode> {
  const projectRoot = await context.deps.findGitRoot(context.io.cwd);
  if (projectRoot === null) {
    err(context, context.errStyle.red(NOT_A_REPOSITORY_MESSAGE));
    return EXIT_CODES.blocked;
  }
  const prompts = promptContextOf(context, DASHBOARD_HELP);
  if (prompts === null) {
    err(context, "pgard dashboard needs an interactive terminal to confirm the project.");
    return EXIT_CODES.usage;
  }
  const entry = context.deps.resolveDashboardEntry();
  if (entry === null) {
    err(
      context,
      context.errStyle.red("The local web dashboard is not installed with this pgard build."),
    );
    return EXIT_CODES.internal;
  }
  out(context, `Project: ${safeText(projectRoot, 500)}`);
  const isConfirmed = await promptConfirm(prompts, "Start the dashboard for this project?");
  if (!isConfirmed) return EXIT_CODES.cancelled;
  const args = ["--project-root", projectRoot];
  if (targetPort !== null) args.push("--target-port", String(targetPort));
  context.keys?.close();
  // The dashboard process handles Ctrl+C itself; stop our scan-cancel prompt from printing.
  context.releaseInterrupts();
  return toKnownExitCode(await context.deps.startDashboardProcess(entry, args));
}
