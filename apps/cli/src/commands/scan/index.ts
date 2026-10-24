import type { ConfirmedWebTarget, ScanScope } from "@pgard/findings";
import { ScanCancelledError, ScanRequestError, type ScanProgressEvent } from "@pgard/scan-core";
import { err, out, suspendKeys, type CommandContext } from "../../context.js";
import { EXIT_CODES, exitCodeForStatus, type ExitCode } from "../../exit-codes.js";
import { createSessionProvider, printMissingClientIdHint } from "../../flows/authenticate.js";
import {
  checkOutputDir,
  confirmInsideRepository,
  offerReportExport,
  saveReports,
} from "../../flows/export-report.js";
import { selectLocalPort } from "../../flows/select-local-port.js";
import type { ReportRequest, ScanVariant } from "../../options.js";
import { UserCancelledError } from "../../ui/components/prompts.js";
import { formatAuthorization, formatScanResult } from "../../ui/formatters/result-view.js";
import { safeText } from "../../ui/formatters/style.js";
import { NOT_A_REPOSITORY_MESSAGE } from "../project/verify.js";

export const SCOPES_BY_VARIANT: Record<ScanVariant, ScanScope[]> = {
  default: ["code", "history"],
  code: ["code"],
  history: ["history"],
  web: ["web"],
  all: ["code", "history", "web"],
};

export interface ScanCommand {
  variant: ScanVariant;
  port: number | null;
  report: ReportRequest | null;
}

function formatProgress(event: ScanProgressEvent): string | null {
  if (event.web !== undefined) {
    return `  web: ${event.web.pagesVisited} page(s) checked`;
  }
  return `  ${event.stage}: ${event.status}${event.message === "" ? "" : ` - ${safeText(event.message, 200)}`}`;
}

/**
 * Shared flow for every `pgard scan` variant: Git root, report pre-checks, (web) authorization
 * and target confirmation, then `runScan`, which runs the authorization gate again itself.
 */
export async function runScanCommand(
  context: CommandContext,
  command: ScanCommand,
): Promise<ExitCode> {
  const scopes = SCOPES_BY_VARIANT[command.variant];
  const projectRoot = await context.deps.findGitRoot(context.io.cwd);
  if (projectRoot === null) {
    err(context, context.errStyle.red(NOT_A_REPOSITORY_MESSAGE));
    return EXIT_CODES.blocked;
  }

  // Report destination problems are input errors: reject them before any network activity.
  let reportDir: string | null = null;
  if (command.report !== null) {
    const check = await checkOutputDir(context, command.report.outputDir, projectRoot);
    if (check.kind === "invalid") {
      err(context, context.errStyle.red(check.message));
      return EXIT_CODES.usage;
    }
    if (check.isInsideRepository && !(await confirmInsideRepository(context))) {
      return EXIT_CODES.usage;
    }
    reportDir = check.outputDir;
  }

  const getGitHubSession = createSessionProvider(context);
  let webTarget: ConfirmedWebTarget | null = null;
  if (scopes.includes("web")) {
    // Confirm authorization before probing any local port; the scan re-checks it anyway.
    suspendKeys(context);
    const outcome = await context.deps.verifyProject(projectRoot, { getGitHubSession });
    if (outcome.summary.decision !== "allowed") {
      out(context, formatAuthorization(outcome.summary, context.style));
      printMissingClientIdHint(context, outcome.summary);
      return EXIT_CODES.blocked;
    }
    if (context.keys === null) {
      err(
        context,
        context.errStyle.yellow(
          "The web target cannot be confirmed without an interactive terminal; web checks are recorded as not tested.",
        ),
      );
    } else {
      const selection = await selectLocalPort(context, command.port);
      if (selection.kind === "back") {
        // Esc: in the menu go back to it; a direct subcommand has no previous step.
        if (context.isMenu) return EXIT_CODES.cancelled;
        throw new UserCancelledError();
      }
      if (selection.kind === "confirmed") webTarget = selection.target;
    }
  }

  err(
    context,
    context.errStyle.dim(`Scanning (${scopes.join(", ")})... Press Ctrl+C twice to cancel.`),
  );
  suspendKeys(context);
  let result;
  try {
    result = await context.deps.runScan(
      { projectRoot, scopes, webTarget },
      {
        authorization: { getGitHubSession },
        webScanner: context.deps.webScanner,
        signal: context.signal,
        env: context.io.env,
        onProgress: (event) => {
          const line = formatProgress(event);
          if (line !== null) err(context, context.errStyle.dim(line));
        },
      },
    );
  } catch (error) {
    if (error instanceof ScanCancelledError) throw new UserCancelledError();
    if (error instanceof ScanRequestError) {
      err(context, context.errStyle.red(safeText(error.message, 300)));
      return EXIT_CODES.usage;
    }
    throw error;
  }

  out(context, "");
  out(context, formatScanResult(result, context.style));
  let exitCode = exitCodeForStatus(result.overallStatus);

  if (result.overallStatus === "blocked") {
    printMissingClientIdHint(context, result.authorization);
    if (command.report !== null)
      out(context, "No report was written because the scan was blocked.");
    return exitCode;
  }
  let isReportSaved = true;
  if (command.report !== null && reportDir !== null) {
    isReportSaved = await saveReports(context, result, command.report.format, reportDir);
  } else if (context.isMenu) {
    isReportSaved = await offerReportExport(context, result, projectRoot);
  }
  if (!isReportSaved && exitCode === EXIT_CODES.ok) exitCode = EXIT_CODES.partial;
  return exitCode;
}
