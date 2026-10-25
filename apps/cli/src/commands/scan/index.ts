import type { ConfirmedWebTarget, ScanScope } from "@pgard/findings";
import {
  ScanCancelledError,
  ScanRequestError,
  type AuthorizationOutcome,
  type ScanProgressEvent,
} from "@pgard/scan-core";
import { err, out, suspendKeys, throwIfCancelled, type CommandContext } from "../../context.js";
import { EXIT_CODES, exitCodeForStatus, type ExitCode } from "../../exit-codes.js";
import { createSessionProvider } from "../../flows/authenticate.js";
import {
  checkOutputDir,
  confirmInsideRepository,
  offerReportExport,
  saveReports,
} from "../../flows/export-report.js";
import { authorizationDepsFor, offerGuidedInstall } from "../../flows/guided-install.js";
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

  const authorization = authorizationDepsFor(context, createSessionProvider(context));
  let webTarget: ConfirmedWebTarget | null = null;
  if (scopes.includes("web")) {
    // Confirm authorization before probing any local port; the scan re-checks it anyway.
    suspendKeys(context);
    let outcome = await context.deps.verifyProject(projectRoot, authorization);
    throwIfCancelled(context);
    if (outcome.summary.decision !== "allowed") {
      out(context, formatAuthorization(outcome.summary, context.style));
      const guided = await offerGuidedInstall(context, outcome, projectRoot, authorization);
      throwIfCancelled(context);
      if (guided !== "reauthorize") return EXIT_CODES.blocked;
      // All five checks again, from scratch; the installation alone is not a pass.
      outcome = await context.deps.verifyProject(projectRoot, authorization);
      throwIfCancelled(context);
      if (outcome.summary.decision !== "allowed") {
        out(context, formatAuthorization(outcome.summary, context.style));
        return EXIT_CODES.blocked;
      }
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

  // Every call runs the full authorization gate inside runScan; nothing is reused between them.
  const scanOnce = async () => {
    err(
      context,
      context.errStyle.dim(`Scanning (${scopes.join(", ")})... Press Ctrl+C twice to cancel.`),
    );
    suspendKeys(context);
    let outcome: AuthorizationOutcome | null = null;
    try {
      const scanned = await context.deps.runScan(
        { projectRoot, scopes, webTarget },
        {
          authorization,
          webScanner: context.deps.webScanner,
          signal: context.signal,
          env: context.io.env,
          onAuthorization: (received) => {
            outcome = received;
          },
          onProgress: (event) => {
            const line = formatProgress(event);
            if (line !== null) err(context, context.errStyle.dim(line));
          },
        },
      );
      return { result: scanned, outcome: outcome as AuthorizationOutcome | null };
    } catch (error) {
      if (error instanceof ScanCancelledError) throw new UserCancelledError();
      if (error instanceof ScanRequestError) {
        err(context, context.errStyle.red(safeText(error.message, 300)));
        return null;
      }
      throw error;
    }
  };

  let scanned = await scanOnce();
  if (scanned === null) return EXIT_CODES.usage;
  out(context, "");
  out(context, formatScanResult(scanned.result, context.style));
  if (scanned.result.overallStatus === "blocked" && scanned.outcome !== null) {
    const guided = await offerGuidedInstall(context, scanned.outcome, projectRoot, authorization);
    throwIfCancelled(context);
    if (guided === "reauthorize") {
      scanned = await scanOnce();
      if (scanned === null) return EXIT_CODES.usage;
      out(context, "");
      out(context, formatScanResult(scanned.result, context.style));
    }
  }
  const { result } = scanned;
  let exitCode = exitCodeForStatus(result.overallStatus);

  if (result.overallStatus === "blocked") {
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
