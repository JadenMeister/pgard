import { homedir } from "node:os";
import path from "node:path";
import type { ScanResult } from "@pgard/findings";
import { ScanCancelledError, ScanRequestError, type ScanProgressEvent } from "@pgard/scan-core";
import { err, out, suspendKeys, type CommandContext } from "../../context.js";
import { EXIT_CODES, exitCodeForStatus, type ExitCode } from "../../exit-codes.js";
import {
  checkOutputDir,
  confirmInsideRepository,
  offerReportExport,
  runReportExport,
  saveReports,
  type ReportExportOutcome,
} from "../../flows/export-report.js";
import { offerPanels } from "../../flows/panels.js";
import type { ReportRequest } from "../../options.js";
import { UserCancelledError } from "../../ui/components/prompts.js";
import { safeText } from "../../ui/formatters/style.js";
import { cliText, type CliText } from "../../ui/i18n/cli-text.js";
import type { TrendData } from "../../ui/panels/types.js";

/**
 * `pgard scan code` without `--require-authorization` (#414, D1 and D4): a code-only scan of the
 * current files. No authorization gate, no sign-in, no network, no Git history; the result says
 * so (JSON 1.7 `scanBasis`, the first line of the text result) and is never stored. It works in
 * any folder: a Git repository (scanned from its top folder, as before) or a folder without Git.
 */
export interface CodeOnlyCommand {
  report: ReportRequest | null;
  panels?: boolean;
  /** `--format json|sarif`: stdout holds one document; no panel view, no menu question. */
  isMachineFormat: boolean;
}

export interface CodeOnlyOutput {
  /** Text mode prints the result here. */
  show: (result: ScanResult) => void;
  /** JSON and SARIF mode print the one document here. */
  finish: (result: ScanResult) => void;
  /** Rule texts in the terminal language (the panel view). */
  localize: (result: ScanResult) => ScanResult;
  /** One progress line, or `null`. */
  progressLine: (event: ScanProgressEvent) => string | null;
}

/** The home folder or the file-system root is never a project to scan as a whole. */
export function isTooBroadForCodeOnly(folder: string, home: string = homedir()): boolean {
  const resolved = path.resolve(folder);
  if (resolved === path.parse(resolved).root) return true;
  return home !== "" && resolved === path.resolve(home);
}

export async function runCodeOnlyScanFlow(
  context: CommandContext,
  command: CodeOnlyCommand,
  output: CodeOnlyOutput,
): Promise<ExitCode> {
  const text: CliText = cliText(context.ruleLocale);
  const progress = (line: string): void => err(context, context.errStyle.dim(line));
  const gitRoot = await context.deps.findGitRoot(context.io.cwd);
  // D4: a folder without Git is scanned as it is; a Git repository from its top folder.
  const projectRoot = gitRoot ?? path.resolve(context.io.cwd);
  if (gitRoot === null && isTooBroadForCodeOnly(projectRoot)) {
    err(context, context.errStyle.red(text.codeOnly.tooBroad));
    return EXIT_CODES.usage;
  }

  // Report destination problems are input errors: rejected before anything is read.
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

  progress(text.progress.scanning("code"));
  suspendKeys(context);
  let result: ScanResult;
  try {
    result = await context.deps.runCodeOnlyScan(
      // `not_checked`: the user asked for a code-only scan; nothing about GitHub was looked at.
      { projectRoot, reason: gitRoot === null ? "not_a_git_repository" : "not_checked" },
      {
        signal: context.signal,
        env: context.io.env,
        advisoryDataDir: context.deps.appDataDir,
        onProgress: (event) => {
          const line = output.progressLine(event);
          if (line !== null) progress(line);
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

  output.show(result);
  // How to get more; on stderr in JSON and SARIF mode (the caller's context routes it there).
  out(context, context.style.dim(text.codeOnly.upgrade));
  output.finish(result);
  let exitCode = exitCodeForStatus(result.overallStatus);

  // Never stored: no result, no incremental state, no trend, no baseline.
  const panelSavedPaths = new Set<string>();
  const exportFromPanels = (): Promise<ReportExportOutcome> =>
    runReportExport(context, result, projectRoot, panelSavedPaths);
  const noTrend = (): Promise<TrendData> => Promise.resolve({ kind: "disabled" });
  let isReportSaved = true;
  if (command.report !== null && reportDir !== null) {
    // D5: a code-only report carries the "not authorized" banner on every page.
    isReportSaved = await saveReports(
      context,
      result,
      command.report.format,
      reportDir,
      panelSavedPaths,
    );
  }
  if (!command.isMachineFormat) {
    isReportSaved =
      (await offerPanels(
        context,
        output.localize(result),
        command.panels === true,
        true,
        noTrend,
        exportFromPanels,
      )) && isReportSaved;
    if (command.report === null && context.isMenu) {
      isReportSaved =
        (await offerReportExport(context, result, projectRoot, panelSavedPaths)) && isReportSaved;
    }
  }
  if (!isReportSaved && exitCode === EXIT_CODES.ok) exitCode = EXIT_CODES.partial;
  return exitCode;
}
