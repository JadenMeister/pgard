import { realpath } from "node:fs";
import { lstat } from "node:fs/promises";
import { homedir, userInfo } from "node:os";
import path from "node:path";
import type { KnownScanBasisReason, ScanResult } from "@pgard/findings";
import {
  isInsideGitDirectory as isInsideGitDirectoryShared,
  tooBroadToScan,
  type EntryKind,
  type TooBroadReason,
} from "@pgard/result-store";
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
 * `pgard scan --code-only`, or `y` after authorization failed (#414, D1 and D4): a code-only scan of the
 * current files. No authorization gate, no sign-in, no network, no Git history; the result says
 * so (JSON 1.7 `scanBasis`, the first line of the text result) and is never stored. It works in
 * any folder: a Git repository (scanned from its top folder, as before) or a folder without Git.
 */
export interface CodeOnlyCommand {
  report: ReportRequest | null;
  panels?: boolean;
  /** `--format json|sarif`: stdout holds one document; no panel view, no menu question. */
  isMachineFormat: boolean;
  /**
   * `scanBasis.reason` in a Git repository: why authorization was not verified (`not_checked`
   * for `--code-only`, or what the failed gate said). Outside one it is always
   * `not_a_git_repository`.
   */
  reason?: KnownScanBasisReason;
  /** The `--report` folder was already checked and confirmed (after `y`): do not ask again. */
  isReportConfirmed?: boolean;
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

/**
 * Why a folder cannot be code-only scanned as a whole, or `null`. Both sides are real paths
 * (symbolic links resolved, the file system's own spelling), compared without case on macOS and
 * Windows; the rule is shared with the web folder chooser (`tooBroadToScan`).
 */
export async function codeOnlyFolderRefusal(
  folder: string,
  home: string = homedir(),
  platform: NodeJS.Platform = process.platform,
): Promise<TooBroadReason | null> {
  const real = async (value: string): Promise<string> => {
    try {
      // The native call returns the file system's own spelling (case) on macOS and Windows.
      return await new Promise<string>((resolve, reject) =>
        realpath.native(value, (error, resolved) => (error ? reject(error) : resolve(resolved))),
      );
    } catch {
      return path.resolve(value);
    }
  };
  const options = { ignoreCase: platform === "darwin" || platform === "win32" };
  // Both spellings: on macOS `/etc`, `/tmp` and `/var` are links into `/private`, so the given
  // path or its real path alone could look narrower than it is.
  return (
    tooBroadToScan(path.resolve(folder), home === "" ? null : path.resolve(home), options) ??
    tooBroadToScan(await real(folder), home === "" ? null : await real(home), options)
  );
}

/**
 * The home folder to refuse: `HOME` (or `USERPROFILE` on Windows) when set and not empty,
 * otherwise the account's own home folder. `null` when neither is known: the scan is refused
 * then, because a folder could not be checked against home.
 */
export function codeOnlyHome(
  env: Readonly<Record<string, string | undefined>>,
  accountHome: () => string = () => userInfo().homedir,
): string | null {
  for (const value of [env.HOME, env.USERPROFILE]) {
    if (value !== undefined && value.trim() !== "") return value;
  }
  try {
    const fromAccount = accountHome();
    return fromAccount.trim() === "" ? null : fromAccount;
  } catch {
    return null;
  }
}

/** The kind of a path without following a symbolic link, for the shared Git layout checks. */
async function entryKind(entry: string): Promise<EntryKind> {
  try {
    const stat = await lstat(entry);
    return stat.isFile() ? "file" : stat.isDirectory() ? "directory" : "other";
  } catch {
    return null;
  }
}

/**
 * True when `cwd` is a Git directory (`.git`, a bare repository) or inside one. Its `config` can
 * hold credentials and its objects are not the current files, so it is never code-only scanned.
 * The rule is shared with the web folder chooser (`@pgard/result-store`).
 */
export function isInsideGitDirectory(cwd: string): Promise<boolean> {
  return isInsideGitDirectoryShared(cwd, entryKind);
}

/**
 * Why the current folder can never be code-only scanned (a `.git` folder, no home folder, a
 * folder too broad to be one project), as the message to show; `null` when it can be. Checked
 * before a code-only scan and before one is offered.
 */
export async function codeOnlyRefusalMessage(
  context: CommandContext,
  gitRoot: string | null,
): Promise<string | null> {
  const text: CliText = cliText(context.ruleLocale);
  const projectRoot = gitRoot ?? path.resolve(context.io.cwd);
  if (gitRoot === null && (await isInsideGitDirectory(context.io.cwd))) {
    return text.codeOnly.gitDirectory;
  }
  const home = codeOnlyHome(context.io.env);
  if (home === null) return text.codeOnly.noHome;
  // Also for a repository: a dotfiles repository at the home folder would scan all of it.
  if ((await codeOnlyFolderRefusal(projectRoot, home)) !== null) {
    return gitRoot === null ? text.codeOnly.tooBroad : text.codeOnly.tooBroadRepository;
  }
  return null;
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
  const refusal = await codeOnlyRefusalMessage(context, gitRoot);
  if (refusal !== null) {
    err(context, context.errStyle.red(refusal));
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
    if (
      check.isInsideRepository &&
      command.isReportConfirmed !== true &&
      !(await confirmInsideRepository(context))
    ) {
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
      {
        projectRoot,
        reason: gitRoot === null ? "not_a_git_repository" : (command.reason ?? "not_checked"),
      },
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
