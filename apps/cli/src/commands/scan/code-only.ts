import { realpath } from "node:fs";
import { lstat, stat as statOf } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import type { KnownScanBasisReason, ScanResult } from "@pgard/findings";
import {
  folderBreadthRefusal,
  folderSafetyProblem,
  isInsideGitDirectory as isInsideGitDirectoryShared,
  type EntryKind,
  type FileIdentity,
  type ScopeStat,
  type TooBroadReason,
} from "@pgard/result-store";
import { ScanCancelledError, ScanRequestError, type ScanProgressEvent } from "@pgard/scan-core";
import { err, out, suspendKeys, type CommandContext } from "../../context.js";
import { codeOnlyHome } from "../../home-dir.js";
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
  identityOf: (target: string) => Promise<FileIdentity> = fileIdentityOf,
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
  const options = {
    ignoreCase: platform === "darwin" || platform === "win32",
    windows: platform === "win32",
    identityOf,
  };
  // Both spellings: on macOS `/etc`, `/tmp` and `/var` are links into `/private`, so the given
  // path or its real path alone could look narrower than it is. Both also get the identity
  // check (device and inode against `/`, home and its parents), so a firmlink or alias spelling
  // the path rules do not know cannot get past (#427). The same helper as the web chooser.
  return (
    (await folderBreadthRefusal(
      path.resolve(folder),
      home === "" ? null : path.resolve(home),
      options,
    )) ??
    (await folderBreadthRefusal(await real(folder), home === "" ? null : await real(home), options))
  );
}

/** Device and inode of a path (links followed), or `null` when it cannot be read. */
async function fileIdentityOf(target: string): Promise<FileIdentity> {
  try {
    const stat = await statOf(target, { bigint: true });
    return { dev: stat.dev, ino: stat.ino };
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

/** The real path of a folder (the file system's own spelling), or its resolved path. */
async function realFolder(folder: string): Promise<string> {
  try {
    return await new Promise<string>((resolve, reject) =>
      realpath.native(folder, (error, resolved) => (error ? reject(error) : resolve(resolved))),
    );
  } catch {
    // Not on disk (or not readable): an absolute path stays as it is; a relative one is resolved.
    return path.isAbsolute(folder) ? folder : path.resolve(folder);
  }
}

export type CodeOnlyPlan =
  | { kind: "refused"; message: string }
  /** `isRepository`: the folder, or one above it, has its own `.git` entry. */
  | { kind: "ok"; projectRoot: string; isRepository: boolean };

/**
 * Where a code-only scan reads, or why it cannot (#414, #427). The repository root is found
 * without Git: the nearest folder at or above the current one with a `.git` entry, never above
 * the home folder, so a repository's own `core.worktree` cannot send the scan elsewhere. It
 * is the same rule as the web chooser, which also refuses the same folders: a `.git` folder,
 * no known home folder, a folder too broad to be a project (or a repository at home, or on a
 * virtual file system), and a folder owned by another user or writable by group or others.
 * The checks run on the final root, whichever way it was found.
 */
export async function codeOnlyPlan(
  context: CommandContext,
  platform: NodeJS.Platform = process.platform,
): Promise<CodeOnlyPlan> {
  const text: CliText = cliText(context.ruleLocale);
  const refused = (message: string): CodeOnlyPlan => ({ kind: "refused", message });
  const home = codeOnlyHome(context.io.env);
  if (home === null) return refused(text.codeOnly.noHome);
  const cwd = await realFolder(context.io.cwd);
  if (await isInsideGitDirectory(cwd)) return refused(text.codeOnly.gitDirectory);
  const repository = await context.deps.findRepositoryRoot(cwd, await realFolder(home));
  const projectRoot = repository === null ? cwd : await realFolder(repository);
  if (repository !== null && (await isInsideGitDirectory(projectRoot))) {
    return refused(text.codeOnly.gitDirectory);
  }
  // Also for a repository: a dotfiles repository at the home folder would scan all of it.
  const breadth = await codeOnlyFolderRefusal(projectRoot, home, platform);
  if (breadth === "virtual") return refused(text.codeOnly.virtualFolder);
  if (breadth !== null) {
    return refused(repository === null ? text.codeOnly.tooBroad : text.codeOnly.tooBroadRepository);
  }
  // The web chooser's rule (T13); on Windows there is no user id and no such mode bits.
  const uid = context.deps.currentUid();
  if (platform !== "win32" && uid !== undefined) {
    const unsafe = await folderSafetyProblem(
      projectRoot,
      await realFolder(home),
      uid,
      (target): Promise<ScopeStat> => lstatScope(target),
    );
    if (unsafe !== null) return refused(text.codeOnly.unsafeFolder(unsafe.problem, unsafe.path));
  }
  return { kind: "ok", projectRoot, isRepository: repository !== null };
}

/** `lstat` in the shape the shared ownership and permission rule reads. */
async function lstatScope(target: string): Promise<ScopeStat> {
  const stat = await lstat(target);
  return {
    isDirectory: stat.isDirectory(),
    isFile: stat.isFile(),
    isSymbolicLink: stat.isSymbolicLink(),
    uid: stat.uid,
    mode: stat.mode,
    dev: stat.dev,
    ino: stat.ino,
  };
}

/** `codeOnlyPlan`'s refusal as a message, or `null` when a code-only scan may go ahead. */
export async function codeOnlyRefusalMessage(context: CommandContext): Promise<string | null> {
  const plan = await codeOnlyPlan(context);
  return plan.kind === "refused" ? plan.message : null;
}

export async function runCodeOnlyScanFlow(
  context: CommandContext,
  command: CodeOnlyCommand,
  output: CodeOnlyOutput,
): Promise<ExitCode> {
  const text: CliText = cliText(context.ruleLocale);
  const progress = (line: string): void => err(context, context.errStyle.dim(line));
  const plan = await codeOnlyPlan(context);
  if (plan.kind === "refused") {
    err(context, context.errStyle.red(plan.message));
    return EXIT_CODES.usage;
  }
  // D4: a folder without Git is scanned as it is; a Git repository from its top folder.
  const { projectRoot } = plan;
  const gitRoot = plan.isRepository ? projectRoot : null;

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

export { codeOnlyHome };
