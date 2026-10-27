import {
  buildSarif,
  countSarifOmitted,
  sarifScanDidNotRun,
  sarifScanIncomplete,
  localizeFindings,
  type ConfirmedWebTarget,
  type ScanResult,
  type ScanScope,
} from "@pgard/findings";
import { WEB_RULE_LIST } from "@pgard/http-local";
import {
  ScanCancelledError,
  ScanRequestError,
  type AuthorizationOutcome,
  type ScanProgressEvent,
} from "@pgard/scan-core";
import { isAuthorizationAllowed } from "@pgard/scan-core";
import { err, out, suspendKeys, throwIfCancelled, type CommandContext } from "../../context.js";
import { EXIT_CODES, exitCodeForStatus, type ExitCode } from "../../exit-codes.js";
import { createSessionProvider } from "../../flows/authenticate.js";
import {
  checkOutputDir,
  confirmInsideRepository,
  offerReportExport,
  runReportExport,
  type ReportExportOutcome,
  saveReports,
} from "../../flows/export-report.js";
import { authorizationDepsFor, offerGuidedInstall } from "../../flows/guided-install.js";
import { getRuleTextCatalog } from "../../rule-texts.js";
import { selectLocalPort } from "../../flows/select-local-port.js";
import { applyStoredBaseline, storeBaseline } from "../../flows/baseline.js";
import { createIncrementalHandle } from "../../flows/incremental.js";
import { loadPreviousScan, scanDiffOf, storeScanResult } from "../../flows/store-result.js";
import type { OutputFormat, ReportRequest, ScanVariant } from "../../options.js";
import { UserCancelledError } from "../../ui/components/prompts.js";
import { formatAuthorization, formatScanResult } from "../../ui/formatters/result-view.js";
import { safeText, terminalWidth } from "../../ui/formatters/style.js";
import { cliText, type CliText } from "../../ui/i18n/cli-text.js";
import type { PreviousScan } from "../../flows/scan-diff-summary.js";
import { offerPanels } from "../../flows/panels.js";
import { loadTrend } from "../../flows/trend.js";
import type { TrendData } from "../../ui/panels/types.js";
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
  /** `json`: stdout carries only the redacted ScanResult, `sarif` only its SARIF 2.1.0 form; everything else goes to stderr. */
  format?: OutputFormat;
  /** List every finding and location in the text result. */
  allFindings?: boolean;
  /** `--panels`: open the full-screen panel view after the text result. */
  panels?: boolean;
  /** `--no-store`. */
  noStore?: boolean;
  /** `--full`: scan everything again instead of building on the last stored scan. */
  full?: boolean;
  /** `pgard baseline set --from-current`: after the scan, store it as the baseline. */
  setBaseline?: boolean;
}

/** `json` and `sarif` both keep stdout for one document; everything else goes to stderr. */
export function isMachineFormat(format: OutputFormat | undefined): boolean {
  return format === "json" || format === "sarif";
}

export const JSON_PORT_REQUIRED_MESSAGE =
  "--format json cannot ask which local service to scan. Pass --port N with web checks, or scan code or history only.";

/** One progress line in the terminal language; unknown stages and messages stay as written. */
export function formatProgress(
  event: ScanProgressEvent,
  t: CliText = cliText("en"),
): string | null {
  if (event.web !== undefined) {
    return t.progress.pagesChecked(event.web.pagesVisited);
  }
  if (t.locale === "en") {
    return `  ${event.stage}: ${event.status}${event.message === "" ? "" : ` - ${safeText(event.message, 200)}`}`;
  }
  // Korean: stage and status words; only messages with a known translation are added.
  const stage = t.progress.stage[event.stage] ?? event.stage;
  const status = t.progress.status[event.status] ?? event.status;
  const message =
    t.progress.message[event.message] ?? t.progress.scoped(event.message, t.progress.stage);
  return `  ${stage}: ${status}${message === undefined ? "" : ` - ${message}`}`;
}

/**
 * Shared flow for every `pgard scan` variant: Git root, report pre-checks, (web) authorization
 * and target confirmation, then `runScan`, which runs the authorization gate again itself.
 */
export async function runScanCommand(
  context: CommandContext,
  command: ScanCommand,
): Promise<ExitCode> {
  const isJson = isMachineFormat(command.format);
  if (isJson && SCOPES_BY_VARIANT[command.variant].includes("web") && command.port === null) {
    // Fail before any network activity: the only way to choose a port is a prompt.
    err(
      context,
      context.errStyle.red(
        command.format === "sarif"
          ? JSON_PORT_REQUIRED_MESSAGE.replace("--format json", "--format sarif")
          : JSON_PORT_REQUIRED_MESSAGE,
      ),
    );
    return EXIT_CODES.usage;
  }
  if (!isJson) {
    return runScanFlow(context, command, {
      show: (result, previous) => showText(context, result, command, previous),
      finish: () => undefined,
    });
  }
  // In JSON mode nothing but the result may reach stdout: every message and every prompt (the
  // port confirmation, the install guide, the in-repository report question) goes to stderr.
  // The key reader stays, so raw mode is suspended during long work. Stdout gets exactly one
  // document: the final result, after any guided install and re-check.
  const flowContext: CommandContext = {
    ...context,
    io: { ...context.io, stdout: context.io.stderr },
    style: context.errStyle,
    canOpenBrowser: false,
  };
  return runScanFlow(flowContext, command, {
    show: () => undefined,
    finish: (result) => {
      if (command.format === "sarif") warnAboutSarif(context, result);
      const document =
        command.format === "sarif" ? buildSarif(result, getRuleTextCatalog()) : result;
      context.io.stdout.write(`${JSON.stringify(document, null, 2)}\n`);
    },
  });
}

function warnAboutSarif(context: CommandContext, result: ScanResult): void {
  const omitted = countSarifOmitted(result);
  if (omitted > 0) {
    err(
      context,
      context.errStyle.yellow(
        `${omitted} findings without a file location (web, ...) are not in SARIF; see the text/JSON output or report.`,
      ),
    );
  }
  if (sarifScanDidNotRun(result)) {
    err(context, context.errStyle.red("Do not upload this SARIF: the scan did not run."));
  } else if (sarifScanIncomplete(result)) {
    err(
      context,
      context.errStyle.red(
        "Do not upload this SARIF: some requested areas did not complete (their alerts would be closed).",
      ),
    );
  }
}

/** Rule texts in the terminal language; the stored and JSON result stay English. */
function localizeResult(context: CommandContext, result: ScanResult): ScanResult {
  const locale = context.ruleLocale ?? "en";
  if (locale === "en" || context.ruleTexts === undefined) return result;
  return { ...result, findings: localizeFindings(result.findings, context.ruleTexts, locale) };
}

function showText(
  context: CommandContext,
  result: ScanResult,
  command: ScanCommand,
  previous: PreviousScan | null,
): void {
  out(context, "");
  out(
    context,
    formatScanResult(localizeResult(context, result), context.style, {
      allFindings: command.allFindings === true,
      locale: context.ruleLocale ?? "en",
      width: terminalWidth(context.io.stdout, context.io.env),
      ...(context.ruleTexts === undefined ? {} : { ruleTexts: context.ruleTexts }),
      diff: scanDiffOf(result, previous),
      // A terminal gets the compact layout with the summary last; a pipe or file keeps the
      // stable form that scripts may parse.
      isTerminal: context.io.stdout.isTTY === true,
    }),
  );
}

interface ResultOutput {
  /** Every scan attempt's result, as it arrives (text mode prints it before any install offer). */
  show: (result: ScanResult, previous: PreviousScan | null) => void;
  /** The final result, once (JSON mode prints it here). */
  finish: (result: ScanResult) => void;
}

async function runScanFlow(
  context: CommandContext,
  command: ScanCommand,
  { show, finish }: ResultOutput,
): Promise<ExitCode> {
  const isJson = isMachineFormat(command.format);
  // Fixed screen text in the terminal language; machine-format output is never translated.
  const text = cliText(context.ruleLocale);
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
    let isBlockedEarly = false;
    if (outcome.summary.decision !== "allowed") {
      out(context, formatAuthorization(outcome.summary, context.style));
      if (isJson) {
        // No port is probed without authorization. The scan below runs the gate again and
        // produces the blocked result, which is the one JSON document on stdout.
        isBlockedEarly = true;
      } else {
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
    }
    if (isBlockedEarly) {
      // Nothing to confirm: the scan will be blocked.
    } else if (context.keys === null) {
      err(context, context.errStyle.yellow(text.notices.webNotConfirmed));
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
    err(context, context.errStyle.dim(text.progress.scanning(scopes.join(", "))));
    suspendKeys(context);
    let outcome: AuthorizationOutcome | null = null;
    // Web checks are always live; the local scopes build on the last stored scan when they can.
    const incremental = createIncrementalHandle(context, {
      noStore: command.noStore === true,
      full: command.full === true,
    });
    try {
      const scanned = await context.deps.runScan(
        { projectRoot, scopes, webTarget },
        {
          authorization,
          webScanner: context.deps.webScanner,
          webRules: WEB_RULE_LIST,
          signal: context.signal,
          env: context.io.env,
          incremental: incremental.dependencies,
          onAuthorization: (received) => {
            outcome = received;
          },
          onProgress: (event) => {
            const line = formatProgress(event, text);
            if (line !== null) err(context, context.errStyle.dim(line));
          },
        },
      );
      const finished = outcome as AuthorizationOutcome | null;
      // The baseline only changes how findings are grouped; it runs after the gate and cannot
      // change the status, the exit code or authorization.
      const withBaseline = await applyStoredBaseline(
        context,
        scanned,
        finished,
        command.noStore === true,
      );
      return { result: withBaseline, outcome: finished, state: incremental.takeState() };
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
  // Read before the result is shown (the summary says what changed) and before it is saved.
  let previous = isJson
    ? null
    : await loadPreviousScan(context, scanned.result, scanned.outcome, command.noStore === true);
  show(scanned.result, previous);
  if (scanned.result.overallStatus === "blocked" && scanned.outcome !== null) {
    const guided = await offerGuidedInstall(context, scanned.outcome, projectRoot, authorization);
    throwIfCancelled(context);
    if (guided === "reauthorize") {
      scanned = await scanOnce();
      if (scanned === null) return EXIT_CODES.usage;
      previous = await loadPreviousScan(
        context,
        scanned.result,
        scanned.outcome,
        command.noStore === true,
      );
      show(scanned.result, previous);
    }
  }
  const { result } = scanned;
  finish(result);
  let exitCode = exitCodeForStatus(result.overallStatus);

  if (result.overallStatus === "blocked") {
    if (command.report !== null) out(context, text.notices.noReportBlocked);
    if (command.panels === true) err(context, context.errStyle.dim(text.panels.notOpenedBlocked));
    return exitCode;
  }
  await storeScanResult(
    context,
    result,
    scanned.outcome,
    projectRoot,
    command.noStore === true,
    isJson,
    isJson ? undefined : previous,
    scanned.state,
  );
  let isBaselineSaved = true;
  if (command.setBaseline === true) {
    isBaselineSaved = await setBaselineFromScan(context, result, scanned.outcome, projectRoot);
  }
  // The panel view comes before any follow-up question (the report offer in the menu), and after
  // a report asked for on the command line is saved, so a cancel inside it loses nothing.
  const panelsResult = (): ScanResult => localizeResult(context, result);
  const wantsPanels = command.panels === true;
  // `baseline set --from-current` only uses the scan; it does not open the panel view by itself.
  const isBaselineRun = command.setBaseline === true;
  const trendLoader = (): Promise<TrendData> =>
    loadTrend(context, scanned.outcome, command.noStore === true, result.scanId);
  let isReportSaved = true;
  // `e` in the panel view: the same prompts and save as the menu's report question.
  const exportFromPanels = (): Promise<ReportExportOutcome> =>
    runReportExport(context, result, projectRoot);
  if (command.report !== null && reportDir !== null) {
    isReportSaved = await saveReports(context, result, command.report.format, reportDir);
    if (!isJson) {
      const isPanelExportOk = await offerPanels(
        context,
        panelsResult(),
        wantsPanels,
        !isBaselineRun,
        trendLoader,
        exportFromPanels,
      );
      isReportSaved = isReportSaved && isPanelExportOk;
    }
  } else {
    // Machine formats keep the terminal untouched: the panel view never opens for them.
    if (!isJson) {
      isReportSaved = await offerPanels(
        context,
        panelsResult(),
        wantsPanels,
        !isBaselineRun,
        trendLoader,
        exportFromPanels,
      );
    }
    if (context.isMenu) {
      isReportSaved = (await offerReportExport(context, result, projectRoot)) && isReportSaved;
    }
  }
  if (!(isReportSaved && isBaselineSaved) && exitCode === EXIT_CODES.ok) {
    exitCode = EXIT_CODES.partial;
  }
  return exitCode;
}

/** `baseline set --from-current`: the scan that just ran becomes the baseline. */
async function setBaselineFromScan(
  context: CommandContext,
  result: ScanResult,
  outcome: AuthorizationOutcome | null,
  projectRoot: string,
): Promise<boolean> {
  const store = context.deps.openResultStore(context.io.env);
  const repositoryId = outcome?.repositoryId;
  if (
    store === null ||
    outcome === null ||
    !isAuthorizationAllowed(outcome) ||
    typeof repositoryId !== "number" ||
    result.overallStatus === "failed"
  ) {
    err(context, context.errStyle.red(cliText(context.ruleLocale).notices.baselineNotSet));
    return false;
  }
  return (await storeBaseline(context, store, result, repositoryId, projectRoot, null)) === 0;
}
