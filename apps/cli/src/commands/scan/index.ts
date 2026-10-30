import {
  buildSarif,
  countSarifOmitted,
  sarifScanDidNotRun,
  sarifScanIncomplete,
  localizeFindings,
  stringifyJsonSafely,
  type ConfirmedWebTarget,
  type KnownScanBasisReason,
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
import {
  err,
  out,
  promptContextOf,
  suspendKeys,
  throwIfCancelled,
  type CommandContext,
} from "../../context.js";
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
import { offerWebTarget, shouldOfferWebTarget } from "../../flows/offer-web-target.js";
import { selectLocalPort } from "../../flows/select-local-port.js";
import { applyStoredBaseline, storeBaseline } from "../../flows/baseline.js";
import { createIncrementalHandle } from "../../flows/incremental.js";
import { loadPreviousScan, scanDiffOf, storeScanResult } from "../../flows/store-result.js";
import type { OutputFormat, ReportRequest, ScanVariant } from "../../options.js";
import { promptConfirm, UserCancelledError } from "../../ui/components/prompts.js";
import { formatAuthorization, formatScanResult } from "../../ui/formatters/result-view.js";
import { safeText, terminalWidth } from "../../ui/formatters/style.js";
import { cliText, type CliText } from "../../ui/i18n/cli-text.js";
import type { PreviousScan } from "../../flows/scan-diff-summary.js";
import { offerPanels } from "../../flows/panels.js";
import { loadTrend } from "../../flows/trend.js";
import type { TrendData } from "../../ui/panels/types.js";
import { NOT_A_REPOSITORY_MESSAGE } from "../project/verify.js";
import { codeOnlyRefusalMessage, runCodeOnlyScanFlow } from "./code-only.js";

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
  /** `--fixes`: show the suggested-fix diffs in the text result. */
  fixes?: boolean;
  /** `--panels`: open the full-screen panel view after the text result. */
  panels?: boolean;
  /** `--no-store`. */
  noStore?: boolean;
  /** `--full`: scan everything again instead of building on the last stored scan. */
  full?: boolean;
  /**
   * `--code-only` (`scan` and `scan code`; also the menu's code-only entry): skip authorization
   * and scan the current files code-only, with no network (#414, D1).
   */
  codeOnly?: boolean;
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
  // D1: after a failed authorization, `scan` and `scan code` may ask to scan code-only, but only
  // with a terminal on both ends; a pipe, CI or a machine format sent to a pipe never asks.
  const canAskCodeOnly = context.keys !== null && context.io.stdout.isTTY === true;
  if (!isJson) {
    return runScanFlow(context, command, canAskCodeOnly, {
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
  return runScanFlow(flowContext, command, canAskCodeOnly, {
    show: () => undefined,
    finish: (result) => {
      if (command.format === "sarif") warnAboutSarif(context, result);
      const document =
        command.format === "sarif" ? buildSarif(result, getRuleTextCatalog()) : result;
      // Escaped so no repository-controlled text (a file name, a branch) can drive the terminal.
      context.io.stdout.write(`${stringifyJsonSafely(document, 2)}\n`);
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
      fixes: command.fixes === true,
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

type RepositoryBlockCode = NonNullable<AuthorizationOutcome["repositoryCode"]>;
/** The repository check's codes for "no single usable github.com remote". */
const REMOTE_FAILURES: ReadonlySet<RepositoryBlockCode> = new Set<RepositoryBlockCode>([
  "no_remote",
  "remote_not_github",
  "remote_ambiguous",
  "remote_unreadable",
]);

/**
 * Why a failed authorization leaves the result unverified, for `scanBasis.reason` of the
 * code-only scan that may follow. From fixed codes and check statuses only, never the text:
 * the folder has no usable GitHub remote or no Git history (the repository check's code), a
 * check could not be verified (a network error, a timeout, no sign-in: `check_failed`), or a
 * check did not pass (`no_approval`).
 */
export function codeOnlyReasonAfter(
  result: ScanResult,
  outcome: AuthorizationOutcome | null,
): KnownScanBasisReason {
  if (result.overallStatus === "failed") return "check_failed";
  const code = outcome?.repositoryCode ?? null;
  if (code !== null && REMOTE_FAILURES.has(code)) return "no_github_remote";
  // A repository with no commit yet has no revision to authorize, so it is reported like a
  // folder without Git (`scanBasis` has no separate code for it).
  if (code === "not_a_git_root" || code === "no_commit_history") return "not_a_git_repository";
  const first = result.authorization.checks.find((check) => check.status !== "passed");
  return first?.status === "unverifiable" ? "check_failed" : "no_approval";
}

async function runScanFlow(
  context: CommandContext,
  command: ScanCommand,
  canAskCodeOnly: boolean,
  { show, finish }: ResultOutput,
): Promise<ExitCode> {
  const isJson = isMachineFormat(command.format);
  // Fixed screen text in the terminal language; machine-format output is never translated.
  const text = cliText(context.ruleLocale);
  const runCodeOnly = (
    reason?: KnownScanBasisReason,
    isReportConfirmed = false,
  ): Promise<ExitCode> =>
    runCodeOnlyScanFlow(
      context,
      {
        report: command.report,
        isMachineFormat: isJson,
        ...(command.panels === true ? { panels: true } : {}),
        ...(reason === undefined ? {} : { reason }),
        ...(isReportConfirmed ? { isReportConfirmed: true } : {}),
      },
      {
        show: (result) => show(result, null),
        finish,
        localize: (result) => localizeResult(context, result),
        progressLine: (event) => formatProgress(event, text),
      },
    );
  // D1: `--code-only` (or the menu's code-only entry) skips authorization altogether.
  if (command.codeOnly === true) return runCodeOnly();
  // D1: only `scan` and `scan code` offer a code-only scan when authorization fails; history and
  // web checks always need it (D2). Without a terminal nothing is asked: exit 3 and a hint.
  // `baseline set --from-current` needs an authorized scan, so it never offers one.
  const offersCodeOnly =
    (command.variant === "default" || command.variant === "code") && command.setBaseline !== true;
  /**
   * After the gate did not pass: offer a code-only scan (a terminal), or say how to get one (no
   * terminal). A folder that can never be code-only scanned (home, too broad, `.git`) is refused
   * at once instead of offered. `true` when the user answered `y`.
   */
  const offerCodeOnly = async (gitRoot: string | null): Promise<boolean> => {
    // `baseline set --from-current`: the approval guidance above is all it needs.
    if (command.setBaseline === true) return false;
    if (!offersCodeOnly) {
      out(context, context.style.dim(text.codeOnly.blockedHint));
      return false;
    }
    const refusal = await codeOnlyRefusalMessage(context, gitRoot);
    if (refusal !== null) {
      err(context, context.errStyle.red(refusal));
      return false;
    }
    const prompts = canAskCodeOnly ? promptContextOf(context, text.codeOnly.promptHelp) : null;
    if (prompts === null) {
      out(context, context.style.dim(text.codeOnly.addFlagHint));
      return false;
    }
    out(context, "");
    return promptConfirm(prompts, text.codeOnly.prompt);
  };
  let scopes = SCOPES_BY_VARIANT[command.variant];
  const projectRoot = await context.deps.findGitRoot(context.io.cwd);
  if (projectRoot === null) {
    // Not a Git repository: the gate cannot pass. Exit 3 unless the user chooses code-only.
    err(context, context.errStyle.red(NOT_A_REPOSITORY_MESSAGE));
    if (await offerCodeOnly(null)) return runCodeOnly("not_a_git_repository");
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

  const sessionProvider = createSessionProvider(context);
  const authorization = authorizationDepsFor(context, sessionProvider);
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
  } else if (
    command.setBaseline !== true &&
    shouldOfferWebTarget(context, {
      isDefaultScope: command.variant === "default",
      hasPort: command.port !== null,
      isMachineFormat: isJson,
    })
  ) {
    // Interactive `pgard scan` with no scope or port: offer detected local servers. Listing the
    // ports is local; a port is only probed once the gate allows the project, as for `--port`.
    let isAllowed = false;
    // Raw mode off while looking, so Ctrl+C during discovery is a SIGINT and still cancels.
    suspendKeys(context);
    const offered = await offerWebTarget(context, {
      beforeProbe: async () => {
        // Only with a sign-in that already exists: the offer never starts a device flow. Without
        // one it is skipped, and the scan signs in as usual. When the gate then does not allow,
        // that session is cached, so the scan's own gate cannot start a second device flow.
        const session = await Promise.resolve()
          .then(() => sessionProvider.existing())
          .catch(() => null);
        if (session === null) return false;
        const outcome = await context.deps.verifyProject(projectRoot, authorization);
        isAllowed = outcome.summary.decision === "allowed";
        return isAllowed;
      },
    });
    throwIfCancelled(context);
    if (offered !== null && isAllowed) {
      // The same identity check and explicit `y` as `--port`; nothing is weaker here.
      const selection = await selectLocalPort(context, offered);
      if (selection.kind === "confirmed") {
        webTarget = selection.target;
        scopes = [...scopes, "web"];
      }
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
          advisoryDataDir: context.deps.appDataDir,
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
  // D1: the gate did not pass (blocked, or it could not finish: a network error, a timeout).
  // Every such run exits 3 with nothing stored and no panel view; `scan` and `scan code` first
  // offer a code-only scan (a terminal) or say how to get one.
  const isUnauthorized =
    result.overallStatus === "blocked" ||
    (result.overallStatus === "failed" && result.scanBasis?.authorization === "not_verified");
  if (isUnauthorized) {
    if (await offerCodeOnly(projectRoot)) {
      return runCodeOnly(codeOnlyReasonAfter(result, scanned.outcome), reportDir !== null);
    }
    finish(result);
    if (command.report !== null) out(context, text.notices.noReportBlocked);
    if (command.panels === true) err(context, context.errStyle.dim(text.panels.notOpenedBlocked));
    return EXIT_CODES.blocked;
  }
  finish(result);
  let exitCode = exitCodeForStatus(result.overallStatus);
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
  // Reports this run saved (`--report`, `e` in the panel, the menu question): never overwritten,
  // and a repeat is reported as already saved.
  const panelSavedPaths = new Set<string>();
  // `e` in the panel view: the same prompts and save as the menu's report question.
  const exportFromPanels = (): Promise<ReportExportOutcome> =>
    runReportExport(context, result, projectRoot, panelSavedPaths);
  if (command.report !== null && reportDir !== null) {
    isReportSaved = await saveReports(
      context,
      result,
      command.report.format,
      reportDir,
      panelSavedPaths,
    );
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
      isReportSaved =
        (await offerReportExport(context, result, projectRoot, panelSavedPaths)) && isReportSaved;
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
