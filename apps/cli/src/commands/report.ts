import { rmdir } from "node:fs/promises";
import type { WrittenReport } from "@pgard/report";
import { isAllowedByGate } from "@pgard/result-store";
import { isAuthorizationAllowed } from "@pgard/scan-core";
import {
  err,
  out,
  promptContextOf,
  suspendKeys,
  throwIfCancelled,
  type CommandContext,
} from "../context.js";
import { EXIT_CODES, type ExitCode } from "../exit-codes.js";
import { createSessionProvider } from "../flows/authenticate.js";
import { isStoreDisabled } from "../flows/baseline.js";
import { checkOutputDir, confirmInsideRepository, saveReports } from "../flows/export-report.js";
import { authorizationDepsFor } from "../flows/guided-install.js";
import { looksAutomated } from "../flows/panels.js";
import { formatScanTime, formatWarnings, isNewerMinor } from "../flows/scan-diff-summary.js";
import { BACK, promptChoice } from "../ui/components/prompts.js";
import { formatAuthorization } from "../ui/formatters/result-view.js";
import { safeText } from "../ui/formatters/style.js";
import { cliText } from "../ui/i18n/cli-text.js";
import { NOT_A_REPOSITORY_MESSAGE } from "./project/verify.js";

export interface ReportCommand {
  /** `null`: ask (menu only); the command line always passes a format. */
  format: "html" | "pdf" | null;
  outputDir: string | null;
  noOpen: boolean;
}

/** Whether the finished report may be opened for a person: a terminal, no automation, not opted out. */
function mayOpen(context: CommandContext, noOpen: boolean): boolean {
  const { io } = context;
  if (noOpen) return false;
  if (io.stdout.isTTY !== true || io.stdin.isTTY !== true) return false;
  return !looksAutomated(io.env);
}

function shortCommit(revision: string | null, unknown: string): string {
  return revision === null ? unknown : safeText(revision.slice(0, 12), 12);
}

/**
 * `pgard report`: renders the newest stored scan of this repository as an HTML or PDF report. No
 * scan runs.
 *
 * Repository identity is the one `pgard baseline` and the panel view use: the five repository
 * checks run first and the store is read only under the GitHub repository id that this very run
 * got back from an allowed outcome. Result files carry no repository id of their own: the
 * store's per-id directory is the key. As defence in depth, a stored result whose `target.repo`
 * whose status is blocked or failed, or that the gate did not allow, is skipped with a warning.
 * A different `target.repo` is accepted with a note: a GitHub rename keeps the id. If identity cannot be confirmed nothing
 * is read: there is no other way to a result.
 *
 * Without `--output-dir` each run writes into a fresh private directory (`mkdtemp`, 0700), so
 * nobody else can plant a file there and repeated runs never collide. An explicit directory
 * keeps the fixed-name, never-overwrite rules of `scan --report`.
 */
export async function runReport(
  context: CommandContext,
  command: ReportCommand,
): Promise<ExitCode> {
  const text = cliText(context.ruleLocale);
  const t = text.commands.reportCommand;
  if (isStoreDisabled(context, false)) {
    err(context, context.errStyle.red(t.storeOff));
    return EXIT_CODES.usage;
  }
  const store = context.deps.openResultStore(context.io.env);
  if (store === null) {
    err(context, context.errStyle.red(t.noStoreDir));
    return EXIT_CODES.internal;
  }
  const projectRoot = await context.deps.findGitRoot(context.io.cwd);
  if (projectRoot === null) {
    err(context, context.errStyle.red(NOT_A_REPOSITORY_MESSAGE));
    return EXIT_CODES.blocked;
  }

  let format = command.format;
  if (format === null) {
    const prompts = promptContextOf(context, t.formatHelp);
    if (prompts === null) {
      err(context, context.errStyle.red(t.formatHelp));
      return EXIT_CODES.usage;
    }
    const picked = await promptChoice<"html" | "pdf">(prompts, t.formatPrompt, [
      { label: "HTML", value: "html" },
      { label: "PDF", value: "pdf" },
    ]);
    if (picked === BACK) return EXIT_CODES.cancelled;
    format = picked;
  }

  // An explicit destination problem is an input error: reject it before any network activity.
  let outputDir: string | null = null;
  if (command.outputDir !== null) {
    const check = await checkOutputDir(context, command.outputDir, projectRoot);
    if (check.kind === "invalid") {
      err(context, context.errStyle.red(check.message));
      return EXIT_CODES.usage;
    }
    if (check.isInsideRepository && !(await confirmInsideRepository(context))) {
      return EXIT_CODES.usage;
    }
    outputDir = check.outputDir;
  }

  // The store is keyed by GitHub's repository id, so the checks run first, like for baselines.
  suspendKeys(context);
  const authorization = authorizationDepsFor(context, createSessionProvider(context));
  const outcome = await context.deps.verifyProject(projectRoot, authorization);
  throwIfCancelled(context);
  if (!isAuthorizationAllowed(outcome) || typeof outcome.repositoryId !== "number") {
    out(context, formatAuthorization(outcome.summary, context.style));
    err(context, context.errStyle.red(t.notVerified));
    return EXIT_CODES.blocked;
  }
  const name = safeText(outcome.repo ?? text.unknown, 120);

  const found = await store.findNewest(outcome.repositoryId, (scan) => {
    if (isNewerMinor(scan.sourceVersion)) {
      return `it uses schema version ${safeText(scan.sourceVersion, 12)}, newer than this PGARD understands.`;
    }
    if (scan.result.overallStatus === "blocked" || scan.result.overallStatus === "failed") {
      return `its status is ${scan.result.overallStatus}.`;
    }
    if (!isAllowedByGate(scan.result)) return "the authorization gate did not allow it.";
    return null;
  });
  for (const line of formatWarnings(found.warnings, text)) {
    err(context, context.errStyle.yellow(line));
  }
  if (found.scan === null) {
    err(context, context.errStyle.red(t.noResult(name)));
    return EXIT_CODES.usage;
  }
  const { result, savedAt } = found.scan;

  // The repository id is the identity; a rename or transfer keeps it, so only say so.
  const storedName = result.target.repo;
  if (storedName !== null && storedName.toLowerCase() !== (outcome.repo ?? "").toLowerCase()) {
    out(context, context.style.dim(t.renamedNote(safeText(storedName, 120))));
  }

  const scanCommit = shortCommit(result.target.revision, text.unknown);
  const scanTime = formatScanTime(savedAt);
  const headRevision = outcome.revision;
  const isStale =
    result.target.revision !== null &&
    headRevision !== null &&
    result.target.revision !== headRevision;
  if (isStale) {
    const head = shortCommit(headRevision, text.unknown);
    out(context, context.style.yellow(t.staleNote(scanTime, scanCommit, head)));
  } else {
    out(context, context.style.dim(t.usingResult(scanTime, scanCommit)));
  }

  let isPrivateDir = false;
  if (outputDir === null) {
    try {
      outputDir = await context.deps.makeReportDir();
      isPrivateDir = true;
    } catch {
      err(context, context.errStyle.red(t.cannotCreateDir));
      return EXIT_CODES.partial;
    }
    const check = await checkOutputDir(context, outputDir, projectRoot);
    if (check.kind === "invalid") {
      err(context, context.errStyle.red(check.message));
      return EXIT_CODES.partial;
    }
    outputDir = check.outputDir;
    if (check.isInsideRepository && !(await confirmInsideRepository(context))) {
      await rmdir(outputDir).catch(() => undefined);
      return EXIT_CODES.usage;
    }
  }

  const saved: { written: WrittenReport[]; errorCode?: string } = { written: [] };
  if (!(await saveReports(context, result, format, outputDir, undefined, saved))) {
    if (isPrivateDir) await rmdir(outputDir).catch(() => undefined);
    if (saved.errorCode === "file_exists") err(context, t.fileExistsHint);
    return EXIT_CODES.partial;
  }
  // Only a file this run just wrote is ever opened.
  const file = saved.written.find((entry) => entry.skipped !== true);
  if (file === undefined || !mayOpen(context, command.noOpen)) return EXIT_CODES.ok;
  if (await context.deps.openLocalFile(file.filePath)) {
    out(context, context.style.dim(t.opened));
  } else {
    err(context, context.errStyle.yellow(t.notOpened));
    err(context, t.openHint);
  }
  return EXIT_CODES.ok;
}
