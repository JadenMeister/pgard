import { stat } from "node:fs/promises";
import path from "node:path";
import type { ScanResult } from "@pgard/findings";
import { ReportWriteError, type ReportFormat } from "@pgard/report";
import { err, out, promptContextOf, type CommandContext } from "../context.js";
import { BACK, promptChoice, promptConfirm, promptText } from "../ui/components/prompts.js";
import { safeText } from "../ui/formatters/style.js";
import { cliText } from "../ui/i18n/cli-text.js";

export type OutputDirCheck =
  | { kind: "ok"; outputDir: string; isInsideRepository: boolean }
  | { kind: "invalid"; message: string };

/** Validates that the output directory exists and whether it lies inside the repository. */
export async function checkOutputDir(
  context: CommandContext,
  outputDir: string,
  projectRoot: string,
  /** `option`: the path came from `--output-dir`; `prompt`: the user typed it in the menu. */
  source: "option" | "prompt" = "option",
): Promise<OutputDirCheck> {
  const absolute = path.resolve(context.io.cwd, outputDir);
  const text = cliText(context.ruleLocale).commands.report;
  const isOption = source === "option";
  try {
    const info = await stat(absolute);
    if (!info.isDirectory()) return { kind: "invalid", message: text.notDirectory(isOption) };
  } catch {
    return { kind: "invalid", message: text.missingDirectory(isOption) };
  }
  return {
    kind: "ok",
    outputDir: absolute,
    isInsideRepository: await context.deps.isPathInsideDirectory(absolute, projectRoot),
  };
}

/**
 * Asks for explicit confirmation when the directory is inside the repository. Without a
 * terminal there is no way to confirm, so the answer is no.
 */
export async function confirmInsideRepository(context: CommandContext): Promise<boolean> {
  const text = cliText(context.ruleLocale).commands.report;
  err(context, context.errStyle.yellow(text.warning(text.insideRepositoryWarning)));
  const prompts = promptContextOf(context, text.help);
  if (prompts === null) {
    err(context, text.cannotConfirm);
    return false;
  }
  return promptConfirm(prompts, text.confirmInside);
}

/** Start of the message `writeReports` gives for a file that already exists. */
const REFUSAL_PREFIX = "Refusing to overwrite existing file: ";

/** Writes the report files; returns false (exit 4) when writing failed. */
export async function saveReports(
  context: CommandContext,
  result: ScanResult,
  format: ReportFormat,
  outputDir: string,
  /** Paths this session already saved: refusing to overwrite one of them is not a failure. */
  savedPaths?: Set<string>,
): Promise<boolean> {
  const text = cliText(context.ruleLocale).commands.report;
  try {
    const written = await context.deps.writeReports(result, {
      format,
      outputDir,
      ...(context.reportLocale === undefined ? {} : { lang: context.reportLocale }),
      ...(context.ruleTexts === undefined ? {} : { ruleTexts: context.ruleTexts }),
    });
    for (const entry of written) {
      savedPaths?.add(entry.filePath);
      out(context, text.saved(entry.format.toUpperCase(), safeText(entry.filePath, 500)));
      if (entry.warning !== undefined) err(context, text.warning(safeText(entry.warning, 500)));
    }
    return true;
  } catch (error) {
    if (error instanceof ReportWriteError && error.code === "file_exists") {
      const existing = error.message.slice(REFUSAL_PREFIX.length);
      if (error.message.startsWith(REFUSAL_PREFIX) && savedPaths?.has(existing) === true) {
        out(context, text.alreadySaved(safeText(existing, 500)));
        return true;
      }
    }
    const message = error instanceof ReportWriteError ? error.message : text.unexpectedWriteError;
    err(context, context.errStyle.red(text.notSaved(safeText(message, 500))));
    return false;
  }
}

/** How an export offer ended: a report was written, writing failed, or nothing was asked/saved. */
export type ReportExportOutcome = "saved" | "failed" | "cancelled";

/** Menu follow-up: offer to save a report after the result was shown. */
export async function offerReportExport(
  context: CommandContext,
  result: ScanResult,
  projectRoot: string,
): Promise<boolean> {
  return (await runReportExport(context, result, projectRoot)) !== "failed";
}

/** The export prompts and save, shared by the menu follow-up and the panel view's `e` key. */
export async function runReportExport(
  context: CommandContext,
  result: ScanResult,
  projectRoot: string,
  savedPaths?: Set<string>,
): Promise<ReportExportOutcome> {
  const text = cliText(context.ruleLocale).commands.report;
  const prompts = promptContextOf(context, text.help);
  if (prompts === null || result.overallStatus === "blocked") return "cancelled";
  const format = await promptChoice<ReportFormat | "none">(prompts, text.savePrompt, [
    { label: text.no, value: "none" },
    { label: "HTML", value: "html" },
    { label: "PDF", value: "pdf" },
    { label: text.both, value: "both" },
  ]);
  if (format === BACK || format === "none") return "cancelled";
  for (;;) {
    const typed = await promptText(prompts, text.outputDirPrompt);
    if (typed === BACK) return "cancelled";
    if (typed.trim() === "") continue;
    const check = await checkOutputDir(context, typed.trim(), projectRoot, "prompt");
    if (check.kind === "invalid") {
      out(context, context.style.red(check.message));
      continue;
    }
    if (check.isInsideRepository && !(await confirmInsideRepository(context))) continue;
    return (await saveReports(context, result, format, check.outputDir, savedPaths))
      ? "saved"
      : "failed";
  }
}
