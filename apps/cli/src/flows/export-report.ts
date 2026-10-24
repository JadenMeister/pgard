import { stat } from "node:fs/promises";
import path from "node:path";
import type { ScanResult } from "@pgard/findings";
import { ReportWriteError, type ReportFormat } from "@pgard/report";
import { err, out, promptContextOf, type CommandContext } from "../context.js";
import { BACK, promptChoice, promptConfirm, promptText } from "../ui/components/prompts.js";
import { safeText } from "../ui/formatters/style.js";

export const REPORT_HELP = `Reports are written only to the directory you enter. Existing files are never
overwritten. Saving inside the Git repository risks committing the report.`;

export type OutputDirCheck =
  | { kind: "ok"; outputDir: string; isInsideRepository: boolean }
  | { kind: "invalid"; message: string };

/** Validates that the output directory exists and whether it lies inside the repository. */
export async function checkOutputDir(
  context: CommandContext,
  outputDir: string,
  projectRoot: string,
): Promise<OutputDirCheck> {
  const absolute = path.resolve(context.io.cwd, outputDir);
  try {
    const info = await stat(absolute);
    if (!info.isDirectory())
      return { kind: "invalid", message: "--output-dir is not a directory." };
  } catch {
    return { kind: "invalid", message: "--output-dir does not exist. Create it first." };
  }
  return {
    kind: "ok",
    outputDir: absolute,
    isInsideRepository: await context.deps.isPathInsideDirectory(absolute, projectRoot),
  };
}

const INSIDE_REPO_WARNING =
  "The output directory is inside the Git repository. A report there could be committed and shared by mistake.";

/**
 * Asks for explicit confirmation when the directory is inside the repository. Without a
 * terminal there is no way to confirm, so the answer is no.
 */
export async function confirmInsideRepository(context: CommandContext): Promise<boolean> {
  err(context, context.errStyle.yellow(`Warning: ${INSIDE_REPO_WARNING}`));
  const prompts = promptContextOf(context, REPORT_HELP);
  if (prompts === null) {
    err(
      context,
      "Cannot confirm without an interactive terminal; choose a directory outside the repository.",
    );
    return false;
  }
  return promptConfirm(prompts, "Save the report inside the repository anyway?");
}

/** Writes the report files; returns false (exit 4) when writing failed. */
export async function saveReports(
  context: CommandContext,
  result: ScanResult,
  format: ReportFormat,
  outputDir: string,
): Promise<boolean> {
  try {
    const written = await context.deps.writeReports(result, { format, outputDir });
    for (const entry of written)
      out(context, `Saved ${entry.format.toUpperCase()} report: ${safeText(entry.filePath, 500)}`);
    return true;
  } catch (error) {
    const message =
      error instanceof ReportWriteError
        ? error.message
        : "Unexpected error while writing the report.";
    err(context, context.errStyle.red(`Report not saved: ${safeText(message, 500)}`));
    return false;
  }
}

/** Menu follow-up: offer to save a report after the result was shown. */
export async function offerReportExport(
  context: CommandContext,
  result: ScanResult,
  projectRoot: string,
): Promise<boolean> {
  const prompts = promptContextOf(context, REPORT_HELP);
  if (prompts === null || result.overallStatus === "blocked") return true;
  const format = await promptChoice<ReportFormat | "none">(prompts, "Save a report?", [
    { label: "No", value: "none" },
    { label: "HTML", value: "html" },
    { label: "PDF", value: "pdf" },
    { label: "HTML and PDF", value: "both" },
  ]);
  if (format === BACK || format === "none") return true;
  for (;;) {
    const typed = await promptText(prompts, "Output directory (must exist):");
    if (typed === BACK) return true;
    if (typed.trim() === "") continue;
    const check = await checkOutputDir(context, typed.trim(), projectRoot);
    if (check.kind === "invalid") {
      out(context, context.style.red(check.message.replace("--output-dir", "That path")));
      continue;
    }
    if (check.isInsideRepository && !(await confirmInsideRepository(context))) continue;
    return saveReports(context, result, format, check.outputDir);
  }
}
