import { mkdir, realpath, stat } from "node:fs/promises";
import path from "node:path";
import type { ScanResult } from "@pgard/findings";
import { ReportWriteError, type ReportFormat, type WrittenReport } from "@pgard/report";
import { err, out, promptContextOf, type CommandContext } from "../context.js";
import { BACK, promptChoice, promptConfirm, promptText } from "../ui/components/prompts.js";
import { safeText } from "../ui/formatters/style.js";
import { codeOnlyHome } from "../home-dir.js";
import { cliText } from "../ui/i18n/cli-text.js";
import { defaultReportDir, expandHome, realFileAccess, shownDir } from "./report-dir.js";

export type OutputDirCheck =
  | { kind: "ok"; outputDir: string; isInsideRepository: boolean }
  /** `missing`: set when the folder does not exist, with its absolute path. */
  | { kind: "invalid"; message: string; missing?: string };

/** Validates that the output directory exists and whether it lies inside the repository. */
export async function checkOutputDir(
  context: CommandContext,
  outputDir: string,
  projectRoot: string,
  /** `option`: the path came from `--output-dir`; `prompt`: the user typed it in the menu. */
  source: "option" | "prompt" = "option",
): Promise<OutputDirCheck> {
  const home = codeOnlyHome(context.io.env);
  const absolute = path.resolve(context.io.cwd, expandHome(outputDir, home, context.deps.platform));
  const text = cliText(context.ruleLocale).commands.report;
  const isOption = source === "option";
  try {
    const info = await stat(absolute);
    if (!info.isDirectory()) return { kind: "invalid", message: text.notDirectory(isOption) };
  } catch (error) {
    const isMissing = (error as NodeJS.ErrnoException).code === "ENOENT";
    return {
      kind: "invalid",
      message: text.missingDirectory(isOption),
      ...(isMissing && !isOption ? { missing: absolute } : {}),
    };
  }
  return {
    kind: "ok",
    outputDir: absolute,
    isInsideRepository: await context.deps.isPathInsideDirectory(absolute, projectRoot),
  };
}

/**
 * Creates a folder the user asked for (mode 0700, with missing parents). It is refused unless the
 * closest existing parent is a real folder that lies inside the home folder once links are
 * resolved, so a link cannot send the new folder somewhere else.
 */
async function createReportDir(target: string, home: string | null): Promise<boolean> {
  if (home === null) return false;
  try {
    let parent = path.dirname(target);
    for (;;) {
      if ((await stat(parent).catch(() => null))?.isDirectory() === true) break;
      const next = path.dirname(parent);
      if (next === parent) return false;
      parent = next;
    }
    const relative = path.relative(await realpath(home), await realpath(parent));
    if (relative.startsWith("..") || path.isAbsolute(relative)) return false;
    await mkdir(target, { recursive: true, mode: 0o700 });
    return true;
  } catch {
    return false;
  }
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

/** Writes the report files; returns false (exit 4) when writing failed. */
export async function saveReports(
  context: CommandContext,
  result: ScanResult,
  format: ReportFormat,
  outputDir: string,
  /**
   * Files this session already saved. They are never overwritten; a planned file in the set is
   * reported as already saved, and the attempt counts as saved when every file was written or
   * skipped this way.
   */
  savedPaths?: Set<string>,
  /** Filled by the call: the files written (or skipped) and the code of a write failure. */
  outcome?: { written: WrittenReport[]; errorCode?: string },
): Promise<boolean> {
  const text = cliText(context.ruleLocale).commands.report;
  try {
    const written = await context.deps.writeReports(result, {
      format,
      outputDir,
      ...(savedPaths === undefined ? {} : { skipExisting: savedPaths }),
      ...(context.reportLocale === undefined ? {} : { lang: context.reportLocale }),
      ...(context.ruleTexts === undefined ? {} : { ruleTexts: context.ruleTexts }),
    });
    outcome?.written.push(...written);
    for (const entry of written) {
      if (entry.skipped === true) {
        out(context, text.alreadySaved(safeText(entry.filePath, 500)));
        continue;
      }
      savedPaths?.add(entry.filePath);
      await realpath(entry.filePath).then(
        (real) => savedPaths?.add(real),
        () => undefined,
      );
      out(context, text.saved(entry.format.toUpperCase(), safeText(entry.filePath, 500)));
      if (entry.warning !== undefined) err(context, text.warning(safeText(entry.warning, 500)));
    }
    return true;
  } catch (error) {
    if (outcome !== undefined && error instanceof ReportWriteError) outcome.errorCode = error.code;
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
  savedPaths?: Set<string>,
): Promise<boolean> {
  return (await runReportExport(context, result, projectRoot, savedPaths)) !== "failed";
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
  const home = codeOnlyHome(context.io.env);
  const platform = context.deps.platform;
  const suggested = await defaultReportDir({
    platform,
    env: context.io.env,
    home,
    ...realFileAccess,
  });
  const shown = suggested === null ? null : shownDir(suggested, home, platform);
  for (;;) {
    const typed = await promptText(prompts, text.outputDirPrompt(shown));
    if (typed === BACK) return "cancelled";
    const chosen = typed.trim() === "" ? suggested : typed.trim();
    if (chosen === null) continue;
    let check = await checkOutputDir(context, chosen, projectRoot, "prompt");
    let isConfirmedInside = false;
    if (check.kind === "invalid" && check.missing !== undefined) {
      const missing = check.missing;
      if (!(await promptConfirm(prompts, text.createQuestion))) continue;
      if (await context.deps.isPathInsideDirectory(missing, projectRoot)) {
        if (!(await confirmInsideRepository(context))) continue;
        isConfirmedInside = true;
      }
      if (!(await createReportDir(missing, home))) {
        out(context, context.style.red(text.cannotCreate));
        continue;
      }
      check = await checkOutputDir(context, missing, projectRoot, "prompt");
    }
    if (check.kind === "invalid") {
      out(context, context.style.red(check.message));
      continue;
    }
    if (
      check.isInsideRepository &&
      !isConfirmedInside &&
      !(await confirmInsideRepository(context))
    ) {
      continue;
    }
    return (await saveReports(context, result, format, check.outputDir, savedPaths))
      ? "saved"
      : "failed";
  }
}
