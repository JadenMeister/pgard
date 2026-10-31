import { lstat, mkdir, realpath, stat } from "node:fs/promises";
import path from "node:path";
import type { ScanResult } from "@pgard/findings";
import { ReportWriteError, type ReportFormat, type WrittenReport } from "@pgard/report";
import { err, out, promptContextOf, type CommandContext } from "../context.js";
import { BACK, promptChoice, promptConfirm, promptText } from "../ui/components/prompts.js";
import { safeText } from "../ui/formatters/style.js";
import { cliText } from "../ui/i18n/cli-text.js";
import {
  defaultReportDir,
  expandHome,
  isInside,
  realFileAccess,
  reportHome,
  shownDir,
} from "./report-dir.js";

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
  const home = reportHome(context.io.env, context.deps.platform);
  const text = cliText(context.ruleLocale).commands.report;
  const isOption = source === "option";
  // `~user` is not expanded (it would be a folder named `~user` under the cwd): same hint as the prompt.
  if (isTildeUser(outputDir, context.deps.platform)) {
    return { kind: "invalid", message: text.tildeUser };
  }
  const absolute = path.resolve(context.io.cwd, expandHome(outputDir, home, context.deps.platform));
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

/** `~name/...`: a `~` that is not `~`, `~/` or (Windows) `~\\`; it is not expanded. */
function isTildeUser(typed: string, platform: NodeJS.Platform): boolean {
  if (!typed.startsWith("~") || typed === "~") return false;
  const next = typed[1];
  return !(next === "/" || (platform === "win32" && next === "\\"));
}

/**
 * Why a folder was not created: `policy` (outside home), `link` (a link on the path), `owner` (a
 * level owned by another user), `home-owner` (this process is not the home folder's owner, for
 * example `sudo`, or its user id is unknown), `writable` (the closest existing parent can be
 * changed by others) or `io` (the file system said no). `folder` names the folder a `writable`
 * refusal is about.
 */
export type CreateOutcome =
  "created" | "policy" | "link" | "owner" | "home-owner" | "writable" | "io";
export interface CreateResult {
  outcome: CreateOutcome;
  folder?: string;
}

/**
 * Creates a folder the user asked for, one level at a time (mode 0700, no `recursive`). The
 * process must run as the owner of the home folder (not `sudo -E`), the closest existing parent
 * must lie inside the home folder once links are resolved and must not be changeable by others
 * (a group-writable folder is fine when it is yours and its group is your primary group, or when
 * it is your home folder; an others-writable one only when sticky and yours), every level made
 * here must be a real directory (not a link) owned by this user and must still resolve inside
 * home right after it is made, so a link cannot send the new folder somewhere else.
 */
export async function createReportDir(
  target: string,
  home: string | null,
  platform: NodeJS.Platform,
  ids: { uid: number | undefined; gid: number | undefined },
): Promise<CreateResult> {
  if (home === null) return { outcome: "policy" };
  try {
    const realHome = await realpath(home);
    // Windows has no uid; its folders are refused only by the home and link checks.
    const owner = platform === "win32" ? undefined : (await stat(realHome)).uid;
    if (platform !== "win32" && ids.uid !== owner) return { outcome: "home-owner" };
    let parent = path.dirname(target);
    for (;;) {
      if ((await stat(parent).catch(() => null))?.isDirectory() === true) break;
      const next = path.dirname(parent);
      if (next === parent) return { outcome: "io" };
      parent = next;
    }
    const realParent = await realpath(parent);
    if (!isInside(realParent, realHome, platform)) return { outcome: "policy" };
    if (owner !== undefined) {
      const info = await stat(realParent);
      const isMine = info.uid === owner;
      const isSticky = (info.mode & 0o1000) !== 0;
      const isHome = realParent === realHome;
      const isOwnGroup = ids.gid !== undefined && info.gid === ids.gid;
      const othersCanWrite = (info.mode & 0o002) !== 0 && !(isSticky && isMine);
      const groupCanWrite = (info.mode & 0o020) !== 0 && !(isMine && (isOwnGroup || isHome));
      if (othersCanWrite || groupCanWrite) return { outcome: "writable", folder: realParent };
    }
    let current = parent;
    for (const name of path.relative(parent, target).split(path.sep)) {
      current = path.join(current, name);
      await mkdir(current, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => {
        if (error.code !== "EEXIST") throw error;
      });
      const info = await lstat(current);
      if (info.isSymbolicLink() || !info.isDirectory()) return { outcome: "link" };
      if (owner !== undefined && info.uid !== owner) return { outcome: "owner" };
      if (!isInside(await realpath(current), realHome, platform)) return { outcome: "policy" };
    }
    return { outcome: isInside(await realpath(target), realHome, platform) ? "created" : "policy" };
  } catch {
    return { outcome: "io" };
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
  const platform = context.deps.platform;
  const home = reportHome(context.io.env, platform);
  const suggested = await defaultReportDir({
    platform,
    env: context.io.env,
    home,
    ...realFileAccess,
  });
  const shown = suggested === null ? null : safeText(shownDir(suggested, home, platform), 500);
  for (;;) {
    const typed = await promptText(prompts, text.outputDirPrompt(shown));
    if (typed === BACK) return "cancelled";
    const chosen = typed.trim() === "" ? suggested : typed.trim();
    if (chosen === null) {
      out(context, context.style.red(text.typeFolder));
      continue;
    }
    if (isTildeUser(chosen, platform)) {
      out(context, context.style.red(text.tildeUser));
      continue;
    }
    let check = await checkOutputDir(context, chosen, projectRoot, "prompt");
    let isConfirmedInside = false;
    if (check.kind === "invalid" && check.missing !== undefined) {
      const missing = check.missing;
      const question = text.createQuestion(safeText(shownDir(missing, home, platform), 500));
      if (!(await promptConfirm(prompts, question))) continue;
      if (await context.deps.isPathInsideDirectory(missing, projectRoot)) {
        if (!(await confirmInsideRepository(context))) continue;
        isConfirmedInside = true;
      }
      const created = await createReportDir(missing, home, platform, {
        uid: context.deps.currentUid(),
        gid: context.deps.currentGid(),
      });
      if (created.outcome !== "created") {
        const refusals = {
          policy: text.homeOnly,
          link: text.linkRefused,
          owner: text.otherUserRefused,
          "home-owner": text.homeOwnedByOther(safeText(home ?? "", 500)),
          writable: text.parentWritable(safeText(created.folder ?? "", 500)),
          io: text.cannotCreate,
        };
        out(context, context.style.red(refusals[created.outcome]));
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
