import type { ScanResult } from "@pgard/findings";
import { err, promptContextOf, type CommandContext } from "../context.js";
import { promptConfirm, UserCancelledError } from "../ui/components/prompts.js";
import { cliText } from "../ui/i18n/cli-text.js";
import { renderPanelsOnce, runPanelsScreen } from "../ui/panels/controller.js";

/** Hidden: `1` renders one plain frame to stdout instead of the interactive view (CI, tests). */
export const PANELS_ONCE_ENV = "PGARD_PANELS_ONCE";

/**
 * The full-screen panel view over a finished scan. Called after the text result, the stored
 * result and any report.
 * - `--panels` in a terminal opens it; a menu scan asks first.
 * - Without a terminal (CI, a pipe) it never opens: the text result already printed is all there
 *   is, with a one-line note on stderr when `--panels` was asked for.
 * - `PGARD_PANELS_ONCE=1` with `--panels` prints one frame and reads no keys.
 * A confirmed Ctrl+C inside the view ends the command with exit code 130, like any prompt.
 */
export async function offerPanels(
  context: CommandContext,
  result: ScanResult,
  isRequested: boolean,
): Promise<void> {
  const locale = context.ruleLocale ?? "en";
  const t = cliText(locale);
  const { io } = context;
  if (isRequested && io.env[PANELS_ONCE_ENV] === "1") {
    renderPanelsOnce({ result, locale, stdout: io.stdout, env: io.env });
    return;
  }
  const keys = context.keys;
  const prompts = promptContextOf(context, t.panels.helpLines.join("\n"));
  if (keys === null || prompts === null || io.stdout.isTTY !== true) {
    if (isRequested) err(context, context.errStyle.dim(t.panels.notTerminal));
    return;
  }
  if (!isRequested) {
    if (!context.isMenu || !(await promptConfirm(prompts, t.panels.offer))) return;
  }
  const exit = await runPanelsScreen({ result, locale, stdout: io.stdout, env: io.env, keys });
  if (exit === "cancel") throw new UserCancelledError();
}
