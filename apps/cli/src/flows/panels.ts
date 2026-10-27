import type { ScanResult } from "@pgard/findings";
import { err, type CommandContext } from "../context.js";
import { UserCancelledError } from "../ui/components/prompts.js";
import { cliText } from "../ui/i18n/cli-text.js";
import { renderPanelsOnce, runPanelsScreen } from "../ui/panels/controller.js";

/** Hidden: `1` renders one plain frame to stdout instead of the interactive view (CI, tests). */
export const PANELS_ONCE_ENV = "PGARD_PANELS_ONCE";

/** SIGTERM arrived while the view was open: the command exits 143. */
export class PanelsTerminatedError extends Error {
  constructor() {
    super("Terminated.");
    this.name = "PanelsTerminatedError";
  }
}

/** `off`, `0`, `false` or `no` (any case) turn the menu's automatic panel view off. */
export const PANELS_ENV = "PGARD_PANELS";

/** The menu's automatic view setting; an unknown value keeps the default and is reported. */
function menuAutoOpen(env: Readonly<Record<string, string | undefined>>): {
  isOn: boolean;
  isUnknown: boolean;
} {
  const value = (env[PANELS_ENV] ?? "").trim().toLowerCase();
  if (["off", "0", "false", "no"].includes(value)) return { isOn: false, isUnknown: false };
  const isKnownOn = ["", "on", "1", "true", "yes"].includes(value);
  return { isOn: true, isUnknown: !isKnownOn };
}

/**
 * The full-screen panel view over a finished scan. Called after the text result (which stays on
 * the main screen) and before any follow-up question.
 * - `--panels` in a terminal opens it, whatever `PGARD_PANELS` says.
 * - A scan from the interactive menu opens it by itself in a terminal, unless
 *   `PGARD_PANELS=off` (an unknown value prints a hint and keeps it on).
 * - Without a terminal (CI, a pipe) it never opens: the text result is all there is, with a
 *   one-line note on stderr when `--panels` was asked for.
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
  if (keys === null || io.stdin.isTTY !== true || io.stdout.isTTY !== true) {
    if (isRequested) err(context, context.errStyle.dim(t.panels.notTerminal));
    return;
  }
  if (!isRequested) {
    // A failed scan has little to show; completed and partial ones open.
    if (!context.isMenu || result.overallStatus === "failed") return;
    const setting = menuAutoOpen(io.env);
    if (setting.isUnknown) err(context, context.errStyle.dim(t.panels.badEnv));
    if (!setting.isOn) return;
  }
  // The cancel controller must not print its "press Ctrl+C again" text onto the alternate screen.
  const resumeInterrupts = context.suspendInterrupts?.();
  try {
    const exit = await runPanelsScreen({ result, locale, stdout: io.stdout, env: io.env, keys });
    if (exit === "cancel") throw new UserCancelledError();
    if (exit === "terminated") throw new PanelsTerminatedError();
  } catch (error) {
    if (error instanceof UserCancelledError || error instanceof PanelsTerminatedError) throw error;
    // The terminal is already restored. The scan finished and was stored: keep its exit code.
    err(context, context.errStyle.yellow(t.panels.failed));
  } finally {
    resumeInterrupts?.();
  }
}
