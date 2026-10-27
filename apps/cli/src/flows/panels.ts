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

/** `off`, `0`, `false` or `no` (any case) turn the automatic panel view off. */
export const PANELS_ENV = "PGARD_PANELS";

/** Variables that say a build system or other automation runs the command. */
const AUTOMATION_VARIABLES = ["GITHUB_ACTIONS", "BUILDKITE", "TF_BUILD", "JENKINS_URL"];

/**
 * Whether the environment looks like automation that may allocate a pseudo-terminal (`script`,
 * `expect`, `docker run -it` in a pipeline) but has nobody to press a key: CI set to anything
 * other than empty, `0` or `false`, one of the build systems' own variables, or TERM=dumb.
 */
export function looksAutomated(env: Readonly<Record<string, string | undefined>>): boolean {
  const ci = (env.CI ?? "").trim().toLowerCase();
  if (ci !== "" && ci !== "0" && ci !== "false") return true;
  if (AUTOMATION_VARIABLES.some((name) => (env[name] ?? "") !== "")) return true;
  return env.TERM === "dumb";
}

/** The automatic view setting; an unknown value keeps the default and is reported. */
function autoOpenSetting(env: Readonly<Record<string, string | undefined>>): {
  isOn: boolean;
  isUnknown: boolean;
  /** Set to an explicit on-value: not overridden by the automation check. */
  isForcedOn: boolean;
} {
  const value = (env[PANELS_ENV] ?? "").trim().toLowerCase();
  if (["off", "0", "false", "no"].includes(value))
    return { isOn: false, isUnknown: false, isForcedOn: false };
  const isKnownOn = ["", "on", "1", "true", "yes"].includes(value);
  return { isOn: true, isUnknown: !isKnownOn, isForcedOn: isKnownOn && value !== "" };
}

/**
 * The full-screen panel view over a finished scan. Called after the text result (which stays on
 * the main screen) and before any follow-up question.
 * - `--panels` in a terminal opens it, whatever `PGARD_PANELS` says.
 * - Every scan, from the menu or `pgard scan ...`, opens it by itself in a terminal, unless
 *   `PGARD_PANELS=off` (an unknown value prints a hint and keeps it on).
 * - Without a terminal (a pipe, a file) it never opens: the text result is all there is, with a
 *   one-line note on stderr when `--panels` was asked for.
 * - The automatic opening also stays off when the environment looks automated (`CI`, the build
 *   systems' variables, TERM=dumb; see `looksAutomated`), because a pseudo-terminal there has
 *   nobody to close the view. `PGARD_PANELS=on` overrides that; `--panels` too, except with
 *   TERM=dumb, which cannot draw a full-screen view (a stderr note says so).
 * - `isAutoAllowed` is false for commands that only use the scan (`baseline set --from-current`).
 * - `PGARD_PANELS_ONCE=1` with `--panels` prints one frame and reads no keys.
 * A confirmed Ctrl+C inside the view ends the command with exit code 130, like any prompt.
 */
export async function offerPanels(
  context: CommandContext,
  result: ScanResult,
  isRequested: boolean,
  isAutoAllowed = true,
): Promise<void> {
  const locale = context.ruleLocale ?? "en";
  const t = cliText(locale);
  const { io } = context;
  if (isRequested && io.env[PANELS_ONCE_ENV] === "1") {
    renderPanelsOnce({
      result,
      locale,
      stdout: io.stdout,
      env: io.env,
      ruleTexts: context.ruleTexts,
    });
    return;
  }
  const keys = context.keys;
  if (keys === null || io.stdin.isTTY !== true || io.stdout.isTTY !== true) {
    if (isRequested) err(context, context.errStyle.dim(t.panels.notTerminal));
    return;
  }
  if (io.env.TERM === "dumb") {
    if (isRequested) err(context, context.errStyle.dim(t.panels.dumbTerminal));
    return;
  }
  if (!isRequested) {
    if (!isAutoAllowed) return;
    // A failed scan has little to show; completed and partial ones open.
    if (result.overallStatus === "failed") return;
    const setting = autoOpenSetting(io.env);
    if (setting.isUnknown) err(context, context.errStyle.dim(t.panels.badEnv));
    if (!setting.isOn) return;
    if (!setting.isForcedOn && looksAutomated(io.env)) return;
  }
  // The cancel controller must not print its "press Ctrl+C again" text onto the alternate screen.
  const resumeInterrupts = context.suspendInterrupts?.();
  try {
    const exit = await runPanelsScreen({
      result,
      locale,
      stdout: io.stdout,
      env: io.env,
      keys,
      ruleTexts: context.ruleTexts,
    });
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
