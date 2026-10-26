import type { CliIo, KeyReader } from "./adapters/terminal.js";
import type { CliDeps } from "./deps.js";
import { UserCancelledError, type PromptContext } from "./ui/components/prompts.js";
import type { Style } from "./ui/formatters/style.js";

/** Per-invocation state, in memory only. (The GitHub sign-in is kept in the OS keychain by the session provider.) */
export interface CommandContext {
  io: CliIo;
  deps: CliDeps;
  /** Style for stdout (results, prompts). */
  style: Style;
  /** Style for stderr (progress, warnings). */
  errStyle: Style;
  /** `null` when stdin/stdout are not a TTY: no prompts, no confirmations. */
  keys: KeyReader | null;
  /** Aborted when the user confirms cancellation during a running scan. */
  signal: AbortSignal;
  /**
   * May offer to open GitHub pages (device sign-in, App install) in the browser: stdout is a TTY
   * and `--no-browser` was not given. Pages open only after the user presses Enter
   * (`offerBrowserOpen`). The URL is always printed as well.
   */
  canOpenBrowser: boolean;
  /** True inside the arrow-key menu (enables follow-up prompts such as report export). */
  isMenu: boolean;
  /** Stops listening for SIGINT (e.g. before handing the terminal to the dashboard process). */
  releaseInterrupts: () => void;
}

/**
 * Call before long-running work: leaves raw mode so Ctrl+C arrives as SIGINT and reaches the
 * cancel controller instead of being queued for the next prompt.
 */
export function suspendKeys(context: CommandContext): void {
  context.keys?.suspend();
}

export function out(context: CommandContext, text: string): void {
  context.io.stdout.write(`${text}\n`);
}

export function err(context: CommandContext, text: string): void {
  context.io.stderr.write(`${text}\n`);
}

export function promptContextOf(context: CommandContext, helpText: string): PromptContext | null {
  if (context.keys === null) return null;
  return { keys: context.keys, out: context.io.stdout, style: context.style, helpText };
}

/**
 * After work that honours `context.signal` (e.g. the device-flow wait inside verifyProject),
 * a confirmed Ctrl+C must end as a cancellation (exit 130), not as a blocked gate (exit 3).
 */
export function throwIfCancelled(context: CommandContext): void {
  if (context.signal.aborted) throw new UserCancelledError();
}
