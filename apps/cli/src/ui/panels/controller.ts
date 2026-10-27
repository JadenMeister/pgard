import type { RuleLocale, RuleTextCatalog, ScanResult } from "@pgard/findings";
import type { KeyReader, OutputStream } from "../../adapters/terminal.js";
import { UserCancelledError } from "../components/prompts.js";
import {
  createStyle,
  isUnicodeTerminal,
  shouldUseColor,
  terminalWidth,
} from "../formatters/style.js";
import { renderFrame, type RenderOptions } from "./layout.js";
import { createPanelsState, reduce, resize } from "./reduce.js";
import type { PanelsExit, PanelsState, Size, TrendData } from "./types.js";

const ENTER_SCREEN = "\u001b[?1049h\u001b[?25l";
const LEAVE_SCREEN = "\u001b[?25h\u001b[?1049l";
const HOME = "\u001b[H";
const CLEAR_TO_LINE_END = "\u001b[K";
const CLEAR_BELOW = "\u001b[J";

export const DEFAULT_ROWS = 24;
const DEFAULT_COLUMNS = 80;

/** What the controller needs of `process`; tests pass an `EventEmitter`. */
export interface ProcessEvents {
  on: (event: string, listener: (...args: any[]) => void) => unknown;
  off: (event: string, listener: (...args: any[]) => void) => unknown;
}

export interface PanelsScreenOptions {
  result: ScanResult;
  locale: RuleLocale;
  stdout: OutputStream & { rows?: number };
  env: Readonly<Record<string, string | undefined>>;
  keys: KeyReader;
  /** Rule catalog: the standards links in the finding detail. */
  ruleTexts?: RuleTextCatalog | undefined;
  /** Stored scan history for the trend panel; default: an empty history. */
  trend?: TrendData | undefined;
  /** Default: the real process. */
  processEvents?: ProcessEvents;
}

function sizeOf(stdout: { columns?: number; rows?: number }): Size {
  const valid = (value: number | undefined, fallback: number): number =>
    typeof value === "number" && value > 0 ? Math.floor(value) : fallback;
  return {
    columns: valid(stdout.columns, DEFAULT_COLUMNS),
    rows: valid(stdout.rows, DEFAULT_ROWS),
  };
}

function renderOptionsOf(options: Pick<PanelsScreenOptions, "stdout" | "env">): RenderOptions {
  return {
    style: createStyle(shouldUseColor(options.stdout, options.env)),
    unicode: isUnicodeTerminal(options.env),
  };
}

function paint(stdout: OutputStream, lines: readonly string[]): void {
  stdout.write(
    `${HOME}${lines.map((line) => `${line}${CLEAR_TO_LINE_END}`).join("\r\n")}${CLEAR_BELOW}`,
  );
}

/**
 * Shows the panel view until Esc (`"back"`) or a confirmed Ctrl+C (`"cancel"`, the caller exits
 * 130). The alternate screen is left and the cursor shown again on every way out: a normal end,
 * an error thrown by a key read, SIGINT (`"cancel"`), SIGTERM (`"terminated"`), process exit and
 * an uncaught exception or unhandled rejection. The last two are only observed
 * (`uncaughtExceptionMonitor`, which Node also fires for rejections it turns into exceptions), so
 * Node keeps its default message and exit code. Resizing the terminal (SIGWINCH reaches Node as the stream's
 * `resize` event) redraws the frame. The caller must make sure both streams are terminals.
 */
export async function runPanelsScreen(options: PanelsScreenOptions): Promise<PanelsExit> {
  const { stdout, keys } = options;
  const events = options.processEvents ?? process;
  const renderOptions = renderOptionsOf(options);
  let state: PanelsState = createPanelsState(
    options.result,
    options.locale,
    sizeOf(stdout),
    options.ruleTexts,
    options.trend,
  );
  let isOpen = false;
  const restore = (): void => {
    if (!isOpen) return;
    isOpen = false;
    stdout.write(LEAVE_SCREEN);
  };
  const draw = (): void => {
    if (isOpen) paint(stdout, renderFrame(state, state.size, renderOptions));
  };
  let interrupt: (exit: PanelsExit) => void = () => undefined;
  const interrupted = new Promise<PanelsExit>((resolve) => {
    interrupt = resolve;
  });
  // The screen is given back at the signal itself, not later in the unwinding: a second
  // interrupt (or the exit that follows) must find the terminal already restored.
  const onInterrupt = (): void => {
    restore();
    interrupt("cancel");
  };
  const onTerminate = (): void => {
    restore();
    interrupt("terminated");
  };
  const onExit = (): void => restore();
  const onResize = (): void => {
    state = resize(state, sizeOf(stdout));
    draw();
  };
  const listen = (): void => {
    events.on("SIGINT", onInterrupt);
    events.on("SIGTERM", onTerminate);
    events.on("exit", onExit);
    events.on("uncaughtExceptionMonitor", onExit);
    stdout.on("resize", onResize);
  };
  const unlisten = (): void => {
    events.off("SIGINT", onInterrupt);
    events.off("SIGTERM", onTerminate);
    events.off("exit", onExit);
    events.off("uncaughtExceptionMonitor", onExit);
    stdout.off("resize", onResize);
  };
  listen();
  isOpen = true;
  stdout.write(ENTER_SCREEN);
  try {
    draw();
    while (state.exit === null) {
      const next = await Promise.race([
        keys.readKey(),
        interrupted.then((exit): PanelsExit => exit),
      ]).catch((error: unknown): PanelsExit => {
        // End of input (a closed terminal, Ctrl+D in line mode): nobody can press a key again,
        // so the view is left like Esc. Other errors are real.
        if (error instanceof UserCancelledError) return "back";
        throw error;
      });
      if (typeof next === "string") return next;
      state = reduce(state, next);
      draw();
    }
    return state.exit;
  } finally {
    unlisten();
    restore();
  }
}

/**
 * The non-interactive path: one frame as plain lines on stdout, no escape codes for the
 * alternate screen, no keys read. `PGARD_PANELS_ONCE=1` selects it (CI, tests, bug reports);
 * the size comes from `COLUMNS` / `LINES` (80x24 by default) so the output is reproducible.
 */
export function renderPanelsOnce(
  options: Omit<PanelsScreenOptions, "keys" | "processEvents">,
): void {
  const rows = Number(options.env.LINES);
  const size: Size = {
    columns: terminalWidth(options.stdout, options.env),
    rows: Number.isInteger(rows) && rows > 0 ? rows : DEFAULT_ROWS,
  };
  const state = createPanelsState(
    options.result,
    options.locale,
    size,
    options.ruleTexts,
    options.trend,
  );
  const lines = renderFrame(state, size, renderOptionsOf(options));
  options.stdout.write(`${lines.map((line) => line.trimEnd()).join("\n")}\n`);
}
