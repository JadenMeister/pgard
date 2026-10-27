import type { Key, KeyReader, OutputStream } from "../../adapters/terminal.js";
import type { Style } from "../formatters/style.js";

/** Thrown when the user confirms cancellation (Ctrl+C then y). Maps to exit 130. */
export class UserCancelledError extends Error {
  constructor() {
    super("Cancelled by the user.");
    this.name = "UserCancelledError";
  }
}

export const BACK = Symbol("back");
export type Back = typeof BACK;

export interface PromptContext {
  keys: KeyReader;
  out: OutputStream;
  style: Style;
  /** Shown when the user presses `?`. */
  helpText: string;
}

function isCtrlC(key: Key): boolean {
  return key.ctrl && key.name === "c";
}

const CLEAR_LINE = "\u001b[2K\r";

/** Ctrl+C anywhere asks before cancelling; `y` cancels, anything else resumes. */
async function confirmCancel(context: PromptContext): Promise<void> {
  context.out.write(`\n${context.style.yellow("Cancel and exit? [y/N] ")}`);
  const key = await context.keys.readKey();
  context.out.write("\n");
  if (key.name === "y" || isCtrlC(key)) throw new UserCancelledError();
}

export interface Choice<T> {
  label: string;
  value: T;
  hint?: string;
}

/** Arrow-key list. Enter selects, Esc returns BACK, `?` shows help, Ctrl+C asks to cancel. */
export async function promptChoice<T>(
  context: PromptContext,
  title: string,
  choices: readonly Choice<T>[],
): Promise<T | Back> {
  let index = 0;
  const { out, style } = context;
  const labelWidth = Math.max(...choices.map((choice) => choice.label.length));
  const render = (isFirst: boolean): void => {
    if (!isFirst) out.write(`\u001b[${choices.length}A`);
    for (const [position, choice] of choices.entries()) {
      const isSelected = position === index;
      const label = `${isSelected ? ">" : " "} ${choice.label.padEnd(labelWidth)}`;
      const hint = choice.hint === undefined ? "" : style.dim(`  ${choice.hint}`);
      out.write(`${CLEAR_LINE}${isSelected ? style.inverse(label) : label}${hint}\n`);
    }
  };
  out.write(
    `${style.bold(title)} ${style.dim("(arrows to move, Enter to select, Esc to go back, ? for help)")}\n`,
  );
  render(true);
  for (;;) {
    const key = await context.keys.readKey();
    if (isCtrlC(key)) {
      await confirmCancel(context);
      render(true);
      continue;
    }
    switch (key.name) {
      case "up":
      case "k":
        index = (index - 1 + choices.length) % choices.length;
        break;
      case "down":
      case "j":
        index = (index + 1) % choices.length;
        break;
      case "return":
      case "enter": {
        const choice = choices[index];
        if (choice !== undefined) return choice.value;
        break;
      }
      case "escape":
        return BACK;
      default:
        if (key.sequence === "?") {
          out.write(`\n${context.helpText}\n\n`);
          render(true);
          continue;
        }
    }
    render(false);
  }
}

/**
 * `[y/N]` confirmation. Only an explicit `y` is yes; Enter, `n` and Esc are no. Ctrl+C asks to
 * cancel.
 */
export async function promptConfirm(context: PromptContext, question: string): Promise<boolean> {
  context.out.write(`${question} [y/N] `);
  for (;;) {
    const key = await context.keys.readKey();
    if (isCtrlC(key)) {
      await confirmCancel(context);
      context.out.write(`${question} [y/N] `);
      continue;
    }
    if (key.name === "y") {
      context.out.write("y\n");
      return true;
    }
    if (
      key.name === "n" ||
      key.name === "return" ||
      key.name === "enter" ||
      key.name === "escape"
    ) {
      context.out.write("N\n");
      return false;
    }
    if (key.sequence === "?") {
      context.out.write(`\n${context.helpText}\n${question} [y/N] `);
    }
  }
}

/**
 * `[Y/n]` confirmation. Enter and `y` are yes; `n` and Esc are no. Ctrl+C asks to cancel.
 */
export async function promptConfirmYes(context: PromptContext, question: string): Promise<boolean> {
  context.out.write(`${question} [Y/n] `);
  for (;;) {
    const key = await context.keys.readKey();
    if (isCtrlC(key)) {
      await confirmCancel(context);
      context.out.write(`${question} [Y/n] `);
      continue;
    }
    if (key.name === "y" || key.name === "return" || key.name === "enter") {
      context.out.write("Y\n");
      return true;
    }
    if (key.name === "n" || key.name === "escape") {
      context.out.write("n\n");
      return false;
    }
  }
}

/**
 * Waits for Enter (`"enter"`) or for `letter` / Esc (`"letter"`); every other key is ignored.
 * `message` is written first. Ctrl+C asks to cancel.
 */
export async function promptEnterOrLetter(
  context: PromptContext,
  message: string,
  letter: string,
): Promise<"enter" | "letter"> {
  context.out.write(`${message}\n`);
  for (;;) {
    const key = await context.keys.readKey();
    if (isCtrlC(key)) {
      await confirmCancel(context);
      context.out.write(`${message}\n`);
      continue;
    }
    if (key.name === "return" || key.name === "enter") return "enter";
    if (key.name === letter || key.name === "escape") return "letter";
  }
}

/** Single-line text input. Enter submits, Esc returns BACK, Ctrl+C asks to cancel. */
export async function promptText(
  context: PromptContext,
  question: string,
  maxLength = 1024,
): Promise<string | Back> {
  let value = "";
  context.out.write(`${question} `);
  for (;;) {
    const key = await context.keys.readKey();
    if (isCtrlC(key)) {
      await confirmCancel(context);
      context.out.write(`${question} ${value}`);
      continue;
    }
    if (key.name === "return" || key.name === "enter") {
      context.out.write("\n");
      return value;
    }
    if (key.name === "escape") {
      context.out.write("\n");
      return BACK;
    }
    if (key.name === "backspace") {
      if (value.length > 0) {
        value = value.slice(0, -1);
        context.out.write("\b \b");
      }
      continue;
    }
    const sequence = key.sequence ?? "";
    // Printable characters only; control and escape sequences are ignored.
    if (!key.ctrl && sequence.length === 1 && sequence >= " " && sequence !== "\u007f") {
      if (value.length < maxLength) {
        value += sequence;
        context.out.write(sequence);
      }
    }
  }
}
