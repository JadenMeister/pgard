import type { Severity } from "@pgard/findings";
import { sanitizeDisplayText } from "@pgard/http-local";

export interface Style {
  /** False for `NO_COLOR`, a non-TTY stream or `TERM=dumb`: plain text, no colour codes. */
  enabled: boolean;
  bold: (text: string) => string;
  dim: (text: string) => string;
  red: (text: string) => string;
  yellow: (text: string) => string;
  green: (text: string) => string;
  blue: (text: string) => string;
  inverse: (text: string) => string;
  severity: (severity: Severity, text: string) => string;
}

function wrap(open: number, close: number): (text: string) => string {
  return (text) => `\u001b[${open}m${text}\u001b[${close}m`;
}

const identity = (text: string): string => text;

export function createStyle(isColorEnabled: boolean): Style {
  if (!isColorEnabled) {
    return {
      enabled: false,
      bold: identity,
      dim: identity,
      red: identity,
      yellow: identity,
      green: identity,
      blue: identity,
      inverse: identity,
      severity: (_severity, text) => text,
    };
  }
  const red = wrap(31, 39);
  const yellow = wrap(33, 39);
  const blue = wrap(34, 39);
  const magenta = wrap(35, 39);
  return {
    enabled: true,
    bold: wrap(1, 22),
    dim: wrap(2, 22),
    red,
    yellow,
    green: wrap(32, 39),
    blue,
    inverse: wrap(7, 27),
    severity: (severity, text) => {
      switch (severity) {
        case "critical":
          return magenta(text);
        case "high":
          return red(text);
        case "medium":
          return yellow(text);
        case "low":
          return blue(text);
        case "info":
          return text;
      }
    },
  };
}

/** Colors only on a TTY, when NO_COLOR is not set and the terminal is not `TERM=dumb`. */
export function shouldUseColor(
  stream: { isTTY?: boolean },
  env: Readonly<Record<string, string | undefined>>,
): boolean {
  return (
    stream.isTTY === true &&
    (env.NO_COLOR === undefined || env.NO_COLOR === "") &&
    env.TERM !== "dumb"
  );
}

/**
 * Whether the terminal can be expected to render Unicode punctuation. Windows consoles other
 * than Windows Terminal, VS Code, ConEmu and similar still use legacy code pages; the Linux
 * virtual console has no such glyphs either.
 */
export function isUnicodeTerminal(
  env: Readonly<Record<string, string | undefined>> = process.env,
  platform: NodeJS.Platform = process.platform,
): boolean {
  if (platform !== "win32") return env.TERM !== "linux" && env.TERM !== "dumb";
  return (
    Boolean(env.WT_SESSION) ||
    Boolean(env.TERMINUS_SUBLIME) ||
    env.ConEmuTask === "{cmd::Cmder}" ||
    env.TERM_PROGRAM === "vscode" ||
    env.TERM === "xterm-256color" ||
    env.TERM === "alacritty" ||
    env.TERMINAL_EMULATOR === "JetBrains-JediTerm"
  );
}

const ASCII_FALLBACKS: ReadonlyArray<readonly [RegExp, string]> = [
  [/\u2026/g, "..."],
  [/[\u2013\u2014]/g, "-"],
  [/[\u2018\u2019]/g, "'"],
  [/[\u201c\u201d]/g, '"'],
];

/** Replaces the few Unicode punctuation marks PGARD emits with ASCII on consoles without them. */
export function toTerminalText(
  text: string,
  env: Readonly<Record<string, string | undefined>> = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  if (isUnicodeTerminal(env, platform)) return text;
  return ASCII_FALLBACKS.reduce((out, [pattern, ascii]) => out.replace(pattern, ascii), text);
}

/**
 * Every string that originates outside PGARD (findings, notes, titles, user input echoed back)
 * goes through this before reaching the terminal: no control characters, bounded length.
 */
export function safeText(value: string, maxLength = 2000): string {
  return toTerminalText(sanitizeDisplayText(value, maxLength));
}

/** Narrowest terminal that still gets bar charts; below this, charts are plain count lines. */
export const MIN_CHART_WIDTH = 60;
const DEFAULT_WIDTH = 80;

/**
 * Columns of the terminal: the stream's width on a TTY, then `COLUMNS`, then 80 (also for pipes
 * and files, which have no width).
 */
export function terminalWidth(
  stream: { isTTY?: boolean; columns?: number },
  env: Readonly<Record<string, string | undefined>>,
): number {
  if (stream.isTTY === true && typeof stream.columns === "number" && stream.columns > 0) {
    return Math.floor(stream.columns);
  }
  const fromEnv = Number(env.COLUMNS);
  return Number.isInteger(fromEnv) && fromEnv > 0 ? fromEnv : DEFAULT_WIDTH;
}
