import type { Severity } from "@pgard/findings";
import { sanitizeDisplayText } from "@pgard/http-local";

export interface Style {
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

/** Colors only on a TTY and when NO_COLOR is not set. */
export function shouldUseColor(
  stream: { isTTY?: boolean },
  env: Readonly<Record<string, string | undefined>>,
): boolean {
  return stream.isTTY === true && (env.NO_COLOR === undefined || env.NO_COLOR === "");
}

/**
 * Every string that originates outside PGARD (findings, notes, titles, user input echoed back)
 * goes through this before reaching the terminal: no control characters, bounded length.
 */
export function safeText(value: string, maxLength = 2000): string {
  return sanitizeDisplayText(value, maxLength);
}
