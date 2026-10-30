import { UNSAFE_DISPLAY_CHARACTERS } from "@pgard/findings";
import { MAX_DISPLAY_TEXT_LENGTH } from "./constants.js";

/** C0/C1 controls, zero-width and bidi override characters (shared with `redactEvidence`). */
const UNSAFE_CHARACTERS = new RegExp(UNSAFE_DISPLAY_CHARACTERS, "g");

/**
 * Makes text received from a local service safe to show in a terminal, log line or report:
 * strips control/bidi characters (no ANSI escape injection), collapses whitespace, caps length.
 */
export function sanitizeDisplayText(value: string, maxLength = MAX_DISPLAY_TEXT_LENGTH): string {
  const cleaned = value.replace(UNSAFE_CHARACTERS, " ").replace(/\s+/g, " ").trim();
  if (cleaned.length <= maxLength) return cleaned;
  let end = maxLength - 1;
  // Do not cut a surrogate pair in half.
  const last = cleaned.charCodeAt(end - 1);
  if (end > 0 && last >= 0xd800 && last <= 0xdbff) end -= 1;
  return `${cleaned.slice(0, end)}\u2026`;
}
