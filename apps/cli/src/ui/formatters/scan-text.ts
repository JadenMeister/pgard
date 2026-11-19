import {
  authorizationReasonText,
  coverageNoteTranslation,
  type AuthorizationCheck,
  type Coverage,
} from "@pgard/findings";
import type { CliText } from "../i18n/cli-text.js";
import { safeText } from "./style.js";

/**
 * A coverage note as the terminal shows it. English shows the stored text. Korean shows the
 * catalog text when the entry carries a known code with valid params (plain, no parentheses), and
 * otherwise the stored English text in parentheses, as before (an old result, an unknown code,
 * tampered params). Control characters are removed and the length is capped either way.
 */
export function coverageNoteDisplay(
  entry: Pick<Coverage, "note" | "noteCode" | "noteParams">,
  t: CliText,
): string | null {
  const shown = coverageNoteTranslation(entry, t.locale);
  if (shown === null) return null;
  const params = entry.noteParams as Record<string, unknown> | undefined;
  if (shown.translated && params?.["rest"] === 1) {
    // The Korean catalog text, then the stored English rest, which stays marked as English.
    const { rest: _rest, ...withoutRest } = params;
    const head = coverageNoteTranslation({ ...entry, noteParams: withoutRest }, t.locale);
    if (head?.translated && shown.text.startsWith(`${head.text} `)) {
      const cappedHead = safeText(head.text, 300);
      const tail = safeText(
        shown.text.slice(head.text.length + 1),
        Math.max(40, 300 - cappedHead.length),
      );
      return `${cappedHead} ${t.scanText(tail)}`;
    }
  }
  return shown.translated ? safeText(shown.text, 300) : t.scanText(safeText(shown.text, 300));
}

/** An authorization reason as the terminal shows it: the Korean sentence when it is a fixed one. */
export function authorizationReasonDisplay(
  check: Pick<AuthorizationCheck, "reason">,
  t: CliText,
  maxLength: number,
): { text: string; translated: boolean } {
  const { text, translated } = authorizationReasonText(check.reason, t.locale);
  return translated
    ? { text: safeText(text, maxLength), translated }
    : { text: safeText(check.reason, maxLength), translated: false };
}
