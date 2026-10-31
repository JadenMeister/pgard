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
