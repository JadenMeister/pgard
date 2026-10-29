import { ApiRequestError } from "../../api/client";
import type { Messages } from "../../i18n/types";

/**
 * Fixed text for an API error code, in the page's language. The server's own messages are English
 * only, so the page maps the code. Unknown codes get the generic text, never the server's.
 */
export function pickerErrorText(m: Messages, error: unknown): string {
  const texts = m.picker.errors as Record<string, string>;
  if (error instanceof ApiRequestError) return texts[error.code] ?? m.picker.errors.generic;
  return m.picker.errors.generic;
}
