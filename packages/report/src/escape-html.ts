const HTML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "`": "&#96;",
};

/**
 * C0 controls except tab/newline, DEL, C1 controls, zero-width characters and bidi
 * embedding/override/isolate characters. They are replaced with a visible `[U+XXXX]` marker so a
 * crafted path or title cannot appear reversed or hide text in the report.
 */
const INVISIBLE_CHARACTERS = new RegExp(
  "[\\u0000-\\u0008\\u000b-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u2069\\ufeff]",
  "g",
);

export function markInvisibleCharacters(value: string): string {
  return value.replace(
    INVISIBLE_CHARACTERS,
    (character) => `[U+${character.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}]`,
  );
}

/** Escapes text for HTML element content and quoted attribute values. */
export function escapeHtml(value: string | number | null | undefined): string {
  if (value === null || value === undefined) return "";
  return markInvisibleCharacters(String(value)).replace(
    /[&<>"'`]/g,
    (character) => HTML_ESCAPES[character] ?? character,
  );
}
