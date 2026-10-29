/**
 * The rule for a folder name typed or dropped in the picker (T3), shared by the browser (for
 * immediate feedback) and the server (which decides). Browser-safe: no dependencies.
 *
 * A name is one path segment, NFC-normalized: 2 to 255 UTF-16 units when typed (a dropped name may
 * be 1), no `/` or `\`, NUL, control or direction-changing character, not `.` or `..`. Case
 * folding and normalization serve only name matching, never containment.
 */

export const MIN_TYPED_NAME_LENGTH = 2;
export const MAX_NAME_LENGTH = 255;

/**
 * C0/C1 controls, zero-width and bidirectional characters, word joiners, BOM and soft hyphen.
 * Starts from the set `sanitizeDisplayText` strips (`UNSAFE_DISPLAY_CHARACTERS` in
 * `@pgard/findings`, checked by a test) and adds the invisible characters that would let two names
 * look the same.
 */
const UNSAFE_NAME_CHARACTERS = new RegExp(
  "[\\u0000-\\u001f\\u007f-\\u009f\\u061c\\u200b-\\u200f\\u2028-\\u202e\\u2066-\\u2069\\u2060-\\u2064\\ufeff\\u00ad]",
);

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export type FolderNameSource = "drop" | "typed";

export type BadNameReason =
  "empty" | "too_short" | "too_long" | "slash" | "control" | "dot" | "malformed" | "not_text";

export type FolderNameCheck =
  { ok: true; name: string; folded: string } | { ok: false; reason: BadNameReason };

/** `toLowerCase` after NFC, never a `toLocale*` function: the Turkish dotless i cannot appear. */
export function foldName(name: string): string {
  return name.normalize("NFC").toLowerCase();
}

export function checkFolderName(raw: unknown, source: FolderNameSource): FolderNameCheck {
  if (typeof raw !== "string") return { ok: false, reason: "not_text" };
  if (raw.length === 0) return { ok: false, reason: "empty" };
  // A lone surrogate cannot be turned into valid text; check before normalizing.
  if (LONE_SURROGATE.test(raw)) return { ok: false, reason: "malformed" };
  const name = raw.normalize("NFC");
  if (name.length > MAX_NAME_LENGTH) return { ok: false, reason: "too_long" };
  if (name.includes("/") || name.includes("\\")) return { ok: false, reason: "slash" };
  if (UNSAFE_NAME_CHARACTERS.test(name)) return { ok: false, reason: "control" };
  if (name === "." || name === "..") return { ok: false, reason: "dot" };
  if (source === "typed" && name.length < MIN_TYPED_NAME_LENGTH) {
    return { ok: false, reason: "too_short" };
  }
  return { ok: true, name, folded: foldName(name) };
}

/**
 * Whether a directory entry name answers the search. `drop` matches the exact name, then the
 * folded one (APFS and HFS+ are case-insensitive and may return NFD); `typed` matches as a prefix
 * or substring of the folded name. 0 is an exact NFC match, 1 a folded match, 2 a typed partial
 * match, `null` no match, so exact matches can be listed first.
 */
export function matchRank(
  entryName: string,
  query: { name: string; folded: string },
  source: FolderNameSource,
): 0 | 1 | 2 | null {
  const entry = entryName.normalize("NFC");
  if (entry === query.name) return 0;
  const folded = entry.toLowerCase();
  if (folded === query.folded) return 1;
  if (source === "typed" && folded.includes(query.folded)) return 2;
  return null;
}
