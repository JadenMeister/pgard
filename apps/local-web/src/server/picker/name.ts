import {
  checkFolderName,
  type BadNameReason,
  type FolderNameSource,
} from "../../shared/folder-name.js";

export { foldName, matchRank } from "../../shared/folder-name.js";

/**
 * T3: the browser sends a folder _name_, never a path. The rule itself is shared with the page
 * (`shared/folder-name.ts`); this adds the fixed messages the API answers with.
 */

const REASON_TEXT: Record<BadNameReason, string> = {
  empty: "The name is empty.",
  too_short: "The name must be 2 or more characters.",
  too_long: "The name is longer than 255 characters.",
  slash: "The name contains a `/`.",
  control: "The name contains a control or direction-changing character.",
  dot: "`.` and `..` are not folder names.",
  malformed: "The name is not valid text.",
  not_text: "The name must be text.",
};

export const BAD_NAME_HINT = "Type or drop only the folder's own name, not a path.";

export type ParsedName =
  | { ok: true; name: string; folded: string }
  | { ok: false; reason: BadNameReason; message: string };

export function parseFolderName(raw: unknown, source: FolderNameSource): ParsedName {
  const checked = checkFolderName(raw, source);
  return checked.ok
    ? checked
    : {
        ok: false,
        reason: checked.reason,
        message: `${REASON_TEXT[checked.reason]} ${BAD_NAME_HINT}`,
      };
}
