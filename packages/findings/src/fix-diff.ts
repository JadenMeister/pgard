/**
 * Suggested-fix diffs (JSON v1.6 `Finding.fix`). Every suggested fix of PGARD is the replacement of
 * ONE line of ONE file, written as a unified diff with a single hunk and no context lines. The
 * restriction is deliberate: a context line is source text that is not part of the fix, and PGARD
 * cannot tell which of it is secret, so none is ever copied into a diff. The lines that are copied
 * (the old and the new line) must come out of secret and path redaction unchanged, or no diff is
 * made at all.
 *
 * Pure functions with no Node APIs, so the browser bundle and the SARIF writer may import them.
 */
import { MAX_FIX_DIFF_LENGTH, type Finding, type FindingFix } from "./contract.js";
import { redactSecrets, scrubAbsolutePaths, UNSAFE_DISPLAY_CHARACTERS } from "./redact.js";

/** Longest line (old or new) a diff may carry. */
export const MAX_FIX_LINE_LENGTH = 400;
const SAFE_PATH = /^[A-Za-z0-9_.@+/-]{1,300}$/;
// Built on first use: redact.ts imports this module back, so nothing may run at load time.
let unsafeLineCharacters: RegExp | undefined;

/** One line replaced by one line, in one file. */
export interface LineReplacement {
  /** Repository-relative POSIX path. */
  path: string;
  /** 1-based number of the replaced line. */
  line: number;
  oldLine: string;
  newLine: string;
}

/** True when `text` is a line that may be copied into a diff: it is unchanged by redaction. */
export function isDiffSafeLine(text: string): boolean {
  if (text.length === 0 || text.length > MAX_FIX_LINE_LENGTH) return false;
  unsafeLineCharacters ??= new RegExp(UNSAFE_DISPLAY_CHARACTERS);
  if (unsafeLineCharacters.test(text)) return false;
  return scrubAbsolutePaths(redactSecrets(text)) === text;
}

/**
 * The unified diff of `replacement`, or `null` when it cannot be written safely: a path or line
 * redaction would change, a line that is empty, over the length cap or holds control characters,
 * a no-op, or a diff over `MAX_FIX_DIFF_LENGTH`.
 */
export function buildLineReplacementDiff(replacement: LineReplacement): string | null {
  const { path, line, oldLine, newLine } = replacement;
  if (!SAFE_PATH.test(path) || path.startsWith("/") || path.split("/").includes("..")) return null;
  if (!Number.isSafeInteger(line) || line < 1) return null;
  if (oldLine === newLine || !isDiffSafeLine(oldLine) || !isDiffSafeLine(newLine)) return null;
  if (redactSecrets(path) !== path) return null;
  const diff = [
    `--- a/${path}`,
    `+++ b/${path}`,
    `@@ -${line},1 +${line},1 @@`,
    `-${oldLine}`,
    `+${newLine}`,
    "",
  ].join("\n");
  return diff.length <= MAX_FIX_DIFF_LENGTH ? diff : null;
}

const HUNK = /^@@ -([1-9]\d{0,8}),1 \+([1-9]\d{0,8}),1 @@$/;

/** Reads back a diff made by `buildLineReplacementDiff`; `null` for anything else. */
export function parseLineReplacementDiff(diff: string): LineReplacement | null {
  if (diff.length > MAX_FIX_DIFF_LENGTH || !diff.endsWith("\n")) return null;
  const lines = diff.slice(0, -1).split("\n");
  if (lines.length !== 5) return null;
  const [from, to, hunk, removed, added] = lines as [string, string, string, string, string];
  if (!from.startsWith("--- a/") || !to.startsWith("+++ b/")) return null;
  const path = from.slice("--- a/".length);
  if (to.slice("+++ b/".length) !== path) return null;
  const match = HUNK.exec(hunk);
  if (match === null || match[1] !== match[2]) return null;
  if (!removed.startsWith("-") || !added.startsWith("+")) return null;
  const replacement: LineReplacement = {
    path,
    line: Number(match[1]),
    oldLine: removed.slice(1),
    newLine: added.slice(1),
  };
  return buildLineReplacementDiff(replacement) === diff ? replacement : null;
}

/**
 * Applies a diff made by `buildLineReplacementDiff` to `text` in memory. `null` when the diff is
 * not one of ours or the line is not exactly the removed line. Only for tests and checks: PGARD
 * itself never applies a diff to a user's file.
 */
export function applyLineReplacementDiff(text: string, diff: string): string | null {
  const replacement = parseLineReplacementDiff(diff);
  if (replacement === null) return null;
  const lines = text.split("\n");
  if (lines[replacement.line - 1] !== replacement.oldLine) return null;
  lines[replacement.line - 1] = replacement.newLine;
  return lines.join("\n");
}

/**
 * Re-checks a fix that is about to be shown or saved. A diff that does not read back as one of
 * ours, or whose lines redaction would change (a result from an older or different writer), is
 * replaced by guidance, so a stored or hand-edited result cannot put a secret on a screen.
 */
export function redactFix(fix: FindingFix): FindingFix {
  if (fix.kind !== "diff") {
    return {
      kind: fix.kind,
      confidence: fix.confidence,
      ...(fix.reason === undefined ? {} : { reason: fix.reason }),
    };
  }
  if (fix.diff !== undefined && parseLineReplacementDiff(fix.diff) !== null) return fix;
  return { kind: "guidance", confidence: fix.confidence, reason: "sensitive_text" };
}

/** Whether the finding carries a diff the front ends may show. */
export function hasFixDiff(finding: Pick<Finding, "fix">): boolean {
  return finding.fix?.kind === "diff" && typeof finding.fix.diff === "string";
}

/** Shown with every diff, in every front end: the label is part of the data, not decoration. */
export const FIX_DISCLAIMER = {
  en: "Suggestion to review. PGARD did not apply it and has not checked that it compiles or keeps behaviour.",
  ko: "검토용 제안입니다. PGARD가 적용하지 않았으며, 컴파일되는지 또는 동작이 유지되는지 확인하지 않았습니다.",
} as const;
