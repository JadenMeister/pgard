import { MAX_JSON_DEPTH, MAX_JSON_TOKENS, MAX_LOCKFILE_LINES } from "../limits.js";

/**
 * Cheap, allocation-free checks run on a lockfile's text before a parser builds objects from it.
 * A file below the byte cap can still be hostile: 63 MiB of `[` or `a:` lines asks a parser for
 * tens of millions of objects. Each check is one linear pass that keeps no per-element state, and
 * returns a plain-words reason when the file must not be parsed (null: go ahead).
 */

/** Lines of a line-based lockfile (yarn.lock, pnpm-lock.yaml, go.mod, go.sum). */
export function lineCountProblem(
  text: string,
  maxLines: number = MAX_LOCKFILE_LINES,
): string | null {
  let lines = 1;
  let at = text.indexOf("\n");
  while (at !== -1) {
    lines += 1;
    if (lines > maxLines) return `has more than ${maxLines} lines`;
    at = text.indexOf("\n", at + 1);
  }
  return null;
}

/** Nesting depth and structural element count of a JSON text (strings are skipped correctly). */
export function jsonShapeProblem(
  text: string,
  maxDepth: number = MAX_JSON_DEPTH,
  maxTokens: number = MAX_JSON_TOKENS,
): string | null {
  let depth = 0;
  let tokens = 0;
  let inString = false;
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (inString) {
      if (code === 0x5c)
        index += 1; // backslash: skip the escaped character
      else if (code === 0x22) inString = false;
      continue;
    }
    if (code === 0x22) inString = true;
    else if (code === 0x7b || code === 0x5b) {
      depth += 1;
      tokens += 1;
      if (depth > maxDepth) return `is nested more than ${maxDepth} levels deep`;
      if (tokens > maxTokens) return `has more than ${maxTokens} JSON elements`;
    } else if (code === 0x7d || code === 0x5d) depth -= 1;
    else if (code === 0x2c) {
      tokens += 1;
      if (tokens > maxTokens) return `has more than ${maxTokens} JSON elements`;
    }
  }
  return null;
}
