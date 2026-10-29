import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import type { Finding } from "@pgard/findings";
import { suggestFix } from "./suggest-fix.js";
import { getRule } from "../rules.js";

/** Largest file read to build a suggestion. */
const MAX_FIX_SOURCE_BYTES = 1024 * 1024;
/** Most distinct files read per scan; later findings get guidance (`too_many`). */
const MAX_FIX_SOURCE_FILES = 200;

function isFixableRule(ruleId: string): boolean {
  try {
    return getRule(ruleId as Parameters<typeof getRule>[0]).fixable === true;
  } catch {
    return false;
  }
}

/**
 * Reads one source file for a suggestion, read-only and bounded: a regular file inside the
 * project (no symbolic link in the path), at most `MAX_FIX_SOURCE_BYTES`, opened without
 * following links and without blocking. `null` for anything else.
 */
async function readSourceText(rootReal: string, relativePath: string): Promise<string | null> {
  if (relativePath === "" || path.isAbsolute(relativePath) || relativePath.includes("\0")) {
    return null;
  }
  const target = path.join(rootReal, ...relativePath.split("/"));
  if (target !== rootReal && !target.startsWith(rootReal + path.sep)) return null;
  let handle;
  try {
    const stats = await lstat(target);
    if (!stats.isFile() || stats.size > MAX_FIX_SOURCE_BYTES) return null;
    // The file must not be reached through a symbolic link anywhere on its path.
    if ((await realpath(target)) !== target) return null;
    handle = await open(
      target,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
    );
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size > MAX_FIX_SOURCE_BYTES) return null;
    const buffer = Buffer.alloc(MAX_FIX_SOURCE_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    return bytesRead > MAX_FIX_SOURCE_BYTES ? null : buffer.toString("utf8", 0, bytesRead);
  } catch {
    return null;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/**
 * Adds `Finding.fix` to the findings of fixable rules. It reads the flagged files read-only (never
 * writes, never runs them) and is deterministic. Findings of other rules, and findings without a
 * file location, are returned unchanged; the input array is not mutated. The suggestion is built
 * from the file as it is now, and the fixer matches the whole flagged line, so a file edited
 * since the scan gives guidance, not a diff for the wrong line.
 */
export async function attachFixSuggestions(
  findings: readonly Finding[],
  projectRoot: string,
  options: { signal?: AbortSignal } = {},
): Promise<Finding[]> {
  const rootReal = await realpath(projectRoot).catch(() => null);
  const texts = new Map<string, string | null>();
  const output: Finding[] = [];
  for (const finding of findings) {
    const { kind, path: relativePath } = finding.location;
    if (
      options.signal?.aborted === true ||
      kind !== "file" ||
      relativePath === null ||
      !isFixableRule(finding.ruleId)
    ) {
      output.push(finding);
      continue;
    }
    if (!texts.has(relativePath)) {
      texts.set(
        relativePath,
        texts.size >= MAX_FIX_SOURCE_FILES || rootReal === null
          ? null
          : await readSourceText(rootReal, relativePath),
      );
    }
    const text = texts.get(relativePath) ?? null;
    if (text === null) {
      const reason = texts.size > MAX_FIX_SOURCE_FILES ? "too_many" : "source_unavailable";
      output.push({ ...finding, fix: { kind: "guidance", confidence: "low", reason } });
      continue;
    }
    const fix = suggestFix(finding, text);
    output.push(fix === null ? finding : { ...finding, fix });
  }
  return output;
}
