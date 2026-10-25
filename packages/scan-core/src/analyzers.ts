import { scanGitHistory } from "@pgard/git-history";
import { scanSourceCode } from "@pgard/source-analysis";
import type { LocalAnalyzer } from "./types.js";

/**
 * `code` scope: source rules decided from the code itself (query statements, server code,
 * configuration). PGARD does not ship or query a vulnerability database.
 */
const analyzeCode: LocalAnalyzer = (context) =>
  scanSourceCode(context.projectRoot, {
    ...(context.signal ? { signal: context.signal } : {}),
  });

/** `history` scope: committed .env files and secrets in tracked files and recent history. */
const analyzeHistory: LocalAnalyzer = (context) =>
  scanGitHistory(context.projectRoot, {
    revision: context.revision,
    ...(context.signal ? { signal: context.signal } : {}),
  });

/** Built-in read-only analyzers for the local scopes. */
export function createDefaultAnalyzers(): Record<"code" | "history", LocalAnalyzer> {
  return { code: analyzeCode, history: analyzeHistory };
}
