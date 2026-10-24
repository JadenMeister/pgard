import { scanDependencies } from "@pgard/advisory";
import { scanGitHistory } from "@pgard/git-history";
import { scanSourceCode } from "@pgard/source-analysis";
import type { LocalAnalyzer } from "./types.js";

/** `code` scope: source rules plus dependency advisories (local OSV data). */
const analyzeCode: LocalAnalyzer = async (context) => {
  const source = await scanSourceCode(context.projectRoot, {
    ...(context.signal ? { signal: context.signal } : {}),
  });
  const dependencies = await scanDependencies(context.projectRoot, {
    env: context.env,
    now: context.now,
  });
  return {
    findings: [...source.findings, ...dependencies.findings],
    coverage: [...source.coverage, ...dependencies.coverage],
    advisoryDb: dependencies.advisoryDb,
  };
};

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
