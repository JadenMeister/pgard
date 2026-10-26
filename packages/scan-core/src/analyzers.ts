import { createHash } from "node:crypto";
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
    projectConfig: context.projectConfig,
  });

/** `history` scope: committed .env files and secrets in tracked files and recent history. */
const analyzeHistory: LocalAnalyzer = async (context) => {
  const output = await scanGitHistory(context.projectRoot, {
    revision: context.revision,
    ...(context.signal ? { signal: context.signal } : {}),
  });
  const patterns = context.projectConfig?.exclude ?? [];
  if (patterns.length === 0) return output;
  // Decision: `exclude` never applies to Git history. A secret that was committed stays exposed
  // in every clone whatever the file is called today, and paths in old commits (renamed,
  // deleted, moved) do not map onto the current tree. The area is informational (completed, no
  // rules); its note carries a hash of the patterns so a later comparison notices a change.
  const setHash = createHash("sha256")
    .update([...patterns].sort().join("\n"))
    .digest("hex")
    .slice(0, 16);
  return {
    ...output,
    coverage: [
      ...output.coverage,
      {
        area: "history:config-excluded",
        scope: "history",
        status: "completed",
        ruleIds: [],
        note: `0 files excluded from history by pgard.config.json: its ${patterns.length} exclude pattern${patterns.length === 1 ? "" : "s"} (set ${setHash}) do not apply to Git history or to tracked files, which are always scanned in full.`,
      },
    ],
  };
};

/** Built-in read-only analyzers for the local scopes. */
export function createDefaultAnalyzers(): Record<"code" | "history", LocalAnalyzer> {
  return { code: analyzeCode, history: analyzeHistory };
}
