import { createHash } from "node:crypto";
import { scanDependencies } from "@pgard/dependencies";
import { compilePathMatcher, type Coverage, type Finding, type RuleStat } from "@pgard/findings";
import { scanGitHistory } from "@pgard/git-history";
import { scanSourceCode } from "@pgard/source-analysis";
import type { AnalyzerContext, LocalAnalyzer } from "./types.js";

/**
 * `code` scope: source rules decided from the code itself (query statements, server code,
 * configuration). PGARD does not ship or query a vulnerability database.
 */
const analyzeCode: LocalAnalyzer = async (context) => {
  const [output, dependencies] = await Promise.all([
    scanSourceCode(context.projectRoot, {
      ...(context.signal ? { signal: context.signal } : {}),
      projectConfig: context.projectConfig,
      ...(context.sourceReuse ? { reuse: context.sourceReuse } : {}),
    }),
    analyzeDependencies(context),
  ]);
  return {
    findings: [...output.findings, ...dependencies.findings],
    coverage: [...output.coverage, ...dependencies.coverage],
    ruleStats: [...(output.ruleStats ?? []), ...dependencies.ruleStats],
    sourceCache: output.fileCache,
    sourceReuse: output.reuse,
  };
};

/**
 * Dependencies are part of the `code` scope: pinned lockfile versions are matched against the OSV
 * data on disk (offline), one `deps:<ecosystem>` area per ecosystem with a lockfile. A project
 * without a supported lockfile gets no such area. An unexpected failure is reported as an area
 * that could not run, never as "no vulnerable dependencies".
 */
async function analyzeDependencies(context: AnalyzerContext): Promise<{
  findings: Finding[];
  coverage: Coverage[];
  ruleStats: RuleStat[];
}> {
  const excluded =
    context.projectConfig !== null && context.projectConfig.exclude.length > 0
      ? compilePathMatcher(context.projectConfig.exclude)
      : null;
  try {
    return await scanDependencies(context.projectRoot, {
      appDataDir: context.advisoryDataDir ?? null,
      ...(context.signal ? { signal: context.signal } : {}),
      now: () => context.now().getTime(),
      ...(excluded === null ? {} : { isExcluded: (path: string) => excluded.matches(path) }),
    });
  } catch (error) {
    if (
      context.signal?.aborted === true ||
      (error instanceof Error && error.name === "AbortError")
    ) {
      throw error;
    }
    return {
      findings: [],
      ruleStats: [],
      coverage: [
        {
          area: "deps:lockfiles",
          scope: "code",
          status: "not_tested",
          ruleIds: ["PG-DEP-001"],
          note: "The dependency check failed unexpectedly; no lockfile was checked for known vulnerable versions.",
        },
      ],
    };
  }
}

/** `history` scope: committed .env files and secrets in tracked files and recent history. */
const analyzeHistory: LocalAnalyzer = async (context) => {
  const output = await scanGitHistory(context.projectRoot, {
    revision: context.revision,
    ...(context.historyIncremental ? { incremental: context.historyIncremental } : {}),
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
