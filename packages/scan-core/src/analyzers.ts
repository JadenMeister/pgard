import type { LocalAnalyzer } from "./types.js";

function notImplemented(scope: "code" | "history"): LocalAnalyzer {
  return async () => ({
    findings: [],
    coverage: [
      {
        area: scope,
        scope,
        status: "not_tested",
        ruleIds: [],
        note: `The ${scope} analyzer is not available in this build.`,
      },
    ],
  });
}

/** Built-in read-only analyzers for the local scopes. */
export function createDefaultAnalyzers(): Record<"code" | "history", LocalAnalyzer> {
  return { code: notImplemented("code"), history: notImplemented("history") };
}
