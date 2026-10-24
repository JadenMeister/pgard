import { scanSourceCode } from "@pgard/source-analysis";
import type { LocalAnalyzer } from "./types.js";

function notImplemented(scope: "code" | "history", area: string, note: string): LocalAnalyzer {
  return async () => ({
    findings: [],
    coverage: [{ area, scope, status: "not_tested", ruleIds: [], note }],
  });
}

const dependencyAdvisoriesUnavailable = notImplemented(
  "code",
  "dependencies:advisory",
  "Dependency advisory checks are not available in this build.",
);

/** `code` scope: source rules plus dependency advisories. */
const analyzeCode: LocalAnalyzer = async (context) => {
  const source = await scanSourceCode(context.projectRoot, {
    ...(context.signal ? { signal: context.signal } : {}),
  });
  const dependencies = await dependencyAdvisoriesUnavailable(context);
  return {
    findings: [...source.findings, ...dependencies.findings],
    coverage: [...source.coverage, ...dependencies.coverage],
  };
};

/** Built-in read-only analyzers for the local scopes. */
export function createDefaultAnalyzers(): Record<"code" | "history", LocalAnalyzer> {
  return {
    code: analyzeCode,
    history: notImplemented(
      "history",
      "history",
      "The history analyzer is not available in this build.",
    ),
  };
}
