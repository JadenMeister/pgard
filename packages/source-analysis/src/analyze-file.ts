import { redactEvidence, type CachedSourceFile } from "@pgard/findings";
import { createSourceFinding } from "./finding-factory.js";
import { analyzeGoSource } from "./go/analyze-go.js";
import { analyzeJsSource, type JsFileFacts } from "./js/analyze-js.js";
import { analyzeVueSource } from "./vue/analyze-vue.js";
import type { SourceLanguage } from "./walk.js";

/** What one file's analysis needs: no file system access, so it can run in a worker. */
export interface FileToAnalyze {
  relativePath: string;
  language: SourceLanguage;
}

/**
 * The facts as they are kept, in a scan and in the stored state alike: a route path is redacted
 * like evidence (it ends up in finding evidence and in a finding's identity), so what is stored
 * never holds more than the result does, and a stored fact gives the same finding as a fresh one.
 */
function storableFacts(facts: JsFileFacts): Record<string, unknown> {
  return {
    ...facts,
    authRoutes: facts.authRoutes.map((route) => ({
      ...route,
      routePath: redactEvidence(route.routePath, { maxLength: 200 }),
    })),
  } as unknown as Record<string, unknown>;
}

/** Analyzes one file's text. Everything a later scan needs to reuse the result is in the entry. */
export function analyzeFile(file: FileToAnalyze, content: string, hash: string): CachedSourceFile {
  const base = { path: file.relativePath, language: file.language, hash };
  if (file.language === "go") {
    const analysis = analyzeGoSource(content, file.relativePath);
    return {
      ...base,
      findings: analysis.findings.map(createSourceFinding),
      facts: null,
      goImports: [...analysis.imports],
      hasJsx: false,
      hasParseErrors: analysis.hasParseErrors,
      capped: analysis.cappedRules.length > 0,
    };
  }
  if (file.language === "vue") {
    const analysis = analyzeVueSource(content, file.relativePath);
    return {
      ...base,
      findings: analysis.findings.map(createSourceFinding),
      facts: analysis.facts ? storableFacts(analysis.facts) : null,
      goImports: [],
      hasJsx: false,
      hasParseErrors: analysis.hasParseErrors,
      capped: analysis.cappedRules.length > 0,
    };
  }
  const analysis = analyzeJsSource(content, file.relativePath);
  return {
    ...base,
    findings: analysis.findings.map(createSourceFinding),
    facts: storableFacts(analysis.facts),
    goImports: [],
    hasJsx: analysis.facts.hasJsx,
    hasParseErrors: analysis.hasParseErrors,
    capped: analysis.cappedRules.length > 0,
  };
}
