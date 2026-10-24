import { parse } from "@vue/compiler-sfc";
import ts from "typescript-api";
import type { RawSourceFinding } from "../finding-factory.js";
import { analyzeJsSource, type JsFileFacts } from "../js/analyze-js.js";

export interface VueAnalysis {
  findings: RawSourceFinding[];
  facts: JsFileFacts | null;
  hasParseErrors: boolean;
  cappedRules: string[];
}

interface TemplateNode {
  type: number;
  props?: TemplateProp[];
  children?: TemplateNode[];
}

interface TemplateProp {
  type: number;
  name: string;
  exp?: { content: string; loc: { start: { line: number } } };
  loc: { start: { line: number } };
}

const NODE_ELEMENT = 1;
const PROP_DIRECTIVE = 7;
const BROWSER_INPUT =
  /\$route\b|\broute\.(query|params|hash)|\blocation\.|\bquery\b|\bparams\b|searchParams/;
const SANITIZED = /\b(sanitize|sanitizeHtml|purify|DOMPurify|escapeHtml|xss)\b/i;

/** Classifies a `v-html` expression without evaluating it. */
function classifyVHtml(
  expression: string,
): Omit<RawSourceFinding, "ruleId" | "path" | "line" | "cause"> | null {
  const trimmed = expression.trim();
  if (/^(['"`])[^'"`$]*\1$/.test(trimmed) || SANITIZED.test(trimmed)) {
    return null;
  }
  if (BROWSER_INPUT.test(trimmed)) {
    return {
      severity: "high",
      status: "suspected",
      confidence: "medium",
      evidence: "browser input (route/query) -> v-html",
    };
  }
  const isComposed = /[`+]/.test(trimmed);
  return {
    severity: isComposed ? "medium" : "low",
    status: "suspected",
    confidence: "low",
    evidence: `${isComposed ? "composed string" : "bound value"} -> v-html (no input source identified)`,
  };
}

/**
 * Analyzes a Vue single-file component: `<script>`/`<script setup>` with the TypeScript AST
 * (same rules as JS/TS) and the template's `v-html` bindings via @vue/compiler-sfc.
 */
export function analyzeVueSource(code: string, path: string): VueAnalysis {
  const { descriptor, errors } = parse(code, { filename: path, sourceMap: false });
  const findings: RawSourceFinding[] = [];
  let facts: JsFileFacts | null = null;
  let hasParseErrors = errors.length > 0;
  const cappedRules = new Set<string>();

  for (const block of [descriptor.script, descriptor.scriptSetup]) {
    if (!block) continue;
    const isTs = block.lang === "ts" || block.lang === "tsx";
    const analysis = analyzeJsSource(block.content, path, {
      lineOffset: block.loc.start.line - 1,
      scriptKind: isTs ? ts.ScriptKind.TSX : ts.ScriptKind.JSX,
    });
    findings.push(...analysis.findings);
    hasParseErrors ||= analysis.hasParseErrors;
    for (const rule of analysis.cappedRules) cappedRules.add(rule);
    facts = facts
      ? {
          imports: [...new Set([...facts.imports, ...analysis.facts.imports])],
          stateChangingRoutes: [
            ...facts.stateChangingRoutes,
            ...analysis.facts.stateChangingRoutes,
          ],
          authRoutes: [...facts.authRoutes, ...analysis.facts.authRoutes],
          usesCookieSession: facts.usesCookieSession || analysis.facts.usesCookieSession,
          hasJsx: facts.hasJsx || analysis.facts.hasJsx,
        }
      : analysis.facts;
  }

  const visit = (node: TemplateNode): void => {
    if (node.type === NODE_ELEMENT) {
      for (const prop of node.props ?? []) {
        if (prop.type === PROP_DIRECTIVE && prop.name === "html" && prop.exp) {
          const classification = classifyVHtml(prop.exp.content);
          if (classification) {
            findings.push({
              ruleId: "PG-XSS-003",
              path,
              line: prop.loc.start.line,
              cause: "v-html",
              ...classification,
            });
          }
        }
      }
    }
    for (const child of node.children ?? []) visit(child);
  };
  const ast = descriptor.template?.ast as TemplateNode | undefined | null;
  if (ast) visit(ast);

  return { findings, facts, hasParseErrors, cappedRules: [...cappedRules] };
}
