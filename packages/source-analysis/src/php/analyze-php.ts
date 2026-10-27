import type { Node } from "web-tree-sitter";
import type { RawSourceFinding } from "../finding-factory.js";
import { PHP_OPERATOR_TOKEN, toAst } from "../jvm/tree.js";
import { analyzePhp, type PhpFinding } from "./php-engine.js";

export const MAX_PHP_FINDINGS_PER_FILE = 25;

export interface PhpFileAnalysis {
  findings: RawSourceFinding[];
  /** Part of the file was not analyzed (nesting too deep, or the work budget ran out). */
  incomplete: boolean;
  /** The per-file finding cap was reached. */
  capped: boolean;
  /** Code forms with SQL-looking text that are not followed (dynamic calls). */
  unsupportedForms: string[];
  /** Libraries with their own SQL or process APIs, which are not supported. */
  unsupportedLibraries: Array<{ label: string; kind: "sql" | "process" }>;
}

/** Strongest first: request input, then untraced, then inferred; then severity. */
const strength = (finding: PhpFinding): number =>
  ({ high: 30, medium: 20, low: 10 })[finding.confidence] +
  ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 } as Record<string, number>)[
    finding.severity
  ]!;

/**
 * Runs the SQL injection and command execution rules over one parsed PHP file. `root` is the root
 * node of the tree parsed from `source`; the result is a pure function of the file's text and path.
 */
export function analyzePhpTree(root: Node, source: string, path: string): PhpFileAnalysis {
  const ast = toAst(root, source, PHP_OPERATOR_TOKEN);
  const analysis = analyzePhp(ast);
  // Per rule: one finding per line and cause (the strongest), then the cap keeps the strongest.
  const byRule = new Map<PhpFinding["ruleId"], PhpFinding[]>();
  for (const finding of analysis.findings) {
    byRule.set(finding.ruleId, [...(byRule.get(finding.ruleId) ?? []), finding]);
  }
  let capped = false;
  const kept: PhpFinding[] = [];
  for (const group of byRule.values()) {
    group.sort((a, b) => strength(b) - strength(a) || a.line - b.line);
    if (group.length > MAX_PHP_FINDINGS_PER_FILE) capped = true;
    kept.push(...group.slice(0, MAX_PHP_FINDINGS_PER_FILE));
  }
  return {
    findings: kept
      .sort((a, b) => a.line - b.line)
      .map((finding): RawSourceFinding => ({ path, ...finding })),
    incomplete: analysis.incomplete || ast.truncated,
    capped,
    unsupportedForms: analysis.unsupported,
    unsupportedLibraries: analysis.libraries,
  };
}
