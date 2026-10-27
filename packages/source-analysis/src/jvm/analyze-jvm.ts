import type { Node } from "web-tree-sitter";
import type { RawSourceFinding } from "../finding-factory.js";
import { annotationFindings } from "./annotation-rules.js";
import { convertJava } from "./java-ir.js";
import { convertKotlin } from "./kotlin-ir.js";
import { analyzeSql, type SqlFinding } from "./sql-engine.js";
import { toAst } from "./tree.js";

export { analyzeMybatisXml, type MybatisAnalysis } from "./mybatis-xml.js";

export const MAX_JVM_FINDINGS_PER_FILE = 25;

export interface JvmAnalysis {
  findings: RawSourceFinding[];
  /** Part of the file was not analyzed (nesting too deep, or the tree was too large to copy). */
  incomplete: boolean;
  /** The per-file finding cap was reached. */
  capped: boolean;
}

const IMPORT = /^\s*import\s+(?:static\s+)?([\w.]+(?:\.\*)?)/gm;

/** The imports of a file, as written (`java.sql.Statement`, `org.springframework.jdbc.core.*`). */
export function importsOf(source: string): string[] {
  const out: string[] = [];
  for (const match of source.matchAll(IMPORT)) out.push(match[1] as string);
  return out;
}

/**
 * Runs the SQL injection rule over one parsed Java or Kotlin file. `root` is the root node of the
 * tree parsed from `source`; nothing outside (`source`, `path`) is read, so the result is a pure
 * function of the file's text and path.
 */
export function analyzeJvmTree(
  root: Node,
  source: string,
  path: string,
  language: "java" | "kotlin",
): JvmAnalysis {
  const ast = toAst(root, source);
  const unit = language === "java" ? convertJava(ast) : convertKotlin(ast);
  unit.imports = importsOf(source);
  const sql = analyzeSql(unit);
  const all: SqlFinding[] = [...sql.findings, ...annotationFindings(unit)];
  // Same line and cause once; the strongest first.
  const confidenceRank = { high: 3, medium: 2, low: 1 } as const;
  all.sort(
    (a, b) => a.line - b.line || confidenceRank[b.confidence] - confidenceRank[a.confidence],
  );
  const seen = new Set<string>();
  const findings: RawSourceFinding[] = [];
  let capped = false;
  for (const finding of all) {
    const key = `${finding.line}:${finding.cause}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (findings.length >= MAX_JVM_FINDINGS_PER_FILE) {
      capped = true;
      break;
    }
    findings.push({ ruleId: "PG-SQL-005", path, ...finding });
  }
  return { findings, incomplete: sql.incomplete || unit.incomplete || ast.truncated, capped };
}
