import type { Node } from "web-tree-sitter";
import type { RawSourceFinding } from "../finding-factory.js";
import { annotationFindings } from "./annotation-rules.js";
import { convertJava } from "./java-ir.js";
import { convertKotlin } from "./kotlin-ir.js";
import { analyzeSql, type SqlFinding } from "./sql-engine.js";
import { MYBATIS_PROVIDERS, UNSUPPORTED_LIBRARIES } from "./jvm-names.js";
import { toAst } from "./tree.js";

export { analyzeMybatisXml, type MybatisAnalysis } from "./mybatis-xml.js";

export const MAX_JVM_FINDINGS_PER_FILE = 25;

export interface JvmAnalysis {
  findings: RawSourceFinding[];
  /** Part of the file was not analyzed (nesting too deep, or the tree was too large to copy). */
  incomplete: boolean;
  /** The per-file finding cap was reached. */
  capped: boolean;
  /** Anonymous and local classes and local functions with a SQL-looking call: not followed. */
  unsupportedForms: string[];
  /** Imported libraries with their own SQL APIs (jOOQ, Exposed, Room, MyBatis providers). */
  unsupportedLibraries: string[];
}

const IMPORT = /^\s*import\s+(?:static\s+)?([\w.]+(?:\.\*)?)/gm;

/** The imports of a file, as written (`java.sql.Statement`, `org.springframework.jdbc.core.*`). */
export function importsOf(source: string): string[] {
  const out: string[] = [];
  for (const match of source.matchAll(IMPORT)) out.push(match[1] as string);
  return out;
}

/** Strongest first: request input, then untraced, then inferred; then severity. */
const strength = (finding: SqlFinding): number =>
  ({ high: 30, medium: 20, low: 10 })[finding.confidence] +
  ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 } as Record<string, number>)[
    finding.severity
  ]!;

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
  // One finding per line and cause: the strongest. The cap then keeps the strongest findings,
  // so a flood of weak ones can never push a real one out.
  all.sort((a, b) => strength(b) - strength(a) || a.line - b.line);
  const seen = new Set<string>();
  const unique: SqlFinding[] = [];
  for (const finding of all) {
    const key = `${finding.line}:${finding.cause}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(finding);
  }
  const capped = unique.length > MAX_JVM_FINDINGS_PER_FILE;
  const findings = unique
    .slice(0, MAX_JVM_FINDINGS_PER_FILE)
    .sort((a, b) => a.line - b.line)
    .map((finding): RawSourceFinding => ({ ruleId: "PG-SQL-005", path, ...finding }));
  // Libraries with their own SQL APIs, and forms not followed, make the coverage partial.
  const libraries = UNSUPPORTED_LIBRARIES.filter((library) =>
    unit.imports.some((name) => name === library.prefix || name.startsWith(`${library.prefix}.`)),
  ).map((library) => library.label);
  for (const cls of [unit.top, ...unit.classes]) {
    for (const method of cls.methods) {
      if (method.annotations.some((annotation) => MYBATIS_PROVIDERS.has(annotation.name))) {
        libraries.push("MyBatis SQL providers");
      }
    }
  }
  return {
    findings,
    incomplete: sql.incomplete || unit.incomplete || ast.truncated,
    capped,
    unsupportedForms: sql.unsupported,
    unsupportedLibraries: [...new Set(libraries)],
  };
}
