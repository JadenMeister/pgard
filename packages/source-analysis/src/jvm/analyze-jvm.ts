import type { Node } from "web-tree-sitter";
import type { RawSourceFinding } from "../finding-factory.js";
import { annotationFindings } from "./annotation-rules.js";
import { analyzeCookies } from "./cookie-rules.js";
import type { ConfigFinding } from "./config-util.js";
import { unsupportedCryptoLibraries } from "./crypto-names.js";
import { cryptoFindings, type CryptoFinding } from "./crypto-rules.js";
import { convertJava } from "./java-ir.js";
import { convertKotlin } from "./kotlin-ir.js";
import { analyzeSpringSecurity } from "./spring-security.js";
import { analyzeSql, type FlowFinding } from "./sql-engine.js";
import { MYBATIS_PROVIDERS, UNSUPPORTED_LIBRARIES } from "./jvm-names.js";
import { PROCESS_AND_FILE_LIBRARIES } from "./os-names.js";
import { toAst } from "./tree.js";
import type { ModelAttribute } from "./web-sinks.js";
import { REFLECTION_TEXT, UNSUPPORTED_TEMPLATE_LIBRARIES } from "./web-names.js";

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
  /** Imported libraries that run processes or open files with their own API (zt-exec, Okio, ...). */
  unsupportedOsLibraries: Array<{ label: string; kind: "process" | "file" }>;
  /** Imported template engines the XSS rule does not read (FreeMarker, Velocity, Pebble, Mustache, ...). */
  unsupportedTemplateLibraries: string[];
  /** Imported cryptography libraries with their own APIs (Bouncy Castle, Tink, Jasypt, ...). */
  unsupportedCryptoLibraries: string[];
  /** The file calls through reflection next to servlet, URL or HTTP client APIs: those calls are not followed. */
  reflectionWeb: boolean;
  /** Values put into a template model under a fixed name (matched to Thymeleaf templates by name). */
  modelAttributes: ModelAttribute[];
  /** Spring Security forms that were not followed (a custom configurer, a helper outside the file). */
  unsupportedSecurityForms: string[];
  /** The file imports Spring Security. */
  usesSpringSecurity: boolean;
}

/** Imports of the APIs the XSS and SSRF rules look at. */
const WEB_API_PREFIXES = [
  "javax.servlet",
  "jakarta.servlet",
  "org.springframework.web",
  "org.springframework.http",
  "java.net",
  "io.ktor",
  "okhttp3",
  "org.apache.http",
  "org.apache.hc",
];

/** Imports that show web security is configured (not only an encoder or the security context). */
const WEB_SECURITY_PREFIXES = [
  "org.springframework.security.config.annotation.web",
  "org.springframework.security.config.web",
  "org.springframework.security.web",
  "org.springframework.security.oauth2.server.resource",
];

// Leading blanks never cross a line end (`\s*` did, so every empty line rescanned all the empty
// lines after it: 256 KiB of newlines took a minute). An import on a later line still matches at
// its own line start, with the same captures.
const IMPORT = /^[^\S\n\r\u2028\u2029]*import\s+(?:static\s+)?([\w.]+(?:\.\*)?)/gm;

const IMPORT_ALIAS = /^[^\S\n\r\u2028\u2029]*import\s+([\w.]+)\s+as\s+(\w+)/gm;

/** Kotlin import aliases: the name used in the file -> the class it stands for. */
export function importAliasesOf(source: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const match of source.matchAll(IMPORT_ALIAS)) {
    const real = (match[1] as string).slice((match[1] as string).lastIndexOf(".") + 1);
    out.set(match[2] as string, real);
  }
  return out;
}

/**
 * The text with comments replaced by a space and the inside of string and character literals
 * dropped, in one pass (so an assignment split by a comment or a newline reads as one, and one
 * inside a string does not count). A `/*` that never closes ends the text.
 */
export function withoutCommentsAndStrings(source: string): string {
  const out: string[] = [];
  let i = 0;
  let from = 0;
  const flush = (to: number): void => {
    if (to > from) out.push(source.slice(from, to));
  };
  while (i < source.length) {
    const char = source[i] as string;
    const next = source[i + 1];
    if (char === "/" && next === "/") {
      flush(i);
      const end = source.indexOf("\n", i);
      i = end < 0 ? source.length : end;
      from = i;
      out.push(" ");
    } else if (char === "/" && next === "*") {
      flush(i);
      const end = source.indexOf("*/", i + 2);
      i = end < 0 ? source.length : end + 2;
      from = i;
      out.push(" ");
    } else if (char === '"' || char === "'") {
      flush(i);
      if (source.startsWith('"""', i)) {
        const end = source.indexOf('"""', i + 3);
        i = end < 0 ? source.length : end + 3;
      } else {
        i += 1;
        while (i < source.length && source[i] !== char && source[i] !== "\n") {
          i += source[i] === "\\" ? 2 : 1;
        }
        i += 1;
      }
      from = i;
      out.push('""');
    } else {
      i += 1;
    }
  }
  flush(Math.min(i, source.length));
  return out.join("");
}

/**
 * `name =`, `name +=`, `a.name =`, `this@K.name =`, Kotlin `name: Type =` and a declaration split
 * across lines: every identifier that comes before an assignment operator (not `==`, `<=`, `>=`,
 * `!=`, `=>`). A field's own declaration counts once. Found from each `=` looking backwards a
 * bounded distance, so the cost is linear in the text.
 */
export function assignCountsOf(source: string): Map<string, number> {
  const counts = new Map<string, number>();
  const text = withoutCommentsAndStrings(source);
  const isWord = (char: string | undefined): boolean => char !== undefined && /[\w$]/.test(char);
  const count = (end: number): void => {
    let at = end;
    while (at >= 0 && /\s/.test(text[at] as string)) at -= 1;
    let start = at;
    while (start >= 0 && isWord(text[start]) && at - start < 128) start -= 1;
    if (start === at || at - start >= 128) return;
    const name = text.slice(start + 1, at + 1);
    if (/^\d/.test(name)) return;
    counts.set(name, (counts.get(name) ?? 0) + 1);
  };
  for (let eq = text.indexOf("="); eq >= 0; eq = text.indexOf("=", eq + 1)) {
    const next = text[eq + 1];
    const prev = text[eq - 1];
    if (next === "=" || next === ">" || prev === "=" || prev === "!") continue;
    let end = eq - 1;
    if (prev === "<" || prev === ">") {
      // `<<=`, `>>=`, `>>>=`; a lone `<=` or `>=` is a comparison.
      if (text[eq - 2] !== prev) continue;
      while (end >= 0 && text[end] === prev) end -= 1;
    } else if (prev !== undefined && "+-*/%&|^".includes(prev)) {
      end -= 1;
    }
    count(end);
    // Kotlin `name: Type =`: the name before the last colon within a short distance.
    let colon = -1;
    for (let at = end, steps = 0; at >= 0 && steps < 80; at -= 1, steps += 1) {
      const char = text[at] as string;
      if (";(){}\n=".includes(char)) break;
      if (char === ":" && text[at - 1] !== ":" && text[at + 1] !== ":") {
        colon = at;
        break;
      }
    }
    if (colon > 0) count(colon - 1);
  }
  return counts;
}

/** The imports of a file, as written (`java.sql.Statement`, `org.springframework.jdbc.core.*`). */
export function importsOf(source: string): string[] {
  const out: string[] = [];
  for (const match of source.matchAll(IMPORT)) out.push(match[1] as string);
  return out;
}

type JvmFinding = FlowFinding | CryptoFinding | ConfigFinding;

/** Strongest first: request input, then untraced, then inferred; then severity. */
const strength = (finding: JvmFinding): number =>
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
  unit.assignCounts = assignCountsOf(source);
  unit.aliases = importAliasesOf(source);
  const sql = analyzeSql(unit);
  const security = analyzeSpringSecurity(unit);
  const all: JvmFinding[] = [
    ...sql.findings,
    ...cryptoFindings(unit),
    ...security.findings,
    ...analyzeCookies(unit),
    ...annotationFindings(unit).map((finding): FlowFinding => ({
      ...finding,
      ruleId: "PG-SQL-005",
    })),
  ];
  // Per rule: one finding per line and cause (the strongest), then the cap keeps the strongest
  // findings, so a flood of weak ones can never push out a real one, nor one rule another's.
  const byRule = new Map<JvmFinding["ruleId"], JvmFinding[]>();
  for (const finding of all)
    byRule.set(finding.ruleId, [...(byRule.get(finding.ruleId) ?? []), finding]);
  let capped = false;
  const kept: JvmFinding[] = [];
  for (const group of byRule.values()) {
    group.sort((a, b) => strength(b) - strength(a) || a.line - b.line);
    const seen = new Set<string>();
    const unique: JvmFinding[] = [];
    for (const finding of group) {
      const key = `${finding.line}:${finding.cause}`;
      if (seen.has(key)) continue;
      seen.add(key);
      unique.push(finding);
    }
    if (unique.length > MAX_JVM_FINDINGS_PER_FILE) capped = true;
    kept.push(...unique.slice(0, MAX_JVM_FINDINGS_PER_FILE));
  }
  const findings = kept
    .sort((a, b) => a.line - b.line)
    .map((finding): RawSourceFinding => ({ path, ...finding }));
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
    unsupportedTemplateLibraries: [
      ...new Set(
        UNSUPPORTED_TEMPLATE_LIBRARIES.filter((library) =>
          unit.imports.some(
            (name) => name === library.prefix || name.startsWith(`${library.prefix}.`),
          ),
        ).map((library) => library.label),
      ),
    ],
    reflectionWeb:
      REFLECTION_TEXT.test(source) &&
      unit.imports.some((name) =>
        WEB_API_PREFIXES.some((prefix) => name === prefix || name.startsWith(`${prefix}.`)),
      ),
    unsupportedCryptoLibraries: unsupportedCryptoLibraries(unit.imports),
    modelAttributes: sql.modelAttributes,
    unsupportedSecurityForms: security.unsupported,
    usesSpringSecurity: unit.imports.some((name) =>
      WEB_SECURITY_PREFIXES.some((prefix) => name === prefix || name.startsWith(`${prefix}.`)),
    ),
    unsupportedOsLibraries: PROCESS_AND_FILE_LIBRARIES.filter((library) =>
      unit.imports.some((name) => name === library.prefix || name.startsWith(`${library.prefix}.`)),
    ).map(({ label, kind }) => ({ label, kind })),
  };
}
