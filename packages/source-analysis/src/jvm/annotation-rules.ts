import type { Annotation, ClassInfo, Expr, MethodInfo, Unit } from "./ir.js";
import { NUMERIC_TYPES } from "./jvm-names.js";
import type { SqlFinding } from "./sql-engine.js";

const MYBATIS_ANNOTATIONS = new Set(["Select", "Update", "Insert", "Delete"]);
const PLACEHOLDER = /\$\{([^}]*)\}/g;
/** `#{...}` that is not the `:#{...}` / `?#{...}` binding forms of Spring Data. */
const SPEL = /(?<![:?])#\{([^}]*)\}/g;
const MAX_ANNOTATION_FINDINGS = 25;

/** Text of a string expression made of literals; a name that is not a literal becomes U+0000. */
function textOf(expr: Expr | null | undefined): string[] {
  if (expr === null || expr === undefined) return [];
  switch (expr.k) {
    case "str":
      return [expr.text];
    case "array":
      return expr.elems.flatMap((elem) => textOf(elem));
    case "bin": {
      if (expr.op !== "+") return [];
      const left = textOf(expr.left);
      const right = textOf(expr.right);
      return [`${left.join("")}${right.join("")}`];
    }
    case "tmpl":
      return [expr.parts.map((part) => (typeof part === "string" ? part : "\u0000")).join("")];
    case "id":
    case "member":
      return ["\u0000"];
    default:
      return [];
  }
}

function annotationText(annotation: Annotation): string[] {
  return textOf(annotation.value ?? annotation.named.get("value"));
}

function eachMethod(unit: Unit): Array<{ method: MethodInfo; cls: ClassInfo }> {
  const out: Array<{ method: MethodInfo; cls: ClassInfo }> = [];
  for (const cls of [unit.top, ...unit.classes]) {
    for (const method of cls.methods) out.push({ method, cls });
  }
  return out;
}

/**
 * `@Select`/`@Update`/`@Insert`/`@Delete` strings (MyBatis) and `@Query` (Spring Data) are fixed
 * at compile time, so the only way request data gets into them is a placeholder the framework
 * fills in with text: MyBatis `${...}` and a Spring Data `#{...}` SpEL expression. `#{...}` in
 * MyBatis and `:name` / `?1` in Spring Data bind a value and are safe.
 */
export function annotationFindings(unit: Unit): SqlFinding[] {
  const out: SqlFinding[] = [];
  // The names are shared with other libraries (Micronaut `@Delete`, Room `@Query`), so the file
  // has to import the library the annotation belongs to.
  const imports = (prefix: string): boolean =>
    unit.imports.some((name) => name === prefix || name.startsWith(`${prefix}.`));
  const mybatis = imports("org.apache.ibatis") || imports("org.mybatis");
  const springData = imports("org.springframework.data");
  for (const { method } of eachMethod(unit)) {
    for (const annotation of method.annotations) {
      if (out.length >= MAX_ANNOTATION_FINDINGS) return out;
      if (mybatis && MYBATIS_ANNOTATIONS.has(annotation.name)) {
        const seen = new Set<string>();
        for (const piece of annotationText(annotation)) {
          for (const match of piece.matchAll(PLACEHOLDER)) {
            const expression = (match[1] ?? "").trim();
            if (seen.has(expression)) continue;
            seen.add(expression);
            out.push(mybatisFinding(annotation, method, expression));
          }
        }
      } else if (springData && annotation.name === "Query") {
        const seen = new Set<string>();
        for (const piece of annotationText(annotation)) {
          for (const match of piece.matchAll(SPEL)) {
            const expression = (match[1] ?? "").trim();
            if (seen.has(expression) || /^#entityName$/.test(expression)) continue;
            seen.add(expression);
            out.push(springDataFinding(annotation, method, expression));
          }
        }
      }
    }
  }
  return out;
}

const shorten = (text: string): string => (text.length > 60 ? `${text.slice(0, 57)}...` : text);

function mybatisFinding(
  annotation: Annotation,
  method: MethodInfo,
  expression: string,
): SqlFinding {
  const parameterName = /^[A-Za-z_][A-Za-z0-9_]*$/.test(expression) ? expression : null;
  const parameter =
    parameterName === null
      ? undefined
      : method.params.find(
          (param) =>
            param.name === parameterName ||
            param.annotations.some(
              (a) => a.name === "Param" && textOf(a.value).join("") === parameterName,
            ),
        );
  const base = {
    line: annotation.line,
    cause: `@${annotation.name}:${method.name}:${expression}`,
  };
  const where = `MyBatis @${annotation.name} on ${method.name}() substitutes "\${${shorten(expression)}}" into the SQL text`;
  const typeName = parameter?.type.replace(/<.*>/s, "").replace(/\?/g, "").trim() ?? "";
  if (/^@[^@]+@[^@]+$/.test(expression)) {
    return {
      ...base,
      severity: "medium",
      status: "suspected",
      confidence: "low",
      evidence: `${where}; static field reference; inferred`,
    };
  }
  if (parameter !== undefined && NUMERIC_TYPES.has(typeName)) {
    return {
      ...base,
      severity: "medium",
      status: "suspected",
      confidence: "low",
      evidence: `${where}; the parameter is declared ${typeName}; inferred`,
    };
  }
  return {
    ...base,
    severity: "high",
    status: "suspected",
    confidence: "medium",
    evidence: `${where} (a mapper parameter comes from the caller; use #{} to bind it)`,
  };
}

function springDataFinding(
  annotation: Annotation,
  method: MethodInfo,
  expression: string,
): SqlFinding {
  const base = {
    line: annotation.line,
    cause: `@Query:${method.name}:${expression}`,
  };
  const where = `Spring Data @Query on ${method.name}() inlines the SpEL expression "#{${shorten(expression)}}" into the query text`;
  // A reference to a method argument (`#name`, `[0]`) puts caller data into the text.
  const referencesArgument = /#(?!entityName\b)[A-Za-z_]|\[\d+\]/.test(expression);
  if (referencesArgument) {
    return {
      ...base,
      severity: "high",
      status: "suspected",
      confidence: "medium",
      evidence: `${where}; it refers to a method argument (bind it with :#{...} or ?#{...})`,
    };
  }
  return {
    ...base,
    severity: "medium",
    status: "suspected",
    confidence: "low",
    evidence: `${where}; it does not refer to a method argument; inferred`,
  };
}
