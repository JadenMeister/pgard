import type { Confidence, FindingStatus, Severity } from "@pgard/findings";
import type { Expr, Stmt, Unit } from "./ir.js";

/** A finding of the configuration rules (Spring Security, cookies, CORS). */
export interface ConfigFinding {
  ruleId: "PG-CSRF-001" | "PG-COOKIE-001" | "PG-CONF-001";
  line: number;
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  evidence: string;
  cause: string;
}

export type CallExpr = Extract<Expr, { k: "call" }>;

export const isCall = (expr: Expr | null | undefined): expr is CallExpr => expr?.k === "call";

/** Java `true` is a literal node, Kotlin `true` is an identifier. */
export const isTrue = (expr: Expr | null | undefined): boolean =>
  expr !== null &&
  expr !== undefined &&
  ((expr.k === "lit" && expr.raw === "true") || (expr.k === "id" && expr.name === "true"));

export const isFalse = (expr: Expr | null | undefined): boolean =>
  expr !== null &&
  expr !== undefined &&
  ((expr.k === "lit" && expr.raw === "false") || (expr.k === "id" && expr.name === "false"));

/** `0`, `0L` and `Duration.ZERO` (a cookie that is being cleared). */
export const isZero = (expr: Expr | null | undefined): boolean =>
  expr !== null &&
  expr !== undefined &&
  ((expr.k === "lit" && expr.raw !== undefined && /^0[lL]?$/.test(expr.raw)) ||
    (expr.k === "id" && /^0[lL]?$/.test(expr.name)) ||
    (expr.k === "member" && expr.name === "ZERO"));

/** The last name of an identifier or member (`SessionCreationPolicy.STATELESS` -> `STATELESS`). */
export function lastName(expr: Expr | null | undefined): string | null {
  if (expr === null || expr === undefined) return null;
  if (expr.k === "id" || expr.k === "member") return expr.name;
  if (expr.k === "call") return expr.name;
  if (expr.k === "cast") return lastName(expr.expr);
  return null;
}

/** The type names and identifiers inside a small expression (`new JwtFilter(a)` -> JwtFilter, a). */
export function namesIn(expr: Expr | null | undefined, depth = 0): string[] {
  if (expr === null || expr === undefined || depth > 6) return [];
  switch (expr.k) {
    case "id":
      return [expr.name];
    case "member":
      return [...namesIn(expr.obj, depth + 1), expr.name];
    case "call":
      return [
        ...namesIn(expr.recv, depth + 1),
        expr.name,
        ...expr.args.flatMap((arg) => namesIn(arg, depth + 1)),
      ];
    case "new":
      return [expr.type, ...expr.args.flatMap((arg) => namesIn(arg, depth + 1))];
    case "cast":
      return namesIn(expr.expr, depth + 1);
    case "other":
      return expr.kids.flatMap((kid) => namesIn(kid, depth + 1));
    default:
      return [];
  }
}

/** Text of the string pieces of an expression, with a name that is not a literal as U+0000. */
export function literalText(expr: Expr | null | undefined): string | null {
  if (expr === null || expr === undefined) return null;
  switch (expr.k) {
    case "str":
      return expr.text;
    case "bin": {
      if (expr.op !== "+") return null;
      const left = literalText(expr.left);
      const right = literalText(expr.right);
      return left === null && right === null ? null : `${left ?? "\u0000"}${right ?? "\u0000"}`;
    }
    case "tmpl":
      return expr.parts.map((part) => (typeof part === "string" ? part : "\u0000")).join("");
    case "id":
    case "member":
    case "call":
      return "\u0000";
    default:
      return null;
  }
}

/** Splits an identifier or cookie name into lower-case words (`sessionId`, `SESSION_ID`, `x-sid`). */
export function wordsOf(text: string): string[] {
  // Names are short; the cap keeps the case-splitting patterns cheap on a hostile literal.
  return text
    .slice(0, 200)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter((word) => word !== "")
    .map((word) => word.toLowerCase());
}

const COLLECTION_FACTORIES = new Set([
  "listOf",
  "setOf",
  "arrayOf",
  "mutableListOf",
  "mutableSetOf",
  "arrayListOf",
  "asList",
  "of",
  "copyOf",
  "singletonList",
  "singleton",
  "stream",
]);

export interface Resolved {
  values: string[];
  /** Every piece was a string literal (or a constant that resolves to one). */
  complete: boolean;
}

/** Looks up a constant by name among the fields of the file (static or not: a best effort). */
function fieldInit(unit: Unit, name: string): Expr | null {
  for (const cls of [unit.top, ...unit.classes]) {
    const field = cls.fields.get(name);
    if (field?.init !== null && field?.init !== undefined && !field.isMutable) return field.init;
  }
  return null;
}

/**
 * The string values of a literal, an array or list of literals, or a constant of this file that
 * holds one. Anything else is reported as incomplete.
 */
export function resolveStrings(unit: Unit, expr: Expr | null | undefined, depth = 0): Resolved {
  if (expr === null || expr === undefined || depth > 4) return { values: [], complete: false };
  switch (expr.k) {
    case "str":
      return { values: [expr.text], complete: true };
    case "array":
      return merge(expr.elems.map((elem) => resolveStrings(unit, elem, depth + 1)));
    case "call":
      if (COLLECTION_FACTORIES.has(expr.name)) {
        return merge(expr.args.map((arg) => resolveStrings(unit, arg, depth + 1)));
      }
      return { values: [], complete: false };
    case "id":
    case "member": {
      const init = fieldInit(unit, expr.name);
      return init === null
        ? { values: [], complete: false }
        : resolveStrings(unit, init, depth + 1);
    }
    case "other":
      // A Kotlin `*array` spread or a collection literal `["a"]`.
      return merge(expr.kids.map((kid) => resolveStrings(unit, kid, depth + 1)));
    case "cast":
      return resolveStrings(unit, expr.expr, depth + 1);
    default:
      return { values: [], complete: false };
  }
}

function merge(parts: Resolved[]): Resolved {
  return {
    values: parts.flatMap((part) => part.values),
    complete: parts.every((part) => part.complete),
  };
}

export interface WalkContext {
  /** Inside an `if`, a loop or a `switch`/`when` arm: the code may not run. */
  conditional: boolean;
}

/**
 * Calls back for every call and assignment of a statement list in source order: a call's
 * receiver chain first, then the call, then its arguments (lambda bodies included).
 */
export function walkBody(
  body: readonly Stmt[] | null,
  onCall: (call: CallExpr, context: WalkContext, parent: CallExpr | null) => void,
  onAssign: (stmt: Extract<Stmt, { s: "assign" }>, context: WalkContext) => void = () => {},
  onStmt: (stmt: Stmt, context: WalkContext) => void = () => {},
  onNew: (expr: Extract<Expr, { k: "new" }>, context: WalkContext) => void = () => {},
): void {
  const stmts = (list: readonly Stmt[] | null, context: WalkContext): void => {
    for (const stmt of list ?? []) stmtVisit(stmt, context);
  };
  const exprs = (
    list: ReadonlyArray<Expr | null | undefined>,
    context: WalkContext,
    parent: CallExpr | null,
  ): void => {
    for (const expr of list)
      if (expr !== null && expr !== undefined) exprVisit(expr, context, parent);
  };
  function exprVisit(expr: Expr, context: WalkContext, parent: CallExpr | null): void {
    switch (expr.k) {
      case "call": {
        // The receiver chain is walked in a loop so a long chain cannot overflow the stack.
        const chain: CallExpr[] = [];
        let current: Expr | null = expr;
        while (isCall(current)) {
          chain.push(current);
          current = current.recv;
        }
        if (current !== null) exprVisit(current, context, null);
        for (let index = chain.length - 1; index >= 0; index -= 1) {
          const call = chain[index] as CallExpr;
          // The parent of a call is the call that takes it as its receiver.
          onCall(call, context, index === 0 ? null : (chain[index - 1] ?? null));
          for (const arg of call.args) exprVisit(arg, context, null);
        }
        break;
      }
      case "member":
        exprVisit(expr.obj, context, null);
        break;
      case "index":
        exprs([expr.obj, expr.index], context, null);
        break;
      case "new":
        onNew(expr, context);
        exprs(expr.args, context, null);
        break;
      case "bin": {
        let current: Expr = expr;
        const rights: Expr[] = [];
        while (current.k === "bin") {
          rights.push(current.right);
          current = current.left;
        }
        exprVisit(current, context, null);
        for (let index = rights.length - 1; index >= 0; index -= 1) {
          exprVisit(rights[index] as Expr, context, null);
        }
        break;
      }
      case "tmpl":
        exprs(
          expr.parts.map((part) => (typeof part === "string" ? null : part)),
          context,
          null,
        );
        break;
      case "cond":
        exprs([expr.test], context, null);
        exprs([expr.a, expr.b], { conditional: true }, null);
        break;
      case "alt":
        exprs(expr.options, { conditional: true }, null);
        break;
      case "cast":
        exprVisit(expr.expr, context, null);
        break;
      case "array":
        exprs(expr.elems, context, null);
        break;
      case "lambda":
        stmts(expr.body, context);
        break;
      case "other":
        exprs(expr.kids, context, null);
        break;
      default:
        break;
    }
  }
  function stmtVisit(stmt: Stmt, context: WalkContext): void {
    onStmt(stmt, context);
    switch (stmt.s) {
      case "local":
        exprs([stmt.init], context, null);
        break;
      case "assign":
        exprs([stmt.target, stmt.value], context, null);
        onAssign(stmt, context);
        break;
      case "expr":
        exprVisit(stmt.expr, context, null);
        break;
      case "if":
        exprVisit(stmt.test, context, null);
        stmts(stmt.then, { conditional: true });
        stmts(stmt.else, { conditional: true });
        break;
      case "loop":
        stmts(stmt.init, context);
        exprs([stmt.test, stmt.each?.iter], context, null);
        stmts(stmt.update, { conditional: true });
        stmts(stmt.body, { conditional: true });
        break;
      case "block":
        stmts(stmt.body, context);
        break;
      case "arms":
        exprs([stmt.subject], context, null);
        for (const arm of stmt.arms) stmts(arm.body, { conditional: true });
        break;
      case "exit":
        exprs([stmt.value], context, null);
        break;
      case "assert":
        exprVisit(stmt.test, context, null);
        break;
    }
  }
  stmts(body, { conditional: false });
}

/** Every method body of the file, with the method's class initializers as one more body. */
export function eachBody(unit: Unit): Array<{ name: string; body: Stmt[]; line: number }> {
  const out: Array<{ name: string; body: Stmt[]; line: number }> = [];
  for (const cls of [unit.top, ...unit.classes]) {
    if (cls.initializers.length > 0) {
      out.push({ name: "<init>", body: cls.initializers, line: cls.initializers[0]?.line ?? 1 });
    }
    for (const method of cls.methods) {
      if (method.body !== null)
        out.push({ name: method.name, body: method.body, line: method.line });
    }
  }
  return out;
}

/** The first call of a receiver chain and its calls in order (`a.b().c()` -> root `a`, [b, c]). */
export function chainOf(expr: Expr): { root: Expr | null; calls: CallExpr[] } {
  const calls: CallExpr[] = [];
  let current: Expr | null = expr;
  while (isCall(current)) {
    calls.push(current);
    current = current.recv;
  }
  calls.reverse();
  return { root: current, calls };
}

/** True when the file imports a package or class by this prefix. */
export function importsFrom(unit: Unit, prefix: string): boolean {
  return unit.imports.some((name) => name === prefix || name.startsWith(`${prefix}.`));
}

export const shorten = (text: string, max = 60): string =>
  text.length > max ? `${text.slice(0, max - 3)}...` : text;
