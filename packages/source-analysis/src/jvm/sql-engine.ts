import type { Confidence, FindingStatus, Severity } from "@pgard/findings";
import {
  guardedWhenFalse,
  guardedWhenTrue,
  pathGuardedWhenFalse,
  pathGuardedWhenTrue,
  type PathGuard,
} from "./guards.js";
import {
  addLeaves,
  baseType,
  combineOrigins,
  constant,
  copy,
  inferred,
  isConstantCase,
  isNumericType,
  isTypeName,
  join,
  leafKey,
  checkOrigin,
  literalText,
  nonConst,
  Scope,
  sourcesOf,
  unknown,
  value,
  type Binding,
  type Context,
  type Leaf,
  type Value,
} from "./flow-values.js";
import { createOsSinks, type OsFinding } from "./os-sinks.js";
import {
  ARCHIVE_IMPORT_PREFIXES,
  COLLECTION_CLASSES,
  ELEMENT_WRITERS,
  IMPORTS_COMMONS_EXEC,
  BENIGN_BARE,
  PATH_KEEPERS,
} from "./os-names.js";
import { walkUnit } from "./ir-walk.js";
import type { ClassInfo, Expr, FieldInfo, LambdaExpr, MethodInfo, Stmt, Unit } from "./ir.js";
import {
  BUILDER_ADDERS,
  BUILDER_TYPES,
  COERCING_CLASSES,
  COLLECTION_FACTORIES,
  COMPOSING,
  GENERIC_SINKS,
  HANDLER_ANNOTATIONS,
  JDBC_SINKS,
  LOOKUPS,
  MUTABLE_COLLECTIONS,
  NON_INPUT_TYPES,
  NUMERIC_MEMBERS,
  NUMERIC_RESULTS,
  NUMERIC_TYPES,
  ORM_SINKS,
  PASS_THROUGH,
  REQUEST_NAME,
  REQUEST_SELF,
  REQUEST_SOURCES,
  REQUEST_TYPES,
  SOURCE_ANNOTATIONS,
  SQL_IMPORT_PREFIXES,
  SQL_NAME,
  SQL_PRODUCERS,
  SQL_TEXT,
  SQL_TYPE,
} from "./jvm-names.js";

/** A finding before the rule id and path are attached. */
export interface SqlFinding {
  line: number;
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  evidence: string;
  cause: string;
}

/** A finding of one of the rules that run on the flow analysis. */
export type FlowFinding = SqlFinding & { ruleId: "PG-SQL-005" | OsFinding["ruleId"] };

export interface SqlAnalysis {
  findings: FlowFinding[];
  /** The tree was deeper than the analysis follows: part of the file was not analyzed. */
  incomplete: boolean;
  /** Code forms with a SQL-looking call that are not followed (anonymous and local classes, ...). */
  unsupported: string[];
}

/** Classes whose static methods are imported by name (`import static ...Files.readAllBytes`). */
const STATIC_OWNERS: ReadonlyArray<[string, string]> = [
  ["java.nio.file.Files", "Files"],
  ["org.apache.commons.io.FileUtils", "FileUtils"],
];

const MAX_DEPTH = 800;
const MAX_FINDINGS = 200;

// ------------------------------------------------------------------ engine

export function analyzeSql(unit: Unit): SqlAnalysis {
  const findings = new Map<string, FlowFinding & { rank: number }>();
  let incomplete = unit.incomplete;
  const classByName = new Map<string, ClassInfo>();
  for (const cls of unit.classes) if (!classByName.has(cls.name)) classByName.set(cls.name, cls);
  const hasSqlLibrary = unit.imports.some((name) =>
    SQL_IMPORT_PREFIXES.some((prefix) => name === prefix || name.startsWith(`${prefix}.`)),
  );
  // Whether the file runs processes at all: `command(...)` or `exec(...)` called without a receiver
  // (Kotlin `apply { }`, `with(...) { }`) or on a variable of unknown type belong to them then.
  let usesProcessBuilder = false;
  let usesRuntime = false;
  /** The class a name stands for: Kotlin `import java.io.File as JFile` makes `JFile` mean `File`. */
  const realName = (name: string): string => unit.aliases.get(name) ?? name;
  /** `import static java.nio.file.Files.readAllBytes` (or `.*`): the class an unqualified call belongs to. */
  const staticOwner = (name: string): string | null => {
    for (const [prefix, owner] of STATIC_OWNERS) {
      for (const imported of unit.imports) {
        if (imported === `${prefix}.${name}` || imported === `${prefix}.*`) return owner;
      }
    }
    return null;
  };
  const os = createOsSinks({
    staticOwner,
    get usesProcessBuilder() {
      return usesProcessBuilder;
    },
    get usesRuntime() {
      return usesRuntime;
    },
    typeOfExpr: (expr, ctx) => {
      const type = typeOfExpr(expr, ctx);
      if (type === null) return null;
      const real = unit.aliases.get(baseType(type));
      return real === undefined ? type : real;
    },
    record: (finding, rank) => record(finding, rank),
    hasArchiveLibrary: unit.imports.some((name) =>
      ARCHIVE_IMPORT_PREFIXES.some((prefix) => name === prefix || name.startsWith(`${prefix}.`)),
    ),
    hasCommonsExec: unit.imports.some(
      (name) => name === IMPORTS_COMMONS_EXEC || name.startsWith(`${IMPORTS_COMMONS_EXEC}.`),
    ),
  });
  const fieldValues = new Map<FieldInfo, Value | null>();
  // Names that are written through an index or a mutating call anywhere in the file: a literal
  // array or collection under such a name is not a fixed table.
  const mutatedNames = new Set<string>();
  const aliasEdges: Array<[string, string]> = [];
  const rootName = (expr: Expr): string | null => {
    let current = expr;
    while (current.k === "member" || current.k === "index") current = current.obj;
    return current.k === "id" ? current.name : null;
  };
  const MUTATORS = new Set([
    "set",
    "put",
    "putAll",
    "putIfAbsent",
    "add",
    "addAll",
    "addFirst",
    "addLast",
    "remove",
    "removeAll",
    "removeIf",
    "retainAll",
    "clear",
    "replace",
    "replaceAll",
    "compute",
    "merge",
    "computeIfAbsent",
    "computeIfPresent",
    "push",
    "pop",
    "sort",
    "fill",
    "setAll",
  ]);
  const STATIC_MUTATORS = new Set([
    "fill",
    "addAll",
    "swap",
    "sort",
    "reverse",
    "shuffle",
    "copy",
    "setAll",
  ]);
  walkUnit(
    unit,
    (expr) => {
      if (expr.k === "new" && realName(baseType(expr.type)) === "ProcessBuilder") {
        usesProcessBuilder = true;
      }
      if (expr.k !== "call") return;
      if (expr.recv === null && realName(expr.name) === "ProcessBuilder") usesProcessBuilder = true;
      if (expr.name === "getRuntime") usesRuntime = true;
      if (MUTATORS.has(expr.name) && expr.recv !== null) {
        const root = rootName(expr.recv);
        if (root !== null) mutatedNames.add(root);
      }
      if (STATIC_MUTATORS.has(expr.name) && expr.args[0] !== undefined) {
        const root = rootName(expr.args[0]);
        if (root !== null) mutatedNames.add(root);
      }
    },
    (stmt) => {
      if (stmt.s === "assign" && (stmt.target.k === "index" || stmt.target.k === "member")) {
        const root = rootName(stmt.target);
        if (root !== null) mutatedNames.add(root);
      }
      // `String[] a = COLS;` and `a = COLS;` make two names for one array.
      const aliased =
        stmt.s === "local" && stmt.init !== null
          ? [stmt.name, stmt.init]
          : stmt.s === "assign" && stmt.op === "="
            ? [rootName(stmt.target), stmt.value]
            : null;
      if (aliased !== null && typeof aliased[0] === "string") {
        const from = aliased[1] as Expr;
        const other = from.k === "id" ? from.name : null;
        if (other !== null) aliasEdges.push([aliased[0], other]);
      }
    },
  );
  for (let changed = true; changed;) {
    changed = false;
    for (const [a, b] of aliasEdges) {
      if (mutatedNames.has(a) !== mutatedNames.has(b)) {
        mutatedNames.add(a);
        mutatedNames.add(b);
        changed = true;
      }
    }
  }
  const pendingLambdas: Array<{
    lambda: LambdaExpr;
    ctx: Context;
    guarded: Binding[];
    pathGuarded: Binding[];
  }> = [];
  const seenLambdas = new Set<LambdaExpr>();
  // Bumped when a variable or builder gains a kind of value it did not hold: a loop is walked
  // again until nothing changes.
  let version = 0;

  const lookupField = (
    cls: ClassInfo | null,
    name: string,
  ): { field: FieldInfo; owner: ClassInfo } | null => {
    for (let current: ClassInfo | null = cls; current !== null; current = current.parent) {
      const found = fieldOf(current, name);
      if (found !== null) return found;
    }
    const top = unit.top.fields.get(name);
    return top === undefined ? null : { field: top, owner: unit.top };
  };
  /** A field of the class, or of a class or interface it extends or implements in this file. */
  function fieldOf(
    cls: ClassInfo,
    name: string,
    seen = new Set<ClassInfo>(),
  ): { field: FieldInfo; owner: ClassInfo } | null {
    if (seen.has(cls) || seen.size > 12) return null;
    seen.add(cls);
    const own = cls.fields.get(name);
    if (own !== undefined) return { field: own, owner: cls };
    for (const superName of cls.supers) {
      const parent = classByName.get(superName);
      if (parent === undefined) continue;
      const inherited = fieldOf(parent, name, seen);
      if (inherited !== null) return inherited;
    }
    return null;
  }

  const rootContext = (cls: ClassInfo | null, report: boolean): Context => ({
    cls,
    scope: new Scope(null),
    conditional: 0,
    builders: [],
    loops: 0,
    deferred: false,
    report,
  });

  /** What a field is worth when read: fixed text only for what cannot change. */
  function fieldValue(field: FieldInfo, owner: ClassInfo): Value {
    if (fieldValues.has(field)) return fieldValues.get(field) ?? unknown(field.name);
    fieldValues.set(field, null); // cycle guard
    const fieldType = baseType(field.type);
    // A builder, an array or a collection can be changed from any method, whatever it starts as;
    // a field that can be assigned is likewise decided where it is assigned.
    const mutableType =
      BUILDER_TYPES.has(fieldType) ||
      /\[\]/.test(field.type ?? "") ||
      MUTABLE_COLLECTIONS.has(fieldType);
    let result: Value = unknown(
      field.isMutable || mutableType ? `mutable field ${field.name}` : field.name,
    );
    if (field.init !== null && !field.isMutable && !field.overridable) {
      const evaluated = evalExpr(
        field.init,
        rootContext(owner === unit.top ? null : owner, false),
        0,
      );
      const dynamic = nonConst(evaluated.leaves);
      // A `final` field or Kotlin `val` that holds a StringBuilder, or an array or collection that
      // is written to somewhere, is not fixed text however it is declared.
      const mutable =
        evaluated.builder ||
        BUILDER_TYPES.has(fieldType) ||
        (evaluated.table && mutatedNames.has(field.name)) ||
        (mutableType && !evaluated.table);
      if (mutable) {
        // Read as text (`base.toString()`), what it holds is decided where it is appended to.
        result = unknown(`mutable field ${field.name}`);
      } else if (dynamic.length === 0) {
        result = evaluated;
      } else if (dynamic.every((leaf) => leaf.k === "inferred")) {
        result = evaluated;
      }
    }
    fieldValues.set(field, result);
    return result;
  }

  // ---------------------------------------------------------------- expression evaluation

  function typeOfExpr(expr: Expr, ctx: Context): string | null {
    if (expr.k === "id") {
      const binding = ctx.scope.find(expr.name);
      if (binding !== null) return binding.type;
      return lookupField(ctx.cls, expr.name)?.field.type ?? null;
    }
    if (expr.k === "member" && expr.obj.k === "id" && expr.obj.name === "this") {
      return lookupField(ctx.cls, expr.name)?.field.type ?? null;
    }
    return null;
  }

  function evalBin(expr: Extract<Expr, { k: "bin" }>, ctx: Context, depth: number): Value {
    // Walk down the left spine once, so a long `+` chain costs a loop, not recursion.
    const spine: Array<Extract<Expr, { k: "bin" }>> = [];
    let current: Expr = expr;
    while (current.k === "bin" && spine.length < 100_000) {
      spine.push(current);
      current = current.left;
    }
    let result = evalExpr(current, ctx, depth + 1);
    // True once `result` is a value made here: further terms are added to it in place.
    let owned = false;
    for (let i = spine.length - 1; i >= 0; i -= 1) {
      const step = spine[i] as Extract<Expr, { k: "bin" }>;
      const right = evalExpr(step.right, ctx, depth + 1);
      if (step.op === "to") escape([result, right], "pair");
      if (step.op === "+" && owned && result.shape === "string concatenation") {
        addLeaves(result.leaves, right.leaves);
      } else if (step.op === "+" || step.op === "to" || step.op === "plus") {
        const merged = join(step.op === "to" ? "pair" : "string concatenation", result, right);
        if (step.op === "to") merged.composed = false;
        // `list + listOf(x)` is still a list.
        merged.coll = result.coll || right.coll;
        result = merged;
        owned = true;
      } else if (step.op === "?:") {
        const merged = join(result.shape, result, right);
        merged.composed = result.composed || right.composed;
        merged.shape = result.shape || right.shape;
        result = merged;
      } else {
        // Arithmetic, comparison and logic produce numbers or booleans.
        const dynamic = nonConst([...result.leaves, ...right.leaves]);
        result = dynamic.length === 0 ? value() : inferred("arithmetic or comparison result");
      }
    }
    return result;
  }

  function formatValue(format: Value, args: Value[], formatExpr: Expr | undefined): Value {
    const literal = formatExpr?.k === "str" ? formatExpr.text : null;
    const leaves: Leaf[] = [];
    addLeaves(leaves, format.leaves);
    if (literal === null) {
      for (const arg of args) addLeaves(leaves, arg.leaves);
      return value(leaves, { composed: true, shape: "String.format" });
    }
    // `%d`, `%x`, `%f`, `%b` and friends only accept numbers or booleans: a String argument fails
    // at run time, so the argument cannot be SQL text. `%s` takes anything.
    const specifier = /%(?:(\d+)\$)?[-#+ 0,(]*\d*(?:\.\d+)?([a-zA-Z%])/g;
    let next = 0;
    for (const match of literal.matchAll(specifier)) {
      const conversion = match[2] as string;
      if (conversion === "%" || conversion === "n") continue;
      const index = match[1] === undefined ? next++ : Number(match[1]) - 1;
      const arg = args[index];
      if (arg === undefined) continue;
      if ("dxXofeEgGbBhH".includes(conversion)) {
        addLeaves(
          leaves,
          nonConst(arg.leaves).length === 0
            ? arg.leaves
            : [{ k: "inferred", why: `%${conversion} accepts only numbers or booleans` }],
        );
      } else {
        addLeaves(leaves, arg.leaves);
      }
    }
    return value(leaves, { composed: true, shape: "String.format" });
  }

  const isLocaleArg = (expr: Expr | undefined): boolean =>
    expr !== undefined &&
    ((expr.k === "member" && expr.obj.k === "id" && expr.obj.name === "Locale") ||
      (expr.k === "id" && /locale/i.test(expr.name)) ||
      (expr.k === "call" && expr.name === "Locale"));

  /** A fixed collection of literals, such as `Map.of("a", "b")` or `new String[]{"a"}`. */
  function tableOf(args: Value[]): Value {
    const leaves: Leaf[] = [];
    for (const arg of args) addLeaves(leaves, arg.leaves);
    const fixed = nonConst(leaves).length === 0;
    return value(leaves, { table: fixed, elems: args, coll: true });
  }

  function guardedBindings(scope: Scope, flag: "guarded" | "pathGuarded" = "guarded"): Binding[] {
    const out: Binding[] = [];
    for (let current: Scope | null = scope; current !== null; current = current.parent) {
      for (const binding of current.vars.values()) if (binding[flag] === true) out.push(binding);
    }
    return out;
  }

  function runLambda(
    lambda: LambdaExpr,
    ctx: Context,
    depth: number,
    implicit: Value | null,
    /** The value the lambda is applied to (a Kotlin let block, a Java forEach lambda). */
    receiver: Value | null = null,
    /** A builder that the lambda's parameter (`it`, or the named one) is. */
    bindTo: Value | null = null,
  ): void {
    // A lambda may run after the code that defines it (and after later assignments to the
    // variables it captures): it is also run once at the end of the method, with those variables
    // holding everything they held.
    if (implicit === null && bindTo === null && !seenLambdas.has(lambda)) {
      seenLambdas.add(lambda);
      pendingLambdas.push({
        lambda,
        ctx,
        guarded: guardedBindings(ctx.scope),
        pathGuarded: guardedBindings(ctx.scope, "pathGuarded"),
      });
    }
    execLambda(lambda, ctx, depth, implicit, receiver, bindTo);
  }

  function execLambda(
    lambda: LambdaExpr,
    ctx: Context,
    depth: number,
    implicit: Value | null,
    receiver: Value | null,
    bindTo: Value | null,
  ): void {
    const scope = new Scope(ctx.scope, true);
    // Request input in the receiver reaches the lambda's parameter.
    const carried = receiver === null ? [] : sourcesOf(receiver.leaves);
    const parameter = (name: string): Value =>
      bindTo !== null
        ? bindTo
        : carried.length > 0
          ? value(
              carried.map((leaf): Leaf =>
                leaf.k === "source" ? { ...leaf, direct: false } : leaf,
              ),
            )
          : unknown(name);
    const bind = (name: string): void => {
      const initial = parameter(name);
      scope.vars.set(name, {
        name,
        type: null,
        value: initial,
        guarded: false,
        ever: [...initial.leaves],
      });
    };
    for (const name of lambda.params) bind(name);
    if (lambda.params.length === 0) bind("it");
    const inner: Context = {
      ...ctx,
      scope,
      conditional: ctx.conditional + 1,
      builders: implicit === null ? ctx.builders : [...ctx.builders, implicit],
    };
    execStmts(lambda.body, inner, depth + 1);
  }

  function drainLambdas(): void {
    while (pendingLambdas.length > 0) {
      const next = pendingLambdas.shift();
      if (next === undefined) break;
      const restore: Binding[] = [];
      const restorePath: Binding[] = [];
      for (const binding of next.guarded) {
        if (!binding.guarded) {
          binding.guarded = true;
          restore.push(binding);
        }
      }
      for (const binding of next.pathGuarded) {
        if (binding.pathGuarded !== true) {
          binding.pathGuarded = true;
          restorePath.push(binding);
        }
      }
      try {
        execLambda(next.lambda, { ...next.ctx, deferred: true }, 0, null, null, null);
      } finally {
        for (const binding of restore) binding.guarded = false;
        for (const binding of restorePath) binding.pathGuarded = false;
      }
    }
  }

  /** `java.io` as a receiver: lower-case names only. */
  function isPackageName(expr: Expr): boolean {
    let current: Expr = expr;
    while (current.k === "member") {
      if (!/^[a-z][a-z0-9_]*$/.test(current.name)) return false;
      current = current.obj;
    }
    return current.k === "id" && /^[a-z][a-z0-9_]*$/.test(current.name);
  }

  /** `java.util.Map` as a receiver: a package of lower-case names, then a class. */
  function qualifiedTypeName(expr: Expr): string | null {
    if (expr.k !== "member" || !isTypeName(expr.name)) return null;
    let current: Expr = expr.obj;
    while (current.k === "member") {
      if (!/^[a-z][a-z0-9_]*$/.test(current.name)) return null;
      current = current.obj;
    }
    return current.k === "id" && /^[a-z][a-z0-9_]*$/.test(current.name) ? expr.name : null;
  }

  function evalCall(expr: Extract<Expr, { k: "call" }>, ctx: Context, depth: number): Value {
    const { name } = expr;
    let recv: Value | null = null;
    let typeReceiver = false;
    let className = "";
    if (expr.recv !== null) {
      const qualified = qualifiedTypeName(expr.recv);
      if (
        expr.recv.k === "id" &&
        isTypeName(expr.recv.name) &&
        ctx.scope.find(expr.recv.name) === null &&
        lookupField(ctx.cls, expr.recv.name) === null
      ) {
        typeReceiver = true;
        className = expr.recv.name;
      } else if (qualified !== null) {
        typeReceiver = true;
        className = qualified;
      } else {
        recv = evalExpr(expr.recv, ctx, depth + 1);
      }
    }
    const args: Value[] = [];
    for (const arg of expr.args) {
      args.push(arg.k === "lambda" ? value() : evalExpr(arg, ctx, depth + 1));
    }

    // Kotlin scope functions on a builder: `StringBuilder().apply { append(x) }`, `sb.also { it.append(x) }`,
    // `sb.let { b -> b.append(x) }`, `with(sb) { append(x) }`.
    const scoped =
      recv?.builder === true
        ? recv
        : name === "with" && expr.recv === null && args[0]?.builder === true
          ? args[0]
          : null;
    if (
      scoped !== null &&
      expr.lambdas.length > 0 &&
      ["apply", "also", "run", "let", "with"].includes(name)
    ) {
      const asParameter = name === "also" || name === "let";
      for (const lambda of expr.lambdas) {
        runLambda(lambda, ctx, depth, scoped, null, asParameter ? scoped : null);
      }
      return name === "apply" || name === "also" || name === "with" ? scoped : copy(scoped);
    }
    if (expr.recv === null && name === "buildString" && expr.lambdas.length > 0) {
      const builder = value([], { builder: true, composed: true, shape: "StringBuilder" });
      for (const lambda of expr.lambdas) runLambda(lambda, ctx, depth, builder);
      return copy(builder);
    }
    for (const lambda of expr.lambdas) {
      if (!(recv?.builder === true)) runLambda(lambda, ctx, depth, null, recv);
    }

    const sinkCall =
      expr.recv !== null &&
      (JDBC_SINKS.has(name) || GENERIC_SINKS.has(name) || ORM_SINKS.has(name));
    if (!sinkCall) escape(args, `${name}()`);
    for (const arg of args) os.escapes(arg);
    if (ctx.report) checkSink(expr, args, ctx);
    noteWrites(expr, args, ctx);
    // Kotlin builds an object by calling its class, plainly (`File(p)`) or by package (`java.io.File(p)`).
    const made =
      /^[A-Z]/.test(name) &&
      (expr.recv === null ? ctx.scope.find(name) === null : isPackageName(expr.recv))
        ? os.construct(realName(name), expr.line, expr.args, args, ctx, false)
        : null;
    if (made !== null) return made;
    const osValue = os.call(expr, recv, args, typeReceiver, realName(className), ctx);
    if (osValue !== null) return osValue;

    // ---- what the call returns ----
    if (recv?.req === true) {
      if (REQUEST_SELF.has(name)) return value([], { req: true });
      if (REQUEST_SOURCES.has(name)) {
        const label = `${expr.recv?.k === "id" ? expr.recv.name : "request"}.${name}`;
        return value([{ k: "source", label, direct: true }]);
      }
      return unknown(name);
    }
    const implicitBuilder =
      (expr.recv === null || (expr.recv.k === "id" && expr.recv.name === "this")) &&
      ctx.builders.length > 0 &&
      BUILDER_ADDERS.has(name)
        ? (ctx.builders[ctx.builders.length - 1] as Value)
        : null;
    const builder = recv?.builder === true ? recv : implicitBuilder;
    if (builder !== null) {
      if (BUILDER_ADDERS.has(name)) {
        const relevant = name === "insert" ? args.slice(1) : args;
        addTracked(builder.leaves, join("StringBuilder", ...relevant).leaves);
        builder.composed = true;
        builder.shape = builder.shape || "StringBuilder";
        return builder;
      }
      if (name === "toString" || name === "build") {
        const snapshot = copy(builder);
        // Through a variable the input is no longer written at the call.
        if (expr.recv?.k === "id") {
          snapshot.leaves = snapshot.leaves.map((leaf) =>
            leaf.k === "source" ? { ...leaf, direct: false } : leaf,
          );
        }
        return snapshot;
      }
      if (["setLength", "delete", "deleteCharAt", "reverse", "setCharAt"].includes(name)) {
        return builder;
      }
    }
    if (expr.recv === null && (name === "StringBuilder" || name === "StringBuffer")) {
      return newBuilder(args);
    }
    if (typeReceiver && className === "String" && name === "format") {
      const shift = isLocaleArg(expr.args[0]) ? 1 : 0;
      return formatValue(args[shift] ?? value(), args.slice(shift + 1), expr.args[shift]);
    }
    if (typeReceiver && className === "MessageFormat" && name === "format") {
      return join("MessageFormat.format", ...args);
    }
    if (name === "formatted" && recv !== null) {
      return formatValue(recv, args, expr.recv ?? undefined);
    }
    if (name === "format" && recv !== null && expr.recv?.k === "str") {
      return formatValue(recv, args, expr.recv);
    }
    if (typeReceiver && COERCING_CLASSES.has(className)) {
      return inferred(`${className}.${name}() gives a number, date or UUID`);
    }
    if (NUMERIC_RESULTS.has(name) && (recv !== null || expr.recv === null)) {
      return inferred(`${name}() gives a number or boolean`);
    }
    if (name === "nCopies" && args[1] !== undefined) return value(args[1].leaves);
    if (name === "name" && expr.args.length === 0 && expr.recv !== null) {
      return nameOf(expr.recv, recv, ctx);
    }
    if (COLLECTION_FACTORIES.has(name) && (typeReceiver || expr.recv === null)) {
      return tableOf(args);
    }
    if (LOOKUPS.has(name) && recv !== null) return lookup(recv);
    if (PASS_THROUGH.has(name)) {
      const parts: Value[] = [];
      if (recv !== null) parts.push(recv);
      parts.push(...args);
      const merged = join(recv?.composed === true ? recv.shape : "string operation", ...parts);
      const dynamic = nonConst(merged.leaves).length > 0;
      merged.composed =
        (recv?.composed ?? false) ||
        args.some((arg) => arg.composed) ||
        COMPOSING.has(name) ||
        (dynamic && args.some((arg) => nonConst(arg.leaves).length > 0));
      if (merged.composed && merged.shape === "string operation") {
        merged.shape = COMPOSING.has(name) ? `String.${name}` : "string operation";
      }
      if (!merged.composed) merged.shape = recv?.shape ?? "";
      return merged;
    }
    // Unknown call: request input that goes in is assumed to come out.
    const carried = sourcesOf([...(recv?.leaves ?? []), ...args.flatMap((arg) => arg.leaves)]);
    if (carried.length > 0) return value(carried, { opaque: `${name}()` });
    if (name === "invoke") return unknown("call");
    return unknown(`${name}()`);
  }

  /** Value read out of a collection: the elements, not the key. */
  function lookup(recv: Value): Value {
    if (recv.table) return inferred("value taken from a fixed allowlist table");
    const carried = sourcesOf(recv.leaves);
    if (carried.length > 0) return value(carried);
    if (nonConst(recv.leaves).length === 0 && recv.leaves.length > 0) {
      return inferred("value taken from a fixed collection");
    }
    return unknown("lookup");
  }

  /** The enum a receiver provably is: a type declared in this file, or `Type.valueOf(...)`. */
  function provableEnum(recvExpr: Expr, ctx: Context): ClassInfo | null {
    if (recvExpr.k === "member" && recvExpr.obj.k === "id") {
      const owner = classByName.get(recvExpr.obj.name);
      if (owner?.isEnum === true && owner.enumConstants.includes(recvExpr.name)) return owner;
    }
    if (recvExpr.k === "call" && recvExpr.name === "valueOf" && recvExpr.recv?.k === "id") {
      const owner = classByName.get(recvExpr.recv.name);
      if (owner?.isEnum === true) return owner;
      const first = recvExpr.args[0];
      if (
        recvExpr.recv.name === "Enum" &&
        first?.k === "member" &&
        first.name === "class" &&
        first.obj.k === "id"
      ) {
        const typed = classByName.get(first.obj.name);
        if (typed?.isEnum === true) return typed;
      }
    }
    const owner = classByName.get(baseType(typeOfExpr(recvExpr, ctx)));
    return owner?.isEnum === true ? owner : null;
  }

  /**
   * `x.name()` / `x.name`. Fixed text only when the receiver is provably an enum of this file;
   * request input in the receiver (a record or data class `name`) is checked next and stays
   * request input; anything else is unknown.
   */
  function nameOf(recvExpr: Expr, recv: Value | null, ctx: Context): Value {
    if (provableEnum(recvExpr, ctx) !== null) return constant("ENUM");
    const carried = recv === null ? [] : sourcesOf(recv.leaves);
    return carried.length > 0 ? value(carried) : unknown("name()");
  }

  /** An enum constant used as text is its `toString()`, which an enum can override. */
  function enumConstantValue(owner: ClassInfo, name: string): Value {
    return owner.methods.some((method) => method.name === "toString")
      ? inferred("enum with its own toString()")
      : constant(name);
  }

  /** `addLeaves` that records a change when a new kind of value arrives (loops iterate on it). */
  function addTracked(into: Leaf[], from: readonly Leaf[]): void {
    const before = into.length;
    addLeaves(into, from);
    if (into.slice(before).some((leaf) => leaf.k !== "const")) version += 1;
  }

  /**
   * A builder used in any way other than as the receiver of append/insert/delete/replace/
   * setLength/toString, or as a sink argument, can be changed where the analysis cannot see it
   * (a field, a collection, an array, another method): it then also holds an unknown value.
   */
  function escape(values: readonly Value[], where: string): void {
    for (const candidate of values) {
      if (candidate.builder) addTracked(candidate.leaves, [{ k: "unknown", name: where }]);
    }
  }

  function newBuilder(args: Value[]): Value {
    const leaves: Leaf[] = [];
    for (const arg of args) addLeaves(leaves, arg.leaves);
    return value(leaves, { builder: true, composed: true, shape: "StringBuilder" });
  }

  function evalIdentifier(name: string, ctx: Context): Value {
    if (name === "true" || name === "false" || name === "null") return value();
    const hit = ctx.scope.lookup(name);
    if (hit !== null) return readBinding(hit.binding, ctx.deferred && hit.captured);
    const found = lookupField(ctx.cls, name);
    if (found !== null) return fieldRead(found.field, found.owner);
    if (isConstantCase(name)) return inferred("constant-style name defined in another file");
    if (REQUEST_NAME.test(name) && name !== "exchange") return value([], { req: true });
    return unknown(name);
  }

  function fieldRead(field: FieldInfo, owner: ClassInfo): Value {
    if (REQUEST_TYPES.has(baseType(field.type))) return value([], { req: true });
    if (field.init === null && REQUEST_NAME.test(field.name)) return value([], { req: true });
    return fieldValue(field, owner);
  }

  function readBinding(binding: Binding, everHeld = false): Value {
    const stored = binding.value;
    if (stored.builder) return stored;
    const held = everHeld ? binding.ever : stored.leaves;
    const leaves = held.map((leaf): Leaf => {
      if (leaf.k === "source")
        return { ...leaf, direct: binding.isParam === true ? leaf.direct : false };
      return leaf;
    });
    let result = everHeld
      ? { ...stored, leaves, table: false, elems: null }
      : { ...stored, leaves };
    if (binding.pathGuarded === true && !binding.guarded && nonConst(leaves).length > 0) {
      // Only the path rule counts a path check: the leaves are marked, not replaced.
      const seen: Leaf[] = [];
      addLeaves(
        seen,
        leaves.map((leaf): Leaf =>
          leaf.k === "source" || leaf.k === "unknown" ? { ...leaf, pg: true } : leaf,
        ),
      );
      result = { ...result, leaves: seen };
    }
    if (binding.guarded && nonConst(leaves).length > 0) {
      const seen: Leaf[] = [];
      addLeaves(
        seen,
        leaves.map((leaf): Leaf =>
          leaf.k === "const" || leaf.k === "inferred"
            ? leaf
            : { k: "inferred", why: "value checked against an allowlist" },
        ),
      );
      result = { ...result, leaves: seen };
    }
    return result;
  }

  function evalMember(expr: Extract<Expr, { k: "member" }>, ctx: Context, depth: number): Value {
    const { obj, name } = expr;
    if (obj.k === "id" && (obj.name === "this" || obj.name === "super")) {
      const found = lookupField(ctx.cls, name);
      return found === null ? unknown(name) : fieldRead(found.field, found.owner);
    }
    if (
      obj.k === "id" &&
      ctx.scope.find(obj.name) === null &&
      lookupField(ctx.cls, obj.name) === null &&
      isTypeName(obj.name)
    ) {
      const owner = classByName.get(obj.name);
      if (owner !== undefined) {
        const inherited = fieldOf(owner, name);
        if (inherited !== null) return fieldRead(inherited.field, inherited.owner);
        if (owner.isEnum && owner.enumConstants.includes(name)) {
          return enumConstantValue(owner, name);
        }
      }
      if (name === "class" || name === "java") return value();
      if (isConstantCase(name)) return inferred("constant-style name defined in another file");
      return unknown(`${obj.name}.${name}`);
    }
    const recv = evalExpr(obj, ctx, depth + 1);
    if (recv.req) {
      if (REQUEST_SELF.has(name)) return value([], { req: true });
      if (REQUEST_SOURCES.has(name)) {
        return value([
          { k: "source", label: `${obj.k === "id" ? obj.name : "request"}.${name}`, direct: true },
        ]);
      }
      return unknown(name);
    }
    const osMember = os.member(expr, recv, ctx);
    if (osMember !== null) return osMember;
    // `sb::append` is parsed as a member access: the builder is used through it.
    if (recv.builder && !NUMERIC_MEMBERS.has(name)) escape([recv], `${name}`);
    if (NUMERIC_MEMBERS.has(name)) return inferred(`${name} gives a number`);
    if (name === "name") return nameOf(obj, recv, ctx);
    if (name === "class") return value();
    const carried = sourcesOf(recv.leaves);
    if (carried.length > 0) return value(carried);
    return unknown(name);
  }

  function evalExpr(expr: Expr, ctx: Context, depth: number): Value {
    if (depth > MAX_DEPTH) {
      incomplete = true;
      return unknown("deep");
    }
    switch (expr.k) {
      case "str":
        return constant(expr.text);
      case "lit":
        return value();
      case "id":
        return evalIdentifier(expr.name, ctx);
      case "member":
        return evalMember(expr, ctx, depth);
      case "index": {
        const recv = evalExpr(expr.obj, ctx, depth + 1);
        evalExpr(expr.index, ctx, depth + 1);
        return lookup(recv);
      }
      case "call":
        return evalCall(expr, ctx, depth);
      case "new": {
        const args = expr.args.map((arg) =>
          arg.k === "lambda" ? value() : evalExpr(arg, ctx, depth + 1),
        );
        const type = baseType(expr.type);
        escape(args, `new ${type}`);
        const made = os.construct(type, expr.line, expr.args, args, ctx);
        if (made !== null) return made;
        if (BUILDER_TYPES.has(type)) return newBuilder(type === "StringJoiner" ? [] : args);
        if (NUMERIC_TYPES.has(type)) return inferred(`new ${type}(...) gives a number`);
        if (type === "String") return join("string operation", ...args);
        if (
          type === "ArrayList" ||
          type === "HashMap" ||
          type === "HashSet" ||
          type === "LinkedList"
        ) {
          return {
            ...unknown(type),
            coll: true,
            elems: args.length === 1 ? (args[0]?.elems ?? null) : null,
          };
        }
        const carried = sourcesOf(args.flatMap((arg) => arg.leaves));
        const created = carried.length > 0 ? value(carried) : unknown(`new ${type}`);
        return COLLECTION_CLASSES.has(type) ? { ...created, coll: true } : created;
      }
      case "bin":
        return evalBin(expr, ctx, depth);
      case "tmpl": {
        const parts = expr.parts.map((part) =>
          typeof part === "string" ? constant(part) : evalExpr(part, ctx, depth + 1),
        );
        return join("string template", ...parts);
      }
      case "cond": {
        evalExpr(expr.test, ctx, depth + 1);
        const a = withGuards(guardsWhen(expr.testText, true), ctx, () =>
          evalExpr(expr.a, ctx, depth + 1),
        );
        const b = withGuards(guardsWhen(expr.testText, false), ctx, () =>
          evalExpr(expr.b, ctx, depth + 1),
        );
        return alternatives([a, b]);
      }
      case "alt":
        return alternatives(expr.options.map((option) => evalExpr(option, ctx, depth + 1)));
      case "cast": {
        const inner = evalExpr(expr.expr, ctx, depth + 1);
        return isNumericType(expr.type) ? inferred(`cast to ${baseType(expr.type)}`) : inner;
      }
      case "array": {
        const elems = expr.elems.map((elem) => evalExpr(elem, ctx, depth + 1));
        escape(elems, "array");
        return tableOf(elems);
      }
      case "lambda":
        runLambda(expr, ctx, depth, null);
        return value();
      case "other": {
        const kids = expr.kids.map((kid) => evalExpr(kid, ctx, depth + 1));
        escape(kids, "expression");
        const carried = sourcesOf(kids.flatMap((kid) => kid.leaves));
        const result = carried.length > 0 ? value(carried) : unknown("expression");
        // `*arrayOf(...)`: the same values, spread; only the command rule reads the elements.
        return expr.spread === true && kids[0] !== undefined
          ? { ...result, elems: kids[0].elems, coll: kids[0].coll }
          : result;
      }
    }
  }

  function alternatives(options: Value[]): Value {
    escape(options, "one of several values");
    const leaves: Leaf[] = [];
    for (const option of options) addLeaves(leaves, option.leaves);
    return value(leaves, {
      composed: options.some((option) => option.composed),
      shape: options.find((option) => option.shape !== "")?.shape ?? "",
      table: options.length > 0 && options.every((option) => option.table),
      path: options.length > 0 && options.every((option) => option.path),
      canon: options.length > 0 && options.every((option) => option.canon),
      origin: combineOrigins(options),
    });
  }

  /** Checks that hold in some code: allowlist checks (all rules) and path checks (path rule only). */
  interface GuardSet {
    allow: string[];
    path: PathGuard[];
  }
  const guardsWhen = (text: string, truth: boolean): GuardSet =>
    truth
      ? { allow: guardedWhenTrue(text), path: pathGuardedWhenTrue(text) }
      : { allow: guardedWhenFalse(text), path: pathGuardedWhenFalse(text) };

  /** A path made by a constructor that is never used is reported once the analysis ends: a check demotes it. */
  const noteGuard = (binding: Binding, permanent: boolean): void => {
    if (permanent) checkOrigin(binding.value.origin);
  };

  /** The variables a path check covers: the one it names (if canonical when it must be) and what it came from. */
  function pathTargets(guard: PathGuard, ctx: Context): Binding[] {
    const first = ctx.scope.find(guard.name);
    if (first === null || (guard.needsCanon && !first.value.canon)) return [];
    const out: Binding[] = [first];
    for (let i = 0; i < out.length && out.length < 8; i += 1) {
      for (const name of out[i]?.derived ?? []) {
        const next = ctx.scope.find(name);
        if (next !== null && !out.includes(next)) out.push(next);
      }
    }
    return out;
  }

  /** Turns the checks on; returns what turns them off again. */
  function applyGuards(set: GuardSet, ctx: Context, permanent = true): Array<() => void> {
    const restore: Array<() => void> = [];
    for (const name of set.allow) {
      const binding = ctx.scope.find(name);
      if (binding !== null && !binding.guarded) {
        binding.guarded = true;
        noteGuard(binding, permanent);
        restore.push(() => {
          binding.guarded = false;
        });
      }
    }
    for (const guard of set.path) {
      for (const binding of pathTargets(guard, ctx)) {
        if (binding.pathGuarded !== true) {
          binding.pathGuarded = true;
          noteGuard(binding, permanent);
          restore.push(() => {
            binding.pathGuarded = false;
          });
        }
      }
    }
    return restore;
  }

  function withGuards<T>(set: GuardSet, ctx: Context, run: () => T): T {
    const restore = applyGuards(set, ctx, false);
    try {
      return run();
    } finally {
      for (const undo of restore) undo();
    }
  }

  // ---------------------------------------------------------------- sinks

  function receiverLooksSql(expr: Expr | null, ctx: Context): boolean {
    if (expr === null) return false;
    const type = typeOfExpr(expr, ctx);
    if (type !== null && SQL_TYPE.test(type)) return true;
    if (expr.k === "id") return SQL_NAME.test(expr.name);
    if (expr.k === "member") return SQL_NAME.test(expr.name);
    if (expr.k === "call") return SQL_PRODUCERS.has(expr.name) || SQL_NAME.test(expr.name);
    return false;
  }

  function describeReceiver(expr: Expr | null): string {
    if (expr === null) return "";
    if (expr.k === "id") return expr.name;
    if (expr.k === "member") return `${describeReceiver(expr.obj) || "this"}.${expr.name}`;
    if (expr.k === "call")
      return `${describeReceiver(expr.recv) ? `${describeReceiver(expr.recv)}.` : ""}${expr.name}()`;
    return "";
  }

  function checkSink(expr: Extract<Expr, { k: "call" }>, args: Value[], ctx: Context): void {
    const { name } = expr;
    const isJdbc = JDBC_SINKS.has(name);
    const isGeneric = GENERIC_SINKS.has(name);
    const isOrm = ORM_SINKS.has(name);
    if (!isJdbc && !isGeneric && !isOrm) return;
    // Spring JDBC and JDBC calls are methods of an object; `query(...)` alone is not one.
    if (expr.recv === null) return;
    const argExpr = expr.args[0];
    const argument = args[0];
    if (argExpr === undefined || argument === undefined) return;
    // `update(entity)` and `execute(runnable)` pass something that is not SQL text.
    if (argExpr.k === "lambda") return;
    const text = literalText(argument.leaves);
    const sqlText = SQL_TEXT.test(text);
    const sqlReceiver = receiverLooksSql(expr.recv, ctx);
    // `query`, `update` and `execute` are everywhere: they need a SQL library in the file and a
    // receiver or text that looks like SQL, or both of those without the import (a DAO whose
    // `jdbcTemplate` comes from a base class in another file).
    if (isGeneric && !((hasSqlLibrary && (sqlReceiver || sqlText)) || (sqlReceiver && sqlText))) {
      return;
    }
    if ((isJdbc || isOrm) && !(hasSqlLibrary || sqlText || sqlReceiver)) return;
    const dynamic = nonConst(argument.leaves);
    if (dynamic.length === 0) return;
    let tainted = sourcesOf(argument.leaves);
    // The result of a helper method (`buildSql(input)`) is a value the analysis cannot follow.
    const helperLeaf = dynamic.find(
      (leaf) => leaf.k === "unknown" && /\(\)$|^mutable field /.test(leaf.name),
    );
    const helper =
      argument.opaque !== "" ? argument.opaque : helperLeaf?.k === "unknown" ? helperLeaf.name : "";
    if (!argument.composed) {
      // A bare value that is not a built string: request input read directly is reported; the
      // result of a helper is reported at low confidence; anything else (a parameter, a field)
      // says nothing about how the text was made.
      if (!sqlReceiver && !sqlText) return;
      if (argument.opaque !== "" || tainted.length === 0) {
        if (helper === "") return;
        // A variable of a type that is not text (a CriteriaQuery) is not SQL.
        const declared = typeOfExpr(argExpr, ctx);
        if (
          declared !== null &&
          !/^(?:String|CharSequence|StringBuilder|StringBuffer|var|val|Object)$/.test(
            baseType(declared),
          )
        ) {
          return;
        }
        tainted = [];
      }
    }
    const fromHelper = !argument.composed && helper !== "" && tainted.length === 0;
    const label = `${describeReceiver(expr.recv) || "call"}.${name}`;
    const shape = argument.shape || (argument.composed ? "built string" : "variable");
    let finding: SqlFinding;
    if (tainted.length > 0) {
      const first = tainted.find((leaf) => leaf.k === "source" && leaf.direct) ?? tainted[0];
      const source = first as Extract<Leaf, { k: "source" }>;
      finding = {
        line: expr.line,
        severity: "high",
        status: source.direct ? "confirmed" : "suspected",
        confidence: "high",
        evidence: `request input (${source.label})${source.direct ? "" : " via variable"} -> ${shape} -> ${label}`,
        cause: label,
      };
    } else if (fromHelper) {
      finding = {
        line: expr.line,
        severity: "medium",
        status: "suspected",
        confidence: "low",
        evidence: `${shape} -> ${label}; value from ${helper}, not followed; inferred`,
        cause: label,
      };
    } else if (dynamic.some((leaf) => leaf.k === "unknown")) {
      finding = {
        line: expr.line,
        severity: "medium",
        status: "suspected",
        confidence: "low",
        evidence: `${shape} -> ${label} (no input source identified)`,
        cause: label,
      };
    } else {
      const reasons = [...new Set(dynamic.map((leaf) => (leaf.k === "inferred" ? leaf.why : "")))]
        .filter(Boolean)
        .slice(0, 2);
      finding = {
        line: expr.line,
        severity: "medium",
        status: "suspected",
        confidence: "low",
        evidence: `${shape} -> ${label}; ${reasons.join("; ")}; inferred`,
        cause: label,
      };
    }
    record(
      finding,
      tainted.length > 0 ? 3 : !fromHelper && dynamic.some((leaf) => leaf.k === "unknown") ? 2 : 1,
    );
  }

  function record(finding: SqlFinding & { ruleId?: FlowFinding["ruleId"] }, rank: number): void {
    const ruleId = finding.ruleId ?? "PG-SQL-005";
    const key = `${ruleId}:${finding.line}:${finding.cause}`;
    const existing = findings.get(key);
    if (existing === undefined || existing.rank < rank) {
      findings.set(key, { ...finding, ruleId, rank });
    }
  }

  // ---------------------------------------------------------------- statements

  const exits = (stmts: readonly Stmt[]): boolean => {
    const last = stmts[stmts.length - 1];
    if (last === undefined) return false;
    if (last.s === "exit") return true;
    if (last.s === "block") return exits(last.body);
    if (last.s === "if") return last.else !== null && exits(last.then) && exits(last.else);
    return false;
  };

  /** The branch ends by giving `name` a fixed value (`if (!ok(x)) { x = "id"; }`). */
  const settles = (stmts: readonly Stmt[], name: string): boolean =>
    stmts.some(
      (stmt) =>
        stmt.s === "assign" &&
        stmt.op === "=" &&
        stmt.target.k === "id" &&
        stmt.target.name === name &&
        stmt.value.k === "str",
    );

  /** Values put into an array or list through an index or a call (`cmd.add(x)`), for the rules on commands and paths. */
  function writeInto(binding: Binding, values: readonly Value[]): void {
    binding.written ??= [];
    const before = binding.written.length;
    for (const item of values) {
      addLeaves(
        binding.written,
        item.leaves.filter((leaf) => !(leaf.k === "inferred" && BENIGN_BARE.test(leaf.why))),
      );
    }
    // A loop is walked again when something new went into a list: a use earlier in the body
    // sees what a later iteration puts in.
    if (binding.written.length > before) version += 1;
  }

  function noteWrites(expr: Extract<Expr, { k: "call" }>, args: Value[], ctx: Context): void {
    if (expr.recv !== null && ELEMENT_WRITERS.has(expr.name)) {
      const root = rootName(expr.recv);
      const binding = root === null ? null : ctx.scope.find(root);
      if (binding !== null) writeInto(binding, args);
    }
    if (expr.name === "addAll" && expr.recv?.k === "id" && expr.recv.name === "Collections") {
      const first = expr.args[0];
      const root = first === undefined ? null : rootName(first);
      const binding = root === null ? null : ctx.scope.find(root);
      if (binding !== null) writeInto(binding, args.slice(1));
    }
  }

  /** `canonical = dest.getCanonicalPath()`: the variable the new one is a conversion of. */
  function derivedOf(init: Expr | null): string[] {
    let current: Expr | null = init;
    while (current !== null) {
      if (current.k === "call" && current.recv !== null && current.args.length === 0) {
        if (!PATH_KEEPERS.has(current.name)) break;
        current = current.recv;
      } else if (current.k === "member" && PATH_KEEPERS.has(current.name)) {
        current = current.obj;
      } else {
        break;
      }
    }
    return current !== null && current !== init && current.k === "id" ? [current.name] : [];
  }

  function declare(ctx: Context, name: string, type: string | null, initial: Value): Binding {
    // A literal array or collection that is written to somewhere is not a fixed table.
    if (initial.table && mutatedNames.has(name)) {
      initial = { ...initial, table: false, leaves: [...initial.leaves, { k: "unknown", name }] };
    }
    const binding: Binding = { name, type, value: initial, guarded: false, ever: [] };
    addLeaves(binding.ever, initial.leaves);
    ctx.scope.vars.set(name, binding);
    return binding;
  }

  function assign(stmt: Extract<Stmt, { s: "assign" }>, ctx: Context, depth: number): void {
    const incoming = evalExpr(stmt.value, ctx, depth + 1);
    if (stmt.target.k !== "id") {
      // Stored in a field, an array or a collection: a builder can be changed from there.
      escape([incoming], "stored");
      os.escapes(incoming);
      evalExpr(stmt.target, ctx, depth + 1);
      const root = rootName(stmt.target);
      const written = root === null ? null : ctx.scope.find(root);
      if (written !== null) writeInto(written, [incoming]);
      return;
    }
    const binding = ctx.scope.find(stmt.target.name);
    if (binding === null) {
      escape([incoming], "stored");
      os.escapes(incoming);
      return;
    }
    const old = binding.value;
    const before = new Set(nonConst(old.leaves).map(leafKey));
    binding.guarded = false;
    binding.pathGuarded = false;
    if (stmt.op === "=") {
      binding.derived = derivedOf(stmt.value);
      if (ctx.conditional === 0) {
        binding.value = incoming;
      } else {
        // Both builders may be the one that is appended to afterwards.
        escape([old, incoming], "assigned conditionally");
        const merged = alternatives([old, incoming]);
        merged.builder = old.builder || incoming.builder;
        binding.value = merged;
      }
    } else if (stmt.op === "+=") {
      if (old.builder) {
        addTracked(old.leaves, incoming.leaves);
      } else {
        binding.value = {
          ...join("string concatenation", old, incoming),
          coll: old.coll || incoming.coll,
        };
      }
    }
    if (isNumericType(binding.type)) {
      binding.value = inferred(`numeric type ${baseType(binding.type)}`);
    }
    if (nonConst(binding.value.leaves).some((leaf) => !before.has(leafKey(leaf)))) version += 1;
    addLeaves(binding.ever, binding.value.leaves);
  }

  function execStmts(stmts: readonly Stmt[], ctx: Context, depth: number): void {
    if (depth > MAX_DEPTH) {
      incomplete = true;
      return;
    }
    for (const stmt of stmts) {
      switch (stmt.s) {
        case "local": {
          let initial = stmt.init === null ? value() : evalExpr(stmt.init, ctx, depth + 1);
          if (isNumericType(stmt.type)) initial = inferred(`numeric type ${baseType(stmt.type)}`);
          else if (initial.builder) initial = { ...initial };
          declare(ctx, stmt.name, stmt.type, initial).derived = derivedOf(stmt.init);
          break;
        }
        case "assign":
          assign(stmt, ctx, depth);
          break;
        case "expr":
          evalExpr(stmt.expr, ctx, depth + 1);
          break;
        case "exit":
          if (stmt.value !== null) os.escapes(evalExpr(stmt.value, ctx, depth + 1));
          break;
        case "assert": {
          evalExpr(stmt.test, ctx, depth + 1);
          applyGuards(guardsWhen(stmt.testText, true), ctx);
          break;
        }
        case "if": {
          evalExpr(stmt.test, ctx, depth + 1);
          const inner = { ...ctx, conditional: ctx.conditional + 1 };
          const whenTrue = guardsWhen(stmt.testText, true);
          const whenFalse = guardsWhen(stmt.testText, false);
          withGuards(whenTrue, ctx, () => {
            execBranch(stmt.then, inner, depth);
          });
          if (stmt.else !== null) {
            const elseBranch = stmt.else;
            withGuards(whenFalse, ctx, () => {
              execBranch(elseBranch, inner, depth);
            });
          }
          // `if (!allowed(x)) throw ...;`: after it, x passed the check.
          const rest = (set: GuardSet, arm: readonly Stmt[] | null): void => {
            if (arm === null) return;
            applyGuards(
              {
                allow: set.allow.filter((name) => {
                  const binding = ctx.scope.find(name);
                  return binding !== null && (exits(arm) || settles(arm, name));
                }),
                path: set.path.filter((guard) => exits(arm) || settles(arm, guard.name)),
              },
              ctx,
            );
          };
          rest(whenFalse, stmt.then);
          rest(whenTrue, stmt.else);
          break;
        }
        case "loop": {
          const scope = new Scope(ctx.scope);
          const loopCtx: Context = {
            ...ctx,
            scope,
            conditional: ctx.conditional + 1,
            loops: ctx.loops + 1,
          };
          execStmts(stmt.init, loopCtx, depth + 1);
          if (stmt.test !== null) evalExpr(stmt.test, loopCtx, depth + 1);
          if (stmt.each !== null) {
            const iter = evalExpr(stmt.each.iter, loopCtx, depth + 1);
            const carried = sourcesOf(iter.leaves);
            const element =
              carried.length > 0
                ? value(carried)
                : iter.table
                  ? inferred("element of a fixed allowlist")
                  : unknown(stmt.each.name);
            declare(
              loopCtx,
              stmt.each.name,
              stmt.each.type,
              isNumericType(stmt.each.type) ? inferred("numeric type") : element,
            );
          }
          // Until nothing changes: what a variable holds can only grow, and each kind of value is
          // bounded, so this ends. A late assignment then reaches uses earlier in the body, through
          // any chain of variables (`prev = cur; cur = next`). Deeply nested loops get fewer passes.
          const passes = ctx.loops >= 6 ? 1 : 40;
          for (let pass = 0; pass < passes; pass += 1) {
            const seen = version;
            execStmts(stmt.body, loopCtx, depth + 1);
            execStmts(stmt.update, loopCtx, depth + 1);
            if (version === seen) break;
            // The last pass allowed still changed something: a cap never means "safe".
            if (pass === passes - 1) incomplete = true;
          }
          break;
        }
        case "block": {
          const scope = new Scope(ctx.scope);
          for (const name of stmt.params) declare({ ...ctx, scope }, name, null, unknown(name));
          execStmts(stmt.body, { ...ctx, scope }, depth + 1);
          break;
        }
        case "arms": {
          if (stmt.subject !== null) evalExpr(stmt.subject, ctx, depth + 1);
          for (const arm of stmt.arms) {
            const scope = new Scope(ctx.scope);
            const armCtx: Context = { ...ctx, scope, conditional: ctx.conditional + 1 };
            for (const name of arm.params) declare(armCtx, name, null, unknown(name));
            execStmts(arm.body, armCtx, depth + 1);
          }
          break;
        }
      }
    }
  }

  function execBranch(stmts: readonly Stmt[], ctx: Context, depth: number): void {
    execStmts(stmts, { ...ctx, scope: new Scope(ctx.scope) }, depth + 1);
  }

  // ---------------------------------------------------------------- methods

  function bindParameters(method: MethodInfo, ctx: Context): void {
    const mapped = method.annotations.some((annotation) =>
      HANDLER_ANNOTATIONS.has(annotation.name),
    );
    for (const param of method.params) {
      const type = baseType(param.type);
      const marked = param.annotations.find((annotation) =>
        SOURCE_ANNOTATIONS.has(annotation.name),
      );
      let initial: Value;
      if (REQUEST_TYPES.has(type)) {
        initial = value([], { req: true });
      } else if (isNumericType(param.type)) {
        initial = inferred(`numeric type ${type}`);
      } else if (classByName.get(type)?.isEnum === true) {
        initial = inferred(`enum type ${type}`);
      } else if (marked !== undefined) {
        initial = value(
          [{ k: "source", label: `@${marked.name} ${param.name}`, direct: true }],
          {},
        );
      } else if (mapped && param.annotations.length === 0 && !NON_INPUT_TYPES.has(type)) {
        initial = value(
          [{ k: "source", label: `handler parameter ${param.name}`, direct: true }],
          {},
        );
      } else if (
        REQUEST_NAME.test(param.name) &&
        /^(?:req|request|httpRequest|servletRequest|call)$/.test(param.name) &&
        type === ""
      ) {
        initial = value([], { req: true });
      } else {
        initial = unknown(param.name);
      }
      ctx.scope.vars.set(param.name, {
        name: param.name,
        type: param.type,
        value: initial,
        guarded: false,
        isParam: true,
        ever: [...initial.leaves],
      });
    }
  }

  function analyzeMethod(method: MethodInfo, cls: ClassInfo): void {
    if (method.body === null) return;
    const ctx = rootContext(cls, true);
    bindParameters(method, ctx);
    execStmts(method.body, ctx, 0);
    drainLambdas();
  }

  const scopes: ClassInfo[] = [unit.top, ...unit.classes];
  for (const cls of scopes) {
    const ctx = rootContext(cls === unit.top ? null : cls, true);
    for (const field of cls.fields.values()) {
      if (field.init !== null) evalExpr(field.init, ctx, 0);
    }
    execStmts(cls.initializers, ctx, 0);
    drainLambdas();
    for (const method of cls.methods) analyzeMethod(method, cls);
  }

  os.flush();
  const ordered = [...findings.values()].sort((a, b) => b.rank - a.rank || a.line - b.line);
  const perRule = new Map<string, number>();
  const kept = ordered.filter((finding) => {
    const count = perRule.get(finding.ruleId) ?? 0;
    perRule.set(finding.ruleId, count + 1);
    return count < MAX_FINDINGS;
  });
  return {
    findings: kept.map(({ rank: _rank, ...finding }) => finding),
    incomplete,
    unsupported: [...new Set(unit.unsupported)],
  };
}
