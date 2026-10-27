import type { Confidence, FindingStatus, Severity } from "@pgard/findings";
import type { Node } from "web-tree-sitter";
import type { RawSourceFinding } from "../finding-factory.js";
import {
  addLeaves,
  constant,
  copy,
  inferred,
  isConstantCase,
  join,
  literalText,
  nonConst,
  Scope,
  sourcesOf,
  unknown,
  value,
  type Binding,
  type Leaf,
  type Value,
} from "../jvm/flow-values.js";
import { SHELL_PROGRAMS } from "../jvm/os-names.js";
import { findWrapper, programName, shellFlag } from "../jvm/os-sinks.js";
import { toAst, type AstNode, type AstResult } from "../jvm/tree.js";
import {
  BATCH_FUNCTIONS,
  COERCIONS,
  COLLECTORS,
  DBAPI_SINKS,
  DB_PRODUCERS,
  ELEMENT_WRITERS,
  EXEC_FUNCTIONS,
  EXITING_CALLS,
  FRAMEWORK_TYPE,
  GENERIC_DBAPI,
  HANDLER_DECORATORS,
  LOOKUPS,
  NON_TEXT_TYPE,
  NUMERIC_CLASSES,
  OS_EXEC,
  PANDAS_SINKS,
  PY_SQL_TEXT,
  REQUEST_ATTRS,
  REQUEST_TYPE,
  SHAPE_TESTS,
  SHELL_STRING_FUNCTIONS,
  SPLITTERS,
  SQL_MODULES,
  SQL_RECEIVER_NAME,
  STAR_IMPORT_MODULES,
  STRING_PASS,
  SUBPROCESS_FUNCTIONS,
  UNSUPPORTED_PROCESS_LIBRARIES,
  UNSUPPORTED_SQL_LIBRARIES,
  VALIDATOR_NAME,
  VIEW_METHODS,
  WEB_MODULES,
  WRAPPERS,
} from "./names.js";

export const MAX_PYTHON_FINDINGS_PER_FILE = 25;

export interface PythonAnalysis {
  findings: RawSourceFinding[];
  /** Part of the file was not analyzed (nesting too deep, or the tree was too large to copy). */
  incomplete: boolean;
  /** The per-file finding cap was reached. */
  capped: boolean;
  /** Call forms whose target cannot be seen (`getattr(...)(...)`, star imports): not followed. */
  unsupportedForms: string[];
  /** Imported libraries with their own raw-SQL API that the rule does not follow. */
  unsupportedLibraries: string[];
  /** Imported libraries that run processes with their own API. */
  unsupportedProcessLibraries: string[];
  /** Frameworks the file imports (Django, Flask, FastAPI), for the coverage note. */
  frameworks: string[];
}

type RuleId = "PG-SQL-006" | "PG-CMD-004";

interface PyFinding {
  ruleId: RuleId;
  line: number;
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  evidence: string;
  cause: string;
}

/** Facts a `Value` carries besides its leaves. */
interface Tags {
  /** A connection, cursor, session or engine. */
  db?: true;
  /** Made by `text()`: the SQL was already judged where the text was made. */
  wrapped?: true;
}
type V = Value & Tags;

type N = AstNode;
type SourceLeaf = Extract<Leaf, { k: "source" }>;

const MAX_DEPTH = 300;
const SPREAD = "*spread";
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const NUMERIC_CONVERSIONS = "diouxXeEfFgGc";
const NUMERIC_SPEC = /^(?:.?[<>=^])?[-+ ]?#?0?\d*[,_]?(?:\.\d+)?[bcdoxXneEfFgG%]$/;
const QUOTE_WHY = "quoted with shlex.quote() (POSIX shells only)";

interface Env {
  scope: Scope;
  /** Depth of conditional code: an assignment there may or may not happen. */
  conditional: number;
  loops: number;
  report: boolean;
  /** Inside a function body (module-level names are then read as they are at the end of the module). */
  inFn: boolean;
  /** Constants of the class body being run, or of the class a method belongs to. */
  cls: Map<string, V> | null;
  className: string | null;
}

interface Pending {
  node: N;
  decorators: N[];
  env: Env;
}

const isSpread = (v: V): boolean => v.shape === SPREAD;

export interface PythonOptions {
  /** The project's manifests name Django, so `.raw()` and `.extra()` are Django's even without an import here. */
  django?: boolean;
}

export function analyzePythonTree(
  root: Node,
  source: string,
  path: string,
  options: PythonOptions = {},
): PythonAnalysis {
  const ast = toAst(root, source);
  return analyzeAst(ast, path, options);
}

function analyzeAst(ast: AstResult, path: string, options: PythonOptions): PythonAnalysis {
  const text = (n: N): string => ast.source.slice(n.start, n.end);
  const kid = (n: N, field: string): N | undefined => n.children.find((c) => c.field === field);
  const named = (n: N): N[] => n.children.filter((c) => !c.anonymous && c.type !== "comment");
  const kidsOf = (n: N, field: string): N[] => n.children.filter((c) => c.field === field);

  let incomplete = ast.truncated;
  const findings = new Map<string, PyFinding & { rank: number }>();
  const unsupported = new Set<string>();
  const writes = new WeakMap<Binding, number>();
  const moduleScope = new Scope(null);
  const queue: Pending[] = [];
  /** Constants of every class run so far, by class name (`Repo.TABLE` from anywhere in the file). */
  const classConsts = new Map<string, Map<string, V>>();

  // ---------------------------------------------------------------- imports

  const aliases = new Map<string, string>();
  const importedModules = new Set<string>();
  const globalNames = new Set<string>();
  /** Attribute names assigned anywhere (`self.x = ...`): never constants. */
  const attrAssigned = new Set<string>();
  {
    const stack: N[] = [ast.root];
    while (stack.length > 0) {
      const node = stack.pop() as N;
      switch (node.type) {
        case "import_statement":
          for (const child of node.children) {
            if (child.field !== "name") continue;
            if (child.type === "aliased_import") {
              const target = kid(child, "name");
              const alias = kid(child, "alias");
              if (target && alias) {
                aliases.set(text(alias), text(target));
                importedModules.add(text(target).split(".")[0] as string);
              }
            } else {
              const full = text(child);
              const head = full.split(".")[0] as string;
              aliases.set(head, head);
              importedModules.add(head);
            }
          }
          break;
        case "import_from_statement": {
          const moduleNode = kid(node, "module_name");
          const moduleName = moduleNode ? text(moduleNode) : "";
          if (moduleName !== "" && !moduleName.startsWith(".")) {
            importedModules.add(moduleName.split(".")[0] as string);
            for (const child of node.children) {
              if (child.type === "wildcard_import") {
                if (STAR_IMPORT_MODULES.has(moduleName))
                  unsupported.add(`star imports from ${moduleName}`);
              } else if (child.field === "name") {
                if (child.type === "aliased_import") {
                  const target = kid(child, "name");
                  const alias = kid(child, "alias");
                  if (target && alias) aliases.set(text(alias), `${moduleName}.${text(target)}`);
                } else {
                  aliases.set(text(child), `${moduleName}.${text(child)}`);
                }
              }
            }
          }
          break;
        }
        case "global_statement":
          for (const child of named(node)) globalNames.add(text(child));
          break;
        case "assignment":
        case "augmented_assignment": {
          const left = kid(node, "left");
          if (left?.type === "attribute") {
            const attr = kid(left, "attribute");
            if (attr) attrAssigned.add(text(attr));
          }
          break;
        }
        default:
          break;
      }
      for (let i = node.children.length - 1; i >= 0; i -= 1) stack.push(node.children[i] as N);
    }
  }
  const hasSqlLibrary = [...importedModules].some((name) => SQL_MODULES.has(name));
  const hasDjango = importedModules.has("django") || options.django === true;

  const frameworks: string[] = [];
  for (const [module, label] of [
    ["django", "Django"],
    ["flask", "Flask"],
    ["fastapi", "FastAPI"],
  ] as const) {
    if (importedModules.has(module)) frameworks.push(label);
  }

  /** `sp.run` -> `subprocess.run` through `import subprocess as sp` and `from x import y`. */
  const qualify = (chain: string, env: Env): string | null => {
    const parts = chain.split(".");
    const head = parts[0] as string;
    const base = aliases.get(head);
    if (base === undefined) return null;
    // A parameter or variable with the same name hides the import.
    const local = env.scope.lookup(head);
    if (local !== null && moduleScope.vars.get(head) !== local.binding) return null;
    return [base, ...parts.slice(1)].join(".");
  };

  const chainOf = (n: N): string | null => {
    if (n.type === "identifier") return text(n);
    if (n.type === "attribute") {
      const obj = kid(n, "object");
      const attr = kid(n, "attribute");
      if (!obj || !attr) return null;
      const head = chainOf(obj);
      return head === null ? null : `${head}.${text(attr)}`;
    }
    return null;
  };

  // ---------------------------------------------------------------- recording

  function record(finding: PyFinding, rank: number): void {
    const key = `${finding.ruleId}:${finding.line}:${finding.cause}`;
    const existing = findings.get(key);
    if (existing === undefined || existing.rank < rank) findings.set(key, { ...finding, rank });
  }

  // ---------------------------------------------------------------- values

  const reqValue = (): V => value([], { req: true });
  const source = (label: string, direct = true): V => value([{ k: "source", label, direct }]);

  const fixedText = (v: V | undefined): string | null => {
    if (v === undefined || isSpread(v) || v.leaves.length === 0) return null;
    if (nonConst(v.leaves).length > 0) return null;
    return literalText(v.leaves);
  };

  /** Leaves with a mark that `shlex.quote()` was applied (only the command rule honors it). */
  const quoted = (v: V): V => ({
    ...copy(v),
    leaves: v.leaves.map((leaf): Leaf =>
      leaf.k === "source" || leaf.k === "unknown" ? { ...leaf, pg: true, pgWhy: QUOTE_WHY } : leaf,
    ),
    composed: true,
  });

  const demoteQuoted = (leaves: readonly Leaf[]): Leaf[] => {
    const out: Leaf[] = [];
    addLeaves(
      out,
      leaves.map((leaf): Leaf =>
        (leaf.k === "source" || leaf.k === "unknown") && leaf.pg === true
          ? { k: "inferred", why: leaf.pgWhy ?? QUOTE_WHY }
          : leaf,
      ),
    );
    return out;
  };

  const GUARD_WHY = "value checked against an allowlist";
  /** Why a variable counts as checked (allowlist, shape test, regex ...). */
  const guardWhy = new WeakMap<Binding, string>();
  /** The reason the last check named for each variable it covers. */
  const whyOf = new Map<string, string>();
  const mark = (out: Set<string>, name: string, why: string): void => {
    out.add(name);
    whyOf.set(name, why);
  };

  /** Reads a variable: request input read through a variable is not direct; a guarded value is inferred. */
  function read(b: Binding, captured: boolean): V {
    const base = b.value as V;
    const leaves: Leaf[] = [];
    addLeaves(
      leaves,
      (captured ? b.ever : base.leaves).map((leaf): Leaf => {
        if (leaf.k === "source") return b.isParam === true ? leaf : { ...leaf, direct: false };
        if (b.guarded && leaf.k === "unknown")
          return { k: "inferred", why: guardWhy.get(b) ?? GUARD_WHY };
        return leaf;
      }),
    );
    const out: V = { ...base, leaves };
    if (b.guarded) {
      out.leaves = leaves.map((leaf): Leaf =>
        leaf.k === "source" ? { k: "inferred", why: guardWhy.get(b) ?? GUARD_WHY } : leaf,
      );
      const seen: Leaf[] = [];
      addLeaves(seen, out.leaves);
      out.leaves = seen;
    }
    return out;
  }

  const constOnly = (v: V): boolean => nonConst(v.leaves).length === 0 && !v.req;

  function moduleRead(name: string, b: Binding): V {
    const v = b.value as V;
    if (writes.get(b) === 1 && !globalNames.has(name) && constOnly(v)) return copy(v);
    const out: V =
      isConstantCase(name) && writes.get(b) === 1 && !globalNames.has(name)
        ? inferred("constant-style module value that is not a literal")
        : unknown(`mutable global ${name}`);
    if (v.db === true) out.db = true;
    return out;
  }

  function evalName(n: N, env: Env): V {
    const name = text(n);
    const found = env.scope.lookup(name);
    if (found !== null) {
      if (env.inFn && moduleScope.vars.get(name) === found.binding) {
        return moduleRead(name, found.binding);
      }
      return read(found.binding, found.captured);
    }
    const imported = aliases.get(name);
    if (imported === "sys.argv") return source("command-line arguments sys.argv");
    if (imported !== undefined) {
      if (/^(?:flask|bottle|quart|sanic|falcon|aiohttp|pyramid)\.request$/.test(imported)) {
        return reqValue();
      }
      return isConstantCase(name)
        ? inferred("constant-style name defined in another file")
        : unknown(name);
    }
    return isConstantCase(name)
      ? inferred("constant-style name defined in another file")
      : unknown(name);
  }

  function assign(env: Env, name: string, v: V): void {
    const existing = env.scope.vars.get(name);
    const incoming: V = { ...v, leaves: [...v.leaves] };
    if (existing === undefined) {
      const created: Binding = {
        name,
        type: v.db === true ? "db" : null,
        value: incoming,
        guarded: false,
        ever: [...incoming.leaves],
      };
      env.scope.vars.set(name, created);
      writes.set(created, 1);
      return;
    }
    writes.set(existing, (writes.get(existing) ?? 0) + 1);
    if (env.conditional > 0) {
      const old = existing.value as V;
      const leaves = [...old.leaves];
      addLeaves(leaves, incoming.leaves);
      existing.value = {
        ...incoming,
        leaves,
        composed: old.composed || incoming.composed,
        table: old.table && incoming.table,
        elems: null,
        db: old.db === true || incoming.db === true ? true : undefined,
      } as V;
    } else {
      existing.value = incoming;
    }
    if (incoming.db === true) existing.type = "db";
    addLeaves(existing.ever, incoming.leaves);
    existing.guarded = false;
  }

  /** The value of one element of a collection or iterable. */
  function elementOf(v: V): V {
    if (v.elems !== null && v.elems.length > 0 && !v.elems.some(isSpread)) {
      const leaves: Leaf[] = [];
      for (const item of v.elems) addLeaves(leaves, item.leaves);
      return value(leaves, { composed: v.elems.some((item) => item.composed) });
    }
    return value([...v.leaves], { composed: v.composed });
  }

  // ---------------------------------------------------------------- guards

  const unwrapParen = (n: N): N => {
    let current = n;
    while (current.type === "parenthesized_expression" || current.type === "named_expression") {
      const inner = current.type === "named_expression" ? kid(current, "value") : named(current)[0];
      if (!inner) break;
      current = inner;
    }
    return current;
  };

  /** A fixed collection of literals: the right side of a membership test that proves a value allowed. */
  function isAllowlist(n: N, env: Env): boolean {
    const node = unwrapParen(n);
    if (["list", "tuple", "set", "dictionary"].includes(node.type)) return true;
    if (node.type === "identifier") {
      const found = env.scope.lookup(text(node));
      if (found !== null) {
        const held = found.binding.value as V;
        return held.table && held.coll;
      }
      return isConstantCase(text(node));
    }
    if (node.type === "attribute") {
      const attr = kid(node, "attribute");
      return attr !== undefined && isConstantCase(text(attr));
    }
    if (node.type === "call") {
      const fn = kid(node, "function");
      if (fn?.type === "attribute") {
        const method = kid(fn, "attribute");
        const obj = kid(fn, "object");
        if (method && obj && ["keys", "values"].includes(text(method)))
          return isAllowlist(obj, env);
      }
      if (fn?.type === "identifier" && ["set", "frozenset", "tuple", "list"].includes(text(fn))) {
        const arg = named(kid(node, "arguments") ?? node)[0];
        return arg !== undefined && isAllowlist(arg, env);
      }
    }
    return false;
  }

  const isLiteral = (n: N, env: Env): boolean => {
    const node = unwrapParen(n);
    if (node.type === "integer" || node.type === "float") return true;
    if (node.type === "string") return !node.children.some((c) => c.type === "interpolation");
    if (node.type === "concatenated_string") return named(node).every((c) => isLiteral(c, env));
    if (node.type === "identifier")
      return isConstantCase(text(node)) && env.scope.lookup(text(node)) === null;
    return false;
  };

  const varName = (n: N): string | null => {
    const node = unwrapParen(n);
    return node.type === "identifier" ? text(node) : null;
  };

  const operatorBetween = (left: N, right: N): string =>
    ast.source.slice(left.end, right.start).replace(/\s+/g, " ").trim();

  const union = (a: Set<string>, b: Set<string>): Set<string> => new Set([...a, ...b]);
  const intersect = (a: Set<string>, b: Set<string>): Set<string> =>
    new Set([...a].filter((x) => b.has(x)));

  /** Names that passed an allowlist or validation check whenever `cond` is true. */
  function guardsTrue(cond: N, env: Env): Set<string> {
    const node = unwrapParen(cond);
    const out = new Set<string>();
    if (node.type === "not_operator") {
      const arg = kid(node, "argument");
      return arg ? guardsFalse(arg, env) : out;
    }
    if (node.type === "boolean_operator") {
      const left = kid(node, "left");
      const right = kid(node, "right");
      if (!left || !right) return out;
      const op = operatorBetween(left, right);
      return op === "or"
        ? intersect(guardsTrue(left, env), guardsTrue(right, env))
        : union(guardsTrue(left, env), guardsTrue(right, env));
    }
    if (node.type === "comparison_operator") {
      const operands = named(node);
      if (operands.length !== 2) return out;
      const [left, right] = operands as [N, N];
      const op = operatorBetween(left, right);
      const leftVar = varName(left);
      const rightVar = varName(right);
      if (op === "in" && leftVar !== null && isAllowlist(right, env)) mark(out, leftVar, GUARD_WHY);
      if (op === "==") {
        if (leftVar !== null && isLiteral(right, env)) mark(out, leftVar, GUARD_WHY);
        if (rightVar !== null && isLiteral(left, env)) mark(out, rightVar, GUARD_WHY);
      }
      return out;
    }
    if (node.type === "call") {
      const fn = kid(node, "function");
      const args = named(kid(node, "arguments") ?? node).filter(
        (a) => a.type !== "keyword_argument",
      );
      if (fn?.type === "attribute") {
        const method = text(kid(fn, "attribute") as N);
        const obj = kid(fn, "object") as N;
        const objVar = varName(obj);
        if (SHAPE_TESTS.has(method) && objVar !== null)
          mark(out, objVar, `value checked with str.${method}() (shape check)`);
        // `re.match(p, x)`, `pattern.fullmatch(x)`
        const chain = chainOf(fn);
        const qualified = chain === null ? null : qualify(chain, env);
        if (["match", "fullmatch", "search"].includes(method)) {
          const target = qualified?.startsWith("re.") ? args[1] : args[0];
          const name = target === undefined ? null : varName(target);
          if (name !== null)
            mark(out, name, "value checked with a regular expression (shape check)");
        }
      } else if (fn?.type === "identifier") {
        const callee = text(fn);
        const only = args.length === 1 ? varName(args[0] as N) : null;
        if (only !== null && VALIDATOR_NAME.test(callee))
          mark(out, only, `value checked with ${callee}()`);
        if (callee === "isinstance" && args.length === 2) {
          const target = varName(args[0] as N);
          const type = text(args[1] as N);
          if (target !== null && NUMERIC_CLASSES.has(type))
            mark(out, target, `value checked to be ${type} (shape check)`);
        }
      }
    }
    return out;
  }

  /** Names that passed a check whenever `cond` is false. */
  function guardsFalse(cond: N, env: Env): Set<string> {
    const node = unwrapParen(cond);
    const out = new Set<string>();
    if (node.type === "not_operator") {
      const arg = kid(node, "argument");
      return arg ? guardsTrue(arg, env) : out;
    }
    if (node.type === "boolean_operator") {
      const left = kid(node, "left");
      const right = kid(node, "right");
      if (!left || !right) return out;
      const op = operatorBetween(left, right);
      return op === "or"
        ? union(guardsFalse(left, env), guardsFalse(right, env))
        : intersect(guardsFalse(left, env), guardsFalse(right, env));
    }
    if (node.type === "comparison_operator") {
      const operands = named(node);
      if (operands.length !== 2) return out;
      const [left, right] = operands as [N, N];
      const op = operatorBetween(left, right);
      const leftVar = varName(left);
      const rightVar = varName(right);
      if (op === "not in" && leftVar !== null && isAllowlist(right, env))
        mark(out, leftVar, GUARD_WHY);
      if (op === "!=") {
        if (leftVar !== null && isLiteral(right, env)) mark(out, leftVar, GUARD_WHY);
        if (rightVar !== null && isLiteral(left, env)) mark(out, rightVar, GUARD_WHY);
      }
    }
    return out;
  }

  /** Runs `body` with the named variables marked as checked; the marks are removed afterwards. */
  function withGuards<T>(names: Set<string>, env: Env, body: () => T): T {
    const changed: Array<[Binding, boolean]> = [];
    for (const name of names) {
      const b = env.scope.lookup(name)?.binding;
      if (b !== undefined && !b.guarded) {
        changed.push([b, b.guarded]);
        b.guarded = true;
        guardWhy.set(b, whyOf.get(name) ?? GUARD_WHY);
      }
    }
    try {
      return body();
    } finally {
      for (const [b, was] of changed) b.guarded = was;
    }
  }

  /**
   * Checks that hold for the rest of a block. A guard made inside a conditional block or a loop
   * body ends with it (`if bad: continue` guards the rest of the loop body, not what follows the loop).
   */
  const guardFrames: Array<Array<[Binding, boolean]>> = [];
  const guardPermanently = (names: Set<string>, env: Env): void => {
    for (const name of names) {
      const b = env.scope.lookup(name)?.binding;
      if (b === undefined) continue;
      guardFrames[guardFrames.length - 1]?.push([b, b.guarded]);
      b.guarded = true;
      guardWhy.set(b, whyOf.get(name) ?? GUARD_WHY);
    }
  };
  function withFrame<T>(body: () => T): T {
    const frame: Array<[Binding, boolean]> = [];
    guardFrames.push(frame);
    try {
      return body();
    } finally {
      guardFrames.pop();
      for (const [b, was] of frame.reverse()) b.guarded = was;
    }
  }
  /** Inside the body of a `try` that has an `except`: a `raise` there may be swallowed. */
  let swallowing = 0;

  /** A block that always leaves: `return`, `raise`, `continue`, `break`, `abort(...)`, `sys.exit(...)`. */
  function exits(block: N | undefined): boolean {
    if (!block) return false;
    const stmts = named(block);
    const last = stmts[stmts.length - 1];
    if (!last) return false;
    switch (last.type) {
      case "raise_statement":
        return swallowing === 0;
      case "return_statement":
      case "continue_statement":
      case "break_statement":
        return true;
      case "expression_statement": {
        const call = named(last)[0];
        if (call?.type !== "call") return false;
        const fn = kid(call, "function");
        const name =
          fn?.type === "identifier"
            ? text(fn)
            : fn?.type === "attribute"
              ? text(kid(fn, "attribute") as N)
              : "";
        return EXITING_CALLS.has(name);
      }
      case "if_statement": {
        const alt = kid(last, "alternative");
        const alts = kidsOf(last, "alternative");
        if (alts.some((a) => a.type === "elif_clause")) return false;
        return alt !== undefined && exits(kid(last, "consequence")) && exits(kid(alt, "body"));
      }
      default:
        return false;
    }
  }

  /** The block gives `name` a fixed value (`if x not in ALLOWED: x = "id"`). */
  function settles(block: N | undefined, name: string): boolean {
    if (!block) return false;
    return named(block).some((stmt) => {
      const assignment = stmt.type === "expression_statement" ? named(stmt)[0] : undefined;
      if (assignment?.type !== "assignment") return false;
      const left = kid(assignment, "left");
      const right = kid(assignment, "right");
      return (
        left !== undefined &&
        right !== undefined &&
        left.type === "identifier" &&
        text(left) === name &&
        ["string", "integer", "float"].includes(right.type) &&
        !right.children.some((c) => c.type === "interpolation")
      );
    });
  }

  // ---------------------------------------------------------------- expressions

  function evalString(n: N, env: Env, depth: number): V {
    const start = n.children.find((c) => c.type === "string_start");
    const prefix = start
      ? text(start)
          .replace(/["']+$/, "")
          .toLowerCase()
      : "";
    const template = prefix.includes("t");
    const parts: V[] = [];
    let interpolated = false;
    let literal = "";
    for (const c of n.children) {
      if (c.type === "string_content" || c.type === "escape_sequence") {
        literal += text(c);
      } else if (c.type === "interpolation") {
        interpolated = true;
        if (literal !== "") parts.push(constant(literal));
        literal = "";
        const expr = kid(c, "expression");
        let v: V = expr ? ev(expr, env, depth + 1) : unknown("interpolation");
        const spec = c.children.find((x) => x.type === "format_specifier");
        const specText = spec ? text(spec).replace(/^:/, "") : "";
        if (nonConst(v.leaves).length > 0) {
          if (template) {
            v = inferred("t-string interpolation, bound by the driver");
          } else if (specText !== "" && !specText.includes("{") && NUMERIC_SPEC.test(specText)) {
            v = inferred(`format spec :${specText} accepts only numbers`);
          }
        }
        parts.push(v);
      }
    }
    if (!interpolated) return constant(literal);
    if (literal !== "") parts.push(constant(literal));
    return join("f-string", ...parts);
  }

  /** `"... %s ..." % args`: arguments of a numeric conversion are inferred numbers. */
  function evalPercent(left: V, right: V, rightNode: N | undefined): V {
    const template = fixedText(left);
    if (template === null) return join("% formatting", left, right);
    const items =
      rightNode !== undefined && unwrapParen(rightNode).type === "tuple" && right.elems !== null
        ? right.elems
        : null;
    const specs = [
      ...template.matchAll(
        /%(?:\(([^)]*)\))?[-#+ 0]*(?:\*|\d+)?(?:\.(?:\*|\d+))?[hlL]?([a-zA-Z%])/g,
      ),
    ].filter((m) => m[2] !== "%");
    const keyed = specs.some((m) => m[1] !== undefined);
    if (specs.length > 0 && specs.every((m) => NUMERIC_CONVERSIONS.includes(m[2] as string))) {
      return join(
        "% formatting",
        left,
        nonConst(right.leaves).length === 0 ? right : inferred("%d accepts only numbers"),
      );
    }
    if (items !== null && !keyed && items.length === specs.length && !items.some(isSpread)) {
      const parts = items.map((item, i) =>
        NUMERIC_CONVERSIONS.includes(specs[i]?.[2] as string) && nonConst(item.leaves).length > 0
          ? inferred(`%${specs[i]?.[2]} accepts only numbers`)
          : item,
      );
      return join("% formatting", left, ...parts);
    }
    return join("% formatting", left, right);
  }

  /** `"...{}...".format(args)`. */
  function evalFormat(recv: V, pos: V[], kw: Map<string, V>): V {
    const template = fixedText(recv);
    const all = [...pos, ...kw.values()];
    if (template === null) return join("str.format", recv, ...all);
    const fields = [...template.matchAll(/\{([^{}!:]*)(?:![rsa])?(?::([^{}]*))?\}/g)];
    if (
      fields.length > 0 &&
      fields.every((m) => m[2] !== undefined && NUMERIC_SPEC.test(m[2] as string))
    ) {
      return join(
        "str.format",
        recv,
        ...all.map((a) => (nonConst(a.leaves).length === 0 ? a : inferred("numeric format spec"))),
      );
    }
    return join("str.format", recv, ...all);
  }

  function evalBinary(n: N, env: Env, depth: number): V {
    // `a + b + c + ...` is followed along its left side in a loop, not by recursion.
    const chain: N[] = [];
    let current = n;
    while (current.type === "binary_operator") {
      const op = current.children.find((c) => c.anonymous)?.type ?? "";
      if (op !== "+" || chain.length > 5000) break;
      chain.push(current);
      const left = kid(current, "left");
      if (!left) break;
      current = left;
    }
    if (chain.length > 0) {
      let acc = ev(current, env, depth + 1);
      for (let i = chain.length - 1; i >= 0; i -= 1) {
        const node = chain[i] as N;
        const right = kid(node, "right") as N;
        acc = add(acc, ev(right, env, depth + 1), kid(node, "left") as N, right);
      }
      return acc;
    }
    const left = kid(n, "left");
    const right = kid(n, "right");
    const op = n.children.find((c) => c.anonymous)?.type ?? "";
    if (!left || !right) return unknown("expression");
    const lv = ev(left, env, depth + 1);
    const rv = ev(right, env, depth + 1);
    switch (op) {
      case "%":
        return evalPercent(lv, rv, right);
      case "*": {
        // `"%s," * n`, `["?"] * n`: the repeated side is the text, the count is a number.
        if (constOnly(lv) && lv.leaves.length > 0)
          return { ...copy(lv), elems: null, coll: lv.coll };
        if (constOnly(rv) && rv.leaves.length > 0)
          return { ...copy(rv), elems: null, coll: rv.coll };
        if (nonConst(lv.leaves).length + nonConst(rv.leaves).length === 0) return value();
        return join("repetition", lv, rv);
      }
      case "|":
      case "&":
        return join("expression", lv, rv);
      default:
        return nonConst([...lv.leaves, ...rv.leaves]).length === 0
          ? value()
          : inferred("arithmetic result");
    }
  }

  const isNumberNode = (n: N): boolean => n.type === "integer" || n.type === "float";

  function add(left: V, right: V, leftNode: N, rightNode: N): V {
    if (isNumberNode(rightNode) || isNumberNode(leftNode)) {
      return nonConst([...left.leaves, ...right.leaves]).length === 0
        ? value()
        : inferred("arithmetic result");
    }
    // List concatenation keeps the position of the elements.
    if ((left.coll || left.elems !== null) && (right.coll || right.elems !== null)) {
      const merged = join("list concatenation", left, right);
      return {
        ...merged,
        coll: true,
        composed: false,
        elems: left.elems !== null && right.elems !== null ? [...left.elems, ...right.elems] : null,
      };
    }
    return join("concatenation", left, right);
  }

  function evalCollection(n: N, env: Env, depth: number): V {
    const items: V[] = [];
    for (const c of named(n)) {
      if (c.type === "list_splat" || c.type === "dictionary_splat") {
        const inner = named(c)[0];
        const v = inner ? ev(inner, env, depth + 1) : unknown("spread");
        items.push({ ...copy(v), shape: SPREAD });
      } else {
        items.push(ev(c, env, depth + 1));
      }
    }
    const leaves: Leaf[] = [];
    for (const item of items) addLeaves(leaves, item.leaves);
    return value(leaves, {
      coll: true,
      elems: items,
      table: items.every((item) => constOnly(item) && !isSpread(item)),
    });
  }

  function evalDictionary(n: N, env: Env, depth: number): V {
    const leaves: Leaf[] = [];
    let table = true;
    for (const c of named(n)) {
      if (c.type === "pair") {
        for (const part of named(c)) {
          const v = ev(part, env, depth + 1);
          addLeaves(leaves, v.leaves);
          if (!constOnly(v)) table = false;
        }
      } else {
        const inner = c.type === "dictionary_splat" ? named(c)[0] : c;
        const v = inner ? ev(inner, env, depth + 1) : unknown("spread");
        addLeaves(leaves, v.leaves);
        table = false;
      }
    }
    return value(leaves, { coll: true, table });
  }

  function evalComprehension(n: N, env: Env, depth: number): V {
    const inner: Env = { ...env, scope: new Scope(env.scope, false) };
    const guards = new Set<string>();
    for (const c of n.children) {
      if (c.type === "for_in_clause") {
        const target = kid(c, "left");
        const iter = kid(c, "right");
        const iterValue = iter ? ev(iter, inner, depth + 1) : unknown("iterable");
        if (target) bindTarget(target, elementOf(iterValue), inner);
      } else if (c.type === "if_clause") {
        const cond = named(c)[0];
        if (cond) {
          ev(cond, inner, depth + 1);
          for (const name of guardsTrue(cond, inner)) guards.add(name);
          guardPermanently(guardsTrue(cond, inner), inner);
        }
      }
    }
    void guards;
    const body = kid(n, "body") ?? named(n)[0];
    const result = body ? ev(body, inner, depth + 1) : value();
    return value([...result.leaves], {
      coll: true,
      composed: result.composed,
      shape: result.shape,
    });
  }

  function evalAttribute(n: N, env: Env, depth: number): V {
    const obj = kid(n, "object");
    const attrNode = kid(n, "attribute");
    if (!obj || !attrNode) return unknown("attribute");
    const attr = text(attrNode);
    const chain = chainOf(n);
    // `self.query` set earlier in this function.
    if (chain !== null) {
      const found = env.scope.lookup(chain);
      if (found !== null) return read(found.binding, found.captured);
    }
    if (chain === "sys.argv" && qualify(chain, env) === "sys.argv")
      return source("command-line arguments sys.argv");
    const o = ev(obj, env, depth + 1);
    if (o.req) {
      if (REQUEST_ATTRS.has(attr)) return source(`request.${attr}`);
      return unknown(`request.${attr}`);
    }
    if (obj.type === "identifier" && text(obj) === "self" && attr === "request") return reqValue();
    // Constants of the class: `self.TABLE`, `cls.TABLE`, `Repo.TABLE`.
    if (obj.type === "identifier" && env.cls !== null && !attrAssigned.has(attr)) {
      const name = text(obj);
      if (name === "self" || name === "cls" || name === env.className) {
        const known = env.cls.get(attr);
        if (known !== undefined) return copy(known);
      }
    }
    if (
      obj.type === "identifier" &&
      !attrAssigned.has(attr) &&
      env.scope.lookup(text(obj)) === null
    ) {
      const known = classConsts.get(text(obj))?.get(attr);
      if (known !== undefined) return copy(known);
    }
    if (sourcesOf(o.leaves).length > 0) return copy(o);
    if (o.db === true) {
      const out: V = unknown(chain ?? attr);
      out.db = true;
      return out;
    }
    if (isConstantCase(attr)) return inferred("constant-style name defined in another file");
    return unknown(chain ?? `${attr}`);
  }

  function evalSubscript(n: N, env: Env, depth: number): V {
    const obj = kid(n, "value");
    const o = obj ? ev(obj, env, depth + 1) : unknown("subscript");
    const indexes = kidsOf(n, "subscript");
    for (const index of indexes) ev(index, env, depth + 1);
    if (o.req) return unknown("request");
    const first = indexes[0];
    if (o.table) {
      if (o.elems !== null && first !== undefined && first.type === "integer") {
        const picked = o.elems[Number(text(first))];
        if (picked !== undefined && !isSpread(picked)) return copy(picked);
      }
      return inferred("value taken from a fixed allowlist table");
    }
    return copy(o);
  }

  function evalConditional(n: N, env: Env, depth: number): V {
    const parts = named(n);
    const [a, test, b] = parts as [N, N, N];
    if (!a || !test || !b) return unknown("expression");
    ev(test, env, depth + 1);
    const va = withGuards(guardsTrue(test, env), env, () => ev(a, env, depth + 1));
    const vb = withGuards(guardsFalse(test, env), env, () => ev(b, env, depth + 1));
    return alt(va, vb);
  }

  function alt(a: V, b: V): V {
    const leaves: Leaf[] = [];
    addLeaves(leaves, a.leaves);
    addLeaves(leaves, b.leaves);
    return value(leaves, {
      composed: a.composed || b.composed,
      shape: a.shape || b.shape,
      table: a.table && b.table,
      coll: a.coll || b.coll,
      opaque: a.opaque || b.opaque,
      req: false,
    });
  }

  function ev(n: N, env: Env, depth = 0): V {
    if (depth > MAX_DEPTH) {
      incomplete = true;
      return unknown("deeply nested expression");
    }
    switch (n.type) {
      case "string":
        return evalString(n, env, depth);
      case "concatenated_string": {
        const parts = named(n).map((c) => ev(c, env, depth + 1));
        return parts.some((p) => p.composed)
          ? join("f-string", ...parts)
          : constant(parts.map((p) => literalText(p.leaves)).join(""));
      }
      case "integer":
      case "float":
      case "true":
      case "false":
      case "none":
      case "ellipsis":
        return value();
      case "identifier":
        return evalName(n, env);
      case "attribute":
        return evalAttribute(n, env, depth);
      case "subscript":
        return evalSubscript(n, env, depth);
      case "call":
        return evalCall(n, env, depth);
      case "binary_operator":
        return evalBinary(n, env, depth);
      case "unary_operator": {
        const arg = kid(n, "argument");
        const v = arg ? ev(arg, env, depth + 1) : value();
        return nonConst(v.leaves).length === 0 ? value() : inferred("arithmetic result");
      }
      case "comparison_operator":
      case "not_operator": {
        for (const c of named(n)) ev(c, env, depth + 1);
        return value();
      }
      case "boolean_operator": {
        const left = kid(n, "left");
        const right = kid(n, "right");
        if (!left || !right) return unknown("expression");
        const lv = ev(left, env, depth + 1);
        const op = operatorBetween(left, right);
        const rv = withGuards(
          op === "or" ? guardsFalse(left, env) : guardsTrue(left, env),
          env,
          () => ev(right, env, depth + 1),
        );
        return alt(lv, rv);
      }
      case "conditional_expression":
        return evalConditional(n, env, depth);
      case "parenthesized_expression":
      case "await":
      case "list_splat":
      case "yield": {
        const inner = named(n)[0];
        return inner ? ev(inner, env, depth + 1) : value();
      }
      case "list":
      case "tuple":
      case "set":
      case "expression_list":
        return evalCollection(n, env, depth);
      case "dictionary":
        return evalDictionary(n, env, depth);
      case "list_comprehension":
      case "generator_expression":
      case "set_comprehension":
      case "dictionary_comprehension":
        return evalComprehension(n, env, depth);
      case "lambda": {
        const body = kid(n, "body");
        const inner: Env = { ...env, scope: new Scope(env.scope, true), inFn: true };
        const params = kid(n, "parameters");
        if (params) bindParams(params, inner, null, false, new Set());
        if (body) ev(body, inner, depth + 1);
        return value();
      }
      case "named_expression": {
        const name = kid(n, "name");
        const val = kid(n, "value");
        const v = val ? ev(val, env, depth + 1) : unknown("expression");
        if (name) bindTarget(name, v, env);
        return v;
      }
      case "assignment":
        return evalAssign(n, env, depth);
      case "slice":
      case "keyword_argument": {
        for (const c of named(n)) ev(c, env, depth + 1);
        return value();
      }
      default: {
        const leaves: Leaf[] = [];
        for (const c of named(n)) addLeaves(leaves, ev(c, env, depth + 1).leaves);
        return value(leaves.length === 0 ? [{ k: "unknown", name: "expression" }] : leaves);
      }
    }
  }

  // ---------------------------------------------------------------- calls

  interface CallInfo {
    node: N;
    line: number;
    name: string;
    qual: string | null;
    recvNode: N | null;
    recvVal: V | null;
    pos: V[];
    posNodes: N[];
    kw: Map<string, V>;
    kwNodes: Map<string, N>;
    kwSplat: boolean;
    /** Values of `**mapping` arguments. */
    splats: V[];
  }

  function evalCall(n: N, env: Env, depth: number): V {
    const fnNode = kid(n, "function");
    const argsNode = kid(n, "arguments");
    if (!fnNode) return unknown("call");
    let name = "";
    let recvNode: N | null = null;
    if (fnNode.type === "identifier") {
      name = text(fnNode);
    } else if (fnNode.type === "attribute") {
      name = text(kid(fnNode, "attribute") as N);
      recvNode = kid(fnNode, "object") ?? null;
    } else if (fnNode.type === "call") {
      // `getattr(obj, "execute")(sql)`, `__import__("os").system(cmd)`: the target is not visible.
      const inner = kid(fnNode, "function");
      const innerName = inner ? text(inner) : "";
      if (/^(?:getattr|__import__|import_module|importlib\.import_module)$/.test(innerName)) {
        unsupported.add(`calls through ${innerName.replace("importlib.", "")}(...)`);
      }
    }
    if (recvNode?.type === "call") {
      const inner = kid(recvNode, "function");
      const innerName = inner ? text(inner) : "";
      if (/^(?:__import__|import_module|importlib\.import_module)$/.test(innerName)) {
        unsupported.add(`calls through ${innerName.replace("importlib.", "")}(...)`);
      }
    }
    const chain = chainOf(fnNode);
    const qual = chain === null ? null : qualify(chain, env);
    const recvVal = recvNode ? ev(recvNode, env, depth + 1) : null;
    const pos: V[] = [];
    const posNodes: N[] = [];
    const kw = new Map<string, V>();
    const kwNodes = new Map<string, N>();
    let kwSplat = false;
    const splats: V[] = [];
    if (argsNode) {
      const argNodes = argsNode.type === "generator_expression" ? [argsNode] : named(argsNode);
      for (const a of argNodes) {
        if (a.type === "keyword_argument") {
          const k = kid(a, "name");
          const v = kid(a, "value");
          if (k && v) {
            kwNodes.set(text(k), v);
            kw.set(text(k), ev(v, env, depth + 1));
          }
        } else if (a.type === "dictionary_splat") {
          kwSplat = true;
          const inner = named(a)[0];
          if (inner) splats.push(ev(inner, env, depth + 1));
        } else if (a.type === "list_splat") {
          const inner = named(a)[0];
          const v = inner ? ev(inner, env, depth + 1) : unknown("spread");
          pos.push({ ...copy(v), shape: SPREAD });
          posNodes.push(a);
        } else {
          pos.push(ev(a, env, depth + 1));
          posNodes.push(a);
        }
      }
    }
    const aliasTarget = posNodes[1];
    if (
      name === "getattr" &&
      recvNode === null &&
      (aliasTarget === undefined
        ? false
        : aliasTarget.type !== "string" ||
          /^["'](?:execute\w*|exec_driver_sql|fetch\w*|system|popen|run|call|check_call|check_output|Popen|getoutput|raw|extra)["']$/.test(
            text(aliasTarget),
          ))
    ) {
      unsupported.add("calls through getattr(...)");
    }
    const info: CallInfo = {
      node: n,
      line: n.line,
      name,
      qual,
      recvNode,
      recvVal,
      pos,
      posNodes,
      kw,
      kwNodes,
      kwSplat,
      splats,
    };
    if (env.report) {
      sqlCheck(info, env);
      commandCheck(info);
    }
    return callResult(info, env);
  }

  const dynamicOf = (v: V | undefined): boolean => v !== undefined && nonConst(v.leaves).length > 0;
  const anySource = (values: readonly V[]): boolean =>
    values.some((v) => sourcesOf(v.leaves).length > 0);

  /** The value a call gives back. */
  function callResult(info: CallInfo, env: Env): V {
    const { name, qual, recvVal, pos, kw } = info;
    const arg0 = pos[0];
    const q = qual ?? "";
    const allArgs = [...pos, ...kw.values(), ...info.splats];

    // Connections, cursors and sessions.
    if (
      DB_PRODUCERS.has(name) &&
      (recvVal?.db === true ||
        name === "cursor" ||
        /^(?:sqlite3|psycopg2?|pymysql|MySQLdb|mysql|sqlalchemy|aiosqlite|asyncpg|aiopg|aiomysql|django|sqlmodel|oracledb|pyodbc)\b/.test(
          q,
        ) ||
        (info.recvNode !== null && SQL_RECEIVER_NAME.test(lastSegment(info.recvNode))) ||
        (qual === null && info.recvNode === null && /^get_(?:db|session)$/.test(name)))
    ) {
      const out: V = unknown(`${name}()`);
      out.db = true;
      return out;
    }
    // SQLAlchemy text(): judged where it is made.
    if (isTextCall(info)) {
      const base: V = arg0 ? { ...copy(arg0) } : value();
      return { ...base, wrapped: true };
    }
    if (name === "parse_args" || name === "parse_known_args") {
      return source("command-line arguments (argparse)");
    }
    // Request objects.
    if (info.recvNode !== null && recvVal !== null) {
      if (recvVal.req) return unknown(`request.${name}()`);
    }
    // Builtins and common helpers by name.
    if (info.recvNode === null || qual !== null) {
      const bare = qual === null ? name : (q.split(".").pop() as string);
      const special = specialCall(info, bare, q);
      if (special !== null) return special;
    }
    if (info.recvNode !== null && recvVal !== null) {
      const method = methodCall(info, recvVal, env);
      if (method !== null) return method;
    }
    // An unknown call: the result is whatever the callee returns.
    const out = unknown(`${name === "" ? "call" : name}()`);
    if (anySource(allArgs) || (recvVal !== null && sourcesOf(recvVal.leaves).length > 0)) {
      out.opaque = `${name === "" ? "call" : name}()`;
    }
    return out;
  }

  function numberResult(args: readonly V[], why: string): V {
    return args.every((a) => nonConst(a.leaves).length === 0) ? value() : inferred(why);
  }

  /** Functions that are not methods of a value: builtins, `shlex`, `re`, `psycopg2.sql`. */
  function specialCall(info: CallInfo, bare: string, q: string): V | null {
    const { pos, kw } = info;
    const arg0 = pos[0];
    const all = [...pos, ...kw.values()];
    if (q === "shlex.quote" || q === "pipes.quote" || q === "shlex.join" || q === "pipes.join") {
      return arg0 ? quoted(arg0) : null;
    }
    if (q === "shlex.split") {
      return arg0 ? { ...copy(arg0), coll: true, elems: null } : value([], { coll: true });
    }
    if (q === "re.sub" || q === "re.subn") {
      const pattern = fixedText(pos[0]);
      const replacement = fixedText(pos[1]);
      const subject = pos[2];
      if (
        subject !== undefined &&
        pattern !== null &&
        replacement === "" &&
        /^\[\^[^\]]+\]/.test(pattern)
      ) {
        return nonConst(subject.leaves).length === 0
          ? copy(subject)
          : inferred("filtered with re.sub to an allowed character set");
      }
      return subject ? copy(subject) : null;
    }
    if (
      /^(?:psycopg2?\.sql\.)?(?:Identifier|Literal|Placeholder)$/.test(q) ||
      (/^(?:Identifier|Literal|Placeholder)$/.test(bare) && /sql/.test(q))
    ) {
      return all.every((a) => nonConst(a.leaves).length === 0)
        ? value()
        : inferred("psycopg sql composition quotes the value");
    }
    if (bare === "SQL" && /sql/.test(q)) return arg0 ? copy(arg0) : value();
    if (bare === "range") return inferred("range() gives numbers");
    if (
      COERCIONS.has(bare) &&
      (q === "" || !q.includes(".") || /^(?:decimal|uuid|math|random|time|builtins)/.test(q))
    ) {
      return numberResult(all, `${bare}() gives a number or a date`);
    }
    if (WRAPPERS.has(bare) && (q === "" || /sql|builtins/.test(q))) {
      if (arg0 === undefined) return value();
      const out = copy(arg0);
      return bare === "str" || bare === "repr" || bare === "bytes"
        ? out
        : { ...out, composed: arg0.composed };
    }
    if (COLLECTORS.has(bare) && q === "") {
      if (arg0 === undefined)
        return value([], { coll: true, elems: [], table: bare !== "map" && bare !== "filter" });
      if (bare === "enumerate" || bare === "zip") {
        const leaves: Leaf[] = [];
        for (const a of pos) addLeaves(leaves, a.leaves);
        return value(leaves, { coll: true });
      }
      if (bare === "map" || bare === "filter") {
        const leaves: Leaf[] = [];
        for (const a of pos.slice(1)) addLeaves(leaves, a.leaves);
        return value(leaves, { coll: true });
      }
      return { ...copy(arg0), coll: true, elems: arg0.elems, table: arg0.table };
    }
    if (bare === "input" && q === "") return source("stdin input()");
    return null;
  }

  function methodCall(info: CallInfo, recv: V, env: Env): V | null {
    const { name, pos, kw, recvNode } = info;
    const arg0 = pos[0];
    if (name === "format") return evalFormat(recv, [...pos, ...info.splats], kw);
    // `text("...").bindparams(...)` is still the same fixed text.
    if (
      ["bindparams", "columns", "execution_options", "params"].includes(name) &&
      recv.wrapped === true
    )
      return copy(recv);
    if (name === "join") {
      const iter = arg0 ?? value();
      const elementLeaves =
        iter.elems !== null && !iter.elems.some(isSpread) ? elementOf(iter) : iter;
      return join("join", recv, elementLeaves);
    }
    if (name === "replace") {
      const out = join("replace", recv, ...pos);
      return { ...out, composed: recv.composed || dynamicOf(arg0) || out.composed };
    }
    if (ELEMENT_WRITERS.has(name) && recvNode?.type === "identifier") {
      const b = env.scope.lookup(text(recvNode))?.binding;
      if (b) {
        const old = b.value as V;
        const added = name === "insert" ? pos.slice(1) : pos;
        const leaves = [...old.leaves];
        for (const item of added) addLeaves(leaves, item.leaves);
        let elems: V[] | null = null;
        if (
          old.elems !== null &&
          env.conditional === 0 &&
          env.loops === 0 &&
          !old.elems.some(isSpread)
        ) {
          if (name === "append" && added[0]) elems = [...old.elems, added[0]];
          else if (name === "extend" && added[0]?.elems != null)
            elems = [...old.elems, ...added[0].elems];
        }
        b.value = { ...old, leaves, elems, table: false, coll: true } as V;
        addLeaves(b.ever, leaves);
        return value();
      }
    }
    if (name === "mogrify") {
      return pos.length > 1 ? inferred("mogrify() binds the parameters") : arg0 ? copy(arg0) : null;
    }
    if (name === "cursor" || (recv.db === true && DB_PRODUCERS.has(name))) {
      const out: V = unknown(`${name}()`);
      out.db = true;
      return out;
    }
    if (LOOKUPS.has(name)) {
      if (recv.table) {
        const fallback = pos.slice(1).filter((item) => nonConst(item.leaves).length > 0);
        const table = inferred("value taken from a fixed allowlist table");
        // A literal default keeps the demotion; a default from the caller does not.
        for (const item of fallback) addLeaves(table.leaves, item.leaves);
        return table;
      }
      const out = copy(recv);
      for (const item of pos.slice(1)) addLeaves(out.leaves, item.leaves);
      return { ...out, elems: null };
    }
    if (SPLITTERS.has(name)) return { ...copy(recv), coll: true, elems: null, composed: false };
    if (STRING_PASS.has(name) || /^(?:str|bytes)$/.test(name))
      return { ...copy(recv), elems: null };
    if (recv.table && ["lower", "upper"].includes(name)) return copy(recv);
    void kw;
    return null;
  }

  // ---------------------------------------------------------------- SQL sinks

  const isTextCall = (info: CallInfo): boolean => {
    const q = info.qual ?? "";
    return /^(?:sqlalchemy|sqlmodel)(?:\.[a-z_]+)*\.(?:text|literal_column)$/.test(q);
  };

  const lastSegment = (n: N | null): string => {
    if (n === null) return "";
    if (n.type === "identifier") return text(n);
    if (n.type === "attribute") return text(kid(n, "attribute") as N);
    if (n.type === "call") {
      const fn = kid(n, "function");
      return fn ? lastSegment(fn) : "";
    }
    return "";
  };

  function sqlCheck(info: CallInfo, env: Env): void {
    const { name, qual, recvNode, recvVal, pos, kw } = info;
    const q = qual ?? "";
    let kind: "dbapi" | "text" | "raw" | "extra" | "rawsql" | "pandas" | "batch" | null = null;
    if (isTextCall(info)) kind = "text";
    else if (name === "RawSQL" && (q.startsWith("django") || (qual === null && hasDjango)))
      kind = "rawsql";
    else if (q.startsWith("pandas.") && PANDAS_SINKS.has(name)) kind = "pandas";
    else if (BATCH_FUNCTIONS.has(name) && q.startsWith("psycopg")) kind = "batch";
    else if (recvNode !== null) {
      if (DBAPI_SINKS.has(name)) kind = "dbapi";
      else if (name === "raw") kind = "raw";
      else if (name === "extra") kind = "extra";
    }
    if (kind === null) return;

    let argument: V | undefined;
    if (kind === "extra") {
      const parts = [
        ...pos.slice(0, 1),
        ...["select", "where", "order_by", "tables"].map((k) => kw.get(k)),
      ].filter((v): v is V => v !== undefined);
      if (parts.length === 0) return;
      argument = join("extra()", ...parts);
    } else {
      const index = kind === "batch" ? 1 : 0;
      argument =
        pos[index] ??
        kw.get("sql") ??
        kw.get("query") ??
        kw.get("statement") ??
        kw.get("raw_query") ??
        kw.get("operation") ??
        kw.get("text");
    }
    if (argument === undefined || isSpread(argument)) return;
    if (kind === "dbapi" && argument.wrapped === true) return;
    const sqlText = PY_SQL_TEXT.test(literalText(argument.leaves));
    const receiverName = lastSegment(recvNode);
    const sqlReceiver =
      recvVal?.db === true ||
      SQL_RECEIVER_NAME.test(receiverName) ||
      (kind === "batch" && pos[0]?.db === true);
    if (kind === "dbapi") {
      const generic = GENERIC_DBAPI.has(name);
      const eligible = generic
        ? (hasSqlLibrary && (sqlReceiver || sqlText)) || (sqlReceiver && sqlText)
        : hasSqlLibrary || sqlReceiver || sqlText;
      if (!eligible) return;
    }
    if (
      kind === "raw" &&
      !(
        hasDjango ||
        sqlText ||
        (recvNode !== null && /\bobjects\b|_default_manager/.test(text(recvNode)))
      )
    )
      return;
    const judged = judge(argument, argument.composed, false);
    if (judged === null) return;
    // A bare value that is not a built string: request input read directly is reported, and so
    // is a value from a lookup; a plain parameter says nothing about how the text was made.
    if (!argument.composed && judged.kind === "unknown") return;
    if (
      !argument.composed &&
      judged.kind === "helper" &&
      !(sqlReceiver || sqlText || kind !== "dbapi")
    )
      return;
    const label =
      kind === "text" || kind === "rawsql" || kind === "pandas" || kind === "batch"
        ? kind === "rawsql"
          ? "RawSQL"
          : (qual ?? name)
              .split(".")
              .filter((_, i, all) => i === 0 || i === all.length - 1)
              .join(".")
        : `${receiverName || "call"}.${name}`;
    const { finding, rank } = sqlFinding(judged, info.line, label);
    record(finding, rank);
    void env;
  }

  function sqlFinding(
    judged: Judged,
    line: number,
    label: string,
  ): { finding: PyFinding; rank: number } {
    const base = { ruleId: "PG-SQL-006" as const, line, cause: label };
    if (judged.kind === "tainted") {
      const { text: from, source: src } = sourceText(judged);
      return {
        finding: {
          ...base,
          severity: "high",
          status: src.direct ? "confirmed" : "suspected",
          confidence: "high",
          evidence: `${from} -> ${judged.shape} -> ${label}`,
        },
        rank: 3,
      };
    }
    const why =
      judged.kind === "helper"
        ? `value from ${judged.helper}, not followed; inferred`
        : judged.kind === "unknown"
          ? "no input source identified; inferred"
          : `${judged.reasons.slice(0, 2).join("; ")}; inferred`;
    return {
      finding: {
        ...base,
        severity: "medium",
        status: "suspected",
        confidence: "low",
        evidence: `${judged.shape} -> ${label}; ${why}`,
      },
      rank: judged.kind === "unknown" ? 2 : 1,
    };
  }

  // ---------------------------------------------------------------- judging a value

  type Kind = "tainted" | "helper" | "unknown" | "inferred";
  interface Judged {
    kind: Kind;
    tainted: SourceLeaf[];
    helper: string;
    reasons: string[];
    shape: string;
    /** The whole value, not a part of a longer one. */
    bare: boolean;
  }

  function judge(
    v: V,
    composed: boolean,
    command: boolean,
    extra: readonly Leaf[] = [],
  ): Judged | null {
    const leaves: Leaf[] = [];
    addLeaves(leaves, command ? demoteQuoted(v.leaves) : v.leaves);
    addLeaves(leaves, command ? demoteQuoted(extra) : extra);
    const dynamic = nonConst(leaves);
    if (dynamic.length === 0) return null;
    const tainted = sourcesOf(leaves) as SourceLeaf[];
    const helperLeaf = dynamic.find(
      (leaf) => leaf.k === "unknown" && /\(\)$|^mutable global /.test(leaf.name),
    );
    const helper = v.opaque !== "" ? v.opaque : helperLeaf?.k === "unknown" ? helperLeaf.name : "";
    const reasons = [
      ...new Set(dynamic.map((leaf) => (leaf.k === "inferred" ? leaf.why : "")).filter(Boolean)),
    ];
    const shape = v.shape || (composed ? "built value" : "value");
    const base = { tainted, helper, reasons, shape, bare: !composed };
    if (!composed) {
      if (v.opaque !== "") return { kind: "helper", ...base, tainted: [] };
      if (tainted.length > 0) return { kind: "tainted", ...base };
      if (helper !== "") return { kind: "helper", ...base };
      if (reasons.length > 0 && !dynamic.some((leaf) => leaf.k === "unknown")) {
        return { kind: "inferred", ...base };
      }
      return { kind: "unknown", ...base };
    }
    if (tainted.length > 0) return { kind: "tainted", ...base };
    if (dynamic.some((leaf) => leaf.k === "unknown")) return { kind: "unknown", ...base };
    return { kind: "inferred", ...base };
  }

  const sourceText = (judged: Judged): { text: string; source: SourceLeaf } => {
    const src = (judged.tainted.find((leaf) => leaf.direct) ?? judged.tainted[0]) as SourceLeaf;
    return {
      text: `${/^(?:command-line|stdin)/.test(src.label) ? "command-line input" : "request input"} (${src.label})${src.direct ? "" : " via variable"}`,
      source: src,
    };
  };

  const lowReason = (judged: Judged): string =>
    judged.kind === "helper"
      ? `value from ${judged.helper}, not followed; inferred`
      : judged.kind === "unknown"
        ? judged.bare
          ? "a value with no identified source (such as a parameter) reaches it; callers not followed; inferred"
          : "no input source identified; inferred"
        : `${judged.reasons.slice(0, 2).join("; ")}; inferred`;

  const rankOf = (kind: Kind): number => (kind === "tainted" ? 3 : kind === "unknown" ? 2 : 1);

  // ---------------------------------------------------------------- command sinks

  type Scope2 = "string" | "shell" | "program" | "argument";
  interface Candidate {
    finding: PyFinding;
    rank: number;
  }

  function commandFinding(
    judged: Judged,
    line: number,
    sink: string,
    scope: Scope2,
    detail: string,
  ): Candidate {
    const critical = scope !== "argument";
    const base = { ruleId: "PG-CMD-004" as const, line, cause: `${sink}:${scope}` };
    if (judged.kind === "tainted") {
      const { text: from, source: src } = sourceText(judged);
      if (critical) {
        return {
          finding: {
            ...base,
            severity: "critical",
            status: src.direct ? "confirmed" : "suspected",
            confidence: "high",
            evidence: `${from} -> ${judged.shape} -> ${detail}`,
          },
          rank: 3,
        };
      }
      return {
        finding: {
          ...base,
          severity: "medium",
          status: "suspected",
          confidence: "medium",
          evidence: `${from} -> ${judged.shape} -> ${detail}; argument injection (fixed program, no shell)`,
        },
        rank: 3,
      };
    }
    return {
      finding: {
        ...base,
        severity: critical ? "medium" : "low",
        status: "suspected",
        confidence: "low",
        evidence: `${judged.shape} -> ${detail}; ${lowReason(judged)}`,
      },
      rank: rankOf(judged.kind),
    };
  }

  const best = (candidates: Candidate[]): Candidate | null =>
    candidates.reduce<Candidate | null>((top, next) => {
      if (top === null) return next;
      const a = top.rank * 10 + (SEVERITY_RANK[top.finding.severity] ?? 0);
      const b = next.rank * 10 + (SEVERITY_RANK[next.finding.severity] ?? 0);
      return b > a ? next : top;
    }, null);

  function commandString(v: V, line: number, sink: string, detail: string): void {
    const judged = judge(v, v.composed, true);
    if (judged === null) return;
    const candidate = commandFinding(judged, line, sink, "string", detail);
    record(candidate.finding, candidate.rank);
  }

  /** An argument list: a shell wrapper, the program name, or the arguments of a fixed program. */
  function commandArgv(items: V[] | null, flat: V, line: number, sink: string): void {
    const candidates: Candidate[] = [];
    const add = (
      v: V,
      composed: boolean,
      scope: Scope2,
      detail: string,
      extras: readonly Leaf[] = [],
    ): void => {
      const judged = judge(v, composed, true, extras);
      if (judged !== null) candidates.push(commandFinding(judged, line, sink, scope, detail));
    };
    if (items !== null) {
      const texts = items.map(fixedText);
      const found = findWrapper(texts);
      const program = found?.program ?? programName(texts[0] ?? null);
      if (found !== null) {
        const restOfLine =
          found.program === "cmd" || found.program === "powershell" || found.program === "pwsh";
        const start = found.flagIndex + 1;
        const scriptEnd = restOfLine ? items.length : start + 1;
        const script = items.slice(start, scriptEnd);
        const scriptValue = script.length === 1 ? (script[0] as V) : join("script", ...script);
        add(
          scriptValue,
          script.length === 1 ? scriptValue.composed : true,
          "shell",
          `${found.program} ${found.flag ?? "<flag>"} script`,
        );
        for (const item of items.slice(scriptEnd)) {
          add(item, item.composed, "argument", `${sink} (argument of ${found.program})`);
        }
      } else {
        const first = items[0];
        if (first !== undefined) add(first, first.composed, "program", `${sink} (program name)`);
        let separated = false;
        for (let i = 1; i < items.length; i += 1) {
          const item = items[i] as V;
          const t = texts[i];
          if (t === "--" || t === "--end-of-options") separated = true;
          const detail = `${sink} (argument of ${program ?? "a program"})`;
          if (separated && t !== "--" && t !== "--end-of-options") {
            const judged = judge(item, item.composed, true);
            if (judged !== null) {
              const after: Judged =
                judged.kind === "tainted"
                  ? { ...judged, kind: "inferred", reasons: ["placed after a -- option separator"] }
                  : judged;
              candidates.push(commandFinding(after, line, sink, "argument", detail));
            }
          } else {
            add(item, item.composed, "argument", detail);
          }
        }
      }
    } else {
      // The list was built in steps or its form is not known: judge it as a whole. A fixed first
      // element is the program.
      const present = flat.leaves;
      const words = present.flatMap((leaf) => (leaf.k === "const" ? leaf.text.split(/\s+/) : []));
      const shell = words
        .map((w) => programName(w))
        .find((w) => w !== null && SHELL_PROGRAMS.has(w));
      const wrapper = shell !== undefined && words.some((w) => shellFlag(shell as string, w));
      const scope: Scope2 = wrapper ? "shell" : present[0]?.k === "const" ? "argument" : "program";
      add(
        flat,
        flat.composed || true,
        scope,
        wrapper
          ? `${shell} script`
          : scope === "program"
            ? `${sink} (program name)`
            : `${sink} (argument)`,
      );
    }
    const top = best(candidates);
    if (top !== null) record(top.finding, top.rank);
  }

  type ShellMode = "yes" | "no" | "maybe";
  function shellMode(info: CallInfo): ShellMode {
    const node = info.kwNodes.get("shell");
    if (node === undefined) return info.kwSplat ? "maybe" : "no";
    if (node.type === "true") return "yes";
    if (node.type === "false" || node.type === "none") return "no";
    if (node.type === "integer") return text(node) === "0" ? "no" : "yes";
    return "maybe";
  }

  const isList = (node: N | undefined, v: V): boolean =>
    v.coll ||
    v.elems !== null ||
    (node !== undefined && ["list", "tuple"].includes(unwrapParen(node).type));

  function commandCheck(info: CallInfo): void {
    const q = info.qual ?? "";
    if (q === "") return;
    const { line, pos, kw } = info;
    if (SHELL_STRING_FUNCTIONS.has(q)) {
      const first = pos[0] ?? kw.get("cmd") ?? kw.get("command");
      if (first === undefined || isSpread(first)) return;
      commandString(first, line, q, `${q} (shell command)`);
      return;
    }
    if (SUBPROCESS_FUNCTIONS.has(q)) {
      const firstNode = info.posNodes[0] ?? info.kwNodes.get("args");
      const first = pos[0] ?? kw.get("args");
      if (first === undefined) return;
      const exe = kw.get("executable");
      if (exe !== undefined && dynamicOf(exe)) {
        const judged = judge(exe, exe.composed, true);
        if (judged !== null) {
          const c = commandFinding(judged, line, q, "program", `${q} (executable=)`);
          record(c.finding, c.rank);
        }
      }
      const mode = shellMode(info);
      if (isList(firstNode, first)) {
        const items = first.elems !== null && !first.elems.some(isSpread) ? first.elems : null;
        if (mode !== "no" && items !== null && items[0] !== undefined) {
          const candidates: Candidate[] = [];
          const script = items[0];
          const judged = judge(script, script.composed, true);
          if (judged !== null) {
            candidates.push(commandFinding(judged, line, q, "shell", `${q} (shell=True command)`));
          }
          const top = best(candidates);
          if (top !== null) record(top.finding, top.rank);
          return;
        }
        if (first.elems !== null && first.elems.some(isSpread)) {
          // `["git", *args]`: the part before the first spread is positional.
          const head = first.elems.findIndex(isSpread);
          const known = first.elems.slice(0, head);
          const rest = first.elems.slice(head);
          const flat = join("argument list", ...rest);
          if (known.length === 0) {
            commandArgv(null, join("argument list", ...first.elems), line, q);
          } else {
            commandArgv([...known, { ...flat, composed: true }], flat, line, q);
          }
          return;
        }
        commandArgv(items, first, line, q);
        return;
      }
      if (isSpread(first)) return;
      commandString(
        first,
        line,
        q,
        mode === "no" ? `${q} (command string)` : `${q} (shell=True command)`,
      );
      return;
    }
    if (EXEC_FUNCTIONS.has(q)) {
      if (pos.length === 0) return;
      const items = pos.some(isSpread) ? null : pos;
      commandArgv(items, join("argument list", ...pos), line, q);
      return;
    }
    if (OS_EXEC.test(q)) {
      const kind = (OS_EXEC.exec(q)?.[1] ?? "") as string;
      const spawn = kind.startsWith("spawn");
      const path = pos[spawn ? 1 : 0];
      if (path === undefined) return;
      const listForm = /v/.test(kind.slice(spawn ? 5 : 4));
      const rest = pos.slice(spawn ? 2 : 1);
      if (listForm) {
        const argv = rest[0];
        const elems = argv?.elems ?? null;
        if (elems !== null && !elems.some(isSpread)) {
          commandArgv([path, ...elems.slice(1)], path, line, q);
        } else {
          commandArgv(null, join("argument list", path, ...(argv ? [argv] : [])), line, q);
        }
      } else {
        const items = [path, ...rest.slice(1)];
        commandArgv(items.some(isSpread) ? null : items, join("argument list", ...items), line, q);
      }
    }
  }

  // ---------------------------------------------------------------- statements

  function bindTarget(target: N, v: V, env: Env): void {
    switch (target.type) {
      case "identifier":
        assign(env, text(target), v);
        break;
      case "attribute": {
        const chain = chainOf(target);
        if (chain !== null) assign(env, chain, v);
        break;
      }
      case "subscript": {
        let root = kid(target, "value");
        while (root && (root.type === "subscript" || root.type === "attribute")) {
          root = kid(root, root.type === "subscript" ? "value" : "object");
        }
        const b = root?.type === "identifier" ? env.scope.lookup(text(root))?.binding : undefined;
        if (b) {
          const old = b.value as V;
          const leaves = [...old.leaves];
          addLeaves(leaves, v.leaves);
          b.value = { ...old, leaves, elems: null, table: false } as V;
          addLeaves(b.ever, leaves);
        }
        break;
      }
      case "pattern_list":
      case "tuple_pattern":
      case "list_pattern":
      case "tuple":
      case "list": {
        const targets = named(target);
        if (
          v.elems !== null &&
          v.elems.length === targets.length &&
          !v.elems.some(isSpread) &&
          !targets.some((t) => t.type === "list_splat_pattern")
        ) {
          targets.forEach((t, i) => bindTarget(t, v.elems?.[i] as V, env));
        } else {
          const element = elementOf(v);
          for (const t of targets) bindTarget(t, element, env);
        }
        break;
      }
      case "list_splat_pattern":
      case "parenthesized_expression": {
        const inner = named(target)[0];
        if (inner)
          bindTarget(
            inner,
            target.type === "list_splat_pattern" ? { ...copy(v), coll: true, elems: null } : v,
            env,
          );
        break;
      }
      default:
        break;
    }
  }

  function evalAssign(n: N, env: Env, depth: number): V {
    const left = kid(n, "left");
    const right = kid(n, "right");
    if (!left) return value();
    if (!right) return value();
    const v =
      right.type === "assignment" ? evalAssign(right, env, depth + 1) : ev(right, env, depth + 1);
    bindTarget(left, v, env);
    return v;
  }

  function execAugmented(n: N, env: Env, depth: number): void {
    const left = kid(n, "left");
    const right = kid(n, "right");
    const op = n.children.find((c) => c.anonymous)?.type ?? "";
    if (!left || !right) return;
    const rv = ev(right, env, depth + 1);
    const lv = ev(left, env, depth + 1);
    let result: V;
    if (op === "+=") result = add(lv, rv, left, right);
    else if (op === "%=") result = evalPercent(lv, rv, right);
    else if (op === "*=") result = constOnly(lv) ? lv : join("repetition", lv, rv);
    else
      result =
        nonConst([...lv.leaves, ...rv.leaves]).length === 0
          ? value()
          : inferred("arithmetic result");
    bindTarget(left, result, env);
  }

  function execBlock(block: N | undefined, env: Env, depth: number): void {
    if (!block) return;
    for (const stmt of named(block)) execStmt(stmt, env, depth + 1);
  }

  function runConditional(block: N | undefined, env: Env, depth: number): void {
    env.conditional += 1;
    try {
      withFrame(() => execBlock(block, env, depth));
    } finally {
      env.conditional -= 1;
    }
  }

  function execIf(n: N, env: Env, depth: number): void {
    const cond = kid(n, "condition");
    const consequence = kid(n, "consequence");
    const alternatives = kidsOf(n, "alternative");
    if (cond) ev(cond, env, depth + 1);
    const whenTrue = cond ? guardsTrue(cond, env) : new Set<string>();
    const whenFalse = cond ? guardsFalse(cond, env) : new Set<string>();
    withGuards(whenTrue, env, () => runConditional(consequence, env, depth));
    let elseBlock: N | undefined;
    let chainFalse = whenFalse;
    for (const alt of alternatives) {
      if (alt.type === "elif_clause") {
        const c = kid(alt, "condition");
        if (c) ev(c, env, depth + 1);
        const t = c ? guardsTrue(c, env) : new Set<string>();
        withGuards(union(chainFalse, t), env, () =>
          runConditional(kid(alt, "consequence"), env, depth),
        );
        chainFalse = union(chainFalse, c ? guardsFalse(c, env) : new Set<string>());
      } else if (alt.type === "else_clause") {
        elseBlock = kid(alt, "body");
        withGuards(chainFalse, env, () => runConditional(elseBlock, env, depth));
      }
    }
    const hasElif = alternatives.some((a) => a.type === "elif_clause");
    if (hasElif) return;
    // After `if not ok(x): raise ...` the check holds for the rest of the function; after
    // `if cond: ... else: raise` the opposite does.
    if (exits(consequence) && !exits(elseBlock)) {
      guardPermanently(whenFalse, env);
    } else if (!exits(consequence) && elseBlock !== undefined && exits(elseBlock)) {
      guardPermanently(whenTrue, env);
    } else if (elseBlock === undefined) {
      for (const name of whenFalse)
        if (settles(consequence, name)) guardPermanently(new Set([name]), env);
    }
  }

  function execLoop(n: N, env: Env, depth: number, bindFirst: () => void): void {
    const passes = env.loops < 3 ? 2 : 1;
    env.loops += 1;
    env.conditional += 1;
    try {
      withFrame(() => {
        for (let i = 0; i < passes; i += 1) {
          bindFirst();
          execBlock(kid(n, "body"), env, depth);
        }
      });
    } finally {
      env.loops -= 1;
      env.conditional -= 1;
    }
    const alternative = kid(n, "alternative");
    if (alternative) runConditional(kid(alternative, "body"), env, depth);
  }

  function execStmt(n: N, env: Env, depth: number): void {
    if (depth > MAX_DEPTH) {
      incomplete = true;
      return;
    }
    switch (n.type) {
      case "expression_statement": {
        for (const c of named(n)) {
          if (c.type === "assignment") evalAssign(c, env, depth);
          else if (c.type === "augmented_assignment") execAugmented(c, env, depth);
          else ev(c, env, depth + 1);
        }
        break;
      }
      case "assignment":
        evalAssign(n, env, depth);
        break;
      case "augmented_assignment":
        execAugmented(n, env, depth);
        break;
      case "return_statement":
      case "raise_statement":
      case "delete_statement":
      case "print_statement":
      case "exec_statement":
        for (const c of named(n)) ev(c, env, depth + 1);
        break;
      case "assert_statement": {
        const parts = named(n);
        for (const c of parts) ev(c, env, depth + 1);
        if (parts[0]) guardPermanently(guardsTrue(parts[0], env), env);
        break;
      }
      case "if_statement":
        execIf(n, env, depth);
        break;
      case "for_statement": {
        const target = kid(n, "left");
        const iter = kid(n, "right");
        const iterValue = iter ? ev(iter, env, depth + 1) : unknown("iterable");
        execLoop(n, env, depth, () => {
          if (target) bindTarget(target, elementOf(iterValue), env);
        });
        break;
      }
      case "while_statement": {
        const cond = kid(n, "condition");
        if (cond) ev(cond, env, depth + 1);
        execLoop(n, env, depth, () => {});
        break;
      }
      case "try_statement": {
        const handles = named(n).some(
          (c) => c.type === "except_clause" || c.type === "except_group_clause",
        );
        for (const c of named(n)) {
          if (c.field === "body" || c.type === "block") {
            if (handles) swallowing += 1;
            try {
              execBlock(c, env, depth);
            } finally {
              if (handles) swallowing -= 1;
            }
          } else if (c.type === "except_clause" || c.type === "except_group_clause") {
            for (const part of named(c)) {
              if (part.type === "as_pattern") {
                const alias = named(part).find((x) => x.type === "as_pattern_target");
                const target = alias ? named(alias)[0] : undefined;
                if (target) bindTarget(target, unknown("exception"), env);
              }
              if (part.type === "block") runConditional(part, env, depth);
            }
          } else if (c.type === "else_clause" || c.type === "finally_clause") {
            runConditional(kid(c, "body") ?? named(c).find((x) => x.type === "block"), env, depth);
          }
        }
        break;
      }
      case "with_statement": {
        const clause = named(n).find((c) => c.type === "with_clause");
        for (const item of clause ? named(clause) : []) {
          const target = named(item)[0];
          const val = kid(item, "value") ?? target;
          if (val?.type === "as_pattern") {
            const expr = named(val)[0];
            const aliasWrap = named(val).find((x) => x.type === "as_pattern_target");
            const alias = aliasWrap ? named(aliasWrap)[0] : undefined;
            const v: V = expr ? ev(expr, env, depth + 1) : unknown("context");
            if (alias) bindTarget(alias, v, env);
          } else if (val) {
            ev(val, env, depth + 1);
          }
        }
        execBlock(kid(n, "body"), env, depth);
        break;
      }
      case "match_statement": {
        const subject = kid(n, "subject");
        const subjectValue: V = subject ? ev(subject, env, depth + 1) : unknown("subject");
        const body = kid(n, "body");
        for (const clause of body ? named(body) : []) {
          if (clause.type !== "case_clause") continue;
          const stack: N[] = named(clause).filter((c) => c.type === "case_pattern");
          while (stack.length > 0) {
            const node = stack.pop() as N;
            if (node.type === "identifier" && text(node) !== "_") {
              assign(env, text(node), elementOf(subjectValue));
            }
            stack.push(...node.children);
          }
          runConditional(kid(clause, "consequence"), env, depth);
        }
        break;
      }
      case "function_definition":
        queue.push({ node: n, decorators: [], env });
        break;
      case "decorated_definition": {
        const def = kid(n, "definition");
        const decorators = n.children.filter((c) => c.type === "decorator");
        if (def?.type === "function_definition") queue.push({ node: def, decorators, env });
        else if (def?.type === "class_definition") execClass(def, env, depth);
        break;
      }
      case "class_definition":
        execClass(n, env, depth);
        break;
      case "global_statement":
      case "nonlocal_statement":
      case "pass_statement":
      case "break_statement":
      case "continue_statement":
      case "import_statement":
      case "import_from_statement":
      case "future_import_statement":
      case "type_alias_statement":
        break;
      default:
        // match statements and other compound statements: their blocks run conditionally.
        for (const c of named(n)) {
          if (c.type === "block") runConditional(c, env, depth);
          else if (c.type.endsWith("_clause")) {
            for (const part of named(c))
              if (part.type === "block") runConditional(part, env, depth);
          } else ev(c, env, depth + 1);
        }
        break;
    }
  }

  function execClass(n: N, env: Env, depth: number): void {
    const name = kid(n, "name");
    const body = kid(n, "body");
    if (!body) return;
    const classScope = new Scope(env.scope, false);
    const consts = new Map<string, V>();
    const clsEnv: Env = {
      ...env,
      scope: classScope,
      cls: consts,
      className: name ? text(name) : null,
      inFn: false,
    };
    // Methods run later with the scope the class was defined in (a class body is not a scope for them).
    const outer = env.scope;
    const before = queue.length;
    execBlock(body, clsEnv, depth);
    for (let i = before; i < queue.length; i += 1) {
      const pending = queue[i] as Pending;
      if (pending.env === clsEnv) pending.env = { ...clsEnv, scope: outer, inFn: env.inFn };
    }
    for (const [attr, b] of classScope.vars) {
      if (writes.get(b) === 1 && constOnly(b.value as V) && !attrAssigned.has(attr)) {
        consts.set(attr, b.value as V);
      }
    }
    if (name) classConsts.set(text(name), consts);
  }

  // ---------------------------------------------------------------- functions

  /** Annotation text -> identifiers it mentions (`Optional[int]` -> Optional, int). */
  const annotationNames = (annotation: string): string[] =>
    annotation.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? [];

  function bindParams(
    params: N,
    env: Env,
    flask: Set<string> | null,
    routeish: boolean,
    numeric: Set<string>,
    cli = false,
  ): void {
    const children = named(params);
    children.forEach((p, index) => {
      let name = "";
      let annotation = "";
      let defaultText = "";
      switch (p.type) {
        case "identifier":
          name = text(p);
          break;
        case "typed_parameter": {
          const id = named(p).find((c) => c.type === "identifier");
          name = id ? text(id) : "";
          annotation = text(kid(p, "type") ?? p);
          break;
        }
        case "default_parameter":
          name = text(kid(p, "name") as N);
          defaultText = text(kid(p, "value") as N);
          break;
        case "typed_default_parameter":
          name = text(kid(p, "name") as N);
          annotation = text(kid(p, "type") as N);
          defaultText = text(kid(p, "value") as N);
          break;
        case "list_splat_pattern":
        case "dictionary_splat_pattern": {
          const id = named(p)[0];
          if (id) assignParam(env, text(id), unknown(`parameter ${text(id)}`));
          return;
        }
        default:
          return;
      }
      if (name === "") return;
      const names = annotationNames(annotation);
      if (index === 0 && (name === "self" || name === "cls")) {
        assignParam(env, name, unknown(name));
        return;
      }
      if (/^(?:request|req)$/.test(name) || names.some((t) => REQUEST_TYPE.test(t))) {
        assignParam(env, name, reqValue());
        return;
      }
      const numericType = names.find((t) => NON_TEXT_TYPE.test(t));
      const depends = /\b(?:Depends|Security)\b/.test(`${annotation} ${defaultText}`);
      let v: V;
      if (numericType !== undefined || numeric.has(name)) {
        v = inferred(`${numericType ?? "converter"} parameter ${name}`);
      } else if (routeish && !depends && !names.some((t) => FRAMEWORK_TYPE.test(t))) {
        v = source(cli ? `command-line argument ${name}` : `route parameter ${name}`);
      } else {
        v = unknown(`parameter ${name}`);
      }
      assignParam(env, name, v);
    });
    void flask;
  }

  function assignParam(env: Env, name: string, v: V): void {
    const b: Binding = {
      name,
      type: null,
      value: v,
      guarded: false,
      ever: [...v.leaves],
      isParam: true,
    };
    env.scope.vars.set(name, b);
    writes.set(b, 1);
  }

  function analyzeFunction(p: Pending): void {
    const params = kid(p.node, "parameters");
    const body = kid(p.node, "body");
    if (!body) return;
    const decoratorNames = p.decorators.map((d) => {
      const expr = named(d)[0];
      const callee = expr?.type === "call" ? kid(expr, "function") : expr;
      return callee ? lastSegment(callee) : "";
    });
    const routeish0 = decoratorNames.some((d) => HANDLER_DECORATORS.has(d));
    const fnName = text(kid(p.node, "name") as N);
    const paramNames = params
      ? named(params).map((x) => text(kid(x, "name") ?? named(x)[0] ?? x))
      : [];
    // A Django-style view takes the request first (after `self` in a class).
    const lead =
      paramNames[0] === "self" || paramNames[0] === "cls" ? paramNames[1] : paramNames[0];
    const requestParam = lead !== undefined && /^(?:request|req)$/.test(lead);
    const webFile = [...importedModules].some((m) => WEB_MODULES.has(m));
    const routeish =
      routeish0 ||
      (requestParam && webFile) ||
      (p.env.cls !== null && VIEW_METHODS.has(fnName) && requestParam && webFile);
    // Flask URL converters: `<int:id>` is validated as a number.
    const numeric = new Set<string>();
    for (const d of p.decorators) {
      for (const m of text(d).matchAll(/<(int|float|uuid):(\w+)>/g)) numeric.add(m[2] as string);
    }
    const scope = new Scope(p.env.scope, p.env.inFn);
    const env: Env = { ...p.env, scope, conditional: 0, loops: 0, report: true, inFn: true };
    const cli = p.decorators.some((d) =>
      /^@\s*(?:click\.|typer\.)?\w*\.?(?:command|option|argument)\(|click\.|typer\./.test(text(d)),
    );
    if (params) bindParams(params, env, null, routeish || cli, numeric, cli && !routeish0);
    execBlock(body, env, 0);
  }

  // ---------------------------------------------------------------- run

  const moduleEnv: Env = {
    scope: moduleScope,
    conditional: 0,
    loops: 0,
    report: true,
    inFn: false,
    cls: null,
    className: null,
  };
  for (const stmt of named(ast.root)) execStmt(stmt, moduleEnv, 0);
  let functions = 0;
  while (queue.length > 0 && functions < 20_000) {
    functions += 1;
    analyzeFunction(queue.shift() as Pending);
  }
  if (queue.length > 0) incomplete = true;

  // ---------------------------------------------------------------- result

  const strength = (f: PyFinding): number =>
    ({ high: 30, medium: 20, low: 10 })[f.confidence] + (SEVERITY_RANK[f.severity] ?? 0);
  const byRule = new Map<RuleId, PyFinding[]>();
  for (const f of findings.values()) byRule.set(f.ruleId, [...(byRule.get(f.ruleId) ?? []), f]);
  let capped = false;
  const kept: PyFinding[] = [];
  for (const group of byRule.values()) {
    group.sort((a, b) => strength(b) - strength(a) || a.line - b.line);
    if (group.length > MAX_PYTHON_FINDINGS_PER_FILE) capped = true;
    kept.push(...group.slice(0, MAX_PYTHON_FINDINGS_PER_FILE));
  }
  const raw = kept
    .sort((a, b) => a.line - b.line)
    .map((f): RawSourceFinding => ({
      path,
      ruleId: f.ruleId,
      line: f.line,
      severity: f.severity,
      status: f.status,
      confidence: f.confidence,
      evidence: f.evidence,
      cause: f.cause,
    }));
  // A call through `getattr(...)` only matters in a file that has SQL or process code.
  const relevantFile =
    hasSqlLibrary ||
    ["os", "subprocess", "commands", "asyncio", "pty"].some((name) => importedModules.has(name));
  return {
    findings: raw,
    incomplete,
    capped,
    unsupportedForms: [...unsupported].filter(
      (form) => !form.startsWith("calls through") || relevantFile,
    ),
    unsupportedLibraries: UNSUPPORTED_SQL_LIBRARIES.filter((l) =>
      importedModules.has(l.module),
    ).map((l) => l.label),
    unsupportedProcessLibraries: UNSUPPORTED_PROCESS_LIBRARIES.filter((l) =>
      importedModules.has(l.module),
    ).map((l) => l.label),
    frameworks,
  };
}
