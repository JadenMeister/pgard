import type { ClassInfo } from "./ir.js";
import { NUMERIC_TYPES } from "./jvm-names.js";

// ------------------------------------------------------------------ values

/**
 * One contribution to a SQL string.
 * - `const`: fixed text (a literal, a `static final` or `const val` built from literals, an enum
 *   constant name). The only kind that is not reported.
 * - `inferred`: probably safe, for a reason the analysis cannot prove (allowlist check, numeric
 *   coercion or type, lookup in a fixed table, constant-style name from another file).
 * - `source`: request input.
 * - `unknown`: dynamic, and nothing says where it comes from.
 */
export type Leaf =
  | { k: "const"; text: string }
  | { k: "inferred"; why: string }
  | { k: "source"; label: string; direct: boolean; pg?: boolean }
  | { k: "unknown"; name: string; pg?: boolean };

/**
 * A file path made by `new File(...)`, `Paths.get(...)`, `resolve(...)` and the like. The path
 * rule reports where the path is used (read, written, deleted); a path that is never used in a
 * way the rule knows is reported where it was made, once, when the analysis ends.
 */
export interface Origin {
  /** A use of the path was reported (or the path went into a longer path). */
  consumed: boolean;
  /** A guard was applied to a variable that holds the path. */
  guarded: boolean;
  /** Reports the finding for the construction (`guarded`: demote it to inferred). */
  report: (guarded: boolean) => void;
  /** For a value that is one of several paths: the origins of the alternatives. */
  parts?: Origin[];
}

/** A use of the path: the finding moves from where it was made to where it is used. */
export function consumeOrigin(origin: Origin | null): void {
  if (origin === null || origin.consumed) return;
  origin.consumed = true;
  for (const part of origin.parts ?? []) consumeOrigin(part);
}

/** A check on a variable that holds the path. */
export function guardOrigin(origin: Origin | null): void {
  if (origin === null || origin.guarded) return;
  origin.guarded = true;
  for (const part of origin.parts ?? []) guardOrigin(part);
}

/** One origin for a value that is either of several paths (`cond ? a : b`). */
export function combineOrigins(values: readonly Value[]): Origin | null {
  const parts = values.flatMap((item) => (item.origin === null ? [] : [item.origin]));
  if (parts.length === 0) return null;
  return { consumed: false, guarded: false, report: () => {}, parts };
}

export interface Value {
  leaves: Leaf[];
  /** Built by concatenation, a template, a format call or a builder (not a bare variable or call). */
  composed: boolean;
  shape: string;
  /** A mutable `StringBuilder`: appends change this object in place. */
  builder: boolean;
  /** An HTTP request object (`HttpServletRequest`, Ktor `call`). */
  req: boolean;
  /** A fixed collection of literals (allowlist table). */
  table: boolean;
  /**
   * Set (to the call, such as `buildSql()`) on the result of a call the analysis does not know
   * that carries request input which went into it.
   */
  opaque: string;
  /** A `File` or `Path` value (made by a path constructor, or converted from one). */
  path: boolean;
  /** Resolved with `normalize()`, a real path or a canonical path: a prefix check on it means something. */
  canon: boolean;
  origin: Origin | null;
  /** The elements of an array or list literal, in order. */
  elems: Value[] | null;
  /** An array or list (its elements are not necessarily known). */
  coll: boolean;
  /** A `ProcessBuilder`. */
  proc: boolean;
  /** A `Runtime`. */
  rt: boolean;
}

export const MAX_LEAVES = 200;

export const value = (leaves: Leaf[] = [], extra: Partial<Value> = {}): Value => ({
  leaves,
  composed: false,
  shape: "",
  builder: false,
  req: false,
  table: false,
  opaque: "",
  path: false,
  canon: false,
  origin: null,
  elems: null,
  coll: false,
  proc: false,
  rt: false,
  ...extra,
});
export const constant = (text: string): Value => value([{ k: "const", text }]);
export const unknown = (name: string): Value => value([{ k: "unknown", name }]);
export const inferred = (why: string): Value => value([{ k: "inferred", why }]);

export const leafKey = (leaf: Leaf): string =>
  leaf.k === "source"
    ? `s:${leaf.label}:${leaf.direct}${leaf.pg === true ? ":pg" : ""}`
    : leaf.k === "unknown"
      ? `u:${leaf.name}${leaf.pg === true ? ":pg" : ""}`
      : leaf.k === "inferred"
        ? `i:${leaf.why}`
        : "";

export const MAX_SOURCE_LEAVES = 400;
export const MAX_OTHER_LEAVES = 100;

/**
 * Appends `from` to `into`, keeping constants in order and every other kind once. Each kind has its
 * own bound, so a long chain of distinct names costs a constant per step and a flood of constants
 * can never push out the first unknown, inferred or request-input leaf: reaching a bound loses
 * detail, never a finding.
 */
export function addLeaves(into: Leaf[], from: readonly Leaf[]): void {
  const counts = { const: 0, source: 0, unknown: 0, inferred: 0 };
  for (const leaf of into) counts[leaf.k] += 1;
  for (const leaf of from) {
    if (leaf.k === "const") {
      if (counts.const < MAX_LEAVES) {
        into.push(leaf);
        counts.const += 1;
      }
      continue;
    }
    if (counts[leaf.k] >= (leaf.k === "source" ? MAX_SOURCE_LEAVES : MAX_OTHER_LEAVES)) continue;
    const key = leafKey(leaf);
    if (!into.some((existing) => existing.k === leaf.k && leafKey(existing) === key)) {
      into.push(leaf);
      counts[leaf.k] += 1;
    }
  }
}

export function join(shape: string, ...parts: Value[]): Value {
  const leaves: Leaf[] = [];
  for (const part of parts) addLeaves(leaves, part.leaves);
  return value(leaves, { composed: true, shape });
}

export const copy = (source: Value): Value => ({
  ...source,
  leaves: [...source.leaves],
  builder: false,
});
export const nonConst = (leaves: readonly Leaf[]): Leaf[] =>
  leaves.filter((leaf) => leaf.k !== "const");
export const sourcesOf = (leaves: readonly Leaf[]): Leaf[] =>
  leaves.filter((leaf) => leaf.k === "source");
export const literalText = (leaves: readonly Leaf[]): string =>
  leaves
    .map((leaf) => (leaf.k === "const" ? leaf.text : " "))
    .join("")
    .slice(0, 2000);

export const baseType = (type: string | null): string => {
  if (type === null) return "";
  let name = type
    .replace(/<.*>/s, "")
    .replace(/\[\]|\?/g, "")
    .trim();
  name = name.slice(name.lastIndexOf(".") + 1);
  return name.replace(/^(?:final|vararg)\s+/, "").trim();
};
export const isNumericType = (type: string | null): boolean => NUMERIC_TYPES.has(baseType(type));
export const isTypeName = (name: string): boolean => /^[A-Z]/.test(name);
export const isConstantCase = (name: string): boolean => /^[A-Z][A-Z0-9_]+$/.test(name);

// ------------------------------------------------------------------ environment

export interface Binding {
  name: string;
  type: string | null;
  value: Value;
  guarded: boolean;
  /** Passed a path check (canonical prefix test, `..` rejection): only the path rule counts it. */
  pathGuarded?: boolean;
  /** Leaves written into the variable through an index or a mutating call (`list.add(x)`). */
  written?: Leaf[];
  /** Variables this one was made from by a path conversion (`canonical = dest.getCanonicalPath()`). */
  derived?: string[];
  /** A method parameter: request input in it is read directly, not "via variable". */
  isParam?: boolean;
  /** Everything the variable has held, for a lambda that runs after later assignments. */
  ever: Leaf[];
}

export class Scope {
  readonly vars = new Map<string, Binding>();
  constructor(
    readonly parent: Scope | null,
    /** The scope of a lambda body: names found beyond it are captured. */
    readonly isLambda = false,
  ) {}
  find(name: string): Binding | null {
    return this.lookup(name)?.binding ?? null;
  }
  lookup(name: string): { binding: Binding; captured: boolean } | null {
    let captured = false;
    for (let scope: Scope | null = this; scope !== null; scope = scope.parent) {
      const found = scope.vars.get(name);
      if (found !== undefined) return { binding: found, captured };
      if (scope.isLambda) captured = true;
    }
    return null;
  }
}

export interface Context {
  cls: ClassInfo | null;
  scope: Scope;
  /** Depth of conditional or repeated code: an assignment there may or may not happen. */
  conditional: number;
  /** Builders that an unqualified `append(...)` (Kotlin `buildString { }`) writes to. */
  builders: Value[];
  /** Loops around this code. */
  loops: number;
  /** Running a lambda body after the code that defines it: captured variables hold all they held. */
  deferred: boolean;
  /** Report sinks (off while a field initializer is evaluated only for its value). */
  report: boolean;
}
