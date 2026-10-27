import type { Confidence, FindingStatus, Severity } from "@pgard/findings";
import { addLeaves, literalText, nonConst, sourcesOf, type Leaf } from "../jvm/flow-values.js";
import {
  SHELL_FLAG_CMD,
  SHELL_FLAG_PD,
  SHELL_FLAG_POSIX,
  SHELL_PROGRAMS,
} from "../jvm/os-names.js";
import { textOf, type AstNode, type AstResult } from "../jvm/tree.js";
import {
  BOOLEAN_FUNCTIONS,
  COMMAND_FUNCTIONS,
  CTYPE_FUNCTIONS,
  DB_CLASSES,
  DB_HANDLE_NAME,
  DB_TYPE,
  ENCODER_FUNCTIONS,
  ESCAPE_FUNCTIONS,
  ESCAPE_METHODS,
  EXIT_FUNCTIONS,
  FILTER_NUMERIC,
  FIXED_FUNCTIONS,
  NUMBER_FUNCTIONS,
  OTHER_SUPERGLOBALS,
  PASS_THROUGH_FUNCTIONS,
  REQUEST_BAGS,
  REQUEST_BENIGN_METHODS,
  REQUEST_FACADE_METHODS,
  REQUEST_FUNCTIONS,
  REQUEST_NAME,
  REQUEST_SUPERGLOBALS,
  REQUEST_THIS_PROPS,
  REQUEST_TYPE,
  SERVER_INPUT_KEY,
  SQL_DISTINCT_METHODS,
  SQL_FACADE_METHODS,
  SQL_FUNCTIONS,
  SQL_FUNCTIONS_FIRST_IF_ONE_ARG,
  SQL_HANDLE_METHODS,
  SQL_RAW_METHODS,
  SQL_TEXT,
  UNSUPPORTED_LIBRARIES,
  VALIDATOR_NAME,
} from "./php-names.js";

/** A finding before the path is attached. */
export interface PhpFinding {
  ruleId: "PG-SQL-006" | "PG-CMD-004";
  line: number;
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  evidence: string;
  cause: string;
}

export interface PhpAnalysis {
  findings: PhpFinding[];
  /** Part of the file was not analyzed (nesting too deep, or the work budget ran out). */
  incomplete: boolean;
  /** Dynamic calls (`$fn(...)`, `$o->$m(...)`, `call_user_func`) with SQL-looking text: not followed. */
  unsupported: string[];
  /** Libraries with their own SQL or process APIs that the file uses. */
  libraries: Array<{ label: string; kind: "sql" | "process" }>;
}

// ------------------------------------------------------------------ values

/** What an expression holds: leaves in the order they contribute, plus a few facts. */
interface PV {
  leaves: Leaf[];
  /** Built by concatenation, interpolation, a format call or implode (not a bare variable or call). */
  composed: boolean;
  shape: string;
  /** The elements of an array literal, in order. */
  elems: PV[] | null;
  /** An array (its elements are not necessarily known). */
  arr: boolean;
  /** A request object (or a bag of request input such as `$request->query`). */
  req: boolean;
  /** Set on the result of a call that is not known and that carried request input. */
  opaque: string;
  /** Already reported where it was made (`DB::raw`). */
  raw: boolean;
  /** A database handle. */
  db: boolean;
  /** An array literal of constants: an allowlist table. */
  table: boolean;
}

const pv = (leaves: Leaf[] = [], extra: Partial<PV> = {}): PV => ({
  leaves,
  composed: false,
  shape: "",
  elems: null,
  arr: false,
  req: false,
  opaque: "",
  raw: false,
  db: false,
  table: false,
  ...extra,
});
const constant = (text: string): PV => pv([{ k: "const", text }]);
const unknown = (name: string): PV => pv([{ k: "unknown", name }]);
const inferred = (why: string): PV => pv([{ k: "inferred", why }]);
const hasDynamic = (value: PV): boolean => nonConst(value.leaves).length > 0;
const own = <T>(table: Readonly<Record<string, T>>, key: string): T | undefined =>
  Object.hasOwn(table, key) ? table[key] : undefined;

/** Value stored in a variable: request input is now reached "via variable". */
function stored(value: PV): PV {
  return {
    ...value,
    leaves: value.leaves.map((leaf) => (leaf.k === "source" ? { ...leaf, direct: false } : leaf)),
  };
}

function join(shape: string, parts: readonly PV[]): PV {
  const leaves: Leaf[] = [];
  for (const part of parts) addLeaves(leaves, part.leaves);
  return pv(leaves, {
    composed: parts.some((part) => hasDynamic(part)),
    shape,
  });
}

function union(a: PV, b: PV): PV {
  const leaves = [...a.leaves];
  addLeaves(leaves, b.leaves);
  return pv(leaves, {
    composed: a.composed || b.composed,
    shape: a.shape || b.shape,
    elems: null,
    arr: a.arr || b.arr,
    req: a.req || b.req,
    opaque: a.opaque || b.opaque,
    raw: a.raw && b.raw,
    db: a.db || b.db,
    table: a.table && b.table,
  });
}

function unionAll(values: readonly PV[]): PV {
  const [first, ...rest] = values;
  return first === undefined ? pv() : rest.reduce(union, first);
}

/** Request input made at this place. */
const source = (label: string): PV =>
  pv([
    { k: "source", label: label.length > 60 ? `${label.slice(0, 57)}...` : label, direct: true },
  ]);

// ------------------------------------------------------------------ environment

type Env = Map<string, PV>;
type Exit = null | "exit" | "break";

interface ClassInfo {
  name: string;
  consts: Map<string, AstNode>;
  props: Map<string, { value: AstNode | null; isPublic: boolean }>;
  reassigned: Set<string>;
}

interface Ctx {
  cls: ClassInfo | null;
}

const MAX_DEPTH = 300;
const MAX_STEPS = 4_000_000;
const MAX_LOOP_NESTING = 3;

const isExpressionWrapper = new Set([
  "parenthesized_expression",
  "error_suppression_expression",
  "clone_expression",
  "by_ref",
  "reference_modifier",
  "print_intrinsic",
]);

const BOOL_OPERATORS = new Set([
  "==",
  "===",
  "!=",
  "!==",
  "<>",
  "<",
  ">",
  "<=",
  ">=",
  "<=>",
  "&&",
  "||",
  "and",
  "or",
  "xor",
  "instanceof",
]);

const CLASS_LIKE = new Set([
  "class_declaration",
  "trait_declaration",
  "enum_declaration",
  "interface_declaration",
]);

export function analyzePhp(ast: AstResult): PhpAnalysis {
  const src = ast.source;
  const text = (node: AstNode): string => textOf(ast, node);
  const findings = new Map<string, PhpFinding & { rank: number }>();
  let incomplete = ast.truncated;
  let steps = 0;
  const unsupported = new Set<string>();
  const classes = new Map<string, ClassInfo>();
  const fileConsts = new Map<string, AstNode>();
  const constMemo = new Map<AstNode, PV>();
  const constBusy = new Set<AstNode>();
  const functionNames = new Set<string>();
  let loopDepth = 0;

  // ---------------------------------------------------------------- tree helpers

  const field = (node: AstNode, name: string): AstNode | undefined =>
    node.children.find((child) => child.field === name);
  const fields = (node: AstNode, name: string): AstNode[] =>
    node.children.filter((child) => child.field === name);
  const named = (node: AstNode): AstNode[] => node.children.filter((child) => !child.anonymous);
  const operatorOf = (node: AstNode): string => {
    const operator = field(node, "operator");
    return operator === undefined ? "" : text(operator).toLowerCase();
  };
  const unwrap = (node: AstNode): AstNode => {
    let current = node;
    for (let i = 0; i < 50 && isExpressionWrapper.has(current.type); i += 1) {
      const inner = named(current)[0];
      if (inner === undefined) break;
      current = inner;
    }
    return current;
  };
  const lastSegment = (name: string): string => name.slice(name.lastIndexOf("\\") + 1);
  /** `exec`, `\exec`, `Foo\bar` -> lower-case last segment; null for anything not a plain name. */
  const calleeName = (node: AstNode | undefined): string | null => {
    if (node === undefined) return null;
    if (node.type === "name" || node.type === "qualified_name") {
      return lastSegment(text(node)).toLowerCase();
    }
    return null;
  };
  const normKey = (node: AstNode): string | null => {
    const key = text(node).replace(/\s+/g, "").replace(/"/g, "'");
    return key.length <= 120 ? key : null;
  };
  const isThis = (node: AstNode | undefined): boolean =>
    node !== undefined && node.type === "variable_name" && text(node) === "$this";

  /** Description of a receiver for the finding label: `$pdo`, `$this->db`, `DB::connection()`. */
  function describe(node: AstNode | undefined): string {
    let current = node;
    let suffix = "";
    for (let i = 0; i < 12 && current !== undefined; i += 1) {
      const type = current.type;
      if (type === "variable_name") return `${text(current)}${suffix}`;
      if (type === "member_access_expression" || type === "nullsafe_member_access_expression") {
        suffix = `->${text(field(current, "name") ?? current)}${suffix}`;
        current = field(current, "object");
      } else if (type === "member_call_expression" || type === "nullsafe_member_call_expression") {
        suffix = `->${text(field(current, "name") ?? current)}()${suffix}`;
        current = field(current, "object");
      } else if (type === "scoped_call_expression") {
        const scope = field(current, "scope");
        return `${scope === undefined ? "" : lastSegment(text(scope))}::${text(field(current, "name") ?? current)}()${suffix}`;
      } else if (type === "function_call_expression") {
        return `${calleeName(field(current, "function")) ?? "call"}()${suffix}`;
      } else if (type === "name" || type === "qualified_name") {
        return `${lastSegment(text(current))}${suffix}`;
      } else {
        return `call${suffix}`;
      }
    }
    return `call${suffix}`;
  }

  /** The `DB` facade is at the root of a call chain (`DB::connection()->select(...)`). */
  function rootIsDbFacade(node: AstNode | undefined): boolean {
    let current = node;
    for (let i = 0; i < 20 && current !== undefined; i += 1) {
      if (current.type === "scoped_call_expression") {
        const scope = field(current, "scope");
        return scope !== undefined && lastSegment(text(scope)) === "DB";
      }
      if (
        current.type === "member_call_expression" ||
        current.type === "nullsafe_member_call_expression" ||
        current.type === "member_access_expression"
      ) {
        current = field(current, "object");
      } else {
        return false;
      }
    }
    return false;
  }

  function looksLikeDb(node: AstNode | undefined, value: PV): boolean {
    if (value.db) return true;
    const last = describe(node).replace(/\(\)/g, "").split(/->|::/).pop()?.replace(/^\$/, "");
    return last !== undefined && DB_HANDLE_NAME.test(last);
  }

  // ---------------------------------------------------------------- pre-pass

  // Classes (constants, properties, which properties are assigned), file constants and functions.
  // One iterative walk: a flat file with a 10 000-term concatenation is a very deep tree.
  {
    const stack: AstNode[] = [ast.root];
    while (stack.length > 0) {
      const node = stack.pop() as AstNode;
      if (CLASS_LIKE.has(node.type)) {
        const nameNode = field(node, "name");
        const body = field(node, "body");
        if (nameNode !== undefined && body !== undefined) {
          const info: ClassInfo = {
            name: text(nameNode),
            consts: new Map(),
            props: new Map(),
            reassigned: new Set(),
          };
          for (const member of body.children) {
            if (member.type === "const_declaration") {
              for (const element of member.children) {
                if (element.type !== "const_element") continue;
                const parts = named(element);
                const constName = parts[0];
                const constValue = parts[1];
                if (constName !== undefined && constValue !== undefined) {
                  info.consts.set(text(constName), constValue);
                }
              }
            } else if (member.type === "enum_case") {
              const caseName = field(member, "name");
              const caseValue = field(member, "value");
              if (caseName !== undefined) {
                info.consts.set(text(caseName), caseValue ?? caseName);
              }
            } else if (member.type === "property_declaration") {
              const isPublic =
                !member.children.some((child) => child.type === "visibility_modifier") ||
                member.children.some(
                  (child) => child.type === "visibility_modifier" && text(child) === "public",
                );
              for (const element of member.children) {
                if (element.type !== "property_element") continue;
                const propName = field(element, "name");
                if (propName !== undefined) {
                  info.props.set(text(propName).replace(/^\$/, ""), {
                    value: field(element, "default_value") ?? null,
                    isPublic,
                  });
                }
              }
            }
          }
          // Properties written anywhere in the class (`$this->x = ...`, promoted parameters).
          const inner: AstNode[] = [body];
          while (inner.length > 0) {
            const current = inner.pop() as AstNode;
            if (
              current.type === "assignment_expression" ||
              current.type === "augmented_assignment_expression" ||
              current.type === "reference_assignment_expression"
            ) {
              const left = field(current, "left");
              if (left !== undefined && left.type === "member_access_expression") {
                const object = field(left, "object");
                const propName = field(left, "name");
                if (isThis(object) && propName !== undefined) {
                  info.reassigned.add(text(propName));
                }
              }
            } else if (current.type === "property_promotion_parameter") {
              const promoted = field(current, "name");
              if (promoted !== undefined) info.reassigned.add(text(promoted).replace(/^\$/, ""));
            }
            for (const child of current.children) inner.push(child);
          }
          if (!classes.has(info.name)) classes.set(info.name, info);
        }
      } else if (node.type === "const_declaration") {
        // Only constants outside a class body reach here with a non-class parent; class constants
        // are also seen again, which is harmless (the file map is only read for bare names).
        for (const element of node.children) {
          if (element.type !== "const_element") continue;
          const parts = named(element);
          const constName = parts[0];
          const constValue = parts[1];
          if (
            constName !== undefined &&
            constValue !== undefined &&
            !fileConsts.has(text(constName))
          ) {
            fileConsts.set(text(constName), constValue);
          }
        }
      } else if (node.type === "function_call_expression") {
        const callee = calleeName(field(node, "function"));
        if (callee === "define") {
          const args = field(node, "arguments");
          const items =
            args === undefined ? [] : args.children.filter((c) => c.type === "argument");
          const first = items[0] === undefined ? undefined : named(items[0])[0];
          const second = items[1] === undefined ? undefined : named(items[1])[0];
          if (first !== undefined && second !== undefined && first.type === "string") {
            const defined = text(first).slice(1, -1);
            if (!fileConsts.has(defined)) fileConsts.set(defined, second);
          }
        }
      } else if (node.type === "function_definition") {
        const nameNode = field(node, "name");
        if (nameNode !== undefined) functionNames.add(text(nameNode).toLowerCase());
      } else if (node.type === "method_declaration") {
        const nameNode = field(node, "name");
        if (nameNode !== undefined) functionNames.add(text(nameNode).toLowerCase());
      }
      for (const child of node.children) stack.push(child);
    }
  }
  const constCtx = (cls: ClassInfo | null): Ctx => ({ cls });
  const constantValue = (node: AstNode, cls: ClassInfo | null): PV => {
    const known = constMemo.get(node);
    if (known !== undefined) return known;
    if (constBusy.has(node)) return unknown("constant (cyclic)");
    constBusy.add(node);
    let result: PV;
    try {
      result = evaluate(node, new Map(), constCtx(cls), 0);
    } finally {
      constBusy.delete(node);
    }
    constMemo.set(node, result);
    return result;
  };

  // ---------------------------------------------------------------- strings

  /** Concatenates the parts of an interpolated string, heredoc or backtick command. */
  function interpolated(node: AstNode, env: Env, ctx: Ctx, depth: number, shape: string): PV {
    const parts: PV[] = [];
    const collect = (parent: AstNode): void => {
      for (const child of parent.children) {
        if (child.anonymous) continue;
        if (child.type === "string_content" || child.type === "escape_sequence") {
          parts.push(constant(text(child)));
        } else if (child.type === "heredoc_body") {
          collect(child);
        } else if (child.type === "heredoc_start" || child.type === "heredoc_end") {
          continue;
        } else if (child.type === "nowdoc_string") {
          parts.push(constant(text(child)));
        } else {
          parts.push(evaluate(child, env, ctx, depth + 1));
        }
      }
    };
    collect(node);
    return join(shape, parts);
  }

  /** Left-to-right operands of a chain of `.`; iterative so a long chain cannot overflow. */
  function concatOperands(node: AstNode): AstNode[] {
    const operands: AstNode[] = [];
    let current: AstNode = node;
    for (;;) {
      const left = field(current, "left");
      const right = field(current, "right");
      if (left === undefined || right === undefined) {
        operands.push(current);
        break;
      }
      operands.push(right);
      if (left.type === "binary_expression" && operatorOf(left) === ".") {
        current = left;
      } else {
        operands.push(left);
        break;
      }
    }
    return operands.reverse();
  }

  function formatString(args: Arg[], shape: string): PV {
    const [format, ...rest] = args;
    if (format === undefined) return unknown("sprintf()");
    const template = literalText(format.value.leaves);
    if (hasDynamic(format.value) || format.value.leaves.length === 0) {
      return join(
        shape,
        args.map((arg) => arg.value),
      );
    }
    const parts: PV[] = [];
    let last = 0;
    let next = 0;
    for (const match of template.matchAll(/%(?:(\d+)\$)?[-+ 0]*(?:'.)?\d*(?:\.\d+)?([a-zA-Z%])/g)) {
      const index = match.index as number;
      if (index > last) parts.push(constant(template.slice(last, index)));
      last = index + match[0].length;
      const conversion = match[2] as string;
      if (conversion === "%") {
        parts.push(constant("%"));
        continue;
      }
      const position = match[1] === undefined ? next++ : Number(match[1]) - 1;
      const arg = rest[position];
      if (arg === undefined) continue;
      if (/[diufFeEgGxXobc]/.test(conversion)) {
        parts.push(
          hasDynamic(arg.value)
            ? inferred(`%${conversion} accepts only numbers or booleans`)
            : constant("0"),
        );
      } else {
        parts.push(arg.value);
      }
    }
    if (last < template.length) parts.push(constant(template.slice(last)));
    return join(shape, parts);
  }

  // ---------------------------------------------------------------- findings

  type Kind = "tainted" | "helper" | "unknown" | "inferred";
  interface Judged {
    kind: Kind;
    shape: string;
    source?: Extract<Leaf, { k: "source" }>;
    helper?: string;
    reasons?: string[];
  }

  /** Classifies what reaches a sink; null when it is fixed (nothing to report). */
  function judge(value: PV): Judged | null {
    const dynamic = nonConst(value.leaves);
    if (dynamic.length === 0) return null;
    const tainted = sourcesOf(value.leaves);
    const helperLeaf = dynamic.find(
      (leaf) => leaf.k === "unknown" && /\(\)$|^property /.test(leaf.name),
    );
    const helper =
      value.opaque !== "" ? value.opaque : helperLeaf?.k === "unknown" ? helperLeaf.name : "";
    const shape = value.shape || (value.composed ? "built string" : "variable");
    if (!value.composed) {
      if (value.opaque === "" && tainted.length > 0) {
        return {
          kind: "tainted",
          shape,
          source: (tainted.find((l) => l.k === "source" && l.direct) ?? tainted[0]) as Extract<
            Leaf,
            { k: "source" }
          >,
        };
      }
      if (helper !== "") return { kind: "helper", shape, helper };
      if (dynamic.every((leaf) => leaf.k === "inferred")) {
        return { kind: "inferred", shape, reasons: reasonsOf(dynamic) };
      }
      // A bare parameter or variable says nothing about how the text was made.
      return null;
    }
    if (tainted.length > 0) {
      return {
        kind: "tainted",
        shape,
        source: (tainted.find((l) => l.k === "source" && l.direct) ?? tainted[0]) as Extract<
          Leaf,
          { k: "source" }
        >,
      };
    }
    if (dynamic.some((leaf) => leaf.k === "unknown")) return { kind: "unknown", shape };
    return { kind: "inferred", shape, reasons: reasonsOf(dynamic) };
  }

  const reasonsOf = (dynamic: readonly Leaf[]): string[] =>
    [...new Set(dynamic.map((leaf) => (leaf.k === "inferred" ? leaf.why : "")))]
      .filter(Boolean)
      .slice(0, 2);

  function record(finding: PhpFinding, rank: number): void {
    const key = `${finding.ruleId}:${finding.line}:${finding.cause}`;
    const existing = findings.get(key);
    if (existing === undefined || existing.rank < rank) findings.set(key, { ...finding, rank });
  }

  const rankOf = (kind: Kind): number => (kind === "tainted" ? 3 : kind === "unknown" ? 2 : 1);

  const lowReason = (judged: Judged): string =>
    judged.kind === "helper"
      ? `; value from ${judged.helper}, not followed; inferred`
      : judged.kind === "unknown"
        ? " (no input source identified)"
        : `; ${(judged.reasons ?? []).join("; ")}; inferred`;

  function reportSql(value: PV | undefined, line: number, label: string): void {
    if (value === undefined || value.raw) return;
    const judged = judge(value);
    if (judged === null) return;
    if (judged.kind === "tainted" && judged.source !== undefined) {
      const origin = judged.source;
      record(
        {
          ruleId: "PG-SQL-006",
          line,
          severity: "high",
          status: origin.direct ? "confirmed" : "suspected",
          confidence: "high",
          evidence: `request input (${origin.label})${origin.direct ? "" : " via variable"} -> ${judged.shape} -> ${label}`,
          cause: label,
        },
        rankOf(judged.kind),
      );
      return;
    }
    record(
      {
        ruleId: "PG-SQL-006",
        line,
        severity: "medium",
        status: "suspected",
        confidence: "low",
        evidence: `${judged.shape} -> ${label}${lowReason(judged)}`,
        cause: label,
      },
      rankOf(judged.kind),
    );
  }

  function reportCommand(
    value: PV | undefined,
    line: number,
    sink: string,
    scope: "string" | "program",
  ): void {
    if (value === undefined) return;
    const judged = judge(value);
    if (judged === null) return;
    const detail = scope === "program" ? `${sink} (program)` : sink;
    const cause = `${sink}:${scope}`;
    if (judged.kind === "tainted" && judged.source !== undefined) {
      const origin = judged.source;
      record(
        {
          ruleId: "PG-CMD-004",
          line,
          severity: "critical",
          status: origin.direct ? "confirmed" : "suspected",
          confidence: "high",
          evidence: `request input (${origin.label})${origin.direct ? "" : " via variable"} -> ${judged.shape} -> ${detail}`,
          cause,
        },
        rankOf(judged.kind),
      );
      return;
    }
    record(
      {
        ruleId: "PG-CMD-004",
        line,
        severity: "medium",
        status: "suspected",
        confidence: "low",
        evidence: `${judged.shape} -> ${detail}${lowReason(judged)}`,
        cause,
      },
      rankOf(judged.kind),
    );
  }

  /** `proc_open([...])` and `new Process([...])`: no shell, so only a program from data or a shell wrapper counts. */
  function reportArrayCommand(value: PV, line: number, sink: string): void {
    const elems = value.elems;
    if (elems === null && hasDynamic(value)) {
      // An array that was changed after it was made: the program position is not known.
      reportCommand(
        pv([{ k: "unknown", name: "array element" }], { composed: true, shape: "command array" }),
        line,
        sink,
        "program",
      );
      return;
    }
    if (elems === null || elems.length === 0) return;
    const program = elems[0] as PV;
    if (hasDynamic(program)) {
      reportCommand(
        program.composed ? program : { ...program, composed: true },
        line,
        sink,
        "program",
      );
      return;
    }
    const name = literalText(program.leaves)
      .trim()
      .replace(/^.*[\\/]/, "")
      .replace(/\.exe$/i, "")
      .toLowerCase();
    if (!SHELL_PROGRAMS.has(name)) return;
    for (let i = 1; i < elems.length - 1; i += 1) {
      const flag = elems[i] as PV;
      if (hasDynamic(flag)) continue;
      const flagText = literalText(flag.leaves).trim();
      if (
        SHELL_FLAG_POSIX.test(flagText) ||
        SHELL_FLAG_CMD.test(flagText) ||
        SHELL_FLAG_PD.test(flagText)
      ) {
        const script = elems[i + 1] as PV;
        reportCommand(
          script.composed ? script : { ...script, composed: true, shape: "shell script" },
          line,
          sink,
          "string",
        );
        return;
      }
    }
  }

  // ---------------------------------------------------------------- calls

  interface Arg {
    node: AstNode;
    value: PV;
    name: string | null;
    spread: boolean;
  }

  function argsOf(call: AstNode, env: Env, ctx: Ctx, depth: number): Arg[] {
    const list =
      field(call, "arguments") ?? call.children.find((child) => child.type === "arguments");
    if (list === undefined) return [];
    const out: Arg[] = [];
    for (const item of list.children) {
      if (item.type !== "argument") continue;
      const nameNode = field(item, "name");
      const expression = named(item).find((child) => child.field !== "name");
      if (expression === undefined) continue;
      const spread = expression.type === "variadic_unpacking";
      const target = spread ? (named(expression)[0] ?? expression) : expression;
      out.push({
        node: target,
        value: evaluate(target, env, ctx, depth + 1),
        name: nameNode === undefined ? null : text(nameNode),
        spread,
      });
    }
    return out;
  }

  const requestInput = (label: string): PV => source(label);

  function helperResult(name: string, args: readonly Arg[], recv?: PV): PV {
    const carries =
      args.some((arg) => sourcesOf(arg.value.leaves).length > 0 || arg.value.opaque !== "") ||
      (recv !== undefined && (sourcesOf(recv.leaves).length > 0 || recv.opaque !== ""));
    return pv([{ k: "unknown", name: `${name}()` }], { opaque: carries ? `${name}()` : "" });
  }

  const dynamicCall = (args: readonly Arg[]): void => {
    if (args.some((arg) => arg.value.composed && SQL_TEXT.test(literalText(arg.value.leaves)))) {
      unsupported.add("dynamic calls");
    }
  };

  function functionCall(node: AstNode, env: Env, ctx: Ctx, depth: number): PV {
    const callee = field(node, "function");
    const line = node.line;
    const name = calleeName(callee);
    if (name === null) {
      if (callee !== undefined) evaluate(callee, env, ctx, depth + 1);
      const args = argsOf(node, env, ctx, depth);
      dynamicCall(args);
      return helperResult("call", args);
    }
    const args = argsOf(node, env, ctx, depth);
    const arg0 = args[0]?.value;

    // SQL
    const sqlPosition =
      own(SQL_FUNCTIONS, name) === undefined
        ? undefined
        : SQL_FUNCTIONS_FIRST_IF_ONE_ARG.has(name) && args.length === 1
          ? 0
          : own(SQL_FUNCTIONS, name);
    if (sqlPosition !== undefined) {
      reportSql(args[sqlPosition]?.value, line, name);
      return unknown(`${name}()`);
    }
    // Commands
    if (COMMAND_FUNCTIONS.has(name)) {
      if (arg0 !== undefined) {
        if (name === "proc_open" && (arg0.elems !== null || arg0.arr)) {
          reportArrayCommand(arg0, line, name);
        } else if (name === "pcntl_exec") {
          reportCommand(
            arg0.composed ? arg0 : { ...arg0, composed: true, shape: "program path" },
            line,
            name,
            "program",
          );
        } else {
          reportCommand(arg0, line, name, "string");
        }
      }
      return unknown(`${name}()`);
    }
    // Calls that never return
    if (EXIT_FUNCTIONS.has(name)) return pv();

    if (name === "request") {
      return args.length > 0 ? requestInput("request()") : pv([], { req: true });
    }
    if (REQUEST_FUNCTIONS.has(name)) return requestInput(`${name}()`);
    if (name === "file_get_contents" && arg0 !== undefined) {
      if (literalText(arg0.leaves).startsWith("php://input")) return requestInput("php://input");
      return helperResult(name, args);
    }
    if (FIXED_FUNCTIONS.has(name)) return constant("0");
    const escapeNote = own(ESCAPE_FUNCTIONS, name);
    if (escapeNote !== undefined) {
      const picked = args.at(name.startsWith("mysqli_") || name.startsWith("pg_escape") ? 1 : 0);
      const value = picked?.value ?? pv();
      return hasDynamic(value) || value.leaves.length === 0 ? inferred(escapeNote) : value;
    }
    if (name === "filter_var") {
      const filter = args[1] === undefined ? "" : text(args[1].node);
      if (FILTER_NUMERIC.test(filter)) return inferred(`validated with ${filter}`);
      return arg0 ?? pv();
    }
    if (name === "sprintf" || name === "vsprintf") {
      if (name === "vsprintf" && args[1] !== undefined) {
        const items = args[1].value.elems;
        return formatString(
          [
            { ...args[0]!, value: args[0]!.value },
            ...(items ?? [args[1].value]).map((value) => ({ ...args[1]!, value })),
          ],
          "sprintf",
        );
      }
      return formatString(args, "sprintf");
    }
    if (name === "implode" || name === "join") {
      const parts = args.map((arg) => arg.value);
      return join("implode", parts);
    }
    if (name === "preg_match" || name === "preg_match_all") {
      const target = args[2]?.node;
      if (target !== undefined && target.type === "variable_name" && args[1] !== undefined) {
        env.set(text(target), stored({ ...args[1].value, composed: false }));
      }
      return constant("0");
    }
    if (name === "array_push" || name === "array_unshift") {
      const target = args[0]?.node;
      if (target !== undefined && target.type === "variable_name") {
        const base = env.get(text(target)) ?? pv();
        env.set(text(target), union(base, stored(unionAll(args.slice(1).map((arg) => arg.value)))));
      }
      return constant("0");
    }
    if (name === "parse_str") {
      const target = args[1]?.node;
      if (target !== undefined && target.type === "variable_name" && args[0] !== undefined) {
        env.set(text(target), stored(args[0].value));
      }
      return constant("0");
    }
    if (name === "call_user_func" || name === "call_user_func_array") {
      dynamicCall(args);
      return helperResult(name, args);
    }
    if (name === "define") return constant("0");
    // `array_map('intval', $ids)` makes numbers, like a cast.
    if (
      name === "array_map" &&
      arg0 !== undefined &&
      !hasDynamic(arg0) &&
      FIXED_FUNCTIONS.has(literalText(arg0.leaves).replace(/^\\/, "").toLowerCase())
    ) {
      return constant("0");
    }
    // The repeat count and the fill count are numbers; only the repeated text matters.
    if (name === "str_repeat") return arg0 ?? pv();
    if (name === "array_fill") return args[2]?.value ?? pv();
    if (name === "range") return constant("0");
    if (NUMBER_FUNCTIONS.has(name))
      return hasDynamic(unionAll(args.map((a) => a.value)))
        ? inferred(`${name}() gives a number, digest or date`)
        : constant("0");
    if (ENCODER_FUNCTIONS.has(name)) {
      return hasDynamic(unionAll(args.map((a) => a.value)))
        ? inferred(`${name}() encodes the value`)
        : unionAll(args.map((a) => a.value));
    }
    if (BOOLEAN_FUNCTIONS.has(name)) return constant("0");
    if (PASS_THROUGH_FUNCTIONS.has(name)) {
      const out = unionAll(args.map((arg) => arg.value));
      return { ...out, composed: out.composed, shape: out.shape, elems: null };
    }
    if (functionNames.has(name)) return helperResult(name, args);
    return helperResult(name, args);
  }

  function memberCall(node: AstNode, env: Env, ctx: Ctx, depth: number): PV {
    const object = field(node, "object");
    const nameNode = field(node, "name");
    const recv = object === undefined ? pv() : evaluate(object, env, ctx, depth + 1);
    const args = argsOf(node, env, ctx, depth);
    const line = node.line;
    if (nameNode === undefined || nameNode.type !== "name") {
      dynamicCall(args);
      return helperResult("call", args, recv);
    }
    const name = text(nameNode);
    const lower = name.toLowerCase();
    const arg0 = args[0]?.value;
    const label = `${describe(object)}->${name}`;

    if (recv.req || (isThis(object) && (lower === "getrequest" || lower === "request"))) {
      if (isThis(object)) return pv([], { req: true });
      if (REQUEST_BENIGN_METHODS.has(lower)) return constant("0");
      return requestInput(`${describe(object)}->${name}()`);
    }
    const escapeMethod = own(ESCAPE_METHODS, lower);
    if (escapeMethod !== undefined && arg0 !== undefined) {
      return hasDynamic(arg0) || arg0.leaves.length === 0 ? inferred(escapeMethod) : arg0;
    }
    if (lower === "escape" && arg0 !== undefined && looksLikeDb(object, recv)) {
      return inferred("escaped with escape()");
    }
    if (SQL_RAW_METHODS.has(lower)) {
      reportSql(arg0, line, `->${name}`);
      return unknown(`${name}()`);
    }
    if (SQL_DISTINCT_METHODS.has(lower)) {
      reportSql(arg0, line, label);
      return unknown(`${name}()`);
    }
    if (SQL_HANDLE_METHODS.has(lower) && arg0 !== undefined) {
      const sqlText = SQL_TEXT.test(literalText(arg0.leaves));
      if (looksLikeDb(object, recv) || sqlText || rootIsDbFacade(object)) {
        reportSql(arg0, line, label);
      }
      return unknown(`${name}()`);
    }
    if (SQL_FACADE_METHODS.has(lower) && arg0 !== undefined) {
      if (recv.db || rootIsDbFacade(object)) {
        reportSql(arg0, line, label);
      }
      return unknown(`${name}()`);
    }
    if (["getpdo", "getconnection", "connection", "getreadpdo", "getwritepdo"].includes(lower)) {
      return pv([], { db: true });
    }
    if (lower === "getrequest" && isThis(object)) return pv([], { req: true });
    // Methods of a value that carries request input return something derived from it.
    return helperResult(name, args, recv);
  }

  function scopedCall(node: AstNode, env: Env, ctx: Ctx, depth: number): PV {
    const scopeNode = field(node, "scope");
    const nameNode = field(node, "name");
    const args = argsOf(node, env, ctx, depth);
    const scope = scopeNode === undefined ? "" : lastSegment(text(scopeNode));
    const name = nameNode === undefined ? "" : text(nameNode);
    const lower = name.toLowerCase();
    const arg0 = args[0]?.value;
    const line = node.line;
    if (nameNode === undefined || nameNode.type !== "name") {
      dynamicCall(args);
      return helperResult("call", args);
    }
    if (scope === "DB") {
      if (lower === "raw") {
        reportSql(arg0, line, "DB::raw");
        const raw = arg0 ?? pv();
        return { ...raw, raw: true };
      }
      if (lower === "connection" || lower === "getpdo") return pv([], { db: true });
      if (SQL_FACADE_METHODS.has(lower)) {
        reportSql(arg0, line, `DB::${name}`);
        return unknown(`DB::${name}()`);
      }
    }
    if (SQL_RAW_METHODS.has(lower)) {
      reportSql(arg0, line, `::${name}`);
      return unknown(`${name}()`);
    }
    if (SQL_DISTINCT_METHODS.has(lower)) {
      reportSql(arg0, line, `${scope}::${name}`);
      return unknown(`${name}()`);
    }
    if (scope === "Process" && lower === "fromshellcommandline") {
      reportCommand(arg0, line, "Process::fromShellCommandline", "string");
      return unknown("Process");
    }
    if (
      scope === "Process" &&
      ["run", "start", "forever", "timeout", "path", "input"].includes(lower)
    ) {
      // Laravel's Process facade: a string is a shell command, an array is run without a shell.
      if (lower === "run" || lower === "start") {
        if (arg0 !== undefined && (arg0.elems !== null || arg0.arr))
          reportArrayCommand(arg0, line, `Process::${name}`);
        else reportCommand(arg0, line, `Process::${name}`, "string");
      }
      return unknown("Process");
    }
    if (scope === "Request" && REQUEST_FACADE_METHODS.has(lower)) {
      return requestInput(`Request::${name}()`);
    }
    return helperResult(name, args);
  }

  function objectCreation(node: AstNode, env: Env, ctx: Ctx, depth: number): PV {
    const classNode = node.children.find(
      (child) => child.type === "name" || child.type === "qualified_name",
    );
    const className = classNode === undefined ? "" : lastSegment(text(classNode));
    const args = argsOf(node, env, ctx, depth);
    const line = node.line;
    if (DB_CLASSES.has(className)) return pv([], { db: true });
    if (className === "Process" && args[0] !== undefined) {
      const command = args[0].value;
      if (command.elems !== null || command.arr) reportArrayCommand(command, line, "new Process");
      else reportCommand(command, line, "new Process", "string");
      return unknown("Process");
    }
    if (REQUEST_TYPE.test(className)) return pv([], { req: true });
    return unknown(`new ${className || "object"}`);
  }

  // ---------------------------------------------------------------- expressions

  function propertyValue(
    object: AstNode | undefined,
    name: string,
    cls: ClassInfo | null,
    isSelf = false,
  ): PV {
    if (isSelf || isThis(object)) {
      if (!isSelf && REQUEST_THIS_PROPS.has(name)) return pv([], { req: true });
      const prop = cls?.props.get(name);
      if (
        cls !== null &&
        prop !== undefined &&
        prop.value !== null &&
        !prop.isPublic &&
        !cls.reassigned.has(name)
      ) {
        const value = constantValue(prop.value, cls);
        if (!hasDynamic(value)) {
          return inferred("property initialised with a literal and not reassigned in this class");
        }
      }
      return unknown(`property ${name}`);
    }
    return unknown(`property ${name}`);
  }

  function evaluate(rawNode: AstNode, env: Env, ctx: Ctx, depth: number): PV {
    steps += 1;
    if (steps > MAX_STEPS || depth > MAX_DEPTH) {
      incomplete = true;
      return unknown("(not analyzed)");
    }
    const node = unwrap(rawNode);
    switch (node.type) {
      case "string":
      case "nowdoc": {
        return constant(
          node.type === "nowdoc" ? text(node) : node.children.map((child) => text(child)).join(""),
        );
      }
      case "integer":
      case "float":
      case "boolean":
      case "null":
        return constant(text(node));
      case "encapsed_string":
        return interpolated(node, env, ctx, depth, "interpolated string");
      case "heredoc":
        return interpolated(node, env, ctx, depth, "heredoc");
      case "shell_command_expression": {
        const value = interpolated(node, env, ctx, depth, "backtick command");
        reportCommand(value, node.line, "backtick operator", "string");
        return unknown("command output");
      }
      case "variable_name": {
        const key = text(node);
        const known = env.get(key);
        if (known !== undefined) return known;
        if (REQUEST_SUPERGLOBALS.has(key)) return source(key);
        if (OTHER_SUPERGLOBALS.has(key)) return unknown(key);
        if (REQUEST_NAME.test(key)) return pv([], { req: true });
        return unknown(key);
      }
      case "dynamic_variable_name": {
        // `${name}` inside a string is `$name`; `$$name` is a variable variable.
        const inner = named(node)[0];
        if (inner !== undefined && inner.type === "name") {
          const key = `$${text(inner)}`;
          return env.get(key) ?? unknown(key);
        }
        if (inner !== undefined) evaluate(inner, env, ctx, depth + 1);
        return unknown("$$variable");
      }
      case "subscript_expression": {
        const [object, index] = named(node);
        if (object === undefined) return unknown("(subscript)");
        const key = normKey(node);
        if (key !== null && env.has(key)) {
          if (index !== undefined) evaluate(index, env, ctx, depth + 1);
          return env.get(key) as PV;
        }
        const indexValue = index === undefined ? pv() : evaluate(index, env, ctx, depth + 1);
        if (object.type === "variable_name") {
          const base = text(object);
          if (REQUEST_SUPERGLOBALS.has(base) && !env.has(base)) {
            return source(index !== undefined && index.type === "string" ? (key ?? base) : base);
          }
          if (base === "$_SERVER" && !env.has(base)) {
            const keyText =
              index !== undefined && index.type === "string" ? text(index).slice(1, -1) : null;
            return keyText === null || SERVER_INPUT_KEY.test(keyText)
              ? source(keyText === null ? "$_SERVER" : (key ?? "$_SERVER"))
              : unknown(key ?? "$_SERVER");
          }
        }
        const base = evaluate(object, env, ctx, depth + 1);
        if (base.req) return source(text(object));
        if (base.table && hasDynamic(indexValue)) {
          return inferred("value taken from a fixed allowlist table");
        }
        return { ...base, composed: false, shape: "", elems: null, table: false, req: false };
      }
      case "member_access_expression":
      case "nullsafe_member_access_expression": {
        const object = field(node, "object");
        const nameNode = field(node, "name");
        const key = normKey(node);
        if (key !== null && env.has(key)) return env.get(key) as PV;
        const base = object === undefined ? pv() : evaluate(object, env, ctx, depth + 1);
        const propName = nameNode === undefined ? "" : text(nameNode);
        if (nameNode !== undefined && nameNode.type !== "name")
          evaluate(nameNode, env, ctx, depth + 1);
        if (base.req) {
          return REQUEST_BAGS.has(propName) ? pv([], { req: true }) : source(key ?? propName);
        }
        if (isThis(object)) return propertyValue(object, propName, ctx.cls);
        if (hasDynamic(base))
          return { ...base, composed: false, shape: "", elems: null, table: false };
        return unknown(`property ${propName}`);
      }
      case "scoped_property_access_expression": {
        const nameNode = field(node, "name");
        const propName = nameNode === undefined ? "" : text(nameNode).replace(/^\$/, "");
        const scope = field(node, "scope");
        if (scope !== undefined && scope.type === "relative_scope") {
          return propertyValue(undefined, propName, ctx.cls, true);
        }
        return unknown(`property ${propName}`);
      }
      case "class_constant_access_expression": {
        const [scope, nameNode] = named(node);
        if (scope === undefined || nameNode === undefined) return unknown("(constant)");
        const constName = text(nameNode);
        if (constName === "class") return constant("class");
        const scopeName = scope.type === "relative_scope" ? "" : lastSegment(text(scope));
        const target =
          scopeName === "" || scopeName === ctx.cls?.name
            ? ctx.cls
            : (classes.get(scopeName) ?? null);
        const defined = target?.consts.get(constName);
        if (target !== null && defined !== undefined) return constantValue(defined, target);
        if (/^[A-Z][A-Z0-9_]*$/.test(constName)) {
          return inferred("constant-style name defined in another file");
        }
        return unknown(`constant ${constName}`);
      }
      case "name": {
        const constName = text(node);
        const defined = fileConsts.get(constName);
        if (defined !== undefined) return constantValue(defined, null);
        if (/^(?:PHP_|M_|E_|DIRECTORY_SEPARATOR$|PATH_SEPARATOR$|__\w+__$)/.test(constName)) {
          return constant(constName);
        }
        if (/^[A-Z][A-Z0-9_]*$/.test(constName)) {
          return inferred("constant-style name defined in another file");
        }
        return unknown(constName);
      }
      case "array_creation_expression":
        return arrayLiteral(node, env, ctx, depth);
      case "binary_expression": {
        const operator = operatorOf(node);
        if (operator === ".") {
          const operands = concatOperands(node);
          return join(
            "concatenation",
            operands.map((operand) => evaluate(operand, env, ctx, depth + 1)),
          );
        }
        const left = field(node, "left");
        const right = field(node, "right");
        const a = left === undefined ? pv() : evaluate(left, env, ctx, depth + 1);
        const b = right === undefined ? pv() : evaluate(right, env, ctx, depth + 1);
        if (operator === "??") return { ...union(a, b), shape: "fallback" };
        if (operator === "or" || operator === "||") return constant("0");
        if (BOOL_OPERATORS.has(operator)) return constant("0");
        return hasDynamic(a) || hasDynamic(b) ? inferred("arithmetic result") : constant("0");
      }
      case "unary_op_expression": {
        const argument = field(node, "argument") ?? named(node)[0];
        const value = argument === undefined ? pv() : evaluate(argument, env, ctx, depth + 1);
        return operatorOf(node) === "!" || !hasDynamic(value)
          ? constant("0")
          : inferred("arithmetic result");
      }
      case "update_expression":
        return constant("0");
      case "cast_expression": {
        const type = text(field(node, "type") ?? node).toLowerCase();
        const value = evaluate(field(node, "value") ?? named(node)[1] ?? node, env, ctx, depth + 1);
        if (/^(?:int|integer|float|double|real|bool|boolean)$/.test(type)) return constant("0");
        return value;
      }
      case "conditional_expression": {
        const condition = field(node, "condition");
        const body = field(node, "body");
        const alternative = field(node, "alternative");
        const test = condition === undefined ? pv() : evaluate(condition, env, ctx, depth + 1);
        const whenTrue = new Map(env);
        const whenFalse = new Map(env);
        if (condition !== undefined) {
          applyGuards(whenTrue, guardKeys(condition, true));
          applyGuards(whenFalse, guardKeys(condition, false));
        }
        const a = body === undefined ? test : evaluate(body, whenTrue, ctx, depth + 1);
        const b =
          alternative === undefined ? pv() : evaluate(alternative, whenFalse, ctx, depth + 1);
        return { ...union(a, b), shape: "conditional" };
      }
      case "match_expression": {
        const results: PV[] = [];
        const subject = field(node, "condition");
        if (subject !== undefined) evaluate(subject, env, ctx, depth + 1);
        const body = field(node, "body");
        for (const arm of body?.children ?? []) {
          const result = field(arm, "return_expression");
          if (result !== undefined) results.push(evaluate(result, env, ctx, depth + 1));
        }
        return { ...unionAll(results), shape: "match" };
      }
      case "assignment_expression":
      case "reference_assignment_expression": {
        const left = field(node, "left");
        const right = field(node, "right");
        const value = right === undefined ? pv() : evaluate(right, env, ctx, depth + 1);
        if (left !== undefined) assignTo(left, value, env, ctx, depth);
        return value;
      }
      case "augmented_assignment_expression": {
        const left = field(node, "left");
        const right = field(node, "right");
        const operator = operatorOf(node);
        const value = right === undefined ? pv() : evaluate(right, env, ctx, depth + 1);
        if (left === undefined) return value;
        const old = evaluate(left, env, ctx, depth + 1);
        let next: PV;
        if (operator === ".=") next = join("concatenation", [old, value]);
        else if (operator === "??=") next = union(old, value);
        else
          next =
            hasDynamic(old) || hasDynamic(value) ? inferred("arithmetic result") : constant("0");
        assignTo(left, next, env, ctx, depth);
        return next;
      }
      case "function_call_expression":
        return functionCall(node, env, ctx, depth);
      case "member_call_expression":
      case "nullsafe_member_call_expression":
        return memberCall(node, env, ctx, depth);
      case "scoped_call_expression":
        return scopedCall(node, env, ctx, depth);
      case "object_creation_expression":
        return objectCreation(node, env, ctx, depth);
      case "anonymous_function":
      case "arrow_function": {
        analyzeFunction(node, env, ctx, depth + 1, node.type === "arrow_function");
        return pv();
      }
      case "sequence_expression": {
        let last = pv();
        for (const child of named(node)) last = evaluate(child, env, ctx, depth + 1);
        return last;
      }
      case "include_expression":
      case "include_once_expression":
      case "require_expression":
      case "require_once_expression":
      case "throw_expression":
      case "exit_statement":
      case "yield_expression":
      case "await_expression": {
        for (const child of named(node)) evaluate(child, env, ctx, depth + 1);
        return unknown("(expression)");
      }
      case "anonymous_class": {
        const anonymous: Ctx = { cls: null };
        for (const member of field(node, "body")?.children ?? []) {
          if (member.type === "method_declaration") {
            analyzeFunction(member, new Map(), anonymous, depth + 1, false);
          }
        }
        return pv();
      }
      case "relative_scope":
      case "variadic_unpacking": {
        const inner = named(node)[0];
        return inner === undefined ? pv() : evaluate(inner, env, ctx, depth + 1);
      }
      case "array_element_initializer":
      case "argument":
        return unionAll(named(node).map((child) => evaluate(child, env, ctx, depth + 1)));
      default: {
        // Anything else: its parts are still evaluated, so sinks inside are found.
        for (const child of named(node)) evaluate(child, env, ctx, depth + 1);
        return unknown("(expression)");
      }
    }
  }

  function arrayLiteral(node: AstNode, env: Env, ctx: Ctx, depth: number): PV {
    const elems: PV[] = [];
    let spread = false;
    for (const element of node.children) {
      if (element.type !== "array_element_initializer") continue;
      const parts = named(element);
      const valueNode = parts[parts.length - 1];
      if (valueNode === undefined) continue;
      if (valueNode.type === "variadic_unpacking") {
        spread = true;
        elems.push(evaluate(valueNode, env, ctx, depth + 1));
        continue;
      }
      if (parts.length > 1) evaluate(parts[0] as AstNode, env, ctx, depth + 1);
      elems.push(evaluate(valueNode, env, ctx, depth + 1));
    }
    const leaves: Leaf[] = [];
    for (const elem of elems) addLeaves(leaves, elem.leaves);
    return pv(leaves, {
      shape: "array",
      arr: true,
      elems: spread ? null : elems,
      table: elems.length > 0 && elems.every((elem) => !hasDynamic(elem)),
    });
  }

  /** Targets of a destructuring pattern (`[$a, 'k' => $b]`, `list(...)`) or a single target. */
  function assignTargets(node: AstNode): AstNode[] {
    const out: AstNode[] = [];
    const stack: AstNode[] = [node];
    while (stack.length > 0) {
      const current = stack.pop() as AstNode;
      if (
        current.type === "list_literal" ||
        current.type === "array_creation_expression" ||
        current.type === "array_element_initializer" ||
        current.type === "pair"
      ) {
        for (const child of named(current)) stack.push(child);
      } else if (current.type === "by_ref") {
        const inner = named(current)[0];
        if (inner !== undefined) stack.push(inner);
      } else {
        out.push(current);
      }
    }
    return out;
  }

  function assignTo(left: AstNode, value: PV, env: Env, ctx: Ctx, depth: number): void {
    const target = unwrap(left);
    if (target.type === "list_literal" || target.type === "array_creation_expression") {
      for (const part of assignTargets(target)) {
        if (part.type === "string" || part.type === "integer") continue;
        assignTo(
          part,
          { ...value, elems: null, composed: false, table: false },
          env,
          ctx,
          depth + 1,
        );
      }
      return;
    }
    if (target.type === "variable_name") {
      const key = text(target);
      for (const existing of [...env.keys()]) {
        if (existing.startsWith(`${key}[`) || existing.startsWith(`${key}->`)) env.delete(existing);
      }
      env.set(key, stored(value));
      return;
    }
    if (target.type === "subscript_expression") {
      const [object, index] = named(target);
      if (index !== undefined) evaluate(index, env, ctx, depth + 1);
      const key = normKey(target);
      if (object !== undefined && object.type === "variable_name") {
        const base = text(object);
        const old = env.get(base) ?? pv();
        const leaves = [...old.leaves];
        addLeaves(leaves, stored(value).leaves);
        env.set(base, { ...old, leaves, table: false, elems: null });
      }
      if (key !== null && index !== undefined) env.set(key, stored(value));
      return;
    }
    if (
      target.type === "member_access_expression" ||
      target.type === "nullsafe_member_access_expression"
    ) {
      const key = normKey(target);
      if (key !== null) env.set(key, stored(value));
      return;
    }
    // Static properties and anything else: nothing to track.
  }

  // ---------------------------------------------------------------- guards

  const keyOf = (node: AstNode | undefined): string | null => {
    if (node === undefined) return null;
    const inner = unwrap(node);
    return inner.type === "variable_name" ||
      inner.type === "subscript_expression" ||
      inner.type === "member_access_expression"
      ? normKey(inner)
      : null;
  };

  const callArgs = (call: AstNode): AstNode[] => {
    const list = field(call, "arguments");
    return (list?.children ?? [])
      .filter((child) => child.type === "argument")
      .map((child) => named(child).find((part) => part.field !== "name"))
      .filter((child): child is AstNode => child !== undefined);
  };

  const isLiteral = (node: AstNode | undefined): boolean => {
    if (node === undefined) return false;
    const inner = unwrap(node);
    return (
      inner.type === "string" ||
      inner.type === "integer" ||
      inner.type === "float" ||
      inner.type === "boolean" ||
      (inner.type === "encapsed_string" &&
        !inner.children.some((c) => c.type !== "string_content" && c.type !== "escape_sequence"))
    );
  };

  /** Variables that passed an allowlist or validator check whenever `node` evaluates to `want`. */
  function guardKeys(rawNode: AstNode, want: boolean, depth = 0): string[] {
    if (depth > 60) return [];
    const node = unwrap(rawNode);
    if (node.type === "unary_op_expression" && operatorOf(node) === "!") {
      const argument = field(node, "argument") ?? named(node)[0];
      return argument === undefined ? [] : guardKeys(argument, !want, depth + 1);
    }
    if (node.type === "binary_expression") {
      const operator = operatorOf(node);
      const left = field(node, "left");
      const right = field(node, "right");
      if (left === undefined || right === undefined) return [];
      if (operator === "&&" || operator === "and" || operator === "||" || operator === "or") {
        const isAnd = operator === "&&" || operator === "and";
        const a = guardKeys(left, want, depth + 1);
        const b = guardKeys(right, want, depth + 1);
        // `a && b` true: both held. `a || b` false: both were false. Otherwise only what both give.
        return isAnd === want ? [...new Set([...a, ...b])] : a.filter((key) => b.includes(key));
      }
      if (operator === "===" || operator === "==" || operator === "!==" || operator === "!=") {
        const positive = operator === "===" || operator === "==";
        const variable = isLiteral(right) ? left : isLiteral(left) ? right : undefined;
        const other = variable === left ? right : left;
        // `filter_var(...) === false`: false means the value passed.
        const fn = unwrap(variable === undefined ? left : variable);
        if (
          variable === undefined ||
          (fn.type === "function_call_expression" && other !== undefined)
        ) {
          const call =
            unwrap(left).type === "function_call_expression" ? unwrap(left) : unwrap(right);
          const against = call === unwrap(left) ? right : left;
          const callName = calleeName(field(call, "function"));
          if (
            callName === "filter_var" &&
            unwrap(against).type === "boolean" &&
            text(unwrap(against)).toLowerCase() === "false"
          ) {
            const [subject, filter] = callArgs(call);
            const passes = positive ? !want : want;
            if (passes && filter !== undefined && FILTER_NUMERIC.test(text(filter))) {
              const key = keyOf(subject);
              return key === null ? [] : [key];
            }
          }
          if (variable === undefined) return [];
        }
        if (positive === want) {
          const key = keyOf(variable);
          return key === null ? [] : [key];
        }
        return [];
      }
      return [];
    }
    if (node.type === "function_call_expression" && want) {
      const name = calleeName(field(node, "function"));
      const args = callArgs(node);
      if (name === null) return [];
      if (name === "in_array") {
        const key = keyOf(args[0]);
        return key === null ? [] : [key];
      }
      if (CTYPE_FUNCTIONS.has(name)) {
        const key = keyOf(args[0]);
        return key === null ? [] : [key];
      }
      if (name === "array_key_exists" || name === "key_exists") {
        const key = keyOf(args[0]);
        return key === null ? [] : [key];
      }
      if (name === "isset") {
        // `isset($allowed[$x])`: $x is a key of a table.
        const out: string[] = [];
        for (const argument of args) {
          const inner = unwrap(argument);
          if (inner.type === "subscript_expression") {
            const [, index] = named(inner);
            const key = keyOf(index);
            if (key !== null && index !== undefined && !isLiteral(index)) out.push(key);
          }
        }
        return out;
      }
      if (name === "preg_match" || name === "preg_match_all") {
        const pattern = args[0] === undefined ? "" : text(unwrap(args[0]));
        if (
          /^['"](.)\^.*\$\1[a-zA-Z]*['"]$/s.test(pattern) ||
          /^['"](.)\^.*\\z\1[a-zA-Z]*['"]$/s.test(pattern)
        ) {
          const key = keyOf(args[1]);
          return key === null ? [] : [key];
        }
        return [];
      }
      if (name === "filter_var") {
        const filter = args[1];
        if (filter !== undefined && FILTER_NUMERIC.test(text(filter))) {
          const key = keyOf(args[0]);
          return key === null ? [] : [key];
        }
        return [];
      }
      if (VALIDATOR_NAME.test(name)) {
        for (const argument of args) {
          const key = keyOf(argument);
          if (key !== null) return [key];
        }
      }
      return [];
    }
    if (node.type === "member_call_expression" || node.type === "scoped_call_expression") {
      const nameNode = field(node, "name");
      if (want && nameNode !== undefined && VALIDATOR_NAME.test(text(nameNode))) {
        for (const argument of callArgs(node)) {
          const key = keyOf(argument);
          if (key !== null) return [key];
        }
      }
    }
    return [];
  }

  function applyGuards(env: Env, keys: readonly string[]): void {
    for (const key of keys) {
      const known = env.get(key);
      const why = "value checked against an allowlist or validator";
      if (known === undefined) {
        env.set(key, inferred(why));
        continue;
      }
      env.set(key, {
        ...known,
        leaves: known.leaves.map((leaf): Leaf =>
          leaf.k === "const" || leaf.k === "inferred" ? leaf : { k: "inferred", why },
        ),
        opaque: "",
        req: false,
      });
    }
  }

  // ---------------------------------------------------------------- statements

  function mergeEnvs(a: Env, b: Env): Env {
    const out: Env = new Map();
    for (const [key, value] of a) {
      const other = b.get(key);
      out.set(key, other === undefined ? value : union(value, other));
    }
    for (const [key, value] of b) if (!a.has(key)) out.set(key, value);
    return out;
  }

  function replaceEnv(target: Env, source: Env): void {
    target.clear();
    for (const [key, value] of source) target.set(key, value);
  }

  const isExitStatement = (node: AstNode): Exit => {
    switch (node.type) {
      case "return_statement":
      case "exit_statement":
      case "continue_statement":
        return "exit";
      case "break_statement":
        return "break";
      case "expression_statement": {
        const inner = named(node)[0];
        if (inner === undefined) return null;
        const call = unwrap(inner);
        if (call.type === "throw_expression") return "exit";
        if (call.type === "function_call_expression") {
          const name = calleeName(field(call, "function"));
          if (name !== null && EXIT_FUNCTIONS.has(name)) {
            // `abort_if($x, 404)` only exits when the condition holds.
            return name === "abort_if" || name === "abort_unless" ? null : "exit";
          }
        }
        return null;
      }
      default:
        return null;
    }
  };

  function block(node: AstNode | undefined, env: Env, ctx: Ctx, depth: number): Exit {
    if (node === undefined) return null;
    if (
      node.type === "compound_statement" ||
      node.type === "colon_block" ||
      node.type === "declaration_list" ||
      node.type === "program"
    ) {
      for (const child of node.children) {
        if (child.anonymous) continue;
        const exit = statement(child, env, ctx, depth);
        if (exit !== null) return exit;
      }
      return null;
    }
    return statement(node, env, ctx, depth);
  }

  function ifChain(
    condition: AstNode | undefined,
    body: AstNode | undefined,
    rest: AstNode[],
    env: Env,
    ctx: Ctx,
    depth: number,
  ): Exit {
    if (condition !== undefined) evaluate(condition, env, ctx, depth + 1);
    const thenEnv: Env = new Map(env);
    const elseEnv: Env = new Map(env);
    if (condition !== undefined) {
      applyGuards(thenEnv, guardKeys(condition, true));
      applyGuards(elseEnv, guardKeys(condition, false));
    }
    const thenExit = block(body, thenEnv, ctx, depth + 1);
    let elseExit: Exit = null;
    const next = rest[0];
    if (next !== undefined) {
      if (next.type === "else_if_clause") {
        elseExit = ifChain(
          field(next, "condition"),
          field(next, "body"),
          rest.slice(1),
          elseEnv,
          ctx,
          depth + 1,
        );
      } else {
        elseExit = block(field(next, "body") ?? named(next)[0], elseEnv, ctx, depth + 1);
      }
    }
    if (thenExit !== null && elseExit !== null) {
      replaceEnv(env, mergeEnvs(thenEnv, elseEnv));
      return thenExit === "exit" && elseExit === "exit" ? "exit" : "break";
    }
    if (thenExit !== null) replaceEnv(env, elseEnv);
    else if (elseExit !== null) replaceEnv(env, thenEnv);
    else replaceEnv(env, mergeEnvs(thenEnv, elseEnv));
    return null;
  }

  function loop(
    body: AstNode | undefined,
    prepare: (env: Env) => void,
    env: Env,
    ctx: Ctx,
    depth: number,
  ): void {
    loopDepth += 1;
    try {
      const before: Env = new Map(env);
      const passes = loopDepth <= MAX_LOOP_NESTING ? 2 : 1;
      if (passes === 1) incomplete = true;
      const inner: Env = new Map(env);
      for (let pass = 0; pass < passes; pass += 1) {
        prepare(inner);
        block(body, inner, ctx, depth + 1);
      }
      replaceEnv(env, mergeEnvs(before, inner));
    } finally {
      loopDepth -= 1;
    }
  }

  function statement(node: AstNode, env: Env, ctx: Ctx, depth: number): Exit {
    steps += 1;
    if (steps > MAX_STEPS || depth > MAX_DEPTH) {
      incomplete = true;
      return null;
    }
    switch (node.type) {
      case "expression_statement": {
        for (const child of named(node)) evaluate(child, env, ctx, depth + 1);
        // `check($x) or die(...)`: afterwards the check held.
        const only = named(node)[0];
        const inner = only === undefined ? undefined : unwrap(only);
        if (inner !== undefined && inner.type === "binary_expression") {
          const operator = operatorOf(inner);
          const right = field(inner, "right");
          const left = field(inner, "left");
          if (
            (operator === "or" || operator === "||") &&
            left !== undefined &&
            right !== undefined
          ) {
            const tail = unwrap(right);
            const exits =
              tail.type === "throw_expression" ||
              tail.type === "exit_statement" ||
              (tail.type === "function_call_expression" &&
                EXIT_FUNCTIONS.has(calleeName(field(tail, "function")) ?? ""));
            if (exits) applyGuards(env, guardKeys(left, true));
          }
        }
        return isExitStatement(node);
      }
      case "return_statement":
      case "exit_statement":
      case "echo_statement": {
        for (const child of named(node)) evaluate(child, env, ctx, depth + 1);
        return isExitStatement(node);
      }
      case "break_statement":
      case "continue_statement":
        return isExitStatement(node);
      case "compound_statement":
      case "colon_block":
        return block(node, env, ctx, depth);
      case "if_statement": {
        const alternatives = node.children.filter((child) => child.field === "alternative");
        return ifChain(
          field(node, "condition"),
          field(node, "body"),
          alternatives,
          env,
          ctx,
          depth,
        );
      }
      case "while_statement": {
        const condition = field(node, "condition");
        loop(
          field(node, "body"),
          (inner) => {
            if (condition !== undefined) evaluate(condition, inner, ctx, depth + 1);
          },
          env,
          ctx,
          depth,
        );
        return null;
      }
      case "do_statement": {
        const condition = field(node, "condition");
        loop(
          field(node, "body"),
          (inner) => {
            if (condition !== undefined) evaluate(condition, inner, ctx, depth + 1);
          },
          env,
          ctx,
          depth,
        );
        return null;
      }
      case "for_statement": {
        const init = field(node, "initialize");
        if (init !== undefined) evaluate(init, env, ctx, depth + 1);
        const condition = field(node, "condition");
        const update = field(node, "update");
        loop(
          field(node, "body"),
          (inner) => {
            if (condition !== undefined) evaluate(condition, inner, ctx, depth + 1);
            if (update !== undefined) evaluate(update, inner, ctx, depth + 1);
          },
          env,
          ctx,
          depth,
        );
        return null;
      }
      case "foreach_statement": {
        const body = field(node, "body");
        const parts = named(node).filter((child) => child !== body);
        const iterable = parts[0];
        const target = parts[1];
        const items = iterable === undefined ? pv() : evaluate(iterable, env, ctx, depth + 1);
        loop(
          body,
          (inner) => {
            if (target === undefined) return;
            const element = {
              ...stored(items),
              composed: false,
              elems: null,
              table: false,
              shape: "",
            };
            for (const part of assignTargets(target)) {
              if (part.type === "string") continue;
              assignTo(part, element, inner, ctx, depth + 1);
            }
          },
          env,
          ctx,
          depth,
        );
        return null;
      }
      case "switch_statement": {
        const condition = field(node, "condition");
        if (condition !== undefined) evaluate(condition, env, ctx, depth + 1);
        const subjectKey = condition === undefined ? null : keyOf(named(condition)[0] ?? condition);
        const blockNode = field(node, "body");
        const arms: Env[] = [];
        let hasDefault = false;
        for (const arm of blockNode?.children ?? []) {
          if (arm.type !== "case_statement" && arm.type !== "default_statement") continue;
          const armEnv: Env = new Map(env);
          if (arm.type === "default_statement") hasDefault = true;
          else {
            const value = field(arm, "value");
            if (value !== undefined) {
              evaluate(value, armEnv, ctx, depth + 1);
              if (subjectKey !== null && isLiteral(value)) applyGuards(armEnv, [subjectKey]);
            }
          }
          let exit: Exit = null;
          for (const child of arm.children) {
            if (child.anonymous || child.field === "value") continue;
            exit = statement(child, armEnv, ctx, depth + 1);
            if (exit !== null) break;
          }
          if (exit !== "exit") arms.push(armEnv);
        }
        const all = hasDefault ? arms : [...arms, new Map(env)];
        if (all.length > 0) replaceEnv(env, all.reduce(mergeEnvs));
        return null;
      }
      case "try_statement": {
        const before: Env = new Map(env);
        const bodyExit = block(field(node, "body"), env, ctx, depth + 1);
        const afterBody: Env = new Map(env);
        const outcomes: Env[] = bodyExit === "exit" ? [] : [afterBody];
        let allExit = bodyExit === "exit";
        for (const clause of node.children) {
          if (clause.type !== "catch_clause") continue;
          const catchEnv = mergeEnvs(before, afterBody);
          const variable = field(clause, "name");
          if (variable !== undefined) catchEnv.set(text(variable), unknown("exception"));
          const exit = block(field(clause, "body"), catchEnv, ctx, depth + 1);
          if (exit !== "exit") {
            outcomes.push(catchEnv);
            allExit = false;
          }
        }
        replaceEnv(env, outcomes.length > 0 ? outcomes.reduce(mergeEnvs) : afterBody);
        const finalClause = node.children.find((child) => child.type === "finally_clause");
        if (finalClause !== undefined)
          block(field(finalClause, "body") ?? named(finalClause)[0], env, ctx, depth + 1);
        return allExit ? "exit" : null;
      }
      case "function_definition":
        analyzeFunction(node, env, ctx, depth + 1, false);
        return null;
      case "class_declaration":
      case "trait_declaration":
      case "enum_declaration":
      case "interface_declaration":
        analyzeClass(node, depth + 1);
        return null;
      case "namespace_definition": {
        const body = field(node, "body");
        if (body !== undefined) block(body, env, ctx, depth + 1);
        return null;
      }
      case "global_declaration":
      case "function_static_declaration":
      case "static_variable_declaration":
      case "const_declaration":
      case "namespace_use_declaration":
      case "declare_statement":
      case "unset_statement":
        if (node.type === "global_declaration") {
          for (const variable of named(node)) {
            if (variable.type === "variable_name") env.set(text(variable), unknown(text(variable)));
          }
        } else if (node.type === "function_static_declaration") {
          for (const declaration of named(node)) {
            const variable = field(declaration, "name");
            if (variable !== undefined) env.set(text(variable), unknown(text(variable)));
          }
        } else if (node.type === "unset_statement") {
          for (const variable of named(node)) {
            if (variable.type === "variable_name") env.delete(text(variable));
          }
        }
        return null;
      case "php_tag":
      case "text":
      case "text_interpolation":
      case "php_end_tag":
      case "comment":
        return null;
      default: {
        // Unknown statement kinds still have their expressions evaluated (sinks inside count).
        for (const child of named(node)) {
          if (child.type.endsWith("_statement") || child.type === "compound_statement") {
            statement(child, env, ctx, depth + 1);
          } else {
            evaluate(child, env, ctx, depth + 1);
          }
        }
        return null;
      }
    }
  }

  // ---------------------------------------------------------------- functions and classes

  function typeText(parameter: AstNode): string {
    const type = field(parameter, "type");
    return type === undefined ? "" : text(type).replace(/^\?/, "").trim();
  }

  function analyzeFunction(
    node: AstNode,
    outer: Env,
    ctx: Ctx,
    depth: number,
    isArrow: boolean,
  ): void {
    const env: Env = new Map();
    if (isArrow) for (const [key, value] of outer) env.set(key, value);
    const use = node.children.find((child) => child.type === "anonymous_function_use_clause");
    for (const variable of use?.children ?? []) {
      if (variable.type !== "variable_name") continue;
      const key = text(variable);
      env.set(key, outer.get(key) ?? unknown(key));
    }
    const params = field(node, "parameters");
    for (const parameter of params?.children ?? []) {
      if (
        parameter.type !== "simple_parameter" &&
        parameter.type !== "variadic_parameter" &&
        parameter.type !== "property_promotion_parameter"
      ) {
        continue;
      }
      const nameNode = field(parameter, "name");
      if (nameNode === undefined) continue;
      const key = text(nameNode);
      const type = typeText(parameter);
      const bare = type.replace(/^\\/, "");
      let value: PV;
      if (REQUEST_TYPE.test(bare) || (type === "" && REQUEST_NAME.test(key))) {
        value = pv([], { req: true });
      } else if (/^(?:int|float|bool|integer)$/i.test(type)) {
        value = inferred(`numeric type ${type.toLowerCase()}`);
      } else if (DB_TYPE.test(type)) {
        value = pv([], { db: true });
      } else {
        value = unknown(key);
      }
      env.set(key, value);
    }
    const body = field(node, "body");
    if (body === undefined) return;
    if (isArrow) evaluate(body, env, ctx, depth + 1);
    else block(body, env, ctx, depth + 1);
  }

  function analyzeClass(node: AstNode, depth: number): void {
    const nameNode = field(node, "name");
    const info = nameNode === undefined ? undefined : classes.get(text(nameNode));
    const ctx: Ctx = { cls: info ?? null };
    const body = field(node, "body");
    for (const member of body?.children ?? []) {
      if (member.type === "method_declaration") {
        analyzeFunction(member, new Map(), ctx, depth + 1, false);
      } else if (member.type === "property_declaration") {
        for (const element of member.children) {
          if (element.type !== "property_element") continue;
          const initial = field(element, "default_value");
          if (initial !== undefined) evaluate(initial, new Map(), ctx, depth + 1);
        }
      }
    }
  }

  // ---------------------------------------------------------------- libraries

  const libraries: Array<{ label: string; kind: "sql" | "process" }> = [];

  return run();

  function run(): PhpAnalysis {
    const env: Env = new Map();
    const ctx: Ctx = { cls: null };
    // The file's top-level code is one scope. Function and class bodies are analyzed where they
    // are declared, each with its own scope.
    block(ast.root, env, ctx, 0);
    for (const library of UNSUPPORTED_LIBRARIES) {
      if (library.pattern.test(src)) libraries.push({ label: library.label, kind: library.kind });
    }
    return {
      findings: [...findings.values()]
        .map(({ rank: _rank, ...finding }) => finding)
        .sort((a, b) => a.line - b.line),
      incomplete,
      unsupported: [...unsupported],
      libraries,
    };
  }
}
