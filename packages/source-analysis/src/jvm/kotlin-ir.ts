import type {
  Annotation,
  ClassInfo,
  Expr,
  FieldInfo,
  LambdaExpr,
  MethodInfo,
  ParamInfo,
  Stmt,
  Unit,
} from "./ir.js";
import { unescapeText } from "./java-ir.js";
import { SQL_CALL_TEXT } from "./jvm-names.js";
import { OS_CALL_TEXT } from "./os-names.js";
import { CRYPTO_CALL_TEXT } from "./crypto-names.js";
import { WEB_CALL_TEXT } from "./web-names.js";
import { textOf, type AstNode, type AstResult } from "./tree.js";

const MAX_DEPTH = 700;
const IDENT_START = /^([A-Za-z_][A-Za-z0-9_]*)([\s\S]*)$/;
const TYPE_NODE = /(?:^|_)type$/;
const NON_INIT = new Set([
  "modifiers",
  "variable_declaration",
  "multi_variable_declaration",
  "property_delegate",
  "getter",
  "setter",
  "type_constraints",
  "type_parameters",
  "user_type",
  "nullable_type",
  "function_type",
  "label",
]);

/** `return`, `return@label` or `throw` at the start of a Kotlin jump expression; `break` and `continue` are not jumps out of a block. */
function jumpOf(source: string): { kind: "return" | "throw"; label: string | null } | null {
  const match = /^(return|throw)(?:@([A-Za-z_][A-Za-z0-9_]*))?(?![A-Za-z0-9_@])/.exec(source);
  return match === null ? null : { kind: match[1] as "return" | "throw", label: match[2] ?? null };
}

export function convertKotlin(ast: AstResult): Unit {
  let incomplete = false;
  const text = (node: AstNode): string => textOf(ast, node);
  const named = (node: AstNode, field: string): AstNode | undefined =>
    node.children.find((child) => child.field === field);
  const ofType = (node: AstNode, type: string): AstNode | undefined =>
    node.children.find((child) => child.type === type);
  const opOf = (node: AstNode): string =>
    node.children.find((child) => child.anonymous)?.type ?? "";
  const nonAnon = (node: AstNode): AstNode[] => node.children.filter((child) => !child.anonymous);
  const simple = (name: string): string => name.slice(name.lastIndexOf(".") + 1);

  const newClass = (name: string, parent: ClassInfo | null, isEnum = false): ClassInfo => ({
    name,
    isEnum,
    enumConstants: [],
    fields: new Map(),
    methods: [],
    initializers: [],
    parent,
    supers: [],
  });
  const unit: Unit = {
    language: "kotlin",
    classes: [],
    top: newClass("", null),
    imports: [],
    aliases: new Map(),
    incomplete: false,
    unsupported: [],
  };

  // ---- expressions ----

  const other = (node: AstNode, depth: number): Expr => ({
    k: "other",
    line: node.line,
    kids: nonAnon(node).map((child) => expr(child, depth + 1)),
  });

  /** Parts of a template: literal text and the expressions between it. */
  function template(node: AstNode, depth: number): Array<string | Expr> {
    const parts: Array<string | Expr> = [];
    const kids = node.children;
    for (let i = 0; i < kids.length; i += 1) {
      const child = kids[i] as AstNode;
      if (child.type === "string_content") {
        const value = text(child);
        const next = kids[i + 1];
        // The grammar leaves a simple `$name` as the content "$" followed by content that starts
        // with the name; read it as the template entry it is.
        if (value === "$" && next?.type === "string_content") {
          const match = IDENT_START.exec(text(next));
          if (match !== null) {
            parts.push({ k: "id", line: next.line, name: match[1] as string });
            if (match[2] !== "") parts.push(match[2] as string);
            i += 1;
            continue;
          }
        }
        parts.push(value);
      } else if (child.type === "escape_sequence") {
        parts.push(unescapeText(text(child)));
      } else if (child.type === "interpolation") {
        const inner = nonAnon(child)[0];
        if (inner === undefined) continue;
        if (inner.type === "character_literal") {
          // `${'$'}` is the idiom for a literal dollar sign in a template.
          parts.push(unescapeText(text(inner).slice(1, -1)));
        } else {
          parts.push(expr(inner, depth + 1));
        }
      }
    }
    return parts;
  }

  function argsOf(
    node: AstNode | undefined,
    depth: number,
  ): Array<{ name: string | null; value: Expr }> {
    const out: Array<{ name: string | null; value: Expr }> = [];
    for (const arg of node?.children ?? []) {
      if (arg.type !== "value_argument") continue;
      const kids = nonAnon(arg);
      const hasName = arg.children.some((child) => child.anonymous && child.type === "=");
      const value = kids[hasName ? 1 : 0];
      if (value === undefined) continue;
      out.push({
        name: hasName && kids[0] !== undefined ? text(kids[0]) : null,
        value: expr(value, depth + 1),
      });
    }
    return out;
  }

  function lambda(node: AstNode, depth: number): LambdaExpr {
    const literal = node.type === "lambda_literal" ? node : ofType(node, "lambda_literal");
    const params: string[] = [];
    const body: Stmt[] = [];
    for (const child of literal?.children ?? []) {
      if (child.type === "lambda_parameters") {
        for (const declaration of child.children) {
          const id = ofType(declaration, "identifier");
          if (id !== undefined) params.push(text(id));
        }
      } else if (!child.anonymous) {
        body.push(...stmt(child, depth + 1));
      }
    }
    return { k: "lambda", line: node.line, params, body };
  }

  function call(node: AstNode, depth: number): Expr {
    const kids = nonAnon(node);
    const callee = kids[0];
    if (callee === undefined) return other(node, depth);
    const argNode = ofType(node, "value_arguments");
    const args = argsOf(argNode, depth).map((arg) => arg.value);
    const lambdas: LambdaExpr[] = [];
    for (const child of node.children) {
      if (child.type === "annotated_lambda") {
        const value = lambda(child, depth + 1);
        lambdas.push(value);
        args.push(value);
      }
    }
    // `f(a) { ... }` and `x.f(a) { ... }`: the call `f(a)` with the lambda as its last argument.
    if (callee.type === "call_expression" && argNode === undefined && lambdas.length > 0) {
      const inner = call(callee, depth + 1);
      if (inner.k === "call") {
        return {
          ...inner,
          line: node.line,
          args: [...inner.args, ...lambdas],
          lambdas: [...inner.lambdas, ...lambdas],
        };
      }
    }
    if (callee.type === "navigation_expression") {
      const parts = nonAnon(callee);
      const obj = parts[0];
      const member = parts[parts.length - 1];
      if (obj !== undefined && member !== undefined && member.type === "identifier") {
        return {
          k: "call",
          line: node.line,
          recv: expr(obj, depth + 1),
          name: text(member),
          args,
          lambdas,
        };
      }
    }
    if (callee.type === "identifier") {
      return { k: "call", line: node.line, recv: null, name: text(callee), args, lambdas };
    }
    // `f(a) { ... }`, `x.query(sql) { ... }`: a call on the result of another call.
    return {
      k: "call",
      line: node.line,
      recv: expr(callee, depth + 1),
      name: "invoke",
      args,
      lambdas,
    };
  }

  function bodyValue(node: AstNode, depth: number): Expr {
    if (node.type === "block") {
      const last = nonAnon(node).at(-1);
      return last === undefined ? { k: "lit", line: node.line } : bodyValue(last, depth + 1);
    }
    return expr(node, depth + 1);
  }

  function expr(node: AstNode, depth = 0): Expr {
    if (depth > MAX_DEPTH) {
      incomplete = true;
      return { k: "other", line: node.line, kids: [] };
    }
    const line = node.line;
    switch (node.type) {
      case "string_literal":
      case "multiline_string_literal": {
        const parts = template(node, depth);
        if (parts.every((part) => typeof part === "string")) {
          return { k: "str", line, text: parts.join("") };
        }
        return { k: "tmpl", line, parts };
      }
      case "identifier":
        return { k: "id", line, name: text(node) };
      case "this_expression":
        return { k: "id", line, name: "this" };
      case "parenthesized_expression": {
        const inner = nonAnon(node)[0];
        return inner === undefined ? { k: "lit", line } : expr(inner, depth + 1);
      }
      case "navigation_expression": {
        const parts = nonAnon(node);
        const obj = parts[0];
        const member = parts[parts.length - 1];
        if (obj === undefined || member === undefined || parts.length < 2)
          return other(node, depth);
        if (member.type !== "identifier") return other(node, depth);
        return { k: "member", line, obj: expr(obj, depth + 1), name: text(member) };
      }
      case "index_expression": {
        const parts = nonAnon(node);
        const obj = parts[0];
        const index = parts[1];
        if (obj === undefined || index === undefined) return other(node, depth);
        return { k: "index", line, obj: expr(obj, depth + 1), index: expr(index, depth + 1) };
      }
      case "call_expression":
        return call(node, depth);
      case "binary_expression":
      case "infix_expression": {
        // Iterative along the left spine (long `+` chains).
        const spine: AstNode[] = [];
        let current = node;
        const leftOf = (n: AstNode): AstNode | undefined =>
          n.type === "binary_expression" ? named(n, "left") : nonAnon(n)[0];
        while (
          (current.type === "binary_expression" || current.type === "infix_expression") &&
          leftOf(current) !== undefined &&
          spine.length < 100_000
        ) {
          spine.push(current);
          current = leftOf(current) as AstNode;
        }
        let value = expr(current, depth + 1);
        for (let i = spine.length - 1; i >= 0; i -= 1) {
          const step = spine[i] as AstNode;
          let op: string;
          let right: AstNode | undefined;
          if (step.type === "binary_expression") {
            op = opOf(step);
            right = named(step, "right");
          } else {
            const kids = nonAnon(step);
            op = kids[1] === undefined ? "" : text(kids[1]);
            right = kids[2];
          }
          value = {
            k: "bin",
            line: step.line,
            op,
            left: value,
            right: right === undefined ? { k: "lit", line: step.line } : expr(right, depth + 1),
          };
        }
        return value;
      }
      case "if_expression": {
        const test = named(node, "condition");
        const branches = nonAnon(node).filter(
          (child) => child !== test && child.field !== "condition",
        );
        const a = branches[0];
        const b = branches[1];
        if (test === undefined || a === undefined) return other(node, depth);
        return {
          k: "cond",
          line,
          test: expr(test, depth + 1),
          testText: text(test),
          a: bodyValue(a, depth + 1),
          b: b === undefined ? { k: "lit", line } : bodyValue(b, depth + 1),
        };
      }
      case "when_expression": {
        const options: Expr[] = [];
        for (const entry of node.children) {
          if (entry.type !== "when_entry") continue;
          const body = nonAnon(entry)
            .filter((child) => child.field !== "condition")
            .at(-1);
          if (body !== undefined) options.push(bodyValue(body, depth + 1));
        }
        return { k: "alt", line, options };
      }
      case "as_expression": {
        const left = named(node, "left");
        const right = named(node, "right");
        if (left === undefined) return other(node, depth);
        return {
          k: "cast",
          line,
          type: right === undefined ? "" : text(right),
          expr: expr(left, depth + 1),
        };
      }
      case "unary_expression": {
        const argument = named(node, "argument") ?? nonAnon(node).at(-1);
        // `x!!` keeps the value of `x`; `!x`, `-x` and `++x` are not text.
        if (opOf(node) === "!!" && argument !== undefined) return expr(argument, depth + 1);
        return { k: "lit", line };
      }
      case "lambda_literal":
      case "annotated_lambda":
        return lambda(node, depth);
      case "collection_literal":
        return { k: "array", line, elems: nonAnon(node).map((child) => expr(child, depth + 1)) };
      case "boolean_literal":
        return { k: "lit", line, raw: text(node) };
      case "number_literal":
        // The text of a number is kept (a cookie `maxAge = 0` clears the cookie).
        return { k: "lit", line, raw: text(node) };
      case "character_literal":
      case "null_literal":
      case "range_expression":
      case "in_expression":
      case "check_expression":
      case "comparison_expression":
      case "equality_expression":
      case "conjunction_expression":
      case "disjunction_expression":
        return { k: "lit", line };
      case "jump_expression":
      case "return_expression":
      case "throw_expression":
        // A `return` or `throw` inside an expression (`x ?: return@label`) leaves the block; a
        // `break` or `continue` only leaves a loop.
        return jumpOf(text(node)) === null
          ? { k: "lit", line }
          : { k: "lit", line, jump: jumpOf(text(node)) as NonNullable<ReturnType<typeof jumpOf>> };
      case "labeled_expression": {
        const inner = nonAnon(node).find((child) => child.type !== "label");
        return inner === undefined ? { k: "lit", line } : expr(inner, depth + 1);
      }
      case "spread_expression":
        return { ...(other(node, depth) as Extract<Expr, { k: "other" }>), spread: true };
      case "callable_reference":
        return other(node, depth);
      case "object_literal":
        if (
          SQL_CALL_TEXT.test(text(node)) ||
          OS_CALL_TEXT.test(text(node)) ||
          WEB_CALL_TEXT.test(text(node)) ||
          CRYPTO_CALL_TEXT.test(text(node))
        ) {
          unit.unsupported.push("anonymous object");
        }
        return other(node, depth);
      default:
        return other(node, depth);
    }
  }

  // ---- statements ----

  function annotationsOf(mods: AstNode | undefined, depth: number): Annotation[] {
    const out: Annotation[] = [];
    for (const child of mods?.children ?? []) {
      if (child.type !== "annotation") continue;
      const invocation = ofType(child, "constructor_invocation");
      const typeNode =
        invocation === undefined ? ofType(child, "user_type") : ofType(invocation, "user_type");
      if (typeNode === undefined) continue;
      const result: Annotation = {
        name: simple(text(typeNode)),
        value: null,
        named: new Map(),
        line: child.line,
      };
      for (const arg of argsOf(
        invocation === undefined ? undefined : ofType(invocation, "value_arguments"),
        depth,
      )) {
        if (arg.name === null) result.value ??= arg.value;
        else {
          result.named.set(arg.name, arg.value);
          if (arg.name === "value") result.value = arg.value;
        }
      }
      out.push(result);
    }
    return out;
  }

  const declType = (declaration: AstNode): string | null => {
    const type = declaration.children.find((child) => TYPE_NODE.test(child.type));
    return type === undefined ? null : text(type);
  };

  function property(node: AstNode, depth: number): Stmt[] {
    const mods = ofType(node, "modifiers");
    const declaration = ofType(node, "variable_declaration");
    const multi = ofType(node, "multi_variable_declaration");
    const keywordText = ast.source.slice(
      mods?.end ?? node.start,
      (declaration ?? multi)?.start ?? node.end,
    );
    const isFinal = /\bval\b/.test(keywordText);
    const initNode = nonAnon(node).find(
      (child) => !NON_INIT.has(child.type) && !TYPE_NODE.test(child.type),
    );
    const delegate = ofType(node, "property_delegate");
    if (multi !== undefined) {
      const source = initNode === undefined ? [] : [expr(initNode, depth + 1)];
      return multi.children
        .filter((child) => child.type === "variable_declaration")
        .map((child): Stmt => {
          const id = ofType(child, "identifier");
          return {
            s: "local",
            line: child.line,
            name: id === undefined ? "" : text(id),
            type: null,
            init: { k: "other", line: child.line, kids: source },
            isFinal,
          };
        });
    }
    if (declaration === undefined) return [];
    const id = ofType(declaration, "identifier");
    if (id === undefined) return [];
    let init: Expr | null = initNode === undefined ? null : expr(initNode, depth + 1);
    if (delegate !== undefined) init = { k: "other", line: node.line, kids: [] };
    const getter = ofType(node, "getter");
    if (getter !== undefined && init === null) init = { k: "other", line: node.line, kids: [] };
    return [
      {
        s: "local",
        line: node.line,
        name: text(id),
        type: declType(declaration),
        init,
        isFinal,
      },
    ];
  }

  function body(node: AstNode | undefined, depth: number): Stmt[] {
    if (node === undefined) return [];
    if (node.type === "block") return block(node, depth + 1);
    return stmt(node, depth + 1);
  }

  function block(node: AstNode, depth: number): Stmt[] {
    const out: Stmt[] = [];
    for (const child of nonAnon(node)) out.push(...stmt(child, depth + 1));
    return out;
  }

  function stmt(node: AstNode, depth = 0): Stmt[] {
    if (depth > MAX_DEPTH) {
      incomplete = true;
      return [];
    }
    const line = node.line;
    switch (node.type) {
      case "property_declaration":
        return property(node, depth);
      case "assignment": {
        const left = named(node, "left");
        const right = named(node, "right");
        if (left === undefined || right === undefined) return [];
        return [
          {
            s: "assign",
            line,
            target: expr(left, depth + 1),
            op: opOf(node) || "=",
            value: expr(right, depth + 1),
          },
        ];
      }
      case "if_expression": {
        const test = named(node, "condition");
        const branches = nonAnon(node).filter(
          (child) => child !== test && child.field !== "condition",
        );
        if (test === undefined) return [];
        return [
          {
            s: "if",
            line,
            test: expr(test, depth + 1),
            testText: text(test),
            then: body(branches[0], depth),
            else: branches[1] === undefined ? null : body(branches[1], depth),
          },
        ];
      }
      case "for_statement": {
        const kids = nonAnon(node).filter((child) => child.type !== "label");
        const variable = kids[0];
        const iter = kids[1];
        const loopBody = kids[2];
        const id = variable === undefined ? undefined : ofType(variable, "identifier");
        return [
          {
            s: "loop",
            line,
            init: [],
            test: null,
            update: [],
            each:
              iter === undefined
                ? null
                : {
                    name: id === undefined ? "" : text(id),
                    type: variable === undefined ? null : declType(variable),
                    iter: expr(iter, depth + 1),
                  },
            body: body(loopBody, depth),
          },
        ];
      }
      case "while_statement":
      case "do_while_statement": {
        const test = named(node, "condition");
        const loopBody = nonAnon(node).find((child) => child.type === "block");
        return [
          {
            s: "loop",
            line,
            init: [],
            test: test === undefined ? null : expr(test, depth + 1),
            update: [],
            each: null,
            body: body(loopBody, depth),
          },
        ];
      }
      case "try_expression": {
        const main = ofType(node, "block");
        const out: Stmt[] = [
          { s: "block", line, body: main === undefined ? [] : block(main, depth), params: [] },
        ];
        const arms: Array<{ params: string[]; body: Stmt[] }> = [];
        for (const child of node.children) {
          if (child.type === "catch_block") {
            const id = ofType(child, "identifier");
            const handler = ofType(child, "block");
            arms.push({
              params: id === undefined ? [] : [text(id)],
              body: handler === undefined ? [] : block(handler, depth),
            });
          } else if (child.type === "finally_block") {
            const handler = ofType(child, "block");
            arms.push({ params: [], body: handler === undefined ? [] : block(handler, depth) });
          }
        }
        if (arms.length > 0) out.push({ s: "arms", line, subject: null, arms });
        return out;
      }
      case "when_expression": {
        const subject = ofType(node, "when_subject");
        const subjectExpr = subject === undefined ? undefined : nonAnon(subject)[0];
        const arms: Array<{ params: string[]; body: Stmt[] }> = [];
        for (const entry of node.children) {
          if (entry.type !== "when_entry") continue;
          const armBody = nonAnon(entry)
            .filter((child) => child.field !== "condition")
            .at(-1);
          arms.push({ params: [], body: body(armBody, depth) });
        }
        return [
          {
            s: "arms",
            line,
            subject: subjectExpr === undefined ? null : expr(subjectExpr, depth + 1),
            arms,
          },
        ];
      }
      case "block":
        return [{ s: "block", line, body: block(node, depth), params: [] }];
      case "return_expression":
      case "throw_expression": {
        const inner = nonAnon(node)[0];
        return [
          {
            s: "exit",
            line,
            value: inner === undefined ? null : expr(inner, depth + 1),
            ...(node.type === "return_expression"
              ? {
                  ret: true,
                  ...(jumpOf(text(node))?.label
                    ? { label: jumpOf(text(node))?.label as string }
                    : {}),
                }
              : { throw: true }),
          },
        ];
      }
      case "labeled_expression": {
        const inner = nonAnon(node).find((child) => child.type !== "label");
        return inner === undefined ? [] : [{ s: "exit", line, value: null }];
      }
      case "function_declaration":
      case "class_declaration":
      case "object_declaration":
        // Local functions and classes are not followed.
        if (
          SQL_CALL_TEXT.test(text(node)) ||
          OS_CALL_TEXT.test(text(node)) ||
          WEB_CALL_TEXT.test(text(node)) ||
          CRYPTO_CALL_TEXT.test(text(node))
        ) {
          unit.unsupported.push(
            node.type === "function_declaration" ? "local function" : "local class",
          );
        }
        return [];
      case "call_expression": {
        const value = call(node, depth);
        // `require(c) { "message" }` is a call on the result of `require(c)`: look at the inner one.
        let inner = node;
        while (nonAnon(inner)[0]?.type === "call_expression") inner = nonAnon(inner)[0] as AstNode;
        const callee = nonAnon(inner)[0];
        // `require(...)`, `check(...)` and `assert(...)` state a condition the code relies on.
        if (
          (callee?.type === "identifier" &&
            ["require", "check", "assert", "checkArgument", "checkState"].includes(text(callee))) ||
          (callee?.type === "navigation_expression" &&
            /^(?:[\w.]+\.)?(?:Preconditions|Assert|Validate)\.(?:checkArgument|checkState|isTrue|state)$/.test(
              text(callee),
            ))
        ) {
          const argNode = ofType(inner, "value_arguments")?.children.find(
            (c) => c.type === "value_argument",
          );
          const arg = argsOf(ofType(inner, "value_arguments"), depth)[0];
          if (arg !== undefined && argNode !== undefined) {
            return [{ s: "assert", line, test: arg.value, testText: text(argNode) }];
          }
        }
        return [{ s: "expr", line, expr: value }];
      }
      default:
        return [{ s: "expr", line, expr: expr(node, depth + 1) }];
    }
  }

  // ---- declarations ----

  function parameters(node: AstNode | undefined, depth: number): ParamInfo[] {
    const out: ParamInfo[] = [];
    let pending: AstNode | undefined;
    for (const child of node?.children ?? []) {
      if (child.type === "parameter_modifiers") {
        pending = child;
      } else if (child.type === "parameter" || child.type === "class_parameter") {
        const id = ofType(child, "identifier");
        if (id !== undefined) {
          const mods = child.type === "class_parameter" ? ofType(child, "modifiers") : pending;
          out.push({
            name: text(id),
            type: declType(child) ?? "",
            annotations: annotationsOf(mods, depth),
          });
        }
        pending = undefined;
      }
    }
    return out;
  }

  const addField = (info: ClassInfo, field: FieldInfo): void => {
    info.fields.set(field.name, field);
  };

  function members(info: ClassInfo, node: AstNode | undefined, depth: number): void {
    for (const member of node?.children ?? []) {
      switch (member.type) {
        case "property_declaration": {
          const mods = ofType(member, "modifiers");
          const isConst = (mods?.children ?? []).some(
            (child) => child.type === "property_modifier" && text(child) === "const",
          );
          for (const declared of property(member, 0)) {
            if (declared.s !== "local") continue;
            addField(info, {
              name: declared.name,
              type: declared.type,
              isFinal: declared.isFinal,
              isStatic: false,
              isConst,
              isMutable: !declared.isFinal,
              overridable: /\b(?:open|abstract|override)\b/.test(
                mods === undefined ? "" : text(mods),
              ),
              init: declared.init,
              line: declared.line,
              annotations: annotationsOf(mods, 1),
            });
          }
          break;
        }
        case "function_declaration": {
          const nameNode = named(member, "name");
          const fnBody = ofType(member, "function_body");
          // An extension function reads its receiver's members without naming it (`writer.write(x)`):
          // the receiver's type is not followed, so web calls in the body are not analyzed.
          const receiverType =
            nameNode === undefined
              ? undefined
              : member.children.find(
                  (child) => TYPE_NODE.test(child.type) && child.start < nameNode.start,
                );
          // Only a servlet or HTTP client receiver, or a sink reached through the implicit `this`
          // (`writer.write(x)`, not `call.writer`), is lost; a Ktor `Application.module()` is not.
          if (
            receiverType !== undefined &&
            (/^(?:Http)?Servlet(?:Request|Response)\b|^HttpServlet\w*|^(?:URL|URI|HttpClient|WebClient|RestTemplate|OkHttpClient)\b/.test(
              text(receiverType),
            ) ||
              /(?<![.\w])(?:writer|outputStream|getWriter\(\)|getOutputStream\(\))/.test(
                text(member),
              ))
          ) {
            unit.unsupported.push("extension function");
          }
          let stmts: Stmt[] | null = null;
          if (fnBody !== undefined) {
            const inner = nonAnon(fnBody)[0];
            if (inner === undefined) stmts = [];
            else if (inner.type === "block") stmts = block(inner, 1);
            else stmts = [{ s: "exit", line: inner.line, value: expr(inner, 1), ret: true }];
          }
          info.methods.push({
            name: nameNode === undefined ? "" : text(nameNode),
            params: parameters(ofType(member, "function_value_parameters"), 0),
            annotations: annotationsOf(ofType(member, "modifiers"), 0),
            body: stmts,
            line: member.line,
            returnType: declType(member),
          } satisfies MethodInfo);
          break;
        }
        case "secondary_constructor": {
          const inner = ofType(member, "block");
          info.methods.push({
            name: "<init>",
            params: parameters(ofType(member, "function_value_parameters"), 0),
            annotations: [],
            body: inner === undefined ? [] : block(inner, 1),
            line: member.line,
          });
          break;
        }
        case "anonymous_initializer": {
          const inner = ofType(member, "block");
          if (inner !== undefined) info.initializers.push(...block(inner, 1));
          break;
        }
        case "companion_object": {
          // Members of a companion are reached as `Name.X` and unqualified from the class.
          members(info, ofType(member, "class_body"), depth + 1);
          break;
        }
        case "enum_entry": {
          const id = ofType(member, "identifier");
          if (id !== undefined) info.enumConstants.push(text(id));
          break;
        }
        case "class_declaration":
        case "object_declaration":
          declaration(member, info);
          break;
        default:
          break;
      }
    }
  }

  function declaration(node: AstNode, parent: ClassInfo | null): void {
    const nameNode = named(node, "name") ?? ofType(node, "identifier");
    const mods = ofType(node, "modifiers");
    const isEnum = (mods?.children ?? []).some(
      (child) => child.type === "class_modifier" && text(child) === "enum",
    );
    const info = newClass(nameNode === undefined ? "" : text(nameNode), parent, isEnum);
    info.annotations = annotationsOf(mods, 0);
    unit.classes.push(info);
    for (const specifiers of node.children) {
      if (specifiers.type !== "delegation_specifiers") continue;
      for (const specifier of specifiers.children) {
        const type = specifier.children.find((child) => child.type === "user_type");
        if (type !== undefined) info.supers.push(simple(text(type).replace(/<.*>/s, "")));
      }
    }
    const constructor = ofType(node, "primary_constructor");
    for (const parameter of parameters(
      constructor === undefined ? undefined : ofType(constructor, "class_parameters"),
      0,
    )) {
      addField(info, {
        name: parameter.name,
        type: parameter.type,
        isFinal: false,
        isStatic: false,
        isConst: false,
        isMutable: true,
        overridable: false,
        init: null,
        line: node.line,
        annotations: parameter.annotations,
      });
    }
    // The class parameters are also parameters of the primary constructor.
    members(info, ofType(node, "class_body") ?? ofType(node, "enum_class_body"), 1);
  }

  for (const child of ast.root.children) {
    if (child.type === "class_declaration" || child.type === "object_declaration") {
      declaration(child, null);
    } else if (child.type === "function_declaration" || child.type === "property_declaration") {
      members(unit.top, { ...ast.root, children: [child] }, 0);
    }
  }
  unit.incomplete = incomplete;
  return unit;
}
