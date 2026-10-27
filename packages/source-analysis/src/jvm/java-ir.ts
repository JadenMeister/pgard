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
import { SQL_CALL_TEXT } from "./jvm-names.js";
import { OS_CALL_TEXT } from "./os-names.js";
import { textOf, type AstNode, type AstResult } from "./tree.js";

/** Deepest nesting the converter follows; deeper code makes the unit `incomplete`. */
const MAX_DEPTH = 700;

const CLASS_KINDS = new Set([
  "class_declaration",
  "interface_declaration",
  "enum_declaration",
  "record_declaration",
  "annotation_type_declaration",
]);
const LITERAL_TYPES = new Set([
  "decimal_integer_literal",
  "hex_integer_literal",
  "octal_integer_literal",
  "binary_integer_literal",
  "decimal_floating_point_literal",
  "hex_floating_point_literal",
  "character_literal",
  "true",
  "false",
  "null_literal",
]);

const ESCAPES: Record<string, string> = {
  n: "\n",
  t: "\t",
  r: "\r",
  b: "\b",
  f: "\f",
  s: " ",
  '"': '"',
  "'": "'",
  "\\": "\\",
  $: "$",
};

/** Decodes the escape sequences that matter for SQL text (`\"`, `\\`, `\n`, `'`). */
export function unescapeText(raw: string): string {
  if (!raw.includes("\\")) return raw;
  return raw.replace(
    /\\(?:u+([0-9a-fA-F]{4})|([\s\S]))/g,
    (_match, hex?: string, char?: string) => {
      if (hex !== undefined) return String.fromCharCode(Number.parseInt(hex, 16));
      return char === undefined ? "" : (ESCAPES[char] ?? char);
    },
  );
}

export function convertJava(ast: AstResult): Unit {
  let incomplete = false;
  const text = (node: AstNode): string => textOf(ast, node);
  const named = (node: AstNode, field: string): AstNode | undefined =>
    node.children.find((child) => child.field === field);
  const all = (node: AstNode, field: string): AstNode[] =>
    node.children.filter((child) => child.field === field);
  const ofType = (node: AstNode, type: string): AstNode | undefined =>
    node.children.find((child) => child.type === type);
  const opOf = (node: AstNode): string =>
    node.children.find((child) => child.anonymous)?.type ?? "";
  const simple = (name: string): string => name.slice(name.lastIndexOf(".") + 1);

  const unit: Unit = {
    language: "java",
    classes: [],
    top: {
      name: "",
      isEnum: false,
      enumConstants: [],
      fields: new Map(),
      methods: [],
      initializers: [],
      parent: null,
      supers: [],
    },
    imports: [],
    aliases: new Map(),
    incomplete: false,
    unsupported: [],
  };

  // ---- expressions ----

  const other = (node: AstNode, depth: number): Expr => ({
    k: "other",
    line: node.line,
    kids: node.children.filter((child) => !child.anonymous).map((child) => expr(child, depth + 1)),
  });

  function stringText(node: AstNode): string {
    let out = "";
    for (const child of node.children) {
      if (child.type === "string_fragment" || child.type === "multiline_string_fragment") {
        out += text(child);
      } else if (child.type === "escape_sequence") {
        out += unescapeText(text(child));
      }
    }
    return out;
  }

  function lambda(node: AstNode, depth: number): LambdaExpr {
    const parameters = named(node, "parameters");
    const params: string[] = [];
    if (parameters?.type === "identifier") params.push(text(parameters));
    else if (parameters !== undefined) {
      for (const child of parameters.children) {
        if (child.type === "identifier") params.push(text(child));
        else if (child.type === "formal_parameter" || child.type === "spread_parameter") {
          const id = named(child, "name") ?? ofType(child, "variable_declarator");
          if (id !== undefined) params.push(text(named(id, "name") ?? id));
        }
      }
    }
    const body = named(node, "body");
    let stmts: Stmt[] = [];
    if (body?.type === "block") stmts = block(body, depth + 1);
    else if (body !== undefined) {
      stmts = [{ s: "expr", line: body.line, expr: expr(body, depth + 1) }];
    }
    return { k: "lambda", line: node.line, params, body: stmts };
  }

  function callArgs(
    node: AstNode | undefined,
    depth: number,
  ): { args: Expr[]; lambdas: LambdaExpr[] } {
    const args: Expr[] = [];
    const lambdas: LambdaExpr[] = [];
    for (const child of node?.children ?? []) {
      if (child.anonymous) continue;
      const value = expr(child, depth + 1);
      args.push(value);
      if (value.k === "lambda") lambdas.push(value);
    }
    return { args, lambdas };
  }

  function switchValues(node: AstNode, depth: number): Expr[] {
    const body = named(node, "body");
    const out: Expr[] = [];
    const visitStmt = (stmt: AstNode): void => {
      if (stmt.type === "expression_statement") {
        const inner = stmt.children.find((child) => !child.anonymous);
        if (inner !== undefined) out.push(expr(inner, depth + 1));
      } else if (stmt.type === "yield_statement") {
        const inner = stmt.children.find((child) => !child.anonymous);
        if (inner !== undefined) out.push(expr(inner, depth + 1));
      } else if (stmt.type === "block") {
        for (const inner of stmt.children) visitStmt(inner);
      }
    };
    for (const arm of body?.children ?? []) {
      for (const child of arm.children) {
        if (child.type !== "switch_label") visitStmt(child);
      }
    }
    return out;
  }

  function expr(node: AstNode, depth = 0): Expr {
    if (depth > MAX_DEPTH) {
      incomplete = true;
      return { k: "other", line: node.line, kids: [] };
    }
    const line = node.line;
    switch (node.type) {
      case "string_literal":
        return { k: "str", line, text: stringText(node) };
      case "identifier":
        return { k: "id", line, name: text(node) };
      case "this":
        return { k: "id", line, name: "this" };
      case "super":
        return { k: "id", line, name: "super" };
      case "parenthesized_expression": {
        const inner = node.children.find((child) => !child.anonymous);
        return inner === undefined ? { k: "lit", line } : expr(inner, depth + 1);
      }
      case "field_access": {
        const obj = named(node, "object");
        const field = named(node, "field");
        if (obj === undefined || field === undefined) return other(node, depth);
        return { k: "member", line, obj: expr(obj, depth + 1), name: text(field) };
      }
      case "array_access": {
        const arr = named(node, "array");
        const index = named(node, "index");
        if (arr === undefined || index === undefined) return other(node, depth);
        return { k: "index", line, obj: expr(arr, depth + 1), index: expr(index, depth + 1) };
      }
      case "method_invocation": {
        const nameNode = named(node, "name");
        if (nameNode === undefined) return other(node, depth);
        const obj = named(node, "object");
        const { args, lambdas } = callArgs(named(node, "arguments"), depth);
        return {
          k: "call",
          line,
          recv: obj === undefined ? null : expr(obj, depth + 1),
          name: text(nameNode),
          args,
          lambdas,
        };
      }
      case "object_creation_expression": {
        const type = named(node, "type");
        const { args } = callArgs(named(node, "arguments"), depth);
        const body = ofType(node, "class_body");
        if (
          body !== undefined &&
          (SQL_CALL_TEXT.test(text(body)) || OS_CALL_TEXT.test(text(body)))
        ) {
          unit.unsupported.push("anonymous class");
        }
        return { k: "new", line, type: type === undefined ? "" : text(type), args };
      }
      case "binary_expression": {
        // Iterative along the left spine: a long `+` chain must not recurse once per term.
        const spine: AstNode[] = [];
        let current = node;
        while (
          current.type === "binary_expression" &&
          named(current, "left") !== undefined &&
          spine.length < 100_000
        ) {
          spine.push(current);
          current = named(current, "left") as AstNode;
        }
        let value = expr(current, depth + 1);
        for (let i = spine.length - 1; i >= 0; i -= 1) {
          const step = spine[i] as AstNode;
          const right = named(step, "right");
          value = {
            k: "bin",
            line: step.line,
            op: opOf(step),
            left: value,
            right: right === undefined ? { k: "lit", line: step.line } : expr(right, depth + 1),
          };
        }
        return value;
      }
      case "ternary_expression": {
        const test = named(node, "condition");
        const a = named(node, "consequence");
        const b = named(node, "alternative");
        if (test === undefined || a === undefined || b === undefined) return other(node, depth);
        return {
          k: "cond",
          line,
          test: expr(test, depth + 1),
          testText: text(test),
          a: expr(a, depth + 1),
          b: expr(b, depth + 1),
        };
      }
      case "cast_expression": {
        const type = named(node, "type");
        const value = named(node, "value");
        if (value === undefined) return other(node, depth);
        return {
          k: "cast",
          line,
          type: type === undefined ? "" : text(type),
          expr: expr(value, depth + 1),
        };
      }
      case "switch_expression":
        return { k: "alt", line, options: switchValues(node, depth) };
      case "lambda_expression":
        return lambda(node, depth);
      case "array_initializer":
      case "element_value_array_initializer":
        return {
          k: "array",
          line,
          elems: node.children.filter((child) => !child.anonymous).map((c) => expr(c, depth + 1)),
        };
      case "array_creation_expression": {
        const init = ofType(node, "array_initializer");
        return init === undefined ? { k: "lit", line } : expr(init, depth + 1);
      }
      case "unary_expression":
      case "update_expression":
      case "instanceof_expression":
      case "class_literal":
        return { k: "lit", line };
      case "assignment_expression": {
        const right = named(node, "right");
        return right === undefined ? { k: "lit", line } : expr(right, depth + 1);
      }
      case "method_reference":
        // `sb::append`: the receiver is used, and can be changed through the reference.
        return other(node, depth);
      default:
        if (node.type === "true" || node.type === "false") {
          return { k: "lit", line, raw: node.type };
        }
        if (LITERAL_TYPES.has(node.type)) return { k: "lit", line };
        return other(node, depth);
    }
  }

  // ---- statements ----

  function modifierWords(mods: AstNode | undefined): string {
    if (mods === undefined) return "";
    let out = "";
    let at = mods.start;
    for (const child of mods.children) {
      if (child.type === "annotation" || child.type === "marker_annotation") {
        out += `${ast.source.slice(at, child.start)} `;
        at = child.end;
      }
    }
    return `${out}${ast.source.slice(at, mods.end)}`;
  }

  function annotations(mods: AstNode | undefined, depth: number): Annotation[] {
    const out: Annotation[] = [];
    for (const child of mods?.children ?? []) {
      if (child.type !== "annotation" && child.type !== "marker_annotation") continue;
      const nameNode = named(child, "name");
      if (nameNode === undefined) continue;
      const result: Annotation = {
        name: simple(text(nameNode)),
        value: null,
        named: new Map(),
        line: child.line,
      };
      for (const arg of named(child, "arguments")?.children ?? []) {
        if (arg.anonymous) continue;
        if (arg.type === "element_value_pair") {
          const key = named(arg, "key");
          const value = named(arg, "value");
          if (key === undefined || value === undefined) continue;
          const converted = expr(value, depth + 1);
          result.named.set(text(key), converted);
          if (text(key) === "value") result.value = converted;
        } else {
          result.value = expr(arg, depth + 1);
        }
      }
      out.push(result);
    }
    return out;
  }

  function localDeclaration(node: AstNode, depth: number): Stmt[] {
    const type = named(node, "type");
    const isFinal = /\bfinal\b/.test(modifierWords(ofType(node, "modifiers")));
    const out: Stmt[] = [];
    for (const declarator of all(node, "declarator")) {
      const name = named(declarator, "name");
      if (name === undefined) continue;
      const value = named(declarator, "value");
      out.push({
        s: "local",
        line: declarator.line,
        name: text(name),
        type: type === undefined ? null : text(type),
        init: value === undefined ? null : expr(value, depth + 1),
        isFinal,
      });
    }
    return out;
  }

  function branch(node: AstNode | undefined, depth: number): Stmt[] {
    if (node === undefined) return [];
    return node.type === "block" ? block(node, depth + 1) : stmt(node, depth + 1);
  }

  function block(node: AstNode, depth: number): Stmt[] {
    const out: Stmt[] = [];
    for (const child of node.children) out.push(...stmt(child, depth + 1));
    return out;
  }

  function armsOf(node: AstNode, depth: number): Stmt[] {
    const subject = named(node, "condition");
    const arms: Array<{ params: string[]; body: Stmt[] }> = [];
    for (const group of named(node, "body")?.children ?? []) {
      const body: Stmt[] = [];
      for (const child of group.children) {
        if (child.type === "switch_label") continue;
        if (group.type === "switch_rule" && child.type === "expression_statement") {
          const inner = child.children.find((c) => !c.anonymous);
          if (inner !== undefined) body.push(...stmt(child, depth + 1));
        } else {
          body.push(...stmt(child, depth + 1));
        }
      }
      arms.push({ params: [], body });
    }
    return [
      {
        s: "arms",
        line: node.line,
        subject: subject === undefined ? null : expr(subject, depth + 1),
        arms,
      },
    ];
  }

  function stmt(node: AstNode, depth = 0): Stmt[] {
    if (depth > MAX_DEPTH) {
      incomplete = true;
      return [];
    }
    const line = node.line;
    switch (node.type) {
      case "local_variable_declaration":
        return localDeclaration(node, depth);
      case "expression_statement": {
        const inner = node.children.find((child) => !child.anonymous);
        if (inner === undefined) return [];
        if (inner.type === "assignment_expression") {
          const left = named(inner, "left");
          const right = named(inner, "right");
          if (left === undefined || right === undefined) return [];
          return [
            {
              s: "assign",
              line,
              target: expr(left, depth + 1),
              op: opOf(inner),
              value: expr(right, depth + 1),
            },
          ];
        }
        return [{ s: "expr", line, expr: expr(inner, depth + 1) }];
      }
      case "if_statement": {
        const test = named(node, "condition");
        if (test === undefined) return [];
        const alternative = named(node, "alternative");
        return [
          {
            s: "if",
            line,
            test: expr(test, depth + 1),
            testText: text(test),
            then: branch(named(node, "consequence"), depth),
            else: alternative === undefined ? null : branch(alternative, depth),
          },
        ];
      }
      case "for_statement": {
        const init: Stmt[] = [];
        for (const child of all(node, "init")) {
          if (child.type === "local_variable_declaration")
            init.push(...localDeclaration(child, depth));
          else init.push({ s: "expr", line: child.line, expr: expr(child, depth + 1) });
        }
        const test = named(node, "condition");
        const update = all(node, "update").map((child): Stmt => ({
          s: "expr",
          line: child.line,
          expr: expr(child, depth + 1),
        }));
        return [
          {
            s: "loop",
            line,
            init,
            test: test === undefined ? null : expr(test, depth + 1),
            update,
            each: null,
            body: branch(named(node, "body"), depth),
          },
        ];
      }
      case "enhanced_for_statement": {
        const name = named(node, "name");
        const value = named(node, "value");
        if (name === undefined || value === undefined) return [];
        const type = named(node, "type");
        return [
          {
            s: "loop",
            line,
            init: [],
            test: null,
            update: [],
            each: {
              name: text(name),
              type: type === undefined ? null : text(type),
              iter: expr(value, depth + 1),
            },
            body: branch(named(node, "body"), depth),
          },
        ];
      }
      case "while_statement":
      case "do_statement": {
        const test = named(node, "condition");
        return [
          {
            s: "loop",
            line,
            init: [],
            test: test === undefined ? null : expr(test, depth + 1),
            update: [],
            each: null,
            body: branch(named(node, "body"), depth),
          },
        ];
      }
      case "block":
        return [{ s: "block", line, body: block(node, depth), params: [] }];
      case "try_statement":
      case "try_with_resources_statement": {
        const body: Stmt[] = [];
        for (const resource of named(node, "resources")?.children ?? []) {
          const name = named(resource, "name");
          const value = named(resource, "value");
          const type = named(resource, "type");
          if (name !== undefined) {
            body.push({
              s: "local",
              line: resource.line,
              name: text(name),
              type: type === undefined ? null : text(type),
              init: value === undefined ? null : expr(value, depth + 1),
              isFinal: true,
            });
          } else if (resource.type === "identifier" || resource.type === "field_access") {
            // A resource that is an existing variable: nothing declared.
          }
        }
        const main = named(node, "body");
        if (main !== undefined) body.push(...block(main, depth));
        const out: Stmt[] = [{ s: "block", line, body, params: [] }];
        const arms: Array<{ params: string[]; body: Stmt[] }> = [];
        for (const child of node.children) {
          if (child.type === "catch_clause") {
            const parameter = ofType(child, "catch_formal_parameter");
            const name = parameter === undefined ? undefined : named(parameter, "name");
            const handler = named(child, "body");
            arms.push({
              params: name === undefined ? [] : [text(name)],
              body: handler === undefined ? [] : block(handler, depth),
            });
          } else if (child.type === "finally_clause") {
            const handler = ofType(child, "block");
            arms.push({ params: [], body: handler === undefined ? [] : block(handler, depth) });
          }
        }
        if (arms.length > 0) out.push({ s: "arms", line, subject: null, arms });
        return out;
      }
      case "switch_expression":
      case "switch_statement":
        return armsOf(node, depth);
      case "synchronized_statement": {
        const body = named(node, "body");
        return body === undefined
          ? []
          : [{ s: "block", line, body: block(body, depth), params: [] }];
      }
      case "labeled_statement": {
        const inner = node.children.find(
          (child) => !child.anonymous && child.type !== "identifier",
        );
        return inner === undefined ? [] : stmt(inner, depth + 1);
      }
      case "return_statement":
      case "throw_statement":
      case "yield_statement": {
        const inner = node.children.find((child) => !child.anonymous);
        return [{ s: "exit", line, value: inner === undefined ? null : expr(inner, depth + 1) }];
      }
      case "break_statement":
      case "continue_statement":
        return [{ s: "exit", line, value: null }];
      case "assert_statement": {
        const test = node.children.find((child) => !child.anonymous);
        return test === undefined
          ? []
          : [{ s: "assert", line, test: expr(test, depth + 1), testText: text(test) }];
      }
      default:
        // Local classes, records, enums and interfaces are not followed.
        if (CLASS_KINDS.has(node.type) || node.type === "local_class_declaration") {
          if (SQL_CALL_TEXT.test(text(node)) || OS_CALL_TEXT.test(text(node))) {
            unit.unsupported.push("local class");
          }
        }
        return [];
    }
  }

  // ---- declarations ----

  function parameters(node: AstNode | undefined, depth: number): ParamInfo[] {
    const out: ParamInfo[] = [];
    for (const child of node?.children ?? []) {
      if (child.type === "formal_parameter") {
        const name = named(child, "name");
        const type = named(child, "type");
        if (name === undefined) continue;
        out.push({
          name: text(name),
          type: type === undefined ? "" : text(type),
          annotations: annotations(ofType(child, "modifiers"), depth),
        });
      } else if (child.type === "spread_parameter") {
        const declarator = ofType(child, "variable_declarator");
        const name = declarator === undefined ? undefined : named(declarator, "name");
        if (name !== undefined) {
          out.push({
            name: text(name),
            type: "String[]",
            annotations: annotations(ofType(child, "modifiers"), depth),
          });
        }
      }
    }
    return out;
  }

  function classDeclaration(node: AstNode, parent: ClassInfo | null): ClassInfo {
    const nameNode = named(node, "name");
    const info: ClassInfo = {
      name: nameNode === undefined ? "" : text(nameNode),
      isEnum: node.type === "enum_declaration",
      enumConstants: [],
      fields: new Map(),
      methods: [],
      initializers: [],
      parent,
      supers: [],
    };
    unit.classes.push(info);
    for (const child of node.children) {
      if (["superclass", "super_interfaces", "extends_interfaces"].includes(child.type)) {
        const stack = [child];
        while (stack.length > 0) {
          const current = stack.pop() as AstNode;
          if (current.type === "type_identifier") info.supers.push(text(current));
          stack.push(...current.children);
        }
      }
    }
    const isInterface =
      node.type === "interface_declaration" || node.type === "annotation_type_declaration";
    // Record components are fields of the record.
    if (node.type === "record_declaration") {
      for (const component of parameters(named(node, "parameters"), 0)) {
        info.fields.set(component.name, {
          name: component.name,
          type: component.type,
          isFinal: true,
          isStatic: false,
          isConst: false,
          isMutable: false,
          overridable: false,
          init: null,
          line: node.line,
        });
      }
    }
    const members = (body: AstNode | undefined): void => {
      for (const member of body?.children ?? []) {
        if (member.type === "enum_body_declarations") {
          members(member);
        } else if (member.type === "enum_constant") {
          const name = named(member, "name");
          if (name !== undefined) info.enumConstants.push(text(name));
        } else if (member.type === "field_declaration" || member.type === "constant_declaration") {
          const words = modifierWords(ofType(member, "modifiers"));
          const type = named(member, "type");
          for (const declarator of all(member, "declarator")) {
            const name = named(declarator, "name");
            if (name === undefined) continue;
            const value = named(declarator, "value");
            const field: FieldInfo = {
              name: text(name),
              type: type === undefined ? null : text(type),
              // Interface fields are implicitly static final.
              isFinal: isInterface || /\bfinal\b/.test(words),
              isStatic: isInterface || /\bstatic\b/.test(words),
              isConst: false,
              isMutable: !(isInterface || /\bfinal\b/.test(words)),
              overridable: false,
              init: value === undefined ? null : expr(value, 1),
              line: declarator.line,
            };
            info.fields.set(field.name, field);
          }
        } else if (
          member.type === "method_declaration" ||
          member.type === "constructor_declaration" ||
          member.type === "compact_constructor_declaration"
        ) {
          const name = named(member, "name");
          const body = named(member, "body");
          const method: MethodInfo = {
            name: name === undefined ? "" : text(name),
            params: parameters(named(member, "parameters"), 0),
            annotations: annotations(ofType(member, "modifiers"), 0),
            body: body === undefined ? null : block(body, 1),
            line: member.line,
          };
          info.methods.push(method);
        } else if (member.type === "static_initializer" || member.type === "block") {
          const inner = member.type === "block" ? member : ofType(member, "block");
          if (inner !== undefined) info.initializers.push(...block(inner, 1));
        } else if (CLASS_KINDS.has(member.type)) {
          classDeclaration(member, info);
        }
      }
    };
    members(named(node, "body"));
    return info;
  }

  for (const child of ast.root.children) {
    if (CLASS_KINDS.has(child.type)) classDeclaration(child, null);
  }
  unit.incomplete = incomplete;
  return unit;
}
