import ts from "typescript-api";

/**
 * A sanitizer call through a proven import still lets script through when it is configured to:
 * DOMPurify with `ADD_TAGS: ["script"]` or an `addHook`, sanitize-html with `allowedTags: false`.
 * The helpers below read the options object of a call (and, for DOMPurify, the file-level hook
 * and `setConfig` calls); a risky or not-visible configuration means the sanitizer is not proven.
 */

const DANGEROUS_TAG = /^(script|iframe|object|embed)$/i;
// A URL pattern that starts with dot-star, such as a bare catch-all or a caret-anchored one.
const PERMISSIVE_REGEXP = /^\/\^?(?:\(\?:|\()*\.\*/;
const EVENT_HANDLER_ATTR = /^on[a-z*]/i;
const MAX_DEPTH = 3;
const MAX_LIST_DEPTH = 8;
const MAX_ENTRIES = 200;
/** Nodes one options object may spend on reading its lists (a hostile object cannot blow up). */
const MAX_LIST_NODES = 2000;

export function isDomPurifyFamily(module: string): boolean {
  return module === "dompurify" || module === "isomorphic-dompurify";
}

/** Resolves an identifier to the expression it stands for; `null` when that is not visible. */
export type ExpressionResolver = (expression: ts.Expression) => ts.Expression | null;

function skipWrappers(node: ts.Expression): ts.Expression {
  let current = node;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isSatisfiesExpression(current) ||
    ts.isTypeAssertionExpression(current)
  )
    current = current.expression;
  return current;
}

function resolved(expression: ts.Expression, resolve: ExpressionResolver | null): ts.Expression {
  const node = skipWrappers(expression);
  if (ts.isIdentifier(node) && resolve) {
    const target = resolve(node);
    if (target) return skipWrappers(target);
  }
  return node;
}

/** Whether a literal-looking value is a literal `false` (or `null`/`undefined`: option unset). */
function isOff(node: ts.Expression): boolean {
  return (
    node.kind === ts.SyntaxKind.FalseKeyword ||
    node.kind === ts.SyntaxKind.NullKeyword ||
    (ts.isIdentifier(node) && node.text === "undefined")
  );
}

/** `sanitizeHtml.defaults.allowedTags` and the like: the library's own safe base lists. */
function isDefaultsList(node: ts.Expression, alias: string | null): boolean {
  if (alias === null) return false;
  if (!ts.isPropertyAccessExpression(node) || !/^allowed/.test(node.name.text)) return false;
  const defaults = node.expression;
  return (
    ts.isPropertyAccessExpression(defaults) &&
    defaults.name.text === "defaults" &&
    ts.isIdentifier(defaults.expression) &&
    defaults.expression.text === alias
  );
}

interface Budget {
  left: number;
  /** Local name of the sanitize-html import: only its `defaults` lists are the safe base. */
  alias: string | null;
}
const newBudget = (alias: string | null): Budget => ({ left: MAX_LIST_NODES, alias });

/**
 * Strings of a list, an object of lists (`allowedAttributes`) or a `{ name, values }` attribute
 * entry; `null` if not visible. The library's `defaults` lists, spread or `concat`ed, are the safe
 * base and contribute nothing: only the names added to them are judged.
 */
function stringsOf(
  expression: ts.Expression,
  resolve: ExpressionResolver | null,
  budget: Budget = newBudget(null),
  depth = 0,
): string[] | null {
  budget.left -= 1;
  if (budget.left < 0) return null;
  const node = resolved(expression, resolve);
  if (ts.isStringLiteralLike(node)) return [node.text];
  if (isDefaultsList(node, budget.alias)) return [];
  if (depth >= MAX_LIST_DEPTH) return null;
  if (ts.isArrayLiteralExpression(node)) {
    if (node.elements.length > MAX_ENTRIES) return null;
    const out: string[] = [];
    for (const element of node.elements) {
      if (ts.isSpreadElement(element)) {
        if (isDefaultsList(skipWrappers(element.expression), budget.alias)) continue;
        return null;
      }
      const inner = stringsOf(element, resolve, budget, depth + 1);
      if (inner === null) return null;
      out.push(...inner);
    }
    return out;
  }
  if (ts.isCallExpression(node)) {
    const callee = skipWrappers(node.expression);
    if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== "concat") return null;
    const out = stringsOf(callee.expression, resolve, budget, depth + 1);
    if (out === null) return null;
    for (const argument of node.arguments) {
      if (ts.isSpreadElement(argument)) return null;
      const inner = stringsOf(argument, resolve, budget, depth + 1);
      if (inner === null) return null;
      out.push(...inner);
    }
    return out;
  }
  if (ts.isObjectLiteralExpression(node)) {
    if (node.properties.length > MAX_ENTRIES) return null;
    // `{ name: 'target', values: [...] }`: the attribute is the name.
    const named = node.properties.find(
      (property): property is ts.PropertyAssignment =>
        ts.isPropertyAssignment(property) &&
        keyOf(property.name) === "name" &&
        ts.isStringLiteralLike(property.initializer),
    );
    if (named && ts.isStringLiteralLike(named.initializer)) return [named.initializer.text];
    const out: string[] = [];
    for (const property of node.properties) {
      if (ts.isSpreadAssignment(property)) {
        if (isDefaultsList(skipWrappers(property.expression), budget.alias)) continue;
        return null;
      }
      if (!ts.isPropertyAssignment(property)) return null;
      const inner = stringsOf(property.initializer, resolve, budget, depth + 1);
      if (inner === null) return null;
      out.push(...inner);
    }
    return out;
  }
  return null;
}

function keyOf(name: ts.PropertyName): string | null {
  if (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) return name.text;
  return null;
}

/**
 * Why `options` (the second argument of a sanitizer call, or the argument of `setConfig`) can let
 * script or event handlers through, or `null` when it cannot. A value that is not visible here
 * (an imported object, a call result, a computed key, a long list) counts as risky: not
 * understood must never read as safe.
 */
export function unsafeSanitizerOptions(
  module: string,
  options: ts.Expression | undefined,
  resolve: ExpressionResolver | null,
  alias: string | null = null,
  depth = 0,
): string | null {
  const family = isDomPurifyFamily(module)
    ? "dompurify"
    : module === "sanitize-html"
      ? "html"
      : null;
  if (family === null || options === undefined) return null;
  const node = resolved(options, resolve);
  if (isOff(node)) return null;
  if (!ts.isObjectLiteralExpression(node) || depth > MAX_DEPTH)
    return "its options are not an inline object, so they are not visible here";
  if (node.properties.length > MAX_ENTRIES) return "its options object is too large to read";
  for (const property of node.properties) {
    if (ts.isSpreadAssignment(property)) {
      const inner = unsafeSanitizerOptions(module, property.expression, resolve, alias, depth + 1);
      if (inner !== null) return inner;
      continue;
    }
    if (ts.isMethodDeclaration(property) || ts.isGetAccessorDeclaration(property)) continue;
    let key: string | null = null;
    let value: ts.Expression | null = null;
    if (ts.isShorthandPropertyAssignment(property)) {
      key = property.name.text;
      value = property.name;
    } else if (ts.isPropertyAssignment(property)) {
      key = keyOf(property.name);
      value = property.initializer;
    }
    if (key === null || value === null) return "it has a computed option name";
    const reason = unsafeOption(family, key, value, resolve, alias);
    if (reason !== null) return reason;
  }
  return null;
}

function unsafeOption(
  family: "dompurify" | "html",
  key: string,
  value: ts.Expression,
  resolve: ExpressionResolver | null,
  alias: string | null,
): string | null {
  const node = resolved(value, resolve);
  if (family === "dompurify") {
    if (key === "ADD_TAGS" || key === "ALLOWED_TAGS") {
      const tags = stringsOf(node, resolve, newBudget(alias));
      if (tags === null) return `${key} is not an inline list of tags`;
      return tags.some((tag) => DANGEROUS_TAG.test(tag))
        ? `${key} allows a script-capable tag`
        : null;
    }
    if (key === "ADD_ATTR" || key === "ALLOWED_ATTR") {
      const attributes = stringsOf(node, resolve, newBudget(alias));
      if (attributes === null) return `${key} is not an inline list of attributes`;
      return attributes.some((attribute) => EVENT_HANDLER_ATTR.test(attribute))
        ? `${key} allows an event-handler attribute`
        : null;
    }
    if (key === "RETURN_DOM_FRAGMENT" || key === "RETURN_DOM")
      return isOff(node) ? null : `${key} returns a DOM node instead of sanitized text`;
    if (key === "ALLOW_UNKNOWN_PROTOCOLS")
      return isOff(node) ? null : "ALLOW_UNKNOWN_PROTOCOLS allows script URLs";
    if (key === "SANITIZE_DOM")
      return node.kind === ts.SyntaxKind.FalseKeyword ? "SANITIZE_DOM is off" : null;
    if (key === "SAFE_FOR_XML")
      return node.kind === ts.SyntaxKind.FalseKeyword ? "SAFE_FOR_XML is off" : null;
    if (key === "ALLOWED_URI_REGEXP")
      return ts.isRegularExpressionLiteral(node) && PERMISSIVE_REGEXP.test(node.text)
        ? "ALLOWED_URI_REGEXP accepts any URL"
        : null;
    return null;
  }
  if (key === "allowedTags") {
    if (node.kind === ts.SyntaxKind.FalseKeyword) return "allowedTags: false allows every tag";
    const tags = stringsOf(node, resolve, newBudget(alias));
    if (tags === null) return "allowedTags is not an inline list of tags";
    return tags.some((tag) => DANGEROUS_TAG.test(tag))
      ? "allowedTags allows a script-capable tag"
      : null;
  }
  if (key === "allowedAttributes") {
    if (node.kind === ts.SyntaxKind.FalseKeyword)
      return "allowedAttributes: false allows every attribute";
    const attributes = stringsOf(node, resolve, newBudget(alias));
    if (attributes === null) return "allowedAttributes is not an inline list";
    return attributes.some((attribute) => EVENT_HANDLER_ATTR.test(attribute) || attribute === "*")
      ? "allowedAttributes allows an event-handler attribute or every attribute"
      : null;
  }
  if (key === "allowVulnerableTags")
    return isOff(node) ? null : "allowVulnerableTags: true keeps script and style content";
  if (key === "allowedSchemes" || key === "allowedSchemesByTag") {
    const schemes = stringsOf(node, resolve, newBudget(alias));
    if (schemes === null) return "allowedSchemes is not an inline list";
    return schemes.some((scheme) => /^(javascript|vbscript)$/i.test(scheme))
      ? "allowedSchemes allows script URLs"
      : null;
  }
  return null;
}

/**
 * File-level DOMPurify changes that apply to every `sanitize` call: any `addHook(...)`, and a
 * `setConfig(...)` whose argument is risky. One bounded pass; `null` when there are none.
 */
export function domPurifyFileRisk(
  sourceFile: ts.SourceFile,
  resolve: ExpressionResolver | null,
): string | null {
  let risk: string | null = null;
  const visit = (node: ts.Node): void => {
    if (risk !== null) return;
    if (ts.isCallExpression(node)) {
      const callee = skipWrappers(node.expression);
      const name = ts.isPropertyAccessExpression(callee)
        ? callee.name.text
        : ts.isIdentifier(callee)
          ? callee.text
          : null;
      if (name === "addHook") {
        if (!isBenignHook(node.arguments[1]))
          risk = "the file registers a DOMPurify hook with addHook()";
      } else if (name === "setConfig") {
        const reason = unsafeSanitizerOptions("dompurify", node.arguments[0], resolve);
        if (reason !== null) risk = `the file calls DOMPurify.setConfig() and ${reason}`;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return risk;
}

/** `=`, `+=`, `||=` and the other assignment operators, and the comma operator. */
function isAssignmentOperator(kind: ts.SyntaxKind): boolean {
  return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}
function isAssignmentOrComma(kind: ts.SyntaxKind): boolean {
  return isAssignmentOperator(kind) || kind === ts.SyntaxKind.CommaToken;
}

const ATTRIBUTE_WRITERS = /^(setAttribute|removeAttribute)$/;
const ATTRIBUTE_READERS = /^(getAttribute|hasAttribute)$/;
const MAX_HOOK_NODES = 200;
const MAX_HOOK_DEPTH = 6;

/**
 * A hook whose whole body only sets, removes or reads attributes with constant names and values
 * (`node.setAttribute('target', '_blank')`, guarded by simple conditions): it cannot add script.
 * Anything else (a call to another function, an assignment, a non-constant value, an event
 * handler or `srcdoc` name, a `javascript:` value) is not benign, and neither is a callback that
 * is not written inline.
 */
function isBenignHook(callback: ts.Expression | undefined): boolean {
  if (!callback) return false;
  const fn = skipWrappers(callback);
  if (!ts.isArrowFunction(fn) && !ts.isFunctionExpression(fn)) return false;
  const budget: Budget = { left: MAX_HOOK_NODES, alias: null };
  const isConstant = (node: ts.Expression | undefined): node is ts.StringLiteralLike =>
    node !== undefined && ts.isStringLiteralLike(skipWrappers(node));
  const textOf = (node: ts.Expression) => (skipWrappers(node) as ts.StringLiteralLike).text;
  const isSafeName = (name: string) => !/^(on|srcdoc$)/i.test(name);
  const isCondition = (node: ts.Expression, depth: number): boolean => {
    budget.left -= 1;
    if (budget.left < 0 || depth > MAX_HOOK_DEPTH) return false;
    const e = skipWrappers(node);
    if (ts.isIdentifier(e) || ts.isStringLiteralLike(e) || ts.isNumericLiteral(e)) return true;
    if (ts.isPropertyAccessExpression(e)) return isCondition(e.expression, depth + 1);
    if (ts.isPrefixUnaryExpression(e))
      return (
        e.operator !== ts.SyntaxKind.PlusPlusToken &&
        e.operator !== ts.SyntaxKind.MinusMinusToken &&
        isCondition(e.operand, depth + 1)
      );
    if (ts.isBinaryExpression(e))
      return (
        !isAssignmentOrComma(e.operatorToken.kind) &&
        isCondition(e.left, depth + 1) &&
        isCondition(e.right, depth + 1)
      );
    if (ts.isCallExpression(e)) {
      const callee = skipWrappers(e.expression);
      return (
        ts.isPropertyAccessExpression(callee) &&
        ATTRIBUTE_READERS.test(callee.name.text) &&
        e.arguments.length === 1 &&
        isConstant(e.arguments[0])
      );
    }
    return false;
  };
  const isWrite = (node: ts.Expression): boolean => {
    const e = skipWrappers(node);
    if (!ts.isCallExpression(e)) return false;
    const callee = skipWrappers(e.expression);
    if (!ts.isPropertyAccessExpression(callee) || !ATTRIBUTE_WRITERS.test(callee.name.text))
      return false;
    const [name, value, ...rest] = e.arguments;
    if (rest.length > 0 || !isConstant(name) || !isSafeName(textOf(name))) return false;
    if (callee.name.text === "removeAttribute") return value === undefined;
    return isConstant(value) && !/^\s*(javascript|vbscript|data):/i.test(textOf(value));
  };
  const isStatement = (node: ts.Node, depth: number): boolean => {
    budget.left -= 1;
    if (budget.left < 0 || depth > MAX_HOOK_DEPTH) return false;
    if (ts.isBlock(node)) return node.statements.every((child) => isStatement(child, depth + 1));
    if (ts.isExpressionStatement(node)) return isWrite(node.expression);
    if (ts.isEmptyStatement(node)) return true;
    if (ts.isReturnStatement(node)) return node.expression === undefined;
    if (ts.isIfStatement(node))
      return (
        isCondition(node.expression, 0) &&
        isStatement(node.thenStatement, depth + 1) &&
        (node.elseStatement === undefined || isStatement(node.elseStatement, depth + 1))
      );
    return false;
  };
  return ts.isBlock(fn.body) ? isStatement(fn.body, 0) : isWrite(fn.body);
}
