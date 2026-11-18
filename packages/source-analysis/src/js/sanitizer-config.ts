import ts from "typescript-api";

/**
 * A sanitizer call through a proven import still lets script through when it is configured to:
 * DOMPurify with `ADD_TAGS: ["script"]` or an `addHook`, sanitize-html with `allowedTags: false`.
 * The helpers below read the options object of a call (and, for DOMPurify, the file-level hook
 * and `setConfig` calls); a risky or not-visible configuration means the sanitizer is not proven.
 */

const DANGEROUS_TAG = /^(script|iframe|object|embed)$/i;
const EVENT_HANDLER_ATTR = /^on[a-z]/i;
const MAX_DEPTH = 3;
const MAX_ENTRIES = 200;

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

/** Strings of an array literal (nested one level for `allowedAttributes`); `null` if not visible. */
function stringsOf(
  expression: ts.Expression,
  resolve: ExpressionResolver | null,
  depth = 0,
): string[] | null {
  const node = resolved(expression, resolve);
  if (ts.isStringLiteralLike(node)) return [node.text];
  if (depth >= MAX_DEPTH) return null;
  if (ts.isArrayLiteralExpression(node)) {
    if (node.elements.length > MAX_ENTRIES) return null;
    const out: string[] = [];
    for (const element of node.elements) {
      if (ts.isSpreadElement(element)) return null;
      const inner = stringsOf(element, resolve, depth + 1);
      if (inner === null) return null;
      out.push(...inner);
    }
    return out;
  }
  if (ts.isObjectLiteralExpression(node)) {
    if (node.properties.length > MAX_ENTRIES) return null;
    const out: string[] = [];
    for (const property of node.properties) {
      if (!ts.isPropertyAssignment(property)) return null;
      const inner = stringsOf(property.initializer, resolve, depth + 1);
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
      const inner = unsafeSanitizerOptions(module, property.expression, resolve, depth + 1);
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
    const reason = unsafeOption(family, key, value, resolve);
    if (reason !== null) return reason;
  }
  return null;
}

function unsafeOption(
  family: "dompurify" | "html",
  key: string,
  value: ts.Expression,
  resolve: ExpressionResolver | null,
): string | null {
  const node = resolved(value, resolve);
  if (family === "dompurify") {
    if (key === "ADD_TAGS" || key === "ALLOWED_TAGS") {
      const tags = stringsOf(node, resolve);
      if (tags === null) return `${key} is not an inline list of tags`;
      return tags.some((tag) => DANGEROUS_TAG.test(tag))
        ? `${key} allows a script-capable tag`
        : null;
    }
    if (key === "ADD_ATTR" || key === "ALLOWED_ATTR") {
      const attributes = stringsOf(node, resolve);
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
    return null;
  }
  if (key === "allowedTags") {
    if (node.kind === ts.SyntaxKind.FalseKeyword) return "allowedTags: false allows every tag";
    const tags = stringsOf(node, resolve);
    if (tags === null) return "allowedTags is not an inline list of tags";
    return tags.some((tag) => DANGEROUS_TAG.test(tag))
      ? "allowedTags allows a script-capable tag"
      : null;
  }
  if (key === "allowedAttributes") {
    if (node.kind === ts.SyntaxKind.FalseKeyword)
      return "allowedAttributes: false allows every attribute";
    const attributes = stringsOf(node, resolve);
    if (attributes === null) return "allowedAttributes is not an inline list";
    return attributes.some((attribute) => EVENT_HANDLER_ATTR.test(attribute))
      ? "allowedAttributes allows an event-handler attribute"
      : null;
  }
  if (key === "allowVulnerableTags")
    return isOff(node) ? null : "allowVulnerableTags: true keeps script and style content";
  if (key === "allowedSchemes") {
    const schemes = stringsOf(node, resolve);
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
      if (name === "addHook") risk = "the file registers a DOMPurify hook with addHook()";
      else if (name === "setConfig") {
        const reason = unsafeSanitizerOptions("dompurify", node.arguments[0], resolve);
        if (reason !== null) risk = `the file calls DOMPurify.setConfig() and ${reason}`;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return risk;
}
