import ts from "typescript-api";

/**
 * Lightweight, intra-file, flow-insensitive taint tracking.
 *
 * - `request`: server-side request input (req.body, ctx.query, event.body, searchParams...).
 * - `browser`: client-side input (location.search, $route.query, useSearchParams...).
 */
export type TaintKind = "request" | "browser";

const REQUEST_ROOTS = new Set(["req", "request", "ctx", "context", "event", "c"]);
const REQUEST_PROPS = new Set([
  "body",
  "query",
  "params",
  "headers",
  "cookies",
  "url",
  "originalUrl",
  "path",
  "files",
  "file",
  "queryStringParameters",
  "pathParameters",
  "multiValueQueryStringParameters",
  "searchParams",
  "formData",
]);
const BROWSER_PATTERNS = [
  /^(window\.)?location\.(search|hash|href|pathname)/,
  /^document\.(URL|documentURI|referrer|cookie|location)/,
  /^(this\.)?\$route\.(query|params|hash|fullPath)/,
  /^route\.(query|params|hash|fullPath)/,
];
/** Calls whose result is considered free of injection-relevant input. */
const SANITIZERS = new Set([
  "parseInt",
  "parseFloat",
  "Number",
  "Boolean",
  "basename",
  "sanitize",
  "sanitizeHtml",
  "escape",
  "escapeHtml",
  "escapeId",
  "encode",
  "isValid",
  "uuid",
  "xss",
]);
const MAX_ASSIGNMENTS = 8;
const BROWSER_SOURCE_CALLS = new Set(["useSearchParams", "useParams", "useRoute", "useLocation"]);

export function unwrap(node: ts.Expression): ts.Expression {
  let current = node;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isAwaitExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isSatisfiesExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

/** `a.b.c` / `a["b"].c` as a dotted string, or `null` if the chain has calls. */
export function accessPath(node: ts.Expression): string | null {
  const parts: string[] = [];
  let current: ts.Expression = unwrap(node);
  for (;;) {
    if (ts.isPropertyAccessExpression(current)) {
      parts.unshift(current.name.text);
      current = unwrap(current.expression);
    } else if (ts.isElementAccessExpression(current)) {
      const argument = current.argumentExpression;
      parts.unshift(ts.isStringLiteralLike(argument) ? argument.text : "*");
      current = unwrap(current.expression);
    } else if (ts.isIdentifier(current)) {
      parts.unshift(current.text);
      return parts.join(".");
    } else if (current.kind === ts.SyntaxKind.ThisKeyword) {
      parts.unshift("this");
      return parts.join(".");
    } else {
      return null;
    }
  }
}

/** Name of the called function: `foo` for `foo()`, `bar` for `a.b.bar()`. */
export function calleeName(call: ts.CallExpression | ts.NewExpression): string | null {
  const callee = unwrap(call.expression);
  if (ts.isIdentifier(callee)) {
    return callee.text;
  }
  if (ts.isPropertyAccessExpression(callee)) {
    return callee.name.text;
  }
  return null;
}

/** Text of the receiver for member calls (`pool` in `pool.query()`), else `null`. */
export function calleeReceiver(call: ts.CallExpression | ts.NewExpression): ts.Expression | null {
  const callee = unwrap(call.expression);
  return ts.isPropertyAccessExpression(callee) ? callee.expression : null;
}

function requestPathKind(path: string): TaintKind | null {
  const parts = path.split(".");
  const [root, ...rest] = parts;
  if (root && REQUEST_ROOTS.has(root) && rest.some((part) => REQUEST_PROPS.has(part))) {
    return "request";
  }
  if (BROWSER_PATTERNS.some((pattern) => pattern.test(path))) {
    return "browser";
  }
  return null;
}

export class TaintTracker {
  private readonly taintedVariables = new Map<string, TaintKind>();
  private readonly dynamicStringVariables = new Set<string>();
  /** Expressions assigned to each identifier (bounded), used to judge identifier arguments. */
  private readonly assignedExpressions = new Map<string, ts.Expression[]>();

  constructor(sourceFile: ts.SourceFile) {
    // Two passes so `const a = req.body; const b = a.x;` propagates regardless of order.
    for (let pass = 0; pass < 2; pass += 1) {
      const visit = (node: ts.Node): void => {
        if (ts.isVariableDeclaration(node) && node.initializer) {
          this.recordBinding(node.name, node.initializer, pass === 0);
        } else if (
          ts.isBinaryExpression(node) &&
          (node.operatorToken.kind === ts.SyntaxKind.EqualsToken ||
            node.operatorToken.kind === ts.SyntaxKind.PlusEqualsToken) &&
          ts.isIdentifier(node.left)
        ) {
          // `sql += " AND x"` with a constant keeps the string static.
          if (
            node.operatorToken.kind === ts.SyntaxKind.PlusEqualsToken &&
            !isStaticString(node.right)
          ) {
            this.dynamicStringVariables.add(node.left.text);
          }
          this.recordBinding(node.left, node.right, pass === 0);
        }
        ts.forEachChild(node, visit);
      };
      visit(sourceFile);
    }
  }

  /** Source text of what was assigned to `name` (first few assignments, bounded). */
  assignedText(name: string, sourceFile: ts.SourceFile): string {
    return (this.assignedExpressions.get(name) ?? [])
      .map((expression) => expression.getText(sourceFile).slice(0, 4000))
      .join(" ");
  }

  private recordBinding(
    name: ts.BindingName | ts.Identifier,
    initializer: ts.Expression,
    isFirstPass: boolean,
  ): void {
    if (isFirstPass && ts.isIdentifier(name)) {
      const list = this.assignedExpressions.get(name.text) ?? [];
      if (list.length < MAX_ASSIGNMENTS) list.push(initializer);
      this.assignedExpressions.set(name.text, list);
    }
    const kind = this.taintOf(initializer);
    const isDynamic = this.isDynamicString(initializer);
    const names: string[] = [];
    const collect = (binding: ts.BindingName) => {
      if (ts.isIdentifier(binding)) {
        names.push(binding.text);
      } else {
        for (const element of binding.elements) {
          if (ts.isBindingElement(element)) {
            collect(element.name);
          }
        }
      }
    };
    collect(name);
    for (const variable of names) {
      if (kind) {
        this.taintedVariables.set(variable, kind);
      }
      if (isDynamic) {
        this.dynamicStringVariables.add(variable);
      }
    }
  }

  /** Taint kind carried by an expression, or `null`. */
  taintOf(node: ts.Expression): TaintKind | null {
    const expression = unwrap(node);
    if (ts.isIdentifier(expression)) {
      return this.taintedVariables.get(expression.text) ?? null;
    }
    if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
      const path = accessPath(expression);
      if (path) {
        const kind = requestPathKind(path);
        if (kind) {
          return kind;
        }
      }
      return this.taintOf(expression.expression);
    }
    if (ts.isTemplateExpression(expression)) {
      return firstKind(expression.templateSpans.map((span) => this.taintOf(span.expression)));
    }
    if (ts.isBinaryExpression(expression)) {
      return firstKind([this.taintOf(expression.left), this.taintOf(expression.right)]);
    }
    if (ts.isConditionalExpression(expression)) {
      return firstKind([this.taintOf(expression.whenTrue), this.taintOf(expression.whenFalse)]);
    }
    if (ts.isArrayLiteralExpression(expression)) {
      return firstKind(
        expression.elements.map((element) =>
          ts.isSpreadElement(element) ? this.taintOf(element.expression) : this.taintOf(element),
        ),
      );
    }
    if (ts.isCallExpression(expression)) {
      const name = calleeName(expression);
      if (name && SANITIZERS.has(name)) {
        return null;
      }
      if (name && BROWSER_SOURCE_CALLS.has(name)) {
        return "browser";
      }
      const receiver = calleeReceiver(expression);
      if (receiver) {
        const receiverKind = this.taintOf(receiver);
        if (receiverKind) {
          return receiverKind;
        }
        const receiverPath = accessPath(receiver);
        if (name === "get" && receiverPath && /searchParams$/.test(receiverPath)) {
          return "request";
        }
        // Hono: `c.req.query("x")`, `c.req.param("id")`, `c.req.header("h")`.
        if (
          name &&
          /^(query|queries|param|header|json|text|parseBody|formData)$/.test(name) &&
          receiverPath !== null &&
          /^(c|ctx|context)\.req$/.test(receiverPath)
        ) {
          return "request";
        }
      }
      return firstKind(
        expression.arguments.map((argument) =>
          ts.isSpreadElement(argument) ? null : this.taintOf(argument),
        ),
      );
    }
    // `new URLSearchParams(location.search)`, `new URL(req.url)` carry their input's taint.
    if (ts.isNewExpression(expression)) {
      const name = calleeName(expression);
      const first = expression.arguments?.[0];
      if ((name === "URLSearchParams" || name === "URL") && first && !ts.isSpreadElement(first)) {
        return this.taintOf(first);
      }
    }
    return null;
  }

  /** True when the expression contains request input *directly* (not via a variable). */
  hasDirectSource(node: ts.Expression): boolean {
    let found = false;
    const visit = (child: ts.Node): void => {
      if (found) {
        return;
      }
      if (ts.isPropertyAccessExpression(child) || ts.isElementAccessExpression(child)) {
        const path = accessPath(child);
        if (path && requestPathKind(path)) {
          found = true;
          return;
        }
      }
      ts.forEachChild(child, visit);
    };
    visit(node);
    return found;
  }

  /** String built at runtime: template with substitutions, `+` with non-literals, concat(). */
  isDynamicString(node: ts.Expression): boolean {
    const expression = unwrap(node);
    if (ts.isTemplateExpression(expression)) {
      return true;
    }
    if (ts.isStringLiteralLike(expression)) {
      return false;
    }
    if (ts.isIdentifier(expression)) {
      return this.dynamicStringVariables.has(expression.text);
    }
    if (
      ts.isBinaryExpression(expression) &&
      expression.operatorToken.kind === ts.SyntaxKind.PlusToken
    ) {
      return !(isStaticString(expression.left) && isStaticString(expression.right));
    }
    if (ts.isCallExpression(expression)) {
      const name = calleeName(expression);
      return name === "concat" || name === "format" || name === "join";
    }
    return false;
  }
}

export function isStaticString(node: ts.Expression): boolean {
  const expression = unwrap(node);
  if (ts.isStringLiteralLike(expression)) {
    return true;
  }
  if (
    ts.isBinaryExpression(expression) &&
    expression.operatorToken.kind === ts.SyntaxKind.PlusToken
  ) {
    return isStaticString(expression.left) && isStaticString(expression.right);
  }
  return false;
}

function firstKind(kinds: (TaintKind | null)[]): TaintKind | null {
  if (kinds.includes("request")) {
    return "request";
  }
  return kinds.includes("browser") ? "browser" : null;
}
