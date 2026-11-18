import { parse } from "@vue/compiler-sfc";
import ts from "typescript-api";
import type { RawSourceFinding } from "../finding-factory.js";
import { isTrustedSanitizerCall, TRUSTED_SANITIZER_MODULES } from "../js/sanitizer-modules.js";
import {
  domPurifyFileRisk,
  isDomPurifyFamily,
  unsafeSanitizerOptions,
} from "../js/sanitizer-config.js";
import { analyzeJsSource, type JsFileFacts } from "../js/analyze-js.js";

export interface VueAnalysis {
  findings: RawSourceFinding[];
  facts: JsFileFacts | null;
  hasParseErrors: boolean;
  cappedRules: string[];
}

interface TemplateNode {
  type: number;
  props?: TemplateProp[];
  children?: TemplateNode[];
}

interface TemplateProp {
  type: number;
  name: string;
  value?: { content: string };
  exp?: { content: string; loc: { start: { line: number } } };
  loc: { start: { line: number } };
}

const NODE_ELEMENT = 1;
const PROP_ATTRIBUTE = 6;
const PROP_DIRECTIVE = 7;
const MAX_TEMPLATE_DEPTH = 500;
const BROWSER_INPUT =
  /\$route\b|\broute\.(query|params|hash)|\blocation\.|\bquery\b|\bparams\b|searchParams/;
const SANITIZED = /\b(sanitize|sanitizeHtml|purify|DOMPurify|escapeHtml|xss)\b/i;

const SANITIZER_MODULES = new Set([...TRUSTED_SANITIZER_MODULES, "escape-html"]);

interface SanitizerRoot {
  module: string;
  /** The imported name of a named import; null for a default or namespace import. */
  named: string | null;
}

interface ScriptSanitizers {
  /** Computed properties whose whole value is one call to an imported sanitizer: name -> module. */
  computeds: Map<string, string>;
  /** Sole, never-reassigned import bindings of a sanitizer module: local name -> module. */
  roots: Map<string, SanitizerRoot>;
  /** Why a DOMPurify hook or `setConfig` in the script makes every sanitize call unsafe, or null. */
  hookRisk: string | null;
}

const OBJECT_WRITERS = new Set(["assign", "defineProperty", "defineProperties", "setPrototypeOf"]);

/** Name written through a property or element, or handed to `Object.assign`-like writers. */
function memberWriteRoot(node: ts.Node): string | null {
  const rootOf = (expression: ts.Expression): string | null => {
    let current = expression;
    while (
      ts.isPropertyAccessExpression(current) ||
      ts.isElementAccessExpression(current) ||
      ts.isParenthesizedExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isAsExpression(current)
    )
      current = current.expression;
    return ts.isIdentifier(current) ? current.text : null;
  };
  if (
    ts.isBinaryExpression(node) &&
    node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
    node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
    (ts.isPropertyAccessExpression(node.left) || ts.isElementAccessExpression(node.left))
  )
    return rootOf(node.left);
  if (ts.isDeleteExpression(node)) return rootOf(node.expression);
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    ts.isIdentifier(node.expression.expression) &&
    (node.expression.expression.text === "Object" ||
      node.expression.expression.text === "Reflect") &&
    (OBJECT_WRITERS.has(node.expression.name.text) || node.expression.name.text === "set") &&
    node.arguments[0]
  )
    return rootOf(node.arguments[0]);
  return null;
}

/**
 * Computed properties whose whole value is one call to an imported sanitizer, by name:
 * `const clean = computed(() => DOMPurify.sanitize(html))` and the options-API `computed: { clean() {} }`.
 * The template only sees the name, so the sanitizing is inferred, never proven: the finding stays.
 */
function scriptSanitizers(
  content: string,
  scriptKind: ts.ScriptKind,
  exposesImports: boolean,
): ScriptSanitizers {
  const found = new Map<string, string>();
  const source = ts.createSourceFile(
    "pgard-vue.tsx",
    content,
    ts.ScriptTarget.Latest,
    true,
    scriptKind,
  );
  const imported = new Map<string, string>();
  const importedName = new Map<string, string>();
  const importCount = new Map<string, number>();
  const count = (name: string) => importCount.set(name, (importCount.get(name) ?? 0) + 1);
  const collect = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const clause = node.importClause;
      const module = node.moduleSpecifier.text;
      if (clause?.name) imported.set(clause.name.text, module);
      const bindings = clause?.namedBindings;
      if (bindings && ts.isNamespaceImport(bindings)) imported.set(bindings.name.text, module);
      else if (bindings && ts.isNamedImports(bindings))
        for (const element of bindings.elements) {
          imported.set(element.name.text, module);
          importedName.set(element.name.text, (element.propertyName ?? element.name).text);
        }
    }
    if (
      (ts.isVariableDeclaration(node) || ts.isParameter(node) || ts.isBindingElement(node)) &&
      ts.isIdentifier(node.name)
    )
      count(node.name.text);
    // A reassigned import, or a function declared under the same name, is not the module's export.
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
      ts.isIdentifier(node.left)
    )
      count(node.left.text);
    if (ts.isFunctionDeclaration(node) && node.name) count(node.name.text);
    // `X.sanitize = ...`, `X["sanitize"] = ...`, `Object.assign(X, ...)` change what X does.
    const written = memberWriteRoot(node);
    if (written) count(written);
    ts.forEachChild(node, collect);
  };
  collect(source);
  const unwrapExpression = (expression: ts.Expression): ts.Expression => {
    let node = expression;
    while (
      ts.isParenthesizedExpression(node) ||
      ts.isAsExpression(node) ||
      ts.isNonNullExpression(node)
    )
      node = node.expression;
    return node;
  };
  const sanitizerOf = (expression: ts.Expression | undefined): string | null => {
    if (!expression) return null;
    const node = unwrapExpression(expression);
    if (!ts.isCallExpression(node)) return null;
    let root: ts.Expression = unwrapExpression(node.expression);
    while (ts.isPropertyAccessExpression(root)) root = unwrapExpression(root.expression);
    if (!ts.isIdentifier(root)) return null;
    const module = imported.get(root.text);
    return module !== undefined && SANITIZER_MODULES.has(module) && !importCount.has(root.text)
      ? `${module}`
      : null;
  };
  const returned = (fn: ts.Node): ts.Expression | undefined => {
    if (!ts.isFunctionLike(fn)) return undefined;
    const body = (fn as ts.FunctionLikeDeclaration).body;
    if (!body) return undefined;
    if (!ts.isBlock(body)) return body;
    const returns: ts.ReturnStatement[] = [];
    const walk = (node: ts.Node): void => {
      if (ts.isReturnStatement(node)) returns.push(node);
      if (!ts.isFunctionLike(node) || node === fn) ts.forEachChild(node, walk);
    };
    walk(body);
    return returns.length === 1 ? returns[0]?.expression : undefined;
  };
  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      ts.isCallExpression(node.initializer) &&
      ts.isIdentifier(node.initializer.expression) &&
      node.initializer.expression.text === "computed" &&
      node.initializer.arguments[0]
    ) {
      const module = sanitizerOf(returned(node.initializer.arguments[0]));
      if (module) found.set(node.name.text, module);
    } else if (
      ts.isPropertyAssignment(node) &&
      node.name.getText(source) === "computed" &&
      ts.isObjectLiteralExpression(node.initializer)
    ) {
      for (const member of node.initializer.properties) {
        if (!ts.isMethodDeclaration(member) && !ts.isPropertyAssignment(member)) continue;
        if (!ts.isIdentifier(member.name)) continue;
        const module = sanitizerOf(
          returned(ts.isMethodDeclaration(member) ? member : member.initializer),
        );
        if (module) found.set(member.name.text, module);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  // Names the component also declares for the template (`data`, `props`, `methods`, `computed`,
  // `inject`, `defineProps`): a template name can then mean either, so the import is unproven.
  const optionNames = componentOptionNames(source, returned);
  const roots = new Map<string, SanitizerRoot>();
  // Only `<script setup>` bindings are visible to the template; imports of a plain `<script>` are not.
  if (exposesImports)
    for (const [name, module] of imported)
      if (SANITIZER_MODULES.has(module) && !importCount.has(name) && !optionNames.has(name))
        roots.set(name, { module, named: importedName.get(name) ?? null });
  const hasDomPurify = [...imported.values()].some(isDomPurifyFamily);
  return {
    computeds: found,
    roots,
    hookRisk: hasDomPurify ? domPurifyFileRisk(source, null) : null,
  };
}

const MAX_OPTION_NAMES = 500;

/** Names declared by the options API (`props`, `data`, ...) and `defineProps`, bounded. */
function componentOptionNames(
  source: ts.SourceFile,
  returned: (fn: ts.Node) => ts.Expression | undefined,
): Set<string> {
  const names = new Set<string>();
  const add = (name: string) => {
    if (names.size < MAX_OPTION_NAMES) names.add(name);
  };
  const keyText = (name: ts.PropertyName): string | null =>
    ts.isIdentifier(name) || ts.isStringLiteralLike(name) ? name.text : null;
  const addKeysOf = (expression: ts.Expression | undefined) => {
    if (!expression) return;
    let node = expression;
    while (ts.isParenthesizedExpression(node) || ts.isAsExpression(node)) node = node.expression;
    if (ts.isArrayLiteralExpression(node)) {
      for (const element of node.elements) if (ts.isStringLiteralLike(element)) add(element.text);
    } else if (ts.isObjectLiteralExpression(node)) {
      for (const property of node.properties) {
        if (ts.isSpreadAssignment(property)) continue;
        const key = property.name ? keyText(property.name) : null;
        if (key !== null) add(key);
      }
    }
  };
  const visit = (node: ts.Node): void => {
    if (
      (ts.isPropertyAssignment(node) || ts.isMethodDeclaration(node)) &&
      (ts.isIdentifier(node.name) || ts.isStringLiteralLike(node.name))
    ) {
      const key = node.name.text;
      const value = ts.isPropertyAssignment(node) ? node.initializer : undefined;
      if (key === "props" || key === "inject" || key === "methods" || key === "computed")
        addKeysOf(value);
      else if (key === "data")
        addKeysOf(returned(ts.isMethodDeclaration(node) ? node : (value as ts.Node)));
    } else if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      (node.expression.text === "defineProps" || node.expression.text === "defineModel")
    ) {
      addKeysOf(node.arguments[0]);
      const type = node.typeArguments?.[0];
      if (type && ts.isTypeLiteralNode(type))
        for (const member of type.members) {
          const key = member.name ? keyText(member.name) : null;
          if (key !== null) add(key);
        }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return names;
}

/**
 * The whole expression as one call `f(x)` or `f.method(x)` on a sanitizer import in `roots`
 * (`DOMPurify.sanitize(html)`), else null. `proven` is false for a method that is not the
 * module's sanitizing entry point (`DOMPurify.getConfig`, `xssFilters.inDoubleQuotedAttr`).
 */
function sanitizerRootOf(
  expression: string,
  roots: Map<string, SanitizerRoot>,
  hookRisk: string | null,
): { module: string; proven: boolean; risk: string | null } | null {
  if (roots.size === 0) return null;
  const source = ts.createSourceFile(
    "pgard-vue-expression.ts",
    `(${expression});`,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const statement = source.statements[0];
  if (!statement || !ts.isExpressionStatement(statement) || source.statements.length !== 1)
    return null;
  let node: ts.Expression = statement.expression;
  while (ts.isParenthesizedExpression(node)) node = node.expression;
  if (!ts.isCallExpression(node)) return null;
  const callee = node.expression;
  const direct = ts.isIdentifier(callee);
  const receiver = direct
    ? callee
    : ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)
      ? callee.expression
      : null;
  if (!receiver) return null;
  const root = roots.get(receiver.text);
  if (!root) return null;
  const name = direct
    ? (root.named ?? receiver.text)
    : (callee as ts.PropertyAccessExpression).name.text;
  const isEntryPoint = isTrustedSanitizerCall(
    root.module,
    root.named === null ? "default" : "named",
    direct ? "direct" : "member",
    name,
  );
  // The template cannot resolve a named options object, so it is read as not visible (risky).
  const risk =
    unsafeSanitizerOptions(root.module, node.arguments[1], null) ??
    (isDomPurifyFamily(root.module) ? hookRisk : null);
  return {
    module: root.module,
    proven: isEntryPoint && risk === null,
    risk: isEntryPoint ? risk : null,
  };
}

type Classification = Omit<RawSourceFinding, "ruleId" | "path" | "line" | "cause">;

const IDENTIFIER = /[A-Za-z_$][\w$]*/g;
const FOR_SEPARATOR = /\s(?:in|of)\s/;
const MAX_LOCAL_NAMES = 100;

/**
 * Names an element introduces for itself and its subtree: `v-for="DOMPurify in items"` aliases
 * and `v-slot` / `#name` / `slot-scope` parameters. Over-inclusive (every identifier of the
 * alias or parameter text, defaults included): a name wrongly taken as local only keeps a finding.
 */
function localTemplateNames(node: TemplateNode): Set<string> {
  const names = new Set<string>();
  const addFrom = (text: string) => {
    for (const match of text.matchAll(IDENTIFIER)) {
      if (names.size >= MAX_LOCAL_NAMES) return;
      names.add(match[0]);
    }
  };
  for (const prop of node.props ?? []) {
    if (prop.type === PROP_DIRECTIVE && prop.name === "for" && prop.exp) {
      const separator = FOR_SEPARATOR.exec(prop.exp.content);
      addFrom(separator ? prop.exp.content.slice(0, separator.index) : prop.exp.content);
    } else if (prop.type === PROP_DIRECTIVE && prop.name === "slot" && prop.exp) {
      addFrom(prop.exp.content);
    } else if (prop.type === PROP_ATTRIBUTE && prop.name === "slot-scope" && prop.value) {
      addFrom(prop.value.content);
    }
  }
  return names;
}

/** Classifies a `v-html` expression without evaluating it. */
function classifyVHtml(
  expression: string,
  scripts: ScriptSanitizers = { computeds: new Map(), roots: new Map(), hookRisk: null },
  shadowed: ReadonlySet<string> = new Set(),
): Classification | null {
  const trimmed = expression.trim();
  const viaComputed = /^[A-Za-z_$][\w$]*$/.test(trimmed)
    ? scripts.computeds.get(trimmed)
    : undefined;
  if (viaComputed !== undefined) {
    return {
      severity: "low",
      status: "suspected",
      confidence: "low",
      evidence: `bound value -> v-html (computed "${trimmed}" wraps a ${viaComputed} call; inferred from the script, verify it covers the whole value and is not configured to allow script or event handlers)`,
    };
  }
  if (/^(['"`])[^'"`$]*\1$/.test(trimmed)) return null;
  // A `v-for` alias or slot prop with the sanitizer's name hides the import inside its subtree.
  const roots =
    shadowed.size === 0
      ? scripts.roots
      : new Map([...scripts.roots].filter(([name]) => !shadowed.has(name)));
  const root = sanitizerRootOf(trimmed, roots, scripts.hookRisk);
  if (root?.proven) return null;
  const rootModule = root?.module ?? null;
  const finding = classifyUnsanitized(trimmed);
  const named = SANITIZED.exec(trimmed);
  if (!named) return finding;
  // The name looks like a sanitizer but is not a proven import (a Vue method, a local function,
  // a global) or is escape-html, which does not cover every context: keep the finding, inferred.
  const note =
    root?.risk != null
      ? `sanitizer \`${named[1] ?? "sanitizer"}\` is configured so script or event handlers can get through (${root.risk}); verify the configuration`
      : rootModule === "escape-html"
        ? `escape-html only escapes & < > " ' and is not sufficient in an attribute, URL or script context; inferred`
        : `sanitizer \`${named[1] ?? "sanitizer"}\` is not a known sanitizer import; inferred`;
  return {
    severity:
      finding.severity === "high" || finding.severity === "critical" ? "medium" : finding.severity,
    status: "suspected",
    confidence: "low",
    evidence: `${finding.evidence} (${note})`,
  };
}

function classifyUnsanitized(trimmed: string): Classification {
  if (BROWSER_INPUT.test(trimmed)) {
    return {
      severity: "high",
      status: "suspected",
      confidence: "medium",
      evidence: "browser input (route/query) -> v-html",
    };
  }
  const isComposed = /[`+]/.test(trimmed);
  return {
    severity: isComposed ? "medium" : "low",
    status: "suspected",
    confidence: "low",
    evidence: `${isComposed ? "composed string" : "bound value"} -> v-html (no input source identified)`,
  };
}

/**
 * Analyzes a Vue single-file component: `<script>`/`<script setup>` with the TypeScript AST
 * (same rules as JS/TS) and the template's `v-html` bindings via @vue/compiler-sfc.
 */
export function analyzeVueSource(code: string, path: string): VueAnalysis {
  const { descriptor, errors } = parse(code, { filename: path, sourceMap: false });
  const findings: RawSourceFinding[] = [];
  let facts: JsFileFacts | null = null;
  let hasParseErrors = errors.length > 0;
  const cappedRules = new Set<string>();
  const scripts: ScriptSanitizers = { computeds: new Map(), roots: new Map(), hookRisk: null };

  for (const block of [descriptor.script, descriptor.scriptSetup]) {
    if (!block) continue;
    const isTs = block.lang === "ts" || block.lang === "tsx";
    const found = scriptSanitizers(
      block.content,
      isTs ? ts.ScriptKind.TSX : ts.ScriptKind.JSX,
      block === descriptor.scriptSetup,
    );
    for (const [name, module] of found.computeds) scripts.computeds.set(name, module);
    for (const [name, root] of found.roots) scripts.roots.set(name, root);
    scripts.hookRisk ??= found.hookRisk;
    const analysis = analyzeJsSource(block.content, path, {
      lineOffset: block.loc.start.line - 1,
      scriptKind: isTs ? ts.ScriptKind.TSX : ts.ScriptKind.JSX,
    });
    findings.push(...analysis.findings);
    hasParseErrors ||= analysis.hasParseErrors;
    for (const rule of analysis.cappedRules) cappedRules.add(rule);
    facts = facts
      ? {
          imports: [...new Set([...facts.imports, ...analysis.facts.imports])],
          stateChangingRoutes: [
            ...facts.stateChangingRoutes,
            ...analysis.facts.stateChangingRoutes,
          ],
          preflightRoutes: [...facts.preflightRoutes, ...analysis.facts.preflightRoutes],
          preflightExposure:
            facts.preflightExposure === "permissive" ||
            analysis.facts.preflightExposure === "permissive"
              ? "permissive"
              : (facts.preflightExposure ?? analysis.facts.preflightExposure),
          strictSession: facts.strictSession || analysis.facts.strictSession,
          authRoutes: [...facts.authRoutes, ...analysis.facts.authRoutes],
          csrfUncoveredPost: [...facts.csrfUncoveredPost, ...analysis.facts.csrfUncoveredPost],
          csrfUncoveredPreflight: [
            ...facts.csrfUncoveredPreflight,
            ...analysis.facts.csrfUncoveredPreflight,
          ],
          unrecognizedRoutes: facts.unrecognizedRoutes + analysis.facts.unrecognizedRoutes,
          usesCookieSession: facts.usesCookieSession || analysis.facts.usesCookieSession,
          hasJsx: facts.hasJsx || analysis.facts.hasJsx,
        }
      : analysis.facts;
  }

  const visit = (node: TemplateNode, outer: ReadonlySet<string>, depth: number): void => {
    // Too deep to follow: stop, and say so (the walk below never recurses further).
    if (depth > MAX_TEMPLATE_DEPTH) {
      hasParseErrors = true;
      return;
    }
    let shadowed = outer;
    if (node.type === NODE_ELEMENT) {
      const local = localTemplateNames(node);
      if (local.size > 0) shadowed = new Set([...outer, ...local]);
      for (const prop of node.props ?? []) {
        if (prop.type === PROP_DIRECTIVE && prop.name === "html" && prop.exp) {
          const classification = classifyVHtml(prop.exp.content, scripts, shadowed);
          if (classification) {
            findings.push({
              ruleId: "PG-XSS-003",
              path,
              line: prop.loc.start.line,
              cause: "v-html",
              ...classification,
            });
          }
        }
      }
    }
    for (const child of node.children ?? []) visit(child, shadowed, depth + 1);
  };
  const ast = descriptor.template?.ast as TemplateNode | undefined | null;
  if (ast) visit(ast, new Set(), 0);

  return { findings, facts, hasParseErrors, cappedRules: [...cappedRules] };
}
