import ts from "typescript-api";
import type { Confidence, FindingStatus, Severity } from "@pgard/findings";
import type { RawSourceFinding } from "../finding-factory.js";
import type { SourceRuleId } from "../rules.js";
import {
  TaintTracker,
  accessPath,
  calleeName,
  calleeReceiver,
  isStaticString,
  unwrap,
  type TaintKind,
} from "./taint.js";
import { createSanitizedBindingCheck, syntheticFileName } from "./sanitized-binding.js";

/** Project-level facts used by cross-file heuristics (CSRF, brute force, ORM detection). */
export interface JsFileFacts {
  imports: string[];
  /**
   * Lines of POST route registrations: the only state-changing method a cross-site page can send
   * with cookies and no CORS preflight (a form post).
   */
  stateChangingRoutes: number[];
  /**
   * Lines of PUT/PATCH/DELETE route registrations. A cross-site request with these methods needs
   * a CORS preflight, so they only count as CSRF-able when `preflightExposure` is set.
   */
  preflightRoutes: number[];
  /**
   * How exposed PUT/PATCH/DELETE are to a credentialed cross-site request: "permissive" (CORS
   * reflects or pattern-matches origins with credentials), "unknown" (unresolvable CORS options, a
   * hand-set Access-Control-Allow-Credentials header or method-override), or null (provably
   * restrictive, or no CORS at all).
   */
  preflightExposure: "permissive" | "unknown" | null;
  /** An express-session/cookie-session configured with `sameSite: "strict"`. */
  strictSession: boolean;
  /** Authentication-like POST routes. */
  authRoutes: { line: number; routePath: string }[];
  usesCookieSession: boolean;
  hasJsx: boolean;
}

export interface JsAnalysis {
  findings: RawSourceFinding[];
  facts: JsFileFacts;
  hasParseErrors: boolean;
  /** Rules whose per-file finding cap was reached (extra findings were dropped). */
  cappedRules: string[];
}

/** Per rule and file; more findings than this are counted as reduced coverage instead. */
export const MAX_FINDINGS_PER_RULE_PER_FILE = 25;

export interface JsAnalysisOptions {
  /** Added to reported line numbers (for script blocks inside .vue files). */
  lineOffset?: number;
  /** Force TSX/JSX parsing. */
  scriptKind?: ts.ScriptKind;
}

const SQL_DRIVER_MODULES = new Set(["pg", "pg-pool", "mysql", "mysql2", "mysql2/promise"]);
// Bounded and newline-tolerant so multi-line SQL templates match without backtracking blowups.
const SQL_TEXT_PATTERN =
  /\b(select\s[\s\S]{0,2000}?\sfrom|insert\s+into|update\s+\S{1,200}\s+set|delete\s+from)\b/i;
const SQL_RECEIVER = /(^|\.)(db|pool|client|conn|connection|sql|database|pg|mysql|knex|tx|trx)$/i;
const CHILD_PROCESS_MODULES = new Set(["child_process", "node:child_process"]);
const SHELL_PROGRAMS = new Set([
  "sh",
  "bash",
  "zsh",
  "/bin/sh",
  "/bin/bash",
  "cmd",
  "cmd.exe",
  "powershell",
  "pwsh",
]);
const FS_MODULES = new Set(["fs", "node:fs", "fs/promises", "node:fs/promises", "fs-extra"]);
const HTTP_CLIENT_MODULES = new Set([
  "axios",
  "got",
  "node-fetch",
  "undici",
  "request",
  "needle",
  "superagent",
  "http",
  "https",
  "node:http",
  "node:https",
]);
const SANITIZER_CALLS =
  /^(sanitize|sanitizeHtml|purify|escape|escapeHtml|encode|xss|filterXSS|htmlEscape)$/i;
const PASSWORD_NAME = /^(password|passwd|pwd|pass|userPassword|newPassword|plainPassword)$/i;
const PASSWORD_TEXT = /pass(word)?|pwd/i;
const HASHING_TEXT =
  /bcrypt|argon2|scrypt|pbkdf2|hashSync|hashPassword|\.hash\(|createHash|crypto\.subtle/i;
const PERSIST_METHODS = new Set([
  "create",
  "createMany",
  "insert",
  "insertOne",
  "insertMany",
  "save",
  "update",
  "updateOne",
  "updateMany",
  "upsert",
  "build",
  "findOneAndUpdate",
]);
const ROUTE_RECEIVERS = /^(app|router|server|api|routes?|fastify|r)$/;
const AUTH_ROUTE =
  /login|log-in|signin|sign-in|sign_in|auth|session|reset|forgot|password|otp|token|verify/i;
/** A cookie value that is a session or token (used when the cookie name does not say so). */
const SESSION_VALUE_WORDS = new Set([
  "sess",
  "session",
  "sessions",
  "sid",
  "token",
  "tokens",
  "jwt",
  "auth",
  "authorization",
]);
/** Words that make a cookie name look like a session or auth cookie (whole words only). */
const SESSION_NAME_WORDS = new Set([
  "sess",
  "session",
  "sessions",
  "sid",
  "token",
  "tokens",
  "jwt",
  "auth",
  "authorization",
  "login",
  "remember",
  "refresh",
]);
/** Weaker evidence: the cookie probably identifies a user, reported at low confidence. */
const WEAK_NAME_WORDS = new Set(["uid", "userid", "user"]);

interface Evidence {
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  flow: string;
}

function scriptKindFor(path: string): ts.ScriptKind {
  if (path.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (path.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (/\.(ts|mts|cts)$/.test(path)) return ts.ScriptKind.TS;
  return ts.ScriptKind.JSX; // .js/.mjs/.cjs may contain JSX in React projects.
}

/**
 * Analyzes one JavaScript/TypeScript source with the TypeScript compiler AST. Never executes
 * or imports the analyzed code.
 */
export function analyzeJsSource(
  code: string,
  path: string,
  options: JsAnalysisOptions = {},
): JsAnalysis {
  const scriptKind = options.scriptKind ?? scriptKindFor(path);
  // Parsed under a fixed name (findings use `path`) so the sanitizer check can build a one-file
  // program from it whatever the real extension is (`.vue`, `.mjs`, ...).
  const sourceFile = ts.createSourceFile(
    syntheticFileName(scriptKind),
    code,
    ts.ScriptTarget.Latest,
    true,
    scriptKind,
  );
  const parseDiagnostics = (sourceFile as unknown as { parseDiagnostics?: unknown[] })
    .parseDiagnostics;
  const hasParseErrors = Array.isArray(parseDiagnostics) && parseDiagnostics.length > 0;
  const lineOffset = options.lineOffset ?? 0;
  const taint = new TaintTracker(sourceFile);
  const findings: RawSourceFinding[] = [];
  const cappedRules = new Set<string>();
  const facts: JsFileFacts = {
    imports: [],
    stateChangingRoutes: [],
    preflightRoutes: [],
    preflightExposure: null,
    strictSession: false,
    authRoutes: [],
    usesCookieSession: false,
    hasJsx: false,
  };

  // Local names bound to modules: `exec` -> child_process, `cp` -> child_process namespace.
  const namedImports = new Map<string, string>();
  const namespaceImports = new Map<string, string>();

  const lineOf = (node: ts.Node) =>
    sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1 + lineOffset;

  const perRuleCount = new Map<string, number>();
  const report = (ruleId: SourceRuleId, node: ts.Node, evidence: Evidence, cause: string) => {
    // Cap per rule and file so generated/minified code cannot flood the result.
    const count = (perRuleCount.get(ruleId) ?? 0) + 1;
    perRuleCount.set(ruleId, count);
    if (count > MAX_FINDINGS_PER_RULE_PER_FILE) {
      cappedRules.add(ruleId);
      return;
    }
    findings.push({
      ruleId,
      path,
      line: lineOf(node),
      severity: evidence.severity,
      status: evidence.status,
      confidence: evidence.confidence,
      evidence: evidence.flow,
      cause,
    });
  };

  const recordModuleBinding = (moduleName: string, binding: ts.BindingName | undefined) => {
    facts.imports.push(moduleName);
    if (!binding) return;
    if (ts.isIdentifier(binding)) {
      namespaceImports.set(binding.text, moduleName);
    } else if (ts.isObjectBindingPattern(binding)) {
      for (const element of binding.elements) {
        const imported =
          element.propertyName && ts.isIdentifier(element.propertyName)
            ? element.propertyName.text
            : ts.isIdentifier(element.name)
              ? element.name.text
              : null;
        if (imported && ts.isIdentifier(element.name)) {
          namedImports.set(element.name.text, `${moduleName}:${imported}`);
        }
      }
    }
  };

  // Pass 1: imports and require() bindings.
  const collectImports = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const moduleName = node.moduleSpecifier.text;
      facts.imports.push(moduleName);
      const clause = node.importClause;
      if (clause?.name) namespaceImports.set(clause.name.text, moduleName);
      const bindings = clause?.namedBindings;
      if (bindings && ts.isNamespaceImport(bindings)) {
        namespaceImports.set(bindings.name.text, moduleName);
      } else if (bindings && ts.isNamedImports(bindings)) {
        for (const element of bindings.elements) {
          const imported = (element.propertyName ?? element.name).text;
          namedImports.set(element.name.text, `${moduleName}:${imported}`);
        }
      }
    } else if (
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      ts.isCallExpression(unwrap(node.initializer))
    ) {
      const call = unwrap(node.initializer) as ts.CallExpression;
      const first = call.arguments[0];
      if (
        ts.isIdentifier(call.expression) &&
        call.expression.text === "require" &&
        first &&
        ts.isStringLiteral(first)
      ) {
        recordModuleBinding(first.text, node.name);
      }
    } else if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "require"
    ) {
      const first = node.arguments[0];
      if (first && ts.isStringLiteral(first)) facts.imports.push(first.text);
    } else if (
      ts.isJsxElement(node) ||
      ts.isJsxSelfClosingElement(node) ||
      ts.isJsxFragment(node)
    ) {
      facts.hasJsx = true;
    }
    ts.forEachChild(node, collectImports);
  };
  collectImports(sourceFile);
  // `const run = util.promisify(exec)` / `promisify(cp.exec)` make `run` an alias of exec.
  const collectPromisified = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const call = unwrap(node.initializer);
      const target =
        ts.isCallExpression(call) && calleeName(call) === "promisify"
          ? call.arguments[0]
          : undefined;
      if (target) {
        const inner = unwrap(target);
        let bound: string | undefined;
        if (ts.isIdentifier(inner)) {
          bound = namedImports.get(inner.text);
        } else if (ts.isPropertyAccessExpression(inner)) {
          const root = accessPath(inner.expression);
          const module = root ? namespaceImports.get(root) : undefined;
          if (module) bound = `${module}:${inner.name.text}`;
        }
        if (bound) namedImports.set(node.name.text, bound);
      }
    }
    ts.forEachChild(node, collectPromisified);
  };
  collectPromisified(sourceFile);
  const importSet = new Set(facts.imports);
  const hasSqlDriver = [...importSet].some((name) => SQL_DRIVER_MODULES.has(name));

  /** Module a call resolves to: `exec()` imported from child_process, or `cp.exec()`. */
  const moduleOfCall = (call: ts.CallExpression): { module: string; member: string } | null => {
    const callee = unwrap(call.expression);
    if (ts.isIdentifier(callee)) {
      const bound = namedImports.get(callee.text);
      if (bound) {
        // Module names may contain ":" (node:fs), so split at the last one.
        const separator = bound.lastIndexOf(":");
        const module = bound.slice(0, separator);
        const member = bound.slice(separator + 1);
        return module && member ? { module, member } : null;
      }
      return null;
    }
    if (ts.isPropertyAccessExpression(callee)) {
      const root = accessPath(callee.expression);
      if (!root) return null;
      const [first, ...rest] = root.split(".");
      const module = first ? namespaceImports.get(first) : undefined;
      if (module) {
        return {
          module: rest.length > 0 ? `${module}/${rest.join("/")}` : module,
          member: callee.name.text,
        };
      }
    }
    return null;
  };

  const classify = (
    expression: ts.Expression,
    acceptBrowser: boolean,
    strong: Omit<Evidence, "flow">,
    weak: Omit<Evidence, "flow"> | null,
    sinkLabel: string,
  ): Evidence | null => {
    const kind: TaintKind | null = taint.taintOf(expression);
    const isTainted = kind === "request" || (acceptBrowser && kind === "browser");
    const source = kind === "browser" ? "browser input" : "request input";
    if (isTainted) {
      const isDirect = taint.hasDirectSource(expression);
      return {
        ...strong,
        status: isDirect && strong.status === "confirmed" ? "confirmed" : "suspected",
        flow: `${source} ${isDirect ? "" : "(via variable) "}-> ${describeShape(expression)} -> ${sinkLabel}`,
      };
    }
    if (weak) {
      return {
        ...weak,
        flow: `${describeShape(expression)} -> ${sinkLabel} (no input source identified)`,
      };
    }
    return null;
  };

  const describeShape = (expression: ts.Expression): string => {
    const node = unwrap(expression);
    if (ts.isTemplateExpression(node)) return "template literal";
    if (ts.isBinaryExpression(node)) return "string concatenation";
    if (ts.isIdentifier(node))
      return taint.isDynamicString(node) ? "dynamically built string" : "variable";
    if (ts.isCallExpression(node)) return `${calleeName(node) ?? "call"}() result`;
    return "expression";
  };

  const isSanitizerCall = (expression: ts.Expression): boolean => {
    const node = unwrap(expression);
    return ts.isCallExpression(node) && SANITIZER_CALLS.test(calleeName(node) ?? "");
  };

  const isSanitizedBinding = createSanitizedBindingCheck(sourceFile, isSanitizerCall);

  /**
   * A sanitizer call, or a variable resolved to its own declaration whose initializer and every
   * write are sanitizer calls (`const clean = DOMPurify.sanitize(html); el.innerHTML = clean;`).
   */
  const isSanitized = (expression: ts.Expression): boolean => {
    if (isSanitizerCall(expression)) return true;
    const node = unwrap(expression);
    return ts.isIdentifier(node) && isSanitizedBinding(node);
  };

  const sqlArgument = (call: ts.CallExpression): ts.Expression | null => {
    const first = call.arguments[0];
    if (!first) return null;
    const node = unwrap(first);
    if (ts.isObjectLiteralExpression(node)) {
      for (const property of node.properties) {
        if (
          ts.isPropertyAssignment(property) &&
          ts.isIdentifier(property.name) &&
          ["text", "sql"].includes(property.name.text)
        ) {
          return property.initializer;
        }
      }
      return null;
    }
    return first;
  };

  const sqlTextOf = (argument: ts.Expression): string => {
    const node = unwrap(argument);
    const own = node.getText(sourceFile);
    return ts.isIdentifier(node) ? `${own} ${taint.assignedText(node.text, sourceFile)}` : own;
  };

  const checkSql = (call: ts.CallExpression, name: string) => {
    if (
      name === "$queryRawUnsafe" ||
      name === "$executeRawUnsafe" ||
      (name === "raw" && accessPath(calleeReceiver(call) ?? call.expression) === "Prisma")
    ) {
      const argument = call.arguments[0];
      // Request input passed straight in is as dangerous as a string built from it.
      if (argument && (taint.isDynamicString(argument) || taint.taintOf(argument) === "request")) {
        const evidence = classify(
          argument,
          false,
          { severity: "high", status: "confirmed", confidence: "high" },
          { severity: "high", status: "suspected", confidence: "medium" },
          name,
        );
        if (evidence) report("PG-SQL-002", call, evidence, name);
      }
      return;
    }
    if (name !== "query" && name !== "execute") return;
    const argument = sqlArgument(call);
    if (!argument) return;
    const isTaintedInput = taint.taintOf(argument) === "request";
    if (!taint.isDynamicString(argument) && !isTaintedInput) return;
    const receiver = calleeReceiver(call);
    const receiverText = receiver ? (accessPath(receiver) ?? "") : "";
    // Identifier arguments are judged by the text they were assigned (`const q = \`SELECT...\``).
    const text = sqlTextOf(argument);
    const isSqlContext =
      hasSqlDriver ||
      SQL_TEXT_PATTERN.test(text) ||
      (isTaintedInput && SQL_RECEIVER.test(receiverText));
    if (!isSqlContext) return;
    const label = `${receiver ? receiverText || "client" : ""}.${name}`;
    const evidence = classify(
      argument,
      false,
      { severity: "high", status: "confirmed", confidence: "high" },
      { severity: "medium", status: "suspected", confidence: "low" },
      label,
    );
    if (evidence) report("PG-SQL-001", call, evidence, label);
  };

  const checkHtmlSink = (
    ruleId: SourceRuleId,
    node: ts.Node,
    value: ts.Expression,
    sink: string,
  ) => {
    if (
      isStaticString(value) ||
      ts.isNoSubstitutionTemplateLiteral(unwrap(value)) ||
      isSanitized(value)
    )
      return;
    const evidence = classify(
      value,
      true,
      { severity: "high", status: "suspected", confidence: "medium" },
      taint.isDynamicString(value)
        ? { severity: "medium", status: "suspected", confidence: "low" }
        : { severity: "low", status: "suspected", confidence: "low" },
      sink,
    );
    if (evidence) report(ruleId, node, evidence, sink);
  };

  const checkCommand = (call: ts.CallExpression) => {
    const resolved = moduleOfCall(call);
    if (!resolved || !CHILD_PROCESS_MODULES.has(resolved.module)) return;
    const { member } = resolved;
    const first = call.arguments[0];
    if (!first) return;
    if (member === "exec" || member === "execSync") {
      if (isStaticString(first)) return;
      const evidence = classify(
        first,
        false,
        { severity: "critical", status: "confirmed", confidence: "high" },
        taint.isDynamicString(first)
          ? { severity: "high", status: "suspected", confidence: "medium" }
          : null,
        `child_process.${member}`,
      );
      if (evidence) report("PG-CMD-001", call, evidence, member);
      return;
    }
    if (["spawn", "spawnSync", "execFile", "execFileSync"].includes(member)) {
      const options = call.arguments.find((argument) =>
        ts.isObjectLiteralExpression(unwrap(argument)),
      );
      const usesShell =
        options !== undefined &&
        (unwrap(options) as ts.ObjectLiteralExpression).properties.some(
          (property) =>
            ts.isPropertyAssignment(property) &&
            property.name.getText(sourceFile) === "shell" &&
            property.initializer.kind !== ts.SyntaxKind.FalseKeyword,
        );
      const args = call.arguments[1];
      const dynamicParts = [
        first,
        ...(args && ts.isArrayLiteralExpression(unwrap(args))
          ? (unwrap(args) as ts.ArrayLiteralExpression).elements.filter(
              (e): e is ts.Expression => !ts.isSpreadElement(e),
            )
          : []),
      ];
      const taintedPart = dynamicParts.find((part) => taint.taintOf(part) === "request");
      // spawn("sh", ["-c", script]) runs a shell even without `shell: true`.
      const arrayArgs =
        args && ts.isArrayLiteralExpression(unwrap(args))
          ? (unwrap(args) as ts.ArrayLiteralExpression).elements
          : null;
      const program = unwrap(first);
      const flag = arrayArgs?.[0] ? unwrap(arrayArgs[0] as ts.Expression) : null;
      const script = arrayArgs?.[1];
      if (
        ts.isStringLiteralLike(program) &&
        SHELL_PROGRAMS.has(program.text) &&
        flag &&
        ts.isStringLiteralLike(flag) &&
        /^[-/]c$/i.test(flag.text) &&
        script &&
        !ts.isSpreadElement(script) &&
        !isStaticString(script)
      ) {
        const evidence = classify(
          script,
          false,
          { severity: "critical", status: "confirmed", confidence: "high" },
          { severity: "high", status: "suspected", confidence: "medium" },
          `child_process.${member}("${program.text}", ["${flag.text}", ...])`,
        );
        if (evidence) report("PG-CMD-001", call, evidence, `${member}-shell-c`);
        return;
      }
      if (usesShell && (taintedPart || dynamicParts.some((part) => taint.isDynamicString(part)))) {
        const target = taintedPart ?? first;
        const evidence = classify(
          target,
          false,
          { severity: "high", status: "suspected", confidence: "high" },
          { severity: "medium", status: "suspected", confidence: "low" },
          `child_process.${member} with shell: true`,
        );
        if (evidence) report("PG-CMD-001", call, evidence, `${member}-shell`);
      } else if (!isStaticString(first) && taint.taintOf(first) === "request") {
        const evidence = classify(
          first,
          false,
          { severity: "high", status: "suspected", confidence: "medium" },
          null,
          `child_process.${member} program`,
        );
        if (evidence) report("PG-CMD-001", call, evidence, `${member}-program`);
      }
    }
  };

  const checkSsrf = (call: ts.CallExpression, name: string) => {
    const resolved = moduleOfCall(call);
    const receiverPath = calleeReceiver(call)
      ? accessPath(calleeReceiver(call) as ts.Expression)
      : null;
    const isHttpCall =
      name === "fetch" ||
      (resolved !== null && HTTP_CLIENT_MODULES.has(resolved.module.split("/")[0] ?? "")) ||
      (receiverPath !== null &&
        /^(axios|got|http|https|superagent|needle|request)$/.test(receiverPath) &&
        /^(get|post|put|patch|delete|head|request)$/.test(name)) ||
      (namespaceImports.get(name) !== undefined &&
        HTTP_CLIENT_MODULES.has(namespaceImports.get(name) ?? ""));
    if (!isHttpCall) return;
    const first = call.arguments[0];
    if (!first) return;
    let target: ts.Expression = first;
    const node = unwrap(first);
    if (ts.isObjectLiteralExpression(node)) {
      const urlProperty = node.properties.find(
        (property): property is ts.PropertyAssignment =>
          ts.isPropertyAssignment(property) &&
          ["url", "baseURL", "host", "hostname"].includes(property.name.getText(sourceFile)),
      );
      if (!urlProperty) return;
      target = urlProperty.initializer;
    }
    if (taint.taintOf(target) !== "request") return;
    const evidence = classify(
      target,
      false,
      { severity: "high", status: "suspected", confidence: "high" },
      null,
      `${name}() request URL`,
    );
    if (evidence) report("PG-SSRF-001", call, evidence, name);
  };

  const checkPath = (call: ts.CallExpression, name: string) => {
    const resolved = moduleOfCall(call);
    const receiverPath = calleeReceiver(call)
      ? accessPath(calleeReceiver(call) as ts.Expression)
      : null;
    const isFsRead =
      resolved !== null &&
      FS_MODULES.has(resolved.module.replace(/\/promises$/, "")) &&
      [
        "readFile",
        "readFileSync",
        "createReadStream",
        "open",
        "openSync",
        "writeFile",
        "writeFileSync",
        "unlink",
        "unlinkSync",
        "rm",
        "rmSync",
      ].includes(resolved.member);
    const isResponseFile =
      receiverPath !== null &&
      /^(res|response|reply|ctx)$/.test(receiverPath) &&
      ["sendFile", "download", "sendfile"].includes(name);
    if (!isFsRead && !isResponseFile) return;
    const first = call.arguments[0];
    if (!first || taint.taintOf(first) !== "request") return;
    if (isResponseFile) {
      const options = call.arguments[1];
      if (
        options &&
        ts.isObjectLiteralExpression(unwrap(options)) &&
        (unwrap(options) as ts.ObjectLiteralExpression).properties.some(
          (property) => property.name?.getText(sourceFile) === "root",
        )
      ) {
        return; // express/send with `root` rejects paths that escape the root.
      }
    }
    const evidence = classify(
      first,
      false,
      { severity: "high", status: "suspected", confidence: "high" },
      null,
      `${isResponseFile ? "res" : "fs"}.${name}`,
    );
    if (evidence) report("PG-PATH-001", call, evidence, name);
  };

  // Per-function facts are computed once per function (not once per call site), so files with
  // many call sites stay linear.
  const functionFactCache = new Map<ts.Node, { hasHashing: boolean; updatesPassword: boolean }>();
  const enclosingFunctionFacts = (node: ts.Node) => {
    let current: ts.Node | undefined = node.parent;
    while (current && !ts.isFunctionLike(current) && !ts.isSourceFile(current))
      current = current.parent;
    const owner = current ?? sourceFile;
    let facts = functionFactCache.get(owner);
    if (facts === undefined) {
      const text = owner.getText(sourceFile);
      facts = {
        hasHashing: HASHING_TEXT.test(text),
        updatesPassword: /\.update\([^)]{0,200}(pass(word)?|pwd)/i.test(text),
      };
      functionFactCache.set(owner, facts);
    }
    return facts;
  };

  const literalValue = (expression: ts.Expression | undefined): "literal" | "fallback" | null => {
    if (!expression) return null;
    const node = unwrap(expression);
    if (ts.isStringLiteralLike(node)) return "literal";
    if (
      ts.isCallExpression(node) &&
      accessPath(node.expression) === "Buffer.from" &&
      node.arguments[0] &&
      ts.isStringLiteralLike(unwrap(node.arguments[0]))
    )
      return "literal";
    if (
      ts.isBinaryExpression(node) &&
      (node.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
        node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken) &&
      ts.isStringLiteralLike(unwrap(node.right))
    )
      return "fallback";
    if (
      ts.isArrayLiteralExpression(node) &&
      node.elements.some((element) => ts.isStringLiteralLike(element))
    )
      return "literal";
    return null;
  };

  const reportHardcodedKey = (node: ts.Node, kind: "literal" | "fallback", where: string) => {
    report(
      "PG-CRYPTO-002",
      node,
      kind === "literal"
        ? {
            severity: "high",
            status: "confirmed",
            confidence: "high",
            flow: `string literal (value redacted) used as ${where}`,
          }
        : {
            severity: "medium",
            status: "suspected",
            confidence: "medium",
            flow: `hardcoded fallback literal (value redacted) used as ${where} when the environment value is missing`,
          },
      where,
    );
  };

  const checkCrypto = (call: ts.CallExpression, name: string) => {
    const resolved = moduleOfCall(call);
    const isCryptoModule = resolved !== null && /^(node:)?crypto$/.test(resolved.module);
    const member = resolved?.member ?? name;
    if ((isCryptoModule || name === "createHash") && member === "createHash") {
      const algorithm = call.arguments[0];
      if (
        algorithm &&
        ts.isStringLiteralLike(unwrap(algorithm)) &&
        /^(md5|sha1)$/i.test((unwrap(algorithm) as ts.StringLiteral).text)
      ) {
        const chainNode = call.parent?.parent?.parent;
        const chain =
          chainNode && chainNode.getWidth(sourceFile) < 2000 ? chainNode.getText(sourceFile) : "";
        if (PASSWORD_TEXT.test(chain) || enclosingFunctionFacts(call).updatesPassword) {
          report(
            "PG-CRYPTO-001",
            call,
            {
              severity: "high",
              status: "suspected",
              confidence: "medium",
              flow: `${(unwrap(algorithm) as ts.StringLiteral).text} digest of a password-like value`,
            },
            "createHash",
          );
        }
      }
    }
    if (
      (name === "MD5" || name === "SHA1" || name === "md5" || name === "sha1") &&
      call.arguments.some((argument) => PASSWORD_TEXT.test(argument.getText(sourceFile)))
    ) {
      report(
        "PG-CRYPTO-001",
        call,
        {
          severity: "high",
          status: "suspected",
          confidence: "medium",
          flow: `${name}() of a password-like value`,
        },
        name,
      );
    }
    if (
      (isCryptoModule || /^create(De)?[Cc]ipheriv$/.test(name)) &&
      /^create(De)?cipheriv$/i.test(member)
    ) {
      const kind = literalValue(call.arguments[1]);
      if (kind) reportHardcodedKey(call, kind, `${member} key`);
      const algorithm = call.arguments[0];
      if (
        algorithm &&
        ts.isStringLiteralLike(unwrap(algorithm)) &&
        /(^des|rc4|rc2|^bf|blowfish|-ecb$)/i.test((unwrap(algorithm) as ts.StringLiteral).text)
      ) {
        report(
          "PG-CRYPTO-003",
          call,
          {
            severity: "medium",
            status: "confirmed",
            confidence: "high",
            flow: `weak cipher "${(unwrap(algorithm) as ts.StringLiteral).text}"`,
          },
          "weak-cipher",
        );
      }
    }
    if (
      (isCryptoModule || name === "createCipher") &&
      (member === "createCipher" || member === "createDecipher")
    ) {
      report(
        "PG-CRYPTO-003",
        call,
        {
          severity: "medium",
          status: "confirmed",
          confidence: "high",
          flow: `deprecated ${member} (key derived without salt, no IV)`,
        },
        member,
      );
    }
    if ((isCryptoModule || name === "createHmac") && member === "createHmac") {
      const kind = literalValue(call.arguments[1]);
      if (kind) reportHardcodedKey(call, kind, "HMAC key");
    }
    const receiverPath = calleeReceiver(call)
      ? accessPath(calleeReceiver(call) as ts.Expression)
      : null;
    const isJwt =
      (resolved !== null && resolved.module === "jsonwebtoken") ||
      (receiverPath !== null && /^(jwt|jsonwebtoken)$/.test(receiverPath));
    if (isJwt && (member === "sign" || member === "verify")) {
      const kind = literalValue(call.arguments[1]);
      if (kind) reportHardcodedKey(call, kind, `JWT ${member} secret`);
    }
  };

  // `const` bindings with an initializer, by name (a name declared twice is ambiguous and ignored).
  // `let` bindings count as const when they are declared with a value and never reassigned.
  const constInits = new Map<string, ts.Expression[]>();
  /** Names bound by destructuring, with the destructured expression: `const { a: b } = req.body`. */
  const destructuredFrom = new Map<string, ts.Expression[]>();
  /** Names of destructured handler parameters that carry request data: `({ body }) => ...`. */
  const requestAliases = new Set<string>();
  const reassigned = new Set<string>();
  const collectAssignments = (node: ts.Node): void => {
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
      ts.isIdentifier(node.left)
    )
      reassigned.add(node.left.text);
    ts.forEachChild(node, collectAssignments);
  };
  collectAssignments(sourceFile);
  const bindingNames = (name: ts.BindingName, into: string[]) => {
    if (ts.isIdentifier(name)) into.push(name.text);
    else
      for (const element of name.elements)
        if (ts.isBindingElement(element)) bindingNames(element.name, into);
  };
  const collectConsts = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
      const isConstLike =
        node.initializer !== undefined &&
        ts.isVariableDeclarationList(node.parent) &&
        ((node.parent.flags & ts.NodeFlags.Const) !== 0 || !reassigned.has(node.name.text));
      const list = constInits.get(node.name.text) ?? [];
      // Reassigned `let`/`var` bindings: two entries make the name ambiguous.
      if (isConstLike && node.initializer) list.push(node.initializer);
      else list.push(node.name, node.name);
      constInits.set(node.name.text, list);
    } else if (ts.isVariableDeclaration(node) && node.initializer) {
      const names: string[] = [];
      bindingNames(node.name, names);
      for (const bound of names) {
        const list = destructuredFrom.get(bound) ?? [];
        list.push(node.initializer);
        destructuredFrom.set(bound, list);
      }
    } else if (
      ts.isParameter(node) &&
      ts.isObjectBindingPattern(node.name) &&
      node.parent &&
      ts.isFunctionLike(node.parent)
    ) {
      for (const element of node.name.elements) {
        if (ts.isIdentifier(element.name) && /^(body|query|params)$/.test(element.name.text))
          requestAliases.add(element.name.text);
      }
    }
    ts.forEachChild(node, collectConsts);
  };
  collectConsts(sourceFile);
  const singleConst = (name: string): ts.Expression | null => {
    const list = constInits.get(name);
    return list && list.length === 1 ? (list[0] ?? null) : null;
  };

  /**
   * Resolves an options object to its effective properties: an object literal, a same-file
   * `const`, and object spreads of either. Returns null when any part cannot be resolved.
   */
  const resolveOptions = (
    expression: ts.Expression,
    depth: number,
  ): Map<string, ts.Expression> | null => {
    if (depth > 4) return null;
    const node = unwrap(expression);
    if (ts.isIdentifier(node)) {
      const init = singleConst(node.text);
      return init ? resolveOptions(init, depth + 1) : null;
    }
    if (!ts.isObjectLiteralExpression(node)) return null;
    const result = new Map<string, ts.Expression>();
    for (const property of node.properties) {
      if (ts.isSpreadAssignment(property)) {
        const spread = resolveOptions(property.expression, depth + 1);
        if (!spread) return null;
        for (const [key, value] of spread) result.set(key, value);
      } else if (ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property)) {
        if (ts.isComputedPropertyName(property.name)) return null;
        const value = ts.isPropertyAssignment(property) ? property.initializer : property.name;
        result.set(property.name.getText(sourceFile).replace(/^['"]|['"]$/g, ""), value);
      }
    }
    // Resolve `{ httpOnly }` shorthand and `httpOnly: flag` to a same-file const literal.
    for (const [key, value] of result) {
      const inner = unwrap(value);
      if (ts.isIdentifier(inner)) {
        const init = singleConst(inner.text);
        if (init) result.set(key, unwrap(init));
      }
    }
    return result;
  };

  const isNextCookieStore = (expression: ts.Expression, depth: number): boolean => {
    if (depth > 3) return false;
    const node = unwrap(expression);
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression))
      return namedImports.get(node.expression.text) === "next/headers:cookies";
    if (ts.isIdentifier(node)) {
      const init = singleConst(node.text);
      return init ? isNextCookieStore(init, depth + 1) : false;
    }
    return false;
  };

  const moduleOfArgument = (argument: ts.Expression | undefined): string | undefined => {
    if (!argument) return undefined;
    const node = unwrap(argument);
    if (ts.isIdentifier(node)) return namespaceImports.get(node.text);
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "require" &&
      node.arguments[0] &&
      ts.isStringLiteral(node.arguments[0])
    )
      return node.arguments[0].text;
    return undefined;
  };

  const raiseExposure = (level: "permissive" | "unknown") => {
    if (facts.preflightExposure !== "permissive") facts.preflightExposure = level;
  };

  /**
   * Three-valued CORS reading for PG-CSRF-001. PUT/PATCH/DELETE need a preflight, so they are only
   * left out when CORS is provably restrictive: absent, no credentials, or a fixed origin list.
   * "permissive" = reflected/pattern/function origin with credentials; "unknown" = options we cannot
   * resolve, an origin held in an identifier, or a hand-set Access-Control-Allow-Credentials header.
   */
  const checkCors = (call: ts.CallExpression, name: string) => {
    if (["header", "setHeader", "set", "append", "writeHead"].includes(name)) {
      const header = call.arguments[0] ? unwrap(call.arguments[0]) : undefined;
      const value = call.arguments[1] ? unwrap(call.arguments[1]) : undefined;
      if (
        header &&
        ts.isStringLiteralLike(header) &&
        header.text.toLowerCase() === "access-control-allow-credentials" &&
        !(value && ts.isStringLiteralLike(value) && value.text.toLowerCase() === "false") &&
        !(value && value.kind === ts.SyntaxKind.FalseKeyword)
      )
        raiseExposure("unknown");
      return;
    }
    let options: ts.Expression | undefined;
    if (name === "register") {
      if (moduleOfArgument(call.arguments[0]) !== "@fastify/cors") return;
      options = call.arguments[1];
    } else {
      if (namespaceImports.get(name) !== "cors" && namespaceImports.get(name) !== "@fastify/cors")
        return;
      options = call.arguments[0];
    }
    if (!options) return; // cors() defaults: wildcard origin, no credentials
    const resolved = resolveOptions(options, 0);
    if (!resolved) {
      raiseExposure("unknown"); // imported or computed options
      return;
    }
    const credentials = resolved.get("credentials");
    if (!credentials || credentials.kind === ts.SyntaxKind.FalseKeyword) return;
    if (credentials.kind !== ts.SyntaxKind.TrueKeyword) {
      raiseExposure("unknown");
      return;
    }
    const origin = resolved.get("origin");
    if (!origin || origin.kind === ts.SyntaxKind.FalseKeyword) return; // wildcard + credentials is rejected
    if (
      origin.kind === ts.SyntaxKind.TrueKeyword ||
      ts.isRegularExpressionLiteral(origin) ||
      ts.isArrowFunction(origin) ||
      ts.isFunctionExpression(origin)
    ) {
      raiseExposure("permissive");
    } else if (ts.isStringLiteralLike(origin)) {
      // a single fixed origin: restrictive
    } else if (
      ts.isArrayLiteralExpression(origin) &&
      origin.elements.every((element) => ts.isStringLiteralLike(element))
    ) {
      // a fixed origin list: restrictive
    } else {
      raiseExposure("unknown"); // identifier, call or mixed list
    }
  };

  // `.save()` receivers per function: `const user = new User(...); user.save()`.
  const saveReceiverCache = new Map<ts.Node, Set<string>>();
  const savedReceivers = (node: ts.Node): Set<string> => {
    let current: ts.Node | undefined = node.parent;
    while (current && !ts.isFunctionLike(current) && !ts.isSourceFile(current))
      current = current.parent;
    const owner = current ?? sourceFile;
    let names = saveReceiverCache.get(owner);
    if (!names) {
      const found = new Set<string>();
      names = found;
      const collect = (child: ts.Node): void => {
        if (ts.isCallExpression(child) && calleeName(child) === "save") {
          const receiver = calleeReceiver(child);
          const inner = receiver ? unwrap(receiver) : null;
          if (inner && ts.isIdentifier(inner)) found.add(inner.text);
        }
        ts.forEachChild(child, collect);
      };
      collect(owner);
      saveReceiverCache.set(owner, found);
    }
    return names;
  };

  const isPlainRequestBase = (node: ts.Expression): boolean => {
    let base: ts.Expression = unwrap(node);
    while (ts.isPropertyAccessExpression(base) || ts.isElementAccessExpression(base))
      base = unwrap(base.expression);
    return ts.isIdentifier(base) && requestAliases.has(base.text);
  };

  /**
   * A plain password at a sink: a direct request read (`req.body.password`), a password-named
   * property, or an identifier that is a parameter/destructured binding named like a password or a
   * `const` assigned directly from such a read. A value returned from any call (`hashSecret(pw)`,
   * `await helper(pw)`) is never plain, so hashing helpers in other functions do not produce findings.
   */
  const isPlainPassword = (node: ts.Expression, depth = 0): boolean => {
    if (depth > 3) return false;
    const inner = unwrap(node);
    if (ts.isPropertyAccessExpression(inner) || ts.isElementAccessExpression(inner)) {
      let base: ts.Expression = inner;
      while (ts.isPropertyAccessExpression(base) || ts.isElementAccessExpression(base))
        base = unwrap(base.expression);
      if (ts.isCallExpression(base) || ts.isNewExpression(base)) return false;
      if (taint.taintOf(inner) === "request") return true;
      if (ts.isIdentifier(base) && requestAliases.has(base.text)) return true;
      return ts.isPropertyAccessExpression(inner) && PASSWORD_NAME.test(inner.name.text);
    }
    if (ts.isIdentifier(inner)) {
      const init = singleConst(inner.text);
      if (init) return isPlainPassword(init, depth + 1);
      // Bound by destructuring a request object: `const { password: plain } = req.body`.
      const sources = destructuredFrom.get(inner.text);
      if (sources?.length === 1 && sources[0]) {
        const source = unwrap(sources[0]);
        if (taint.taintOf(source) === "request") return true;
        if (ts.isIdentifier(source) && requestAliases.has(source.text)) return true;
        if (
          (ts.isPropertyAccessExpression(source) || ts.isElementAccessExpression(source)) &&
          isPlainRequestBase(source)
        )
          return true;
      }
      return PASSWORD_NAME.test(inner.text);
    }
    return false;
  };

  /** `user.password = req.body.password; user.save()` without hashing. */
  const checkPasswordAssignment = (node: ts.BinaryExpression) => {
    if (
      node.operatorToken.kind !== ts.SyntaxKind.EqualsToken ||
      !ts.isPropertyAccessExpression(node.left) ||
      !PASSWORD_NAME.test(node.left.name.text)
    )
      return;
    const receiver = unwrap(node.left.expression);
    if (!ts.isIdentifier(receiver) || !isPlainPassword(node.right)) return;
    if (!savedReceivers(node).has(receiver.text)) return;
    if (enclosingFunctionFacts(node).hasHashing) return;
    report(
      "PG-AUTH-001",
      node,
      {
        severity: "high",
        status: "suspected",
        confidence: taint.taintOf(unwrap(node.right)) === "request" ? "medium" : "low",
        flow: "password value assigned to a model instance, then save() without a hashing call in the same function",
      },
      "password:save",
    );
  };

  /** Strings and comments replaced by neutral text so `?`, `,` and `(` inside them are not counted. */
  const cleanSql = (sql: string) =>
    sql.replace(/'(?:[^']|'')*'|"[^"]*"|--[^\n]*|\/\*[\s\S]*?\*\//g, (match) =>
      match.startsWith("'") ? "'_'" : match.startsWith('"') ? match.replace(/[^\w"]/g, "_") : " ",
    );

  /** Text inside the parentheses that open at `open`, and the index after the closing one. */
  const balancedGroup = (text: string, open: number): { inner: string; end: number } | null => {
    let depth = 0;
    for (let index = open; index < text.length; index += 1) {
      if (text[index] === "(") depth += 1;
      else if (text[index] === ")") {
        depth -= 1;
        if (depth === 0) return { inner: text.slice(open + 1, index), end: index + 1 };
      }
    }
    return null;
  };

  const splitTopLevel = (text: string): string[] => {
    const parts: string[] = [];
    let depth = 0;
    let start = 0;
    for (let index = 0; index < text.length; index += 1) {
      const char = text[index];
      if (char === "(") depth += 1;
      else if (char === ")") depth -= 1;
      else if (char === "," && depth === 0) {
        parts.push(text.slice(start, index).trim());
        start = index + 1;
      }
    }
    parts.push(text.slice(start).trim());
    return parts;
  };

  /** Position (`$2`, `?`) or name (`@pw`, `:pw`) of a bind placeholder; undefined for anything else. */
  const placeholderRef = (rawToken: string, before: string): number | string | undefined => {
    const token = rawToken.replace(/::\w+$/, "").trim();
    const numbered = /^\$(\d{1,3})$/.exec(token);
    if (numbered?.[1]) return Number(numbered[1]) - 1;
    if (token === "?") return (before.match(/\?/g) ?? []).length;
    const named = /^[:@$](\w+)$/.exec(token);
    return named?.[1];
  };

  const SQL_HASH_TEXT = /crypt\(|digest\(|hash|sha\d|md5|argon/i;

  /** Raw SQL `INSERT ... (password) VALUES ($1)` / `SET password = $1` fed a plain value. */
  const checkRawSqlPassword = (call: ts.CallExpression, name: string) => {
    if (!["query", "execute", "run", "exec", "raw"].includes(name)) return;
    const literalText = (argument: ts.Expression | undefined): string | null => {
      let node = argument ? unwrap(argument) : undefined;
      if (node && ts.isIdentifier(node)) {
        const init = singleConst(node.text);
        node = init ? unwrap(init) : undefined;
      }
      return node && ts.isStringLiteralLike(node) ? node.text : null;
    };
    const raw = literalText(call.arguments[0]);
    if (!raw || raw.length > 2000 || SQL_HASH_TEXT.test(raw)) return;
    let params: ts.Expression | undefined = call.arguments[1]
      ? unwrap(call.arguments[1])
      : undefined;
    if (params && ts.isIdentifier(params)) {
      const init = singleConst(params.text);
      params = init ? unwrap(init) : undefined;
    }
    if (!params || !(ts.isArrayLiteralExpression(params) || ts.isObjectLiteralExpression(params)))
      return;
    const sql = cleanSql(raw);
    if (!/\b(insert|update)\b/i.test(sql) || !/\b(password|passwd|pwd|pass)\b/i.test(sql)) return;

    // Which bind placeholder feeds the password column: a ref, "none" (a literal/function value
    // there) or "unparsed" (structure not understood).
    let ref: number | string | "none" | "unparsed" = "unparsed";
    const insert = /insert\s+(?:or\s+\w+\s+)?into\s+[^\s(]{1,200}\s*\(/i.exec(sql);
    if (insert) {
      const columnGroup = balancedGroup(sql, insert.index + insert[0].length - 1);
      const values = columnGroup ? /^\s*values\s*\(/i.exec(sql.slice(columnGroup.end)) : null;
      const valueGroup =
        columnGroup && values ? balancedGroup(sql, columnGroup.end + values[0].length - 1) : null;
      if (columnGroup && valueGroup) {
        const columns = splitTopLevel(columnGroup.inner).map((column) =>
          column.replace(/^.*\./, "").replace(/["`[\]]/g, ""),
        );
        const tokens = splitTopLevel(valueGroup.inner);
        const column = columns.findIndex((entry) => PASSWORD_NAME.test(entry));
        if (column >= 0 && columns.length === tokens.length) {
          ref = placeholderRef(tokens[column] ?? "", tokens.slice(0, column).join(",")) ?? "none";
        }
      }
    } else {
      const update =
        /\bset\b[\s\S]{0,500}?\b(?:password|passwd|pwd|pass)\b\s*=\s*(\$\d{1,3}|\?|[:@]\w+)/i.exec(
          sql,
        );
      if (update?.[1]) {
        const before = sql.slice(0, update.index + update[0].length - update[1].length);
        ref = placeholderRef(update[1], before) ?? "none";
      }
    }
    if (ref === "none") return;

    const entries = ts.isArrayLiteralExpression(params)
      ? params.elements.map((element, index) => [index, element] as const)
      : params.properties.flatMap((property) =>
          ts.isPropertyAssignment(property)
            ? [[property.name.getText(sourceFile), property.initializer] as const]
            : ts.isShorthandPropertyAssignment(property)
              ? [[property.name.text, property.name] as const]
              : [],
        );
    let value: ts.Expression | undefined;
    let confidence: Confidence = "low";
    if (ref === "unparsed") {
      // Column and value lists did not line up (or were not understood): fall back to any bound
      // value that is itself a plain password read, at low confidence. Request values for other
      // columns are not enough.
      value = entries.find(
        ([, element]) =>
          !ts.isSpreadElement(element) &&
          isPlainPassword(element) &&
          /pass|pwd/i.test(unwrap(element).getText(sourceFile).slice(0, 200)),
      )?.[1];
    } else {
      value = entries.find(([key]) => key === ref)?.[1];
      if (value && ts.isSpreadElement(value)) return;
      if (value && !isPlainPassword(value)) return;
      confidence = value && taint.taintOf(unwrap(value)) === "request" ? "medium" : "low";
    }
    if (!value) return;
    if (enclosingFunctionFacts(call).hasHashing) return;
    report(
      "PG-AUTH-001",
      call,
      {
        severity: "high",
        status: "suspected",
        confidence,
        flow: `password value -> raw SQL ${name}() without a hashing call in the same function`,
      },
      "password:sql",
    );
  };

  const checkSessionConfig = (call: ts.CallExpression, name: string) => {
    const module = namespaceImports.get(name);
    if (module !== "express-session" && module !== "cookie-session") return;
    const options = call.arguments[0];
    if (!options || !ts.isObjectLiteralExpression(unwrap(options))) {
      facts.usesCookieSession = true;
      return;
    }
    const properties = (unwrap(options) as ts.ObjectLiteralExpression).properties;
    const get = (props: ts.NodeArray<ts.ObjectLiteralElementLike>, key: string) =>
      props.find(
        (property): property is ts.PropertyAssignment =>
          ts.isPropertyAssignment(property) && property.name.getText(sourceFile) === key,
      );
    for (const key of ["secret", "keys"]) {
      const kind = literalValue(get(properties, key)?.initializer);
      if (kind) reportHardcodedKey(call, kind, `${module} ${key}`);
    }
    const cookie = module === "express-session" ? get(properties, "cookie")?.initializer : options;
    // `cookie: COOKIE_OPTIONS` and `sameSite: SAME_SITE` resolve through same-file consts.
    const cookieOptions = cookie ? resolveOptions(cookie, 0) : new Map<string, ts.Expression>();
    if (cookie && !cookieOptions) {
      facts.usesCookieSession = true;
      report(
        "PG-COOKIE-001",
        call,
        {
          severity: "low",
          status: "suspected",
          confidence: "low",
          flow: `${module} cookie with options not resolvable (imported/computed); flags unverified`,
        },
        `${module}-cookie`,
      );
      return;
    }
    const missing: string[] = [];
    const flag = (key: string, defaultOn: boolean) => {
      const value = cookieOptions?.get(key);
      if (value === undefined ? !defaultOn : value.kind === ts.SyntaxKind.FalseKeyword)
        missing.push(key);
    };
    flag("httpOnly", true);
    flag("secure", false);
    const sameSite = cookieOptions?.get("sameSite");
    if (!sameSite || sameSite.kind === ts.SyntaxKind.FalseKeyword) missing.push("sameSite");
    // SameSite=Strict keeps the session cookie off every cross-site request, so it is not CSRF-able.
    const isStrict =
      sameSite !== undefined &&
      ts.isStringLiteralLike(unwrap(sameSite)) &&
      (unwrap(sameSite) as ts.StringLiteral).text.toLowerCase() === "strict";
    if (isStrict) facts.strictSession = true;
    else facts.usesCookieSession = true;
    if (missing.length > 0) {
      report(
        "PG-COOKIE-001",
        call,
        {
          severity: "medium",
          status: "suspected",
          confidence: "medium",
          flow: `${module} cookie without ${missing.join(", ")}`,
        },
        `${module}-cookie`,
      );
    }
  };

  const checkResponseCookie = (call: ts.CallExpression, name: string) => {
    const receiver = calleeReceiver(call);
    const receiverPath = receiver ? accessPath(receiver) : null;
    if (name !== "cookie" || !receiverPath || !/^(res|response|reply)$/.test(receiverPath)) return;
    reportCookieCall(call, call.arguments[0], call.arguments[1], call.arguments[2], "res.cookie");
  };

  /** Cookie APIs other than `res.cookie`: Next.js, Koa, NextResponse and Hono. */
  const checkNextCookie = (call: ts.CallExpression, name: string) => {
    if (name === "setCookie") {
      // Hono: setCookie(c, name, value, options)
      if (
        ts.isIdentifier(call.expression) &&
        namedImports.get(call.expression.text) === "hono/cookie:setCookie"
      )
        reportCookieCall(
          call,
          call.arguments[1],
          call.arguments[2],
          call.arguments[3],
          "setCookie",
        );
      return;
    }
    if (name !== "set") return;
    const receiver = calleeReceiver(call);
    if (!receiver) return;
    const receiverPath = accessPath(receiver);
    if (receiverPath && /^(ctx|context)\.cookies$/.test(receiverPath)) {
      // Koa sets httpOnly unless told otherwise.
      reportCookieCall(
        call,
        call.arguments[0],
        call.arguments[1],
        call.arguments[2],
        "ctx.cookies.set",
        { httpOnly: true },
      );
      return;
    }
    if (
      receiverPath &&
      /^(res|response|nextResponse)\.cookies$/i.test(receiverPath) &&
      facts.imports.includes("next/server")
    ) {
      reportCookieCall(
        call,
        call.arguments[0],
        call.arguments[1],
        call.arguments[2],
        "response.cookies.set",
      );
      return;
    }
    if (!isNextCookieStore(receiver, 0)) return;
    const first = call.arguments[0] ? unwrap(call.arguments[0]) : undefined;
    if (first && ts.isObjectLiteralExpression(first)) {
      const options = resolveOptions(first, 0);
      const named = options?.get("name");
      const value = options?.get("value");
      reportCookieCall(call, named, value, first, "cookies().set");
      return;
    }
    reportCookieCall(call, first, call.arguments[1], call.arguments[2], "cookies().set");
  };

  /** Identifier words of an expression's text (`accessToken` -> access, token). */
  const identifierWords = (text: string): string[] =>
    (text.match(/[A-Za-z_$][\w$]*/g) ?? []).flatMap((identifier) =>
      identifier
        .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
        .split(/[\s_$]+/)
        .map((word) => word.toLowerCase()),
    );

  /**
   * Shared judgement for response-cookie APIs. Only cookies that look like a session or auth
   * cookie (by name, or by a session/token value) are judged. If the options object cannot be
   * resolved, a session-like cookie is still reported, at low confidence, with the flags unverified.
   */
  const reportCookieCall = (
    call: ts.CallExpression,
    cookieName: ts.Expression | undefined,
    cookieValue: ts.Expression | undefined,
    options: ts.Expression | undefined,
    api: string,
    defaults: { httpOnly?: boolean } = {},
  ) => {
    const nameNode = cookieName ? unwrap(cookieName) : undefined;
    const nameText =
      nameNode && ts.isStringLiteralLike(nameNode)
        ? nameNode.text
        : (nameNode?.getText(sourceFile).slice(0, 80) ?? "");
    const nameWords = identifierWords(nameText.replace(/^__(host|secure)-/i, ""));
    const isStrongName =
      /connect\.sid/i.test(nameText) || nameWords.some((word) => SESSION_NAME_WORDS.has(word));
    const isWeakName = !isStrongName && nameWords.some((word) => WEAK_NAME_WORDS.has(word));
    const isSessionLike = isStrongName || isWeakName;
    // A hand-rolled session cookie is a cookie session for PG-CSRF-001.
    if (isStrongName) facts.usesCookieSession = true;
    // A cookie with a non-session name still counts when it carries a session or token value.
    const valueNode = cookieValue ? unwrap(cookieValue) : undefined;
    const carriesToken =
      !isSessionLike &&
      valueNode !== undefined &&
      !ts.isStringLiteralLike(valueNode) &&
      identifierWords(valueNode.getText(sourceFile).slice(0, 200)).some((word) =>
        SESSION_VALUE_WORDS.has(word),
      );
    if (!isSessionLike && !carriesToken) return;
    const severity = isStrongName ? "medium" : "low";
    const kind = isSessionLike ? "session-like name" : "session or token value";
    let resolved: Map<string, ts.Expression> | null = new Map();
    if (options) resolved = resolveOptions(options, 0);
    if (!resolved) {
      report(
        "PG-COOKIE-001",
        call,
        {
          severity: "low",
          status: "suspected",
          confidence: "low",
          flow: `${api}(${kind}) with options not resolvable (imported/computed); flags unverified`,
        },
        `${api}:${nameText}`,
      );
      return;
    }
    const isTrue = (key: string) => resolved.get(key)?.kind === ts.SyntaxKind.TrueKeyword;
    const hasSameSite = (() => {
      const value = resolved.get("sameSite");
      return value !== undefined && value.kind !== ts.SyntaxKind.FalseKeyword;
    })();
    const httpOnlyDefault =
      defaults.httpOnly === true && resolved.get("httpOnly")?.kind !== ts.SyntaxKind.FalseKeyword;
    const missing = [
      ...(isTrue("httpOnly") || httpOnlyDefault ? [] : ["httpOnly"]),
      ...(isTrue("secure") ? [] : ["secure"]),
      ...(hasSameSite ? [] : ["sameSite"]),
    ];
    if (missing.length === 0) return;
    report(
      "PG-COOKIE-001",
      call,
      {
        severity,
        status: "suspected",
        confidence: isStrongName ? "medium" : "low",
        flow: `${api}(${kind}) without ${missing.join(", ")}`,
      },
      `${api}:${nameText}`,
    );
  };

  const checkRoute = (call: ts.CallExpression, name: string) => {
    const receiver = calleeReceiver(call);
    const receiverPath = receiver ? accessPath(receiver) : null;
    if (!receiverPath || !ROUTE_RECEIVERS.test(receiverPath)) return;
    if (!["post", "put", "patch", "delete"].includes(name)) return;
    const route = call.arguments[0];
    if (!route || !ts.isStringLiteralLike(unwrap(route)) || call.arguments.length < 2) return;
    const line = lineOf(call);
    if (name === "post") facts.stateChangingRoutes.push(line);
    else facts.preflightRoutes.push(line);
    const routePath = (unwrap(route) as ts.StringLiteral).text;
    if (name === "post" && AUTH_ROUTE.test(routePath)) facts.authRoutes.push({ line, routePath });
  };

  const checkPlaintextPassword = (object: ts.ObjectLiteralExpression) => {
    for (const property of object.properties) {
      let value: ts.Expression | null = null;
      if (
        ts.isPropertyAssignment(property) &&
        PASSWORD_NAME.test(property.name.getText(sourceFile))
      )
        value = property.initializer;
      else if (ts.isShorthandPropertyAssignment(property) && PASSWORD_NAME.test(property.name.text))
        value = property.name;
      if (!value) continue;
      const node = unwrap(value);
      if (!isPlainPassword(node)) continue;
      // `new Model({ password })` persists through a later `instance.save()`.
      if (
        object.parent &&
        ts.isNewExpression(object.parent) &&
        object.parent.arguments?.[0] === object
      ) {
        const created = object.parent;
        const target = created.parent;
        const savedHere =
          ts.isIdentifier(created.expression) &&
          /^[A-Z]/.test(created.expression.text) &&
          ((ts.isVariableDeclaration(target) &&
            ts.isIdentifier(target.name) &&
            savedReceivers(created).has(target.name.text)) ||
            (ts.isPropertyAccessExpression(target) && target.name.text === "save"));
        if (!savedHere || enclosingFunctionFacts(created).hasHashing) continue;
        report(
          "PG-AUTH-001",
          property,
          {
            severity: "high",
            status: "suspected",
            confidence: taint.taintOf(node) === "request" ? "medium" : "low",
            flow: "password value -> new Model(...).save() without a hashing call in the same function",
          },
          "password:save",
        );
        continue;
      }
      // Find the persistence call this object belongs to (directly or under `data:`).
      let current: ts.Node = object;
      let call: ts.CallExpression | null = null;
      for (let depth = 0; depth < 4 && current.parent; depth += 1) {
        current = current.parent;
        if (ts.isCallExpression(current)) {
          call = current;
          break;
        }
      }
      if (!call || !PERSIST_METHODS.has(calleeName(call) ?? "")) continue;
      if (enclosingFunctionFacts(call).hasHashing) continue;
      report(
        "PG-AUTH-001",
        property,
        {
          severity: "high",
          status: "suspected",
          confidence: taint.taintOf(node) === "request" ? "medium" : "low",
          flow: `password value -> ${calleeName(call)}() without a hashing call in the same function`,
        },
        `password:${calleeName(call)}`,
      );
    }
  };

  // Pass 2: rules.
  const visit = (node: ts.Node): void => {
    if (ts.isBinaryExpression(node)) checkPasswordAssignment(node);
    if (ts.isCallExpression(node)) {
      const name = calleeName(node);
      if (name) {
        checkSql(node, name);
        checkCommand(node);
        checkSsrf(node, name);
        checkPath(node, name);
        checkCrypto(node, name);
        checkSessionConfig(node, name);
        checkResponseCookie(node, name);
        checkNextCookie(node, name);
        checkCors(node, name);
        checkRawSqlPassword(node, name);
        checkRoute(node, name);
        if (name === "insertAdjacentHTML" && node.arguments[1])
          checkHtmlSink("PG-XSS-001", node, node.arguments[1], "insertAdjacentHTML");
        if (
          (name === "write" || name === "writeln") &&
          accessPath(calleeReceiver(node) ?? node.expression) === "document" &&
          node.arguments[0]
        )
          checkHtmlSink("PG-XSS-001", node, node.arguments[0], `document.${name}`);
      }
    } else if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isPropertyAccessExpression(node.left) &&
      (node.left.name.text === "innerHTML" || node.left.name.text === "outerHTML")
    ) {
      checkHtmlSink("PG-XSS-001", node, node.right, node.left.name.text);
    } else if (
      ts.isJsxAttribute(node) &&
      node.name.getText(sourceFile) === "dangerouslySetInnerHTML"
    ) {
      const initializer = node.initializer;
      if (initializer && ts.isJsxExpression(initializer) && initializer.expression) {
        const object = unwrap(initializer.expression);
        if (ts.isObjectLiteralExpression(object)) {
          const html = object.properties.find(
            (property): property is ts.PropertyAssignment =>
              ts.isPropertyAssignment(property) && property.name.getText(sourceFile) === "__html",
          );
          if (html) checkHtmlSink("PG-XSS-002", node, html.initializer, "dangerouslySetInnerHTML");
        } else {
          checkHtmlSink("PG-XSS-002", node, object, "dangerouslySetInnerHTML");
        }
      }
    } else if (ts.isObjectLiteralExpression(node)) {
      checkPlaintextPassword(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);

  if (facts.imports.includes("method-override")) raiseExposure("unknown");
  facts.imports = [...new Set(facts.imports)];
  return { findings, facts, hasParseErrors, cappedRules: [...cappedRules] };
}
