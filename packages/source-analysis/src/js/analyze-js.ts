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
/** Process-level values that a request cannot influence. */
const TRUSTED_PATHS = new Set(["process.execPath", "process.platform", "__dirname", "__filename"]);
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

  const INFERRED_NOTE =
    "value inferred to be fixed through a constant, allowlist or alias; verify it cannot hold request input";

  const checkSql = (call: ts.CallExpression, name: string) => {
    if (
      name === "$queryRawUnsafe" ||
      name === "$executeRawUnsafe" ||
      (name === "raw" && accessPath(calleeReceiver(call) ?? call.expression) === "Prisma")
    ) {
      const argument = call.arguments[0];
      if (argument && isStrictInert(argument, "sql")) return;
      const inferred = argument !== undefined && isInertValue(argument, "sql");
      // Prisma.raw() splices its text into the statement as-is, so a value that cannot be shown
      // to be fixed is reported at low confidence (the caller may well pass user input).
      const isRawHelper = name === "raw";
      // Request input passed straight in is as dangerous as a string built from it.
      if (
        argument &&
        (isRawHelper || taint.isDynamicString(argument) || taint.taintOf(argument) === "request")
      ) {
        const evidence = classify(
          argument,
          false,
          { severity: "high", status: "confirmed", confidence: "high" },
          isRawHelper && !taint.isDynamicString(argument)
            ? { severity: "medium", status: "suspected", confidence: "low" }
            : { severity: "high", status: "suspected", confidence: "medium" },
          name,
        );
        if (evidence)
          report("PG-SQL-002", call, inferred ? demote(evidence, INFERRED_NOTE) : evidence, name);
      }
      return;
    }
    if (name !== "query" && name !== "execute") return;
    const argument = sqlArgument(call);
    if (!argument) return;
    // Fixed text (literals, numeric coercion, a literal module constant) is not reported. Values
    // that are only inferred to be fixed (allowlist tables, aliases, local constants) are kept at
    // low confidence.
    if (isStrictInert(argument, "sql")) return;
    const inferred = isInertValue(argument, "sql");
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
    if (evidence)
      report("PG-SQL-001", call, inferred ? demote(evidence, INFERRED_NOTE) : evidence, label);
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
      if (isStaticString(first) || isStrictInert(first, "cmd")) return;
      const inferred = isInertValue(first, "cmd");
      const evidence = classify(
        first,
        false,
        { severity: "critical", status: "confirmed", confidence: "high" },
        taint.isDynamicString(first)
          ? { severity: "high", status: "suspected", confidence: "medium" }
          : null,
        `child_process.${member}`,
      );
      if (evidence)
        report("PG-CMD-001", call, inferred ? demote(evidence, INFERRED_NOTE) : evidence, member);
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
        !isStaticString(script) &&
        !isStrictInert(script, "cmd")
      ) {
        const inferred = isInertValue(script, "cmd");
        const evidence = classify(
          script,
          false,
          { severity: "critical", status: "confirmed", confidence: "high" },
          { severity: "high", status: "suspected", confidence: "medium" },
          `child_process.${member}("${program.text}", ["${flag.text}", ...])`,
        );
        if (evidence)
          report(
            "PG-CMD-001",
            call,
            inferred ? demote(evidence, INFERRED_NOTE) : evidence,
            `${member}-shell-c`,
          );
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

  /** `"https://api.example.com/" + x` or a template starting with a fixed scheme and host. */
  const hasFixedHost = (target: ts.Expression): boolean => {
    let head: ts.Node = unwrap(target);
    while (ts.isBinaryExpression(head) && head.operatorToken.kind === ts.SyntaxKind.PlusToken)
      head = unwrap(head.left);
    const text = ts.isTemplateExpression(head)
      ? head.head.text
      : ts.isStringLiteralLike(head)
        ? head.text
        : "";
    return /^https?:\/\/[^/$\s{}]+\//.test(text);
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
    // An exact hostname allowlist plus a protocol check on the same URL, before the request.
    const subject = canonicalSubject(target);
    const hostGuard = subject.stable ? guardHolds(call, "host", subject.text) : null;
    const protocolGuard = subject.stable ? guardHolds(call, "protocol", subject.text) : null;
    const hasHost = hostGuard !== null;
    const evidence = classify(
      target,
      false,
      { severity: "high", status: "suspected", confidence: "high" },
      null,
      `${name}() request URL`,
    );
    if (!evidence) return;
    if (hostGuard !== null && protocolGuard !== null) {
      // Recognised, not proven: keep the finding at low confidence.
      report(
        "PG-SSRF-001",
        call,
        demote(
          evidence,
          `hostname guard recognised at L${lineOf(hostGuard)} and protocol guard at L${lineOf(protocolGuard)}; verify they dominate the request`,
        ),
        name,
      );
    } else if (hasHost) {
      // Fail closed: the host is checked but the protocol is not, so keep a weaker finding.
      report(
        "PG-SSRF-001",
        call,
        {
          ...evidence,
          severity: "medium",
          confidence: "low",
          flow: `${evidence.flow} (hostname checked, protocol not checked)`,
        },
        name,
      );
    } else if (hasFixedHost(target)) {
      report(
        "PG-SSRF-001",
        call,
        {
          ...evidence,
          severity: "medium",
          confidence: "low",
          flow: `${evidence.flow} (host is fixed; only the path is user-controlled)`,
        },
        name,
      );
    } else {
      report("PG-SSRF-001", call, evidence, name);
    }
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
    // A `realpath`/`path.resolve` result checked with startsWith(<fixed root> + sep) on an earlier
    // statement that dominates the file operation. The variable must be bound once and never
    // changed, and its initializer must be the resolving call itself.
    const pathArgument = unwrap(first);
    let pathGuard: ts.Node | null = null;
    if (ts.isIdentifier(pathArgument)) {
      const init = soleConst(pathArgument.text, pathArgument);
      const initializer = init ? unwrap(init) : null;
      const isResolved =
        initializer !== null && ts.isCallExpression(initializer) && isNormalizingCall(initializer);
      if (isResolved && isStableName(pathArgument.text, true))
        pathGuard = guardHolds(call, "prefix", pathArgument.text);
    }
    const evidence = classify(
      first,
      false,
      { severity: "high", status: "suspected", confidence: "high" },
      null,
      `${isResponseFile ? "res" : "fs"}.${name}`,
    );
    if (evidence)
      report(
        "PG-PATH-001",
        call,
        pathGuard
          ? demote(
              evidence,
              `guard recognised at L${lineOf(pathGuard)} (startsWith(<root> + sep)); verify it dominates the file operation, and that the guard root is not wider than the resolve base (it is not compared with it)`,
            )
          : evidence,
        name,
      );
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
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "encode" &&
      ts.isNewExpression(unwrap(node.expression.expression)) &&
      calleeName(unwrap(node.expression.expression) as ts.NewExpression) === "TextEncoder" &&
      bindingCount.get("TextEncoder") === undefined &&
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

  /**
   * A fixed string at the sink: a literal, or a name whose only binding is a constant (or a
   * never-reassigned `let`) initialised with one. `via` names the constant for the evidence.
   */
  const fixedString = (
    expression: ts.Expression | undefined,
    depth = 0,
  ): { text: string; via: string | null } | null => {
    if (!expression || depth > 3) return null;
    const node = unwrap(expression);
    if (ts.isStringLiteralLike(node)) return { text: node.text, via: null };
    if (ts.isIdentifier(node)) {
      const init = soleConst(node.text, node);
      const resolved = init ? fixedString(init, depth + 1) : null;
      return resolved ? { text: resolved.text, via: resolved.via ?? node.text } : null;
    }
    return null;
  };
  /** `literalValue`, also following a sole-binding constant: `jwt.sign(p, SECRET)`. */
  const fixedKey = (
    expression: ts.Expression | undefined,
  ): { kind: "literal" | "fallback"; via: string | null } | null => {
    const direct = literalValue(expression);
    if (direct) return { kind: direct, via: null };
    if (!expression) return null;
    const node = unwrap(expression);
    if (!ts.isIdentifier(node)) return null;
    const init = soleConst(node.text, node);
    const kind = init ? literalValue(init) : null;
    return kind ? { kind, via: node.text } : null;
  };

  const reportHardcodedKey = (
    node: ts.Node,
    key: { kind: "literal" | "fallback"; via: string | null },
    where: string,
  ) => {
    const { kind } = key;
    const held = key.via === null ? "" : ` held in constant ${key.via}`;
    report(
      "PG-CRYPTO-002",
      node,
      kind === "literal"
        ? {
            severity: "high",
            status: "confirmed",
            confidence: "high",
            flow: `string literal (value redacted)${held} used as ${where}`,
          }
        : {
            severity: "medium",
            status: "suspected",
            confidence: "medium",
            flow: `hardcoded fallback literal (value redacted)${held} used as ${where} when the environment value is missing`,
          },
      where,
    );
  };

  const checkCrypto = (call: ts.CallExpression, name: string) => {
    const resolved = moduleOfCall(call);
    const isCryptoModule = resolved !== null && /^(node:)?crypto$/.test(resolved.module);
    const member = resolved?.member ?? name;
    if ((isCryptoModule || name === "createHash") && member === "createHash") {
      const algorithm = fixedString(call.arguments[0]);
      if (algorithm && /^(md5|sha1)$/i.test(algorithm.text)) {
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
              flow: `${algorithm.text}${algorithm.via ? ` (held in constant ${algorithm.via})` : ""} digest of a password-like value`,
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
      const kind = fixedKey(call.arguments[1]);
      if (kind) reportHardcodedKey(call, kind, `${member} key`);
      const algorithm = fixedString(call.arguments[0]);
      if (algorithm && /(^des|rc4|rc2|^bf|blowfish|-ecb$)/i.test(algorithm.text)) {
        report(
          "PG-CRYPTO-003",
          call,
          {
            severity: "medium",
            status: "confirmed",
            confidence: "high",
            flow: `weak cipher "${algorithm.text}"${algorithm.via ? ` (held in constant ${algorithm.via})` : ""}`,
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
      const kind = fixedKey(call.arguments[1]);
      if (kind) reportHardcodedKey(call, kind, "HMAC key");
    }
    const receiverPath = calleeReceiver(call)
      ? accessPath(calleeReceiver(call) as ts.Expression)
      : null;
    const isJwt =
      (resolved !== null && resolved.module === "jsonwebtoken") ||
      (receiverPath !== null && /^(jwt|jsonwebtoken)$/.test(receiverPath));
    if (isJwt && (member === "sign" || member === "verify")) {
      const kind = fixedKey(call.arguments[1]);
      if (kind) reportHardcodedKey(call, kind, `JWT ${member} secret`);
    }
    // jose: `new SignJWT(claims)....sign(key)` and `jwtVerify(token, key)`.
    const receiverNode = calleeReceiver(call);
    if (
      member === "sign" &&
      receiverNode &&
      receiverNode.getWidth(sourceFile) < 2000 &&
      /\bnew\s+SignJWT\s*\(/.test(receiverNode.getText(sourceFile)) &&
      importSet.has("jose")
    ) {
      const kind = fixedKey(call.arguments[0]);
      if (kind) reportHardcodedKey(call, kind, "JWT sign secret");
    }
    if (name === "jwtVerify" && resolved?.module === "jose") {
      const kind = fixedKey(call.arguments[1]);
      if (kind) reportHardcodedKey(call, kind, "JWT verify secret");
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
  /** Marks every identifier a write target names: `x =`, `[x] =`, `({ a, b: c = 1 } =`, `for (x of`. */
  const markWrite = (target: ts.Node): void => {
    const node = ts.isExpression(target) ? unwrap(target) : target;
    if (ts.isIdentifier(node)) {
      reassigned.add(node.text);
    } else if (ts.isArrayLiteralExpression(node)) {
      for (const element of node.elements)
        markWrite(ts.isSpreadElement(element) ? element.expression : element);
    } else if (ts.isObjectLiteralExpression(node)) {
      for (const property of node.properties) {
        if (ts.isPropertyAssignment(property)) markWrite(property.initializer);
        else if (ts.isShorthandPropertyAssignment(property)) reassigned.add(property.name.text);
        else if (ts.isSpreadAssignment(property)) markWrite(property.expression);
      }
    } else if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken
    ) {
      markWrite(node.left);
    }
  };
  const collectAssignments = (node: ts.Node): void => {
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
    ) {
      markWrite(node.left);
    } else if (
      (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) &&
      (node.operator === ts.SyntaxKind.PlusPlusToken ||
        node.operator === ts.SyntaxKind.MinusMinusToken)
    ) {
      markWrite(node.operand);
    } else if (
      (ts.isForOfStatement(node) || ts.isForInStatement(node)) &&
      !ts.isVariableDeclarationList(node.initializer)
    ) {
      markWrite(node.initializer);
    }
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

  // ---- Binding and mutation facts used to prove a value or guard sound (PG-SQL/CMD/PATH/SSRF). ----
  // Every binding of a name anywhere in the file counts, so a parameter, destructured variable,
  // catch variable or function with the same name makes a module constant unusable as evidence.
  const bindingCount = new Map<string, number>();
  const mutatedRoots = new Set<string>();
  const tableMisuse = new Set<string>();
  /** Names used as more than a property read or a request argument: aliased, passed on, assigned. */
  const nonReadUses = new Map<string, ts.Node[]>();
  const seenVars = new Map<ts.Node, Set<string>>();
  const countBinding = (name: string) => bindingCount.set(name, (bindingCount.get(name) ?? 0) + 1);
  const rootName = (expression: ts.Expression): string | null => {
    let current = unwrap(expression);
    for (;;) {
      if (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current))
        current = unwrap(current.expression);
      else if (ts.isCallExpression(current)) current = unwrap(current.expression);
      else break;
    }
    return ts.isIdentifier(current) ? current.text : null;
  };
  const rootIdentifier = (expression: ts.Expression): ts.Identifier | null => {
    let current = unwrap(expression);
    for (;;) {
      if (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current))
        current = unwrap(current.expression);
      else if (ts.isCallExpression(current)) current = unwrap(current.expression);
      else break;
    }
    return ts.isIdentifier(current) ? current : null;
  };
  const isWriteTarget = (access: ts.Node): boolean => {
    const parent = access.parent;
    return (
      (ts.isBinaryExpression(parent) &&
        parent.left === access &&
        parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
        parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment) ||
      ts.isDeleteExpression(parent) ||
      ((ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent)) &&
        (parent.operator === ts.SyntaxKind.PlusPlusToken ||
          parent.operator === ts.SyntaxKind.MinusMinusToken))
    );
  };
  const MUTATING_METHOD =
    /^(set|add|delete|clear|push|pop|shift|unshift|splice|sort|reverse|append|fill|copyWithin)/;
  const READ_ONLY_METHODS = new Set(["get", "has", "includes", "indexOf"]);
  const collectFacts = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) || ts.isParameter(node)) {
      const names: string[] = [];
      bindingNames(node.name, names);
      names.forEach(countBinding);
      if (
        ts.isVariableDeclaration(node) &&
        ts.isVariableDeclarationList(node.parent) &&
        (node.parent.flags & (ts.NodeFlags.Let | ts.NodeFlags.Const)) === 0
      ) {
        // `var` declared again in the same function: the repeat with a value is a reassignment.
        let owner: ts.Node | undefined = node.parent;
        while (owner && !ts.isFunctionLike(owner) && !ts.isSourceFile(owner)) owner = owner.parent;
        const seen = seenVars.get(owner ?? sourceFile) ?? new Set<string>();
        seenVars.set(owner ?? sourceFile, seen);
        for (const name of names) {
          if (seen.has(name) && node.initializer) reassigned.add(name);
          seen.add(name);
        }
      }
    } else if (
      (ts.isFunctionDeclaration(node) ||
        ts.isFunctionExpression(node) ||
        ts.isClassDeclaration(node) ||
        ts.isClassExpression(node) ||
        ts.isEnumDeclaration(node) ||
        ts.isImportSpecifier(node) ||
        ts.isImportClause(node) ||
        ts.isNamespaceImport(node)) &&
      node.name &&
      ts.isIdentifier(node.name)
    ) {
      countBinding(node.name.text);
    } else if (ts.isModuleDeclaration(node) && ts.isIdentifier(node.name)) {
      countBinding(node.name.text);
    }
    // Writes through a property or element, or a mutating call, change what a value holds.
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
    ) {
      const left = unwrap(node.left);
      if (!ts.isIdentifier(left)) {
        const root = rootName(left);
        if (root) mutatedRoots.add(root);
      }
    } else if (
      (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) &&
      (node.operator === ts.SyntaxKind.PlusPlusToken ||
        node.operator === ts.SyntaxKind.MinusMinusToken)
    ) {
      const root = rootName(node.operand);
      if (root) mutatedRoots.add(root);
    } else if (ts.isDeleteExpression(node)) {
      const root = rootName(node.expression);
      if (root) mutatedRoots.add(root);
    } else if (ts.isCallExpression(node)) {
      const callee = accessPath(node.expression);
      if (
        callee !== null &&
        /^(Object\.(assign|defineProperty|defineProperties|setPrototypeOf)|Reflect\.(set|defineProperty|deleteProperty))$/.test(
          callee,
        ) &&
        node.arguments[0]
      ) {
        const root = rootName(node.arguments[0]);
        if (root) mutatedRoots.add(root);
      }
      const target = unwrap(node.expression);
      if (ts.isPropertyAccessExpression(target) && MUTATING_METHOD.test(target.name.text)) {
        const path = accessPath(target.expression) ?? "";
        const root = rootName(target.expression);
        if (root && !/(^|\.)searchParams$/.test(path)) mutatedRoots.add(root);
      }
    }
    // A reference that is not a plain read (`T[k]`, `T.k`, `T.get(k)`, `k in T`) may change the
    // table or let it escape, so it is not a fixed allowlist.
    if (ts.isIdentifier(node) && node.parent) {
      let current: ts.Node = node;
      while (
        current.parent &&
        (ts.isParenthesizedExpression(current.parent) ||
          ts.isAsExpression(current.parent) ||
          ts.isNonNullExpression(current.parent) ||
          ts.isSatisfiesExpression(current.parent)) &&
        current.parent.expression === current
      )
        current = current.parent;
      const parent = current.parent;
      const isDeclaration =
        (ts.isVariableDeclaration(parent) && parent.name === current) ||
        (ts.isParameter(parent) && parent.name === current) ||
        (ts.isPropertyAccessExpression(parent) && parent.name === current) ||
        (ts.isPropertyAssignment(parent) && parent.name === current) ||
        (ts.isBindingElement(parent) &&
          (parent.name === current || parent.propertyName === current)) ||
        ((ts.isFunctionDeclaration(parent) || ts.isFunctionExpression(parent)) &&
          parent.name === current) ||
        ((ts.isMethodDeclaration(parent) || ts.isPropertyDeclaration(parent)) &&
          parent.name === current) ||
        ts.isTypeNode(parent) ||
        ts.isQualifiedName(parent) ||
        ts.isImportSpecifier(parent) ||
        ts.isImportClause(parent) ||
        ts.isNamespaceImport(parent);
      if (!isDeclaration) {
        let isRead = false;
        if (ts.isPropertyAccessExpression(parent) && parent.expression === current) {
          const grand = parent.parent;
          isRead =
            ts.isCallExpression(grand) && grand.expression === parent
              ? READ_ONLY_METHODS.has(parent.name.text)
              : !isWriteTarget(parent);
        } else if (ts.isElementAccessExpression(parent) && parent.expression === current) {
          isRead = !isWriteTarget(parent);
        } else if (
          ts.isBinaryExpression(parent) &&
          parent.operatorToken.kind === ts.SyntaxKind.InKeyword &&
          parent.right === current
        ) {
          isRead = true;
        }
        if (!isRead) tableMisuse.add(node.text);
        if (!isRead) {
          const uses = nonReadUses.get(node.text) ?? [];
          uses.push(current);
          nonReadUses.set(node.text, uses);
        }
      }
    }
    ts.forEachChild(node, collectFacts);
  };
  collectFacts(sourceFile);
  const HTTP_CLIENTS = new Set([...HTTP_CLIENT_MODULES, "ky", "ofetch", "cross-fetch"]);
  const LOG_METHODS = /^(log|info|warn|error|debug|trace)$/;
  /** A call that only reads its arguments: a real HTTP client, a logger, or a lookup in a literal list. */
  const isTrustedReadCall = (call: ts.CallExpression): boolean => {
    const callee = unwrap(call.expression);
    if (ts.isIdentifier(callee)) {
      if (callee.text === "fetch" || callee.text === "String")
        return bindingCount.get(callee.text) === undefined;
      const module = namespaceImports.get(callee.text);
      if (module !== undefined && HTTP_CLIENTS.has(module))
        return bindingCount.get(callee.text) === 1;
    }
    const resolved = moduleOfCall(call);
    if (resolved !== null && HTTP_CLIENTS.has(resolved.module.split("/")[0] ?? "")) return true;
    if (ts.isPropertyAccessExpression(callee)) {
      const path = accessPath(callee.expression);
      if (path === "console" && bindingCount.get("console") === undefined) return true;
      if (path !== null && /^(log|logger)$/i.test(path) && LOG_METHODS.test(callee.name.text))
        return true;
      if (/^(has|includes|indexOf)$/.test(callee.name.text))
        return isStringCollection(callee.expression);
    }
    return false;
  };
  const isReadOnlyUse = (use: ts.Node): boolean => {
    let parent = use.parent;
    // `log.info({ url }, "msg")`: the value is only placed in an object handed to a logger.
    if (
      (ts.isShorthandPropertyAssignment(parent) ||
        (ts.isPropertyAssignment(parent) && parent.initializer === use)) &&
      ts.isObjectLiteralExpression(parent.parent)
    ) {
      const object = parent.parent;
      const call = object.parent;
      return (
        ts.isCallExpression(call) &&
        call.arguments.some((argument) => argument === object) &&
        isTrustedReadCall(call)
      );
    }
    parent = use.parent;
    if (ts.isCallExpression(parent) && parent.arguments.some((argument) => argument === use))
      return isTrustedReadCall(parent);
    if (
      ts.isNewExpression(parent) &&
      calleeName(parent) === "URL" &&
      parent.arguments?.some((argument) => argument === use)
    )
      return bindingCount.get("URL") === undefined;
    return (
      ts.isPropertyAccessExpression(parent) &&
      parent.expression === use &&
      /^(toString|valueOf)$/.test(parent.name.text)
    );
  };
  const escapeCache = new Map<string, boolean>();
  /** The value is aliased, passed to an unknown function, or assigned: it may be changed there. */
  const escapesAsSubject = (name: string): boolean => {
    let escaped = escapeCache.get(name);
    if (escaped === undefined) {
      escaped = (nonReadUses.get(name) ?? []).some((use) => !isReadOnlyUse(use));
      escapeCache.set(name, escaped);
    }
    return escaped;
  };
  /** A module constant that no other binding of the same name can shadow. */
  const soleConst = (name: string, use: ts.Node): ts.Expression | null => {
    if (bindingCount.get(name) !== 1 || reassigned.has(name)) return null;
    const init = singleConst(name);
    if (!init) return null;
    // Block scope: the declaring block must enclose the use (module level encloses everything).
    let container: ts.Node | undefined = init.parent;
    while (
      container &&
      !ts.isBlock(container) &&
      !ts.isSourceFile(container) &&
      !ts.isModuleBlock(container) &&
      !ts.isCaseBlock(container)
    )
      container = container.parent;
    if (!container) return null;
    if (ts.isSourceFile(container)) return init;
    return container.pos <= use.pos && use.end <= container.end ? init : null;
  };
  const isExported = (initializer: ts.Expression): boolean => {
    const statement = initializer.parent.parent.parent;
    return (
      ts.isVariableStatement(statement) &&
      (ts.getCombinedModifierFlags(statement.declarationList.declarations[0] as ts.Declaration) &
        ts.ModifierFlags.Export) !==
        0
    );
  };
  /** Names of the scope's own bindings, for resolving an identifier to its declaration. */
  const scopeNames = new Map<ts.Node, Map<string, ts.Node>>();
  const namesDeclaredBy = (scope: ts.Node): Map<string, ts.Node> => {
    let names = scopeNames.get(scope);
    if (names) return names;
    const own = new Map<string, ts.Node>();
    names = own;
    const add = (binding: ts.BindingName, declaration: ts.Node) => {
      const found: string[] = [];
      bindingNames(binding, found);
      for (const name of found) own.set(name, declaration);
    };
    const isBlockScoped = (list: ts.VariableDeclarationList) =>
      (list.flags & (ts.NodeFlags.Let | ts.NodeFlags.Const)) !== 0;
    // `var` hoists to the enclosing function (or the file): it is the same binding in nested blocks.
    const hoistVars = (node: ts.Node): void => {
      if (ts.isVariableDeclarationList(node) && !isBlockScoped(node))
        for (const declaration of node.declarations) add(declaration.name, declaration);
      if (node !== scope && ts.isFunctionLike(node)) return;
      ts.forEachChild(node, hoistVars);
    };
    if (ts.isFunctionLike(scope)) {
      for (const parameter of scope.parameters) add(parameter.name, parameter);
      const body = (scope as ts.FunctionLikeDeclaration).body;
      if (body) hoistVars(body);
    }
    if (ts.isSourceFile(scope)) hoistVars(scope);
    const addStatements = (statements: readonly ts.Statement[]) => {
      for (const statement of statements) {
        if (ts.isVariableStatement(statement)) {
          if (isBlockScoped(statement.declarationList))
            for (const declaration of statement.declarationList.declarations)
              add(declaration.name, declaration);
        } else if (
          (ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)) &&
          statement.name
        )
          own.set(statement.name.text, statement);
      }
    };
    if (ts.isBlock(scope) || ts.isSourceFile(scope) || ts.isModuleBlock(scope))
      addStatements(scope.statements);
    if (ts.isCaseBlock(scope)) for (const clause of scope.clauses) addStatements(clause.statements);
    if (
      (ts.isForStatement(scope) || ts.isForInStatement(scope) || ts.isForOfStatement(scope)) &&
      scope.initializer &&
      ts.isVariableDeclarationList(scope.initializer) &&
      isBlockScoped(scope.initializer)
    )
      for (const declaration of scope.initializer.declarations) add(declaration.name, declaration);
    if (ts.isCatchClause(scope) && scope.variableDeclaration)
      add(scope.variableDeclaration.name, scope.variableDeclaration);
    scopeNames.set(scope, own);
    return own;
  };
  /** Identity of the binding an identifier refers to ("g" when it is not declared in a scope). */
  const bindingIdentity = (identifier: ts.Identifier): string => {
    let current: ts.Node | undefined = identifier.parent;
    while (current) {
      const declaration = namesDeclaredBy(current).get(identifier.text);
      if (declaration) return String(declaration.pos);
      current = current.parent;
    }
    return "g";
  };
  /** A call that normalizes a path: `path.resolve` or `fs.realpath*` reached through an import. */
  const isNormalizingCall = (call: ts.CallExpression): boolean => {
    const resolved = moduleOfCall(call);
    if (!resolved) return false;
    const callee = accessPath(call.expression);
    // A local binding of the same name shadows the import.
    if (bindingCount.get(callee ? (callee.split(".")[0] ?? "") : "") !== 1) return false;
    const module = resolved.module.replace(/^node:/, "");
    if (/^path(\/(posix|win32))?$/.test(module)) return resolved.member === "resolve";
    if (/^fs(\/promises)?$/.test(module))
      return resolved.member === "realpath" || resolved.member === "realpathSync";
    return false;
  };
  const isConstDeclaration = (initializer: ts.Expression): boolean =>
    ts.isVariableDeclaration(initializer.parent) &&
    ts.isVariableDeclarationList(initializer.parent.parent) &&
    (initializer.parent.parent.flags & ts.NodeFlags.Const) !== 0;
  /** A binding no later assignment, property write or mutating call can change. */
  const isStableName = (name: string, followed: boolean): boolean =>
    !reassigned.has(name) && !mutatedRoots.has(name) && (!followed || bindingCount.get(name) === 1);

  /**
   * A fixed lookup table: a `const` `Map` of pairs, object literal, or `Object.freeze` of either,
   * where every value is inert and nothing ever writes to it or lets it escape. Indexing it with
   * any key yields one of those values.
   */
  const isInertTable = (expression: ts.Expression, depth: number): boolean => {
    if (depth > 4) return false;
    const node = unwrap(expression);
    if (ts.isIdentifier(node)) {
      const init = soleConst(node.text, node);
      return (
        init !== null &&
        isConstDeclaration(init) &&
        !isExported(init) &&
        !tableMisuse.has(node.text) &&
        !mutatedRoots.has(node.text) &&
        isInertTable(init, depth + 1)
      );
    }
    if (ts.isCallExpression(node) && accessPath(node.expression) === "Object.freeze") {
      const inner = node.arguments[0];
      return inner ? isInertTable(inner, depth + 1) : false;
    }
    if (ts.isNewExpression(node) && calleeName(node) === "Map") {
      const entries = node.arguments?.[0] ? unwrap(node.arguments[0]) : null;
      return (
        entries !== null &&
        ts.isArrayLiteralExpression(entries) &&
        entries.elements.every((entry) => {
          const pair = ts.isSpreadElement(entry) ? null : unwrap(entry);
          const value =
            pair && ts.isArrayLiteralExpression(pair) && pair.elements.length === 2
              ? pair.elements[1]
              : undefined;
          return (
            value !== undefined &&
            !ts.isSpreadElement(value) &&
            isInertValue(value, "sql", depth + 1)
          );
        })
      );
    }
    if (ts.isObjectLiteralExpression(node)) {
      return node.properties.every(
        (property) =>
          ts.isPropertyAssignment(property) &&
          !ts.isComputedPropertyName(property.name) &&
          isInertValue(property.initializer, "sql", depth + 1),
      );
    }
    return false;
  };

  /**
   * True when an expression can only produce a fixed or numeric value, whatever the request holds:
   * literals, module constants no other binding shadows, numeric coercion, a value picked from a
   * literal allowlist table, and, for commands, the `quote()` imported from `shell-quote`.
   * Anything unresolved is not inert, so unclear evidence keeps its finding.
   */
  /** `quote()` imported from `shell-quote` (the only binding of that name; a local one shadows it). */
  const isShellQuoteCall = (call: ts.CallExpression): boolean => {
    const resolved = moduleOfCall(call);
    const callee = accessPath(call.expression);
    const root = callee ? (callee.split(".")[0] ?? "") : "";
    return (
      resolved?.module === "shell-quote" &&
      resolved.member === "quote" &&
      bindingCount.get(root) === 1
    );
  };
  /** A built-in nothing in the file shadows, reassigns or writes a member of (`Math.max = …`). */
  const isPristineGlobal = (root: string): boolean =>
    bindingCount.get(root) === undefined && !reassigned.has(root) && !mutatedRoots.has(root);

  const isInertValue = (expression: ts.Expression, context: "sql" | "cmd", depth = 0): boolean => {
    if (depth > 6) return false;
    const node = unwrap(expression);
    if (
      ts.isStringLiteralLike(node) ||
      ts.isNumericLiteral(node) ||
      node.kind === ts.SyntaxKind.TrueKeyword ||
      node.kind === ts.SyntaxKind.FalseKeyword ||
      node.kind === ts.SyntaxKind.NullKeyword
    )
      return true;
    const inert = (child: ts.Expression) => isInertValue(child, context, depth + 1);
    if (ts.isTemplateExpression(node)) return node.templateSpans.every((s) => inert(s.expression));
    if (ts.isPrefixUnaryExpression(node)) return true; // +x, -x, ~x, !x are numbers or booleans
    if (ts.isBinaryExpression(node)) {
      const kind = node.operatorToken.kind;
      if (
        kind === ts.SyntaxKind.PlusToken ||
        kind === ts.SyntaxKind.BarBarToken ||
        kind === ts.SyntaxKind.QuestionQuestionToken ||
        kind === ts.SyntaxKind.AmpersandAmpersandToken
      )
        return inert(node.left) && inert(node.right);
      return (
        kind === ts.SyntaxKind.MinusToken ||
        kind === ts.SyntaxKind.AsteriskToken ||
        kind === ts.SyntaxKind.SlashToken ||
        kind === ts.SyntaxKind.PercentToken ||
        kind === ts.SyntaxKind.AsteriskAsteriskToken
      );
    }
    if (ts.isConditionalExpression(node)) return inert(node.whenTrue) && inert(node.whenFalse);
    const fixedPath = accessPath(node);
    if (fixedPath !== null && TRUSTED_PATHS.has(fixedPath)) {
      const root = fixedPath.split(".")[0] ?? "";
      return isPristineGlobal(root);
    }
    if (ts.isIdentifier(node)) {
      if (node.text === "undefined") return bindingCount.get("undefined") === undefined;
      const init = soleConst(node.text, node);
      return init !== null && inert(init);
    }
    if (ts.isElementAccessExpression(node) || ts.isPropertyAccessExpression(node))
      return isInertTable(node.expression, 0);
    if (ts.isCallExpression(node)) {
      const name = calleeName(node);
      const receiver = calleeReceiver(node);
      const receiverPath = receiver ? accessPath(receiver) : null;
      if (name === "parseInt" || name === "parseFloat" || name === "Number") {
        const root = (receiverPath ?? name).split(".")[0] ?? "";
        return (receiver === null || receiverPath === "Number") && isPristineGlobal(root);
      }
      if (receiverPath === "Math") return isPristineGlobal("Math");
      if (name === "get" && receiver && node.arguments.length === 1)
        return isInertTable(receiver, 0);
      if (context === "cmd" && name) return isShellQuoteCall(node);
    }
    return false;
  };

  /**
   * Full suppression is reserved for values that are fixed by the expression itself: literals,
   * numeric coercion, a module-level constant initialised to a literal (sole binding, never
   * assigned), and `shell-quote`'s `quote()`. Everything else `isInertValue` accepts is only
   * inferred (allowlist tables, aliases, local constants) and is demoted instead of dropped.
   */
  const isStrictInert = (expression: ts.Expression, context: "sql" | "cmd", depth = 0): boolean => {
    if (depth > 6) return false;
    const node = unwrap(expression);
    if (
      ts.isStringLiteralLike(node) ||
      ts.isNumericLiteral(node) ||
      node.kind === ts.SyntaxKind.TrueKeyword ||
      node.kind === ts.SyntaxKind.FalseKeyword ||
      node.kind === ts.SyntaxKind.NullKeyword
    )
      return true;
    const strict = (child: ts.Expression) => isStrictInert(child, context, depth + 1);
    if (ts.isTemplateExpression(node)) return node.templateSpans.every((s) => strict(s.expression));
    if (ts.isPrefixUnaryExpression(node)) return true;
    if (ts.isBinaryExpression(node)) {
      const kind = node.operatorToken.kind;
      if (
        kind === ts.SyntaxKind.PlusToken ||
        kind === ts.SyntaxKind.BarBarToken ||
        kind === ts.SyntaxKind.QuestionQuestionToken
      )
        return strict(node.left) && strict(node.right);
      return (
        kind === ts.SyntaxKind.MinusToken ||
        kind === ts.SyntaxKind.AsteriskToken ||
        kind === ts.SyntaxKind.SlashToken ||
        kind === ts.SyntaxKind.PercentToken
      );
    }
    if (ts.isIdentifier(node)) {
      const init = soleConst(node.text, node);
      if (init === null) return false;
      let container: ts.Node | undefined = init.parent;
      while (container && !ts.isBlock(container) && !ts.isSourceFile(container))
        container = container.parent;
      const value = unwrap(init);
      return (
        container !== undefined &&
        ts.isSourceFile(container) &&
        (ts.isStringLiteralLike(value) || ts.isNumericLiteral(value))
      );
    }
    if (ts.isCallExpression(node)) {
      const name = calleeName(node);
      const receiver = calleeReceiver(node);
      const receiverPath = receiver ? accessPath(receiver) : null;
      if (name === "parseInt" || name === "parseFloat" || name === "Number") {
        const root = (receiverPath ?? name).split(".")[0] ?? "";
        return (receiver === null || receiverPath === "Number") && isPristineGlobal(root);
      }
      if (receiverPath === "Math") return isPristineGlobal("Math");
      // Only `quote()` is fixed by the expression itself; command tables are demoted, not dropped.
      if (context === "cmd") return isShellQuoteCall(node);
    }
    return false;
  };

  /** Keep the finding but cap it at low confidence and medium severity, saying why. */
  const demote = (evidence: Evidence, note: string): Evidence => ({
    ...evidence,
    severity:
      evidence.severity === "critical" || evidence.severity === "high"
        ? "medium"
        : evidence.severity,
    status: "suspected",
    confidence: "low",
    flow: `${evidence.flow} (${note})`,
  });

  const enclosingFunction = (node: ts.Node): ts.Node => {
    let current: ts.Node | undefined = node.parent;
    while (current && !ts.isFunctionLike(current) && !ts.isSourceFile(current))
      current = current.parent;
    return current ?? sourceFile;
  };

  /** Control never continues past this statement (`return`, `throw`, or a block that does). */
  const exitsScope = (statement: ts.Statement): boolean =>
    ts.isReturnStatement(statement) ||
    ts.isThrowStatement(statement) ||
    (ts.isBlock(statement) && statement.statements.some((inner) => exitsScope(inner)));

  const splitOn = (expression: ts.Expression, operator: ts.SyntaxKind): ts.Expression[] => {
    const node = unwrap(expression);
    return ts.isBinaryExpression(node) && node.operatorToken.kind === operator
      ? [...splitOn(node.left, operator), ...splitOn(node.right, operator)]
      : [node];
  };

  interface Subject {
    text: string;
    /** Every name the value depends on is bound once and never reassigned or written through. */
    stable: boolean;
  }

  /** Canonical name of the value a URL/string variable carries, following `new URL(x)` and `.href`. */
  const canonicalSubject = (expression: ts.Expression, depth = 0): Subject => {
    const node = unwrap(expression);
    const terminal = (): Subject => {
      const root = accessPath(node) === null ? null : rootIdentifier(node);
      return {
        // The binding's identity keeps an inner `u` (loop variable, nested block) apart from the
        // outer `u` the guard checked.
        text: root
          ? `${bindingIdentity(root)}:${node.getText(sourceFile)}`
          : node.getText(sourceFile),
        stable: root !== null && isStableName(root.text, false) && !escapesAsSubject(root.text),
      };
    };
    if (depth > 5) return { text: node.getText(sourceFile), stable: false };
    if (ts.isNewExpression(node) && calleeName(node) === "URL" && node.arguments?.[0])
      return canonicalSubject(node.arguments[0], depth + 1);
    if (ts.isCallExpression(node)) {
      const receiver = calleeReceiver(node);
      if (calleeName(node) === "toString" && receiver && node.arguments.length === 0)
        return canonicalSubject(receiver, depth + 1);
      if (calleeName(node) === "String" && !receiver && node.arguments[0])
        return canonicalSubject(node.arguments[0], depth + 1);
    }
    if (ts.isPropertyAccessExpression(node) && node.name.text === "href")
      return canonicalSubject(node.expression, depth + 1);
    if (ts.isIdentifier(node)) {
      const init = soleConst(node.text, node);
      if (init) {
        const inner = unwrap(init);
        if (
          ts.isNewExpression(inner) ||
          ts.isIdentifier(inner) ||
          ts.isPropertyAccessExpression(inner) ||
          ts.isCallExpression(inner)
        ) {
          const resolved = canonicalSubject(inner, depth + 1);
          return {
            text: resolved.text,
            stable:
              resolved.stable && isStableName(node.text, true) && !escapesAsSubject(node.text),
          };
        }
      }
    }
    return terminal();
  };

  /** `u.hostname` / `u.protocol` (also through one const alias) -> canonical subject of `u`. */
  const urlPartSubject = (
    expression: ts.Expression,
    part: "host" | "protocol",
    depth = 0,
  ): Subject | null => {
    const node = unwrap(expression);
    if (depth > 3) return null;
    if (ts.isPropertyAccessExpression(node)) {
      const names = part === "host" ? ["hostname", "host"] : ["protocol"];
      return names.includes(node.name.text) ? canonicalSubject(node.expression) : null;
    }
    if (ts.isCallExpression(node) && calleeName(node) === "toLowerCase") {
      const receiver = calleeReceiver(node);
      return receiver ? urlPartSubject(receiver, part, depth + 1) : null;
    }
    if (ts.isIdentifier(node)) {
      const init = soleConst(node.text, node);
      const resolved = init ? urlPartSubject(init, part, depth + 1) : null;
      return resolved
        ? {
            ...resolved,
            stable:
              resolved.stable && isStableName(node.text, true) && !escapesAsSubject(node.text),
          }
        : null;
    }
    return null;
  };

  interface GuardFact {
    kind: "host" | "protocol" | "prefix";
    subject: string;
    stable: boolean;
  }

  /** True for a literal list of strings that nothing ever changes or lets escape. */
  const isStringCollection = (expression: ts.Expression, depth = 0): boolean => {
    if (depth > 4) return false;
    const node = unwrap(expression);
    if (ts.isIdentifier(node)) {
      const init = soleConst(node.text, node);
      return (
        init !== null &&
        isConstDeclaration(init) &&
        !isExported(init) &&
        !tableMisuse.has(node.text) &&
        !mutatedRoots.has(node.text) &&
        isStringCollection(init, depth + 1)
      );
    }
    if (ts.isNewExpression(node) && calleeName(node) === "Set" && node.arguments?.[0])
      return isStringCollection(node.arguments[0], depth + 1);
    if (
      ts.isCallExpression(node) &&
      accessPath(node.expression) === "Object.freeze" &&
      node.arguments[0]
    )
      return isStringCollection(node.arguments[0], depth + 1);
    return (
      ts.isArrayLiteralExpression(node) &&
      node.elements.length > 0 &&
      node.elements.every(
        (element) => !ts.isSpreadElement(element) && ts.isStringLiteralLike(unwrap(element)),
      )
    );
  };

  const endsWithSeparator = (expression: ts.Expression): boolean => {
    const node = unwrap(expression);
    if (ts.isStringLiteralLike(node)) return node.text.endsWith("/") || node.text.endsWith("\\");
    if (ts.isTemplateExpression(node)) {
      const last = node.templateSpans[node.templateSpans.length - 1];
      if (!last) return false;
      return last.literal.text === ""
        ? endsWithSeparator(last.expression)
        : /[/\\]$/.test(last.literal.text);
    }
    const path = accessPath(node);
    return path !== null && /(^|\.)sep$/.test(path);
  };

  /** A root that is a literal or a constant no request value reaches. */
  const isFixedRoot = (expression: ts.Expression, depth = 0): boolean => {
    if (depth > 4) return false;
    const node = unwrap(expression);
    if (ts.isStringLiteralLike(node)) return true;
    if (ts.isTemplateExpression(node))
      return node.templateSpans.every((span) => isFixedRoot(span.expression, depth + 1));
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken)
      return isFixedRoot(node.left, depth + 1) && isFixedRoot(node.right, depth + 1);
    const fixedPath = accessPath(node);
    if (fixedPath !== null && TRUSTED_PATHS.has(fixedPath)) return true;
    if (ts.isIdentifier(node)) {
      const init = soleConst(node.text, node);
      return (
        init !== null &&
        isStableName(node.text, true) &&
        taint.taintOf(node) === null &&
        taint.taintOf(init) === null
      );
    }
    return false;
  };

  /** `ROOT + sep`, `${ROOT}${sep}`, or a literal ending in a separator, with a fixed root. */
  const isFixedRootWithSeparator = (expression: ts.Expression): boolean => {
    const base = unwrap(expression);
    if (ts.isStringLiteralLike(base)) return base.text.length > 1 && endsWithSeparator(base);
    if (ts.isBinaryExpression(base) && base.operatorToken.kind === ts.SyntaxKind.PlusToken)
      return endsWithSeparator(base.right) && isFixedRoot(base.left);
    if (ts.isTemplateExpression(base)) {
      const last = base.templateSpans[base.templateSpans.length - 1];
      if (!last || !endsWithSeparator(base)) return false;
      const rest = base.templateSpans.slice(0, last.literal.text === "" ? -1 : undefined);
      return rest.every((span) => isFixedRoot(span.expression));
    }
    return false;
  };

  const equalityFacts = (left: ts.Expression, right: ts.Expression): GuardFact[] => {
    const facts: GuardFact[] = [];
    for (const [value, other] of [
      [left, right],
      [right, left],
    ] as const) {
      if (!ts.isStringLiteralLike(unwrap(value))) continue;
      const host = urlPartSubject(other, "host");
      const protocol = urlPartSubject(other, "protocol");
      if (host) facts.push({ kind: "host", subject: host.text, stable: host.stable });
      if (protocol)
        facts.push({ kind: "protocol", subject: protocol.text, stable: protocol.stable });
    }
    return facts;
  };

  /** What must hold when `expression` evaluates to true. */
  const factsWhenTrue = (expression: ts.Expression): GuardFact[] => {
    const node = unwrap(expression);
    if (ts.isBinaryExpression(node)) {
      const kind = node.operatorToken.kind;
      if (kind === ts.SyntaxKind.AmpersandAmpersandToken)
        return [...factsWhenTrue(node.left), ...factsWhenTrue(node.right)];
      if (
        kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
        kind === ts.SyntaxKind.EqualsEqualsToken
      )
        return equalityFacts(node.left, node.right);
      return [];
    }
    if (ts.isCallExpression(node)) {
      const name = calleeName(node);
      const receiver = calleeReceiver(node);
      const argument = node.arguments[0];
      if (!receiver || !argument || node.arguments.length !== 1) return [];
      if ((name === "has" || name === "includes") && isStringCollection(receiver)) {
        const host = urlPartSubject(argument, "host");
        const protocol = urlPartSubject(argument, "protocol");
        return [
          ...(host ? [{ kind: "host" as const, subject: host.text, stable: host.stable }] : []),
          ...(protocol
            ? [{ kind: "protocol" as const, subject: protocol.text, stable: protocol.stable }]
            : []),
        ];
      }
      if (name === "startsWith") {
        const base = unwrap(argument);
        if (ts.isStringLiteralLike(base) && /^https?:\/\//.test(base.text)) {
          const subject = canonicalSubject(receiver);
          return [{ kind: "protocol", subject: subject.text, stable: subject.stable }];
        }
        const subject = unwrap(receiver);
        if (ts.isIdentifier(subject) && isFixedRootWithSeparator(base))
          return [
            { kind: "prefix", subject: subject.text, stable: isStableName(subject.text, true) },
          ];
      }
    }
    return [];
  };

  /** What must hold after `if (expression) <exit>` falls through (every `||` operand was false). */
  const factsWhenFalse = (expression: ts.Expression): GuardFact[] =>
    splitOn(expression, ts.SyntaxKind.BarBarToken).flatMap((part) => {
      if (ts.isPrefixUnaryExpression(part) && part.operator === ts.SyntaxKind.ExclamationToken)
        return factsWhenTrue(part.operand);
      if (
        ts.isBinaryExpression(part) &&
        (part.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
          part.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsToken)
      )
        return equalityFacts(part.left, part.right);
      return [];
    });

  // Facts are computed once per `if` and indexed once per block, so many sinks in one function
  // stay linear: a sink asks one map lookup per enclosing block instead of re-walking the function.
  const factKey = (kind: GuardFact["kind"], subject: string) => `${kind}\u0000${subject}`;
  const ifFalseFacts = new Map<ts.IfStatement, GuardFact[]>();
  const ifTrueFacts = new Map<ts.IfStatement, GuardFact[]>();
  /** Per block: fact key -> end offset of the earliest early-exit `if` that establishes it. */
  const exitGuardCache = new Map<ts.Node, Map<string, { end: number; node: ts.Node }>>();
  const exitGuardsOf = (container: ts.Block | ts.SourceFile) => {
    let guards = exitGuardCache.get(container);
    if (guards === undefined) {
      guards = new Map<string, { end: number; node: ts.Node }>();
      for (const statement of container.statements) {
        if (!ts.isIfStatement(statement) || statement.elseStatement) continue;
        if (!exitsScope(statement.thenStatement)) continue;
        let facts = ifFalseFacts.get(statement);
        if (facts === undefined) {
          facts = factsWhenFalse(statement.expression);
          ifFalseFacts.set(statement, facts);
        }
        for (const fact of facts) {
          if (!fact.stable) continue;
          const key = factKey(fact.kind, fact.subject);
          if (!guards.has(key)) guards.set(key, { end: statement.getEnd(), node: statement });
        }
      }
      exitGuardCache.set(container, guards);
    }
    return guards;
  };

  /**
   * Whether a guard fact provably holds at `node`: an early-exit `if` that is an earlier statement
   * of a block enclosing the node (so it dominates it), or an enclosing `if` whose then-branch
   * holds the node. Guards inside other branches, loops, `try` blocks or other functions do not
   * count, and neither do facts about a value that is reassigned or written through.
   */
  const guardHolds = (node: ts.Node, kind: GuardFact["kind"], subject: string): ts.Node | null => {
    const owner = enclosingFunction(node);
    const key = factKey(kind, subject);
    let child: ts.Node = node;
    let current: ts.Node | undefined = node.parent;
    while (current) {
      if (ts.isBlock(current) || ts.isSourceFile(current)) {
        const guard = exitGuardsOf(current).get(key);
        if (guard !== undefined && guard.end <= child.getStart(sourceFile)) return guard.node;
      } else if (ts.isIfStatement(current) && child === current.thenStatement) {
        let when = ifTrueFacts.get(current);
        if (when === undefined) {
          when = factsWhenTrue(current.expression);
          ifTrueFacts.set(current, when);
        }
        if (when.some((fact) => fact.stable && fact.kind === kind && fact.subject === subject))
          return current;
      }
      if (current === owner) break;
      child = current;
      current = current.parent;
    }
    return null;
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
      const kind = fixedKey(get(properties, key)?.initializer);
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
