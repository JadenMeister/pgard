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

/** Project-level facts used by cross-file heuristics (CSRF, brute force, ORM detection). */
export interface JsFileFacts {
  imports: string[];
  /** Lines of POST/PUT/PATCH/DELETE route registrations. */
  stateChangingRoutes: number[];
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
const SESSION_COOKIE_NAME = /sess|sid|token|auth|jwt|login|remember|connect\.sid/i;

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
  const sourceFile = ts.createSourceFile(
    path,
    code,
    ts.ScriptTarget.Latest,
    true,
    options.scriptKind ?? scriptKindFor(path),
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

  const isSanitized = (expression: ts.Expression): boolean => {
    const node = unwrap(expression);
    return ts.isCallExpression(node) && SANITIZER_CALLS.test(calleeName(node) ?? "");
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

  // Function text is computed once per function (not once per call site) to keep large files linear.
  const functionTextCache = new Map<ts.Node, string>();
  const enclosingFunctionText = (node: ts.Node): string => {
    let current: ts.Node | undefined = node.parent;
    while (current && !ts.isFunctionLike(current) && !ts.isSourceFile(current))
      current = current.parent;
    const owner = current ?? sourceFile;
    let text = functionTextCache.get(owner);
    if (text === undefined) {
      text = owner.getText(sourceFile);
      functionTextCache.set(owner, text);
    }
    return text;
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
        const chain = call.parent?.parent?.parent?.getText(sourceFile) ?? "";
        const functionText = enclosingFunctionText(call);
        if (PASSWORD_TEXT.test(chain) || /\.update\([^)]*(pass(word)?|pwd)/i.test(functionText)) {
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

  const checkSessionConfig = (call: ts.CallExpression, name: string) => {
    const module = namespaceImports.get(name);
    if (module !== "express-session" && module !== "cookie-session") return;
    facts.usesCookieSession = true;
    const options = call.arguments[0];
    if (!options || !ts.isObjectLiteralExpression(unwrap(options))) return;
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
    const cookieProps =
      cookie && ts.isObjectLiteralExpression(unwrap(cookie))
        ? (unwrap(cookie) as ts.ObjectLiteralExpression).properties
        : null;
    const missing: string[] = [];
    const flag = (key: string, defaultOn: boolean) => {
      const value = cookieProps ? get(cookieProps, key)?.initializer : undefined;
      if (value === undefined ? !defaultOn : value.kind === ts.SyntaxKind.FalseKeyword)
        missing.push(key);
    };
    flag("httpOnly", true);
    flag("secure", false);
    const sameSite = cookieProps ? get(cookieProps, "sameSite")?.initializer : undefined;
    if (!sameSite || sameSite.kind === ts.SyntaxKind.FalseKeyword) missing.push("sameSite");
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
    facts.usesCookieSession = true;
    const cookieName = call.arguments[0];
    const options = call.arguments[2];
    if (options && !ts.isObjectLiteralExpression(unwrap(options))) return; // unknown options object
    const props = options ? (unwrap(options) as ts.ObjectLiteralExpression).properties : null;
    const isTrue = (key: string) =>
      props?.some(
        (property) =>
          ts.isPropertyAssignment(property) &&
          property.name.getText(sourceFile) === key &&
          property.initializer.kind === ts.SyntaxKind.TrueKeyword,
      ) ?? false;
    const has = (key: string) =>
      props?.some((property) => property.name?.getText(sourceFile) === key) ?? false;
    const missing = [
      ...(isTrue("httpOnly") ? [] : ["httpOnly"]),
      ...(isTrue("secure") ? [] : ["secure"]),
      ...(has("sameSite") ? [] : ["sameSite"]),
    ];
    if (missing.length === 0) return;
    const nameText =
      cookieName && ts.isStringLiteralLike(unwrap(cookieName))
        ? (unwrap(cookieName) as ts.StringLiteral).text
        : "";
    const isSessionLike = SESSION_COOKIE_NAME.test(nameText);
    report(
      "PG-COOKIE-001",
      call,
      {
        severity: isSessionLike ? "medium" : "low",
        status: "suspected",
        confidence: isSessionLike ? "medium" : "low",
        flow: `res.cookie(${isSessionLike ? "session-like name" : "cookie"}) without ${missing.join(", ")}`,
      },
      `res.cookie:${nameText}`,
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
    facts.stateChangingRoutes.push(line);
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
      const isPlain =
        taint.taintOf(node) === "request" ||
        (ts.isIdentifier(node) && PASSWORD_NAME.test(node.text)) ||
        (ts.isPropertyAccessExpression(node) && PASSWORD_NAME.test(node.name.text));
      if (!isPlain) continue;
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
      if (HASHING_TEXT.test(enclosingFunctionText(call))) continue;
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

  facts.imports = [...new Set(facts.imports)];
  return { findings, facts, hasParseErrors, cappedRules: [...cappedRules] };
}
