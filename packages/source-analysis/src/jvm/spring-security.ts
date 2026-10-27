import type { Annotation, Expr, MethodInfo, Stmt, Unit } from "./ir.js";
import {
  eachBody,
  importsFrom,
  isCall,
  isFalse,
  isTrue,
  lastName,
  literalText,
  namesIn,
  resolveStrings,
  shorten,
  walkBody,
  type CallExpr,
  type ConfigFinding,
} from "./config-util.js";

/**
 * PG-CSRF-001 and PG-CONF-001 for Spring Security configuration in Java and Kotlin:
 *
 * - CSRF protection switched off (`csrf().disable()`, `csrf(c -> c.disable())`,
 *   `csrf(AbstractHttpConfigurer::disable)`, the Kotlin DSL `csrf { disable() }`), judged by what
 *   the same filter chain says about sessions. A chain that is explicitly STATELESS and takes
 *   bearer tokens (`oauth2ResourceServer`, a JWT filter) is silent: no cookie is sent for a
 *   forged request to ride on. Every other state is reported, and what cannot be told is low and
 *   marked "inferred".
 * - Security misconfiguration: a catch-all `permitAll`, `web.ignoring()` of paths that are not
 *   static resources, a wildcard CORS origin together with credentials, `@EnableWebSecurity(debug
 *   = true)`.
 *
 * Only the calls the file shows are read. A filter chain that is finished by a custom configurer
 * (`apply`, `with`), by a helper this file does not define, or by a customizer held in a variable
 * is listed in `unsupported`, which makes the area partial.
 */
export interface SpringSecurityAnalysis {
  findings: ConfigFinding[];
  /** Forms that were not followed (one entry per kind). */
  unsupported: string[];
}

const HTTP_TYPE = /\b(?:HttpSecurity|ServerHttpSecurity)\b/;
const CHAIN_RETURN = /\b(?:SecurityFilterChain|SecurityWebFilterChain)\b/;
const MATCHERS = new Set([
  "requestMatchers",
  "antMatchers",
  "mvcMatchers",
  "regexMatchers",
  "pathMatchers",
  "securityMatcher",
  "securityMatchers",
]);
const CATCH_ALL_NAMES = new Set(["anyRequest", "anyExchange"]);
const RESTRICTIVE = new Set([
  "authenticated",
  "fullyAuthenticated",
  "hasRole",
  "hasAnyRole",
  "hasAuthority",
  "hasAnyAuthority",
  "hasIpAddress",
  "denyAll",
  "access",
]);
const SESSION_FEATURES = new Set(["formLogin", "rememberMe", "oauth2Login", "saml2Login"]);
const BEARER_FEATURES = new Set(["oauth2ResourceServer"]);
const FILTER_ADDERS = new Set(["addFilterBefore", "addFilterAfter", "addFilterAt", "addFilter"]);
const BEARER_NAME = /jwt|jws|jwe|bearer|token/i;
const STATIC_PATH =
  /^\/(?:static|css|js|images?|img|assets|fonts?|webjars|resources|icons?|vendor|dist|lib|libs|styles|scripts|favicon\.ico|robots\.txt)(?:\/.*)?$|\.(?:css|js|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|otf)$/i;
/** Public endpoints that are not static files (documentation, health): reported low. */
const KNOWN_PUBLIC =
  /^\/(?:swagger-ui|swagger-resources|v[23]\/api-docs|api-docs|error|health|ping|actuator\/health)(?:\b.*)?$/i;
const VERBS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]);

const simpleType = (type: string): string => type.replace(/<.*>/s, "").trim();

/** `AbstractHttpConfigurer::disable`: a method reference to `disable`. */
function isDisableRef(expr: Expr): boolean {
  if (expr.k === "member") return expr.name === "disable";
  if (expr.k === "other") {
    const last = expr.kids[expr.kids.length - 1];
    return last?.k === "id" && last.name === "disable";
  }
  return false;
}

/**
 * Whether a lambda disables what it configures: `c -> c.disable()`, `{ disable() }`,
 * `{ it.disable() }`. "conditional" when the call is only in a branch.
 */
function disableIn(expr: Expr): "yes" | "conditional" | null {
  if (expr.k !== "lambda") return null;
  let found: "yes" | "conditional" | null = null;
  walkBody(expr.body, (call, context) => {
    if (
      call.name === "disable" &&
      call.args.length === 0 &&
      (call.recv === null || call.recv.k === "id")
    ) {
      if (!context.conditional) found = "yes";
      else found ??= "conditional";
    }
  });
  return found;
}

const isDisablingArg = (expr: Expr): boolean => isDisableRef(expr) || disableIn(expr) === "yes";

const IGNORING = /^ignoring(?:Request|Ant|Mvc)Matchers?$/;

/** Paths a `csrf` customizer exempts with `ignoringRequestMatchers(...)` (and its older names). */
function ignoredPaths(unit: Unit, calls: readonly CallExpr[]): { paths: string[]; all: boolean } {
  const paths: string[] = [];
  let all = false;
  for (const call of calls) {
    for (const arg of call.args) {
      if (isCall(arg) && CATCH_ALL_NAMES.has(arg.name)) all = true;
      const resolved = resolveStrings(unit, arg.k === "new" ? (arg.args[0] ?? arg) : arg);
      if (resolved.values.some((value) => value === "/**" || value === "/**/*")) all = true;
      paths.push(...resolved.values);
    }
  }
  return { paths, all };
}

interface Fact {
  line: number;
  call: CallExpr;
  /** Switched off for everything, only in a branch, or only for some paths. */
  kind: "full" | "conditional" | "partial";
  paths: string[];
}

interface ChainFacts {
  csrfDisabled: Fact[];
  formLogin: boolean;
  sessionFeature: string | null;
  sessionManagement: boolean;
  policy: "stateless" | "session" | "unknown" | null;
  /** `oauth2ResourceServer` with Spring's default bearer handling. */
  bearer: boolean;
  /** A custom `bearerTokenResolver` or a form or query parameter token on the resource server. */
  customBearer: boolean;
  /** A filter whose name suggests JWT or token auth (only the name is known). */
  tokenFilter: boolean;
  httpBasic: boolean;
  /** The resource server accepts the token in a form-encoded body. */
  formToken: boolean;
  scoped: boolean;
  unsupported: Set<string>;
}

function emptyFacts(): ChainFacts {
  return {
    csrfDisabled: [],
    formLogin: false,
    sessionFeature: null,
    sessionManagement: false,
    policy: null,
    bearer: false,
    customBearer: false,
    tokenFilter: false,
    httpBasic: false,
    formToken: false,
    scoped: false,
    unsupported: new Set(),
  };
}

function policyOf(expr: Expr | null | undefined): "stateless" | "session" | "unknown" {
  const name = lastName(expr);
  if (name === "STATELESS") return "stateless";
  if (name === "IF_REQUIRED" || name === "ALWAYS" || name === "NEVER") return "session";
  return "unknown";
}

function isChainMethod(method: MethodInfo): boolean {
  return (
    method.params.some((param) => HTTP_TYPE.test(param.type)) ||
    CHAIN_RETURN.test(method.returnType ?? "")
  );
}

export function analyzeSpringSecurity(unit: Unit): SpringSecurityAnalysis {
  const findings: ConfigFinding[] = [];
  const unsupported = new Set<string>();
  const springSecurity = importsFrom(unit, "org.springframework.security");
  const spring = importsFrom(unit, "org.springframework");
  const allClasses = [unit.top, ...unit.classes];
  const allMethods = allClasses.flatMap((cls) => cls.methods);

  if (springSecurity) {
    // Filter chains: a method that takes the HttpSecurity builder or returns the chain. A helper
    // this file defines and that a chain passes the builder to is read as part of that chain.
    const chainMethods = allMethods.filter(
      (method) => method.body !== null && isChainMethod(method),
    );
    const helperNames = new Set<string>();
    const byName = new Map<string, MethodInfo[]>();
    for (const method of allMethods) {
      byName.set(method.name, [...(byName.get(method.name) ?? []), method]);
    }
    const httpParamOf = (method: MethodInfo): string | null =>
      method.params.find((param) => HTTP_TYPE.test(param.type))?.name ?? null;
    // Which chain methods are only helpers of another one.
    for (const method of chainMethods) {
      const http = httpParamOf(method);
      if (http === null) continue;
      walkBody(method.body, (call) => {
        if (call.recv !== null || !passes(call.args, http)) return;
        for (const callee of byName.get(call.name) ?? []) {
          if (callee !== method && isChainMethod(callee)) helperNames.add(callee.name);
        }
      });
    }
    const roots = chainMethods.filter((method) => !helperNames.has(method.name));
    for (const method of roots.length > 0 ? roots : chainMethods) {
      judgeChain(unit, method, byName, findings, unsupported, httpParamOf);
    }
    // `web.ignoring()` and catch-all rules are read in every method body (a WebSecurityCustomizer
    // bean is not a chain method).
    for (const { body } of eachBody(unit)) ignoringFindings(unit, body, findings);
    for (const cls of allClasses) {
      for (const annotation of cls.annotations ?? []) {
        if (annotation.name === "EnableWebSecurity" && isTrue(annotation.named.get("debug"))) {
          findings.push({
            ruleId: "PG-CONF-001",
            line: annotation.line,
            severity: "low",
            status: "suspected",
            confidence: "medium",
            evidence:
              "@EnableWebSecurity(debug = true) logs every request's headers and the security filter chain; turn it off outside local development",
            cause: "enable-web-security-debug",
          });
        }
      }
    }
  }

  if (spring) corsFindings(unit, findings);
  return { findings, unsupported: [...unsupported] };
}

const passes = (args: readonly Expr[], name: string): boolean =>
  args.some((arg) => arg.k === "id" && arg.name === name);

// ---------------------------------------------------------------------------------- CSRF + chain

function judgeChain(
  unit: Unit,
  method: MethodInfo,
  byName: Map<string, MethodInfo[]>,
  findings: ConfigFinding[],
  unsupported: Set<string>,
  httpParamOf: (method: MethodInfo) => string | null,
): void {
  const facts = emptyFacts();
  const calls: Array<{ call: CallExpr; parent: CallExpr | null; seq: number }> = [];
  const visited = new Set<MethodInfo>();
  /** Local variables of the chain methods, by name (the last initializer wins). */
  const locals = new Map<string, Expr>();
  const collect = (current: MethodInfo, depth: number): void => {
    if (visited.has(current) || depth > 6) return;
    visited.add(current);
    const http = httpParamOf(current);
    walkBody(
      current.body,
      (call, _context, parent) => {
        calls.push({ call, parent, seq: calls.length });
        if (http === null) return;
        // The builder is handed to something: follow it when this file defines it.
        if (call.recv === null && passes(call.args, http)) {
          const callees = (byName.get(call.name) ?? []).filter(
            (callee) => callee.body !== null && callee !== current,
          );
          if (callees.length > 0) {
            for (const callee of callees) collect(callee, depth + 1);
          } else if (call.name !== http) {
            facts.unsupported.add(
              "a helper that is given the HttpSecurity builder and is not in this file",
            );
          }
        } else if (call.recv !== null && !passes([call.recv], http) && passes(call.args, http)) {
          facts.unsupported.add(
            "a helper that is given the HttpSecurity builder and is not in this file",
          );
        }
        if (
          (call.name === "apply" || call.name === "with") &&
          call.args.some((arg) => arg.k !== "lambda") &&
          !passes(call.args, http)
        ) {
          facts.unsupported.add("a custom configurer (apply or with) on the filter chain");
        }
      },
      (assign) => {
        const target = assign.target;
        const name = target.k === "member" || target.k === "id" ? target.name : null;
        if (name === "sessionCreationPolicy") {
          facts.sessionManagement = true;
          facts.policy = mergePolicy(facts.policy, policyOf(assign.value));
        }
      },
      (stmt) => {
        if (stmt.s === "local" && stmt.init !== null) locals.set(stmt.name, stmt.init);
      },
    );
  };
  collect(method, 0);

  let hasSecurityMatcher = false;
  // Calls inside `securityMatchers(...)` select the chain; they are not authorization rules.
  const selecting = new Set<CallExpr>();
  for (const { call } of calls) {
    if (call.name !== "securityMatcher" && call.name !== "securityMatchers") continue;
    for (const arg of call.args) {
      const body: Stmt[] =
        arg.k === "lambda" ? arg.body : [{ s: "expr", line: arg.line, expr: arg }];
      walkBody(body, (inner) => selecting.add(inner));
    }
  }
  const off = (call: CallExpr, parent: CallExpr | null): boolean =>
    parent?.name === "disable" || call.args.some(isDisablingArg);
  for (const { call, parent } of calls) {
    const name = call.name;
    if (name === "csrf") {
      csrfFact(unit, call, parent, facts, locals);
    } else if (SESSION_FEATURES.has(name)) {
      if (!off(call, parent)) {
        if (name === "formLogin") facts.formLogin = true;
        facts.sessionFeature ??= name;
      }
    } else if (name === "httpBasic") {
      if (!off(call, parent)) facts.httpBasic = true;
    } else if (name === "sessionManagement") {
      facts.sessionManagement = true;
    } else if (name === "sessionCreationPolicy") {
      facts.policy = mergePolicy(facts.policy, policyOf(call.args[0]));
    } else if (name === "securityContextRepository") {
      if (namesIn(call.args[0]).some((part) => /NoOp/i.test(part))) {
        facts.policy = mergePolicy(facts.policy, "stateless");
      }
    } else if (BEARER_FEATURES.has(name)) {
      if (!off(call, parent)) facts.bearer = true;
    } else if (name === "bearerTokenResolver") {
      facts.customBearer = true;
    } else if (
      name === "allowFormEncodedBodyParameter" ||
      name === "setAllowFormEncodedBodyParameter" ||
      name === "allowUriQueryParameter" ||
      name === "setAllowUriQueryParameter"
    ) {
      // `(false)` keeps the default. A literal true lets a form post carry the token, which a
      // forged form can use; anything else is only unclear.
      if (isTrue(call.args[0]) && /FormEncoded/.test(name)) facts.formToken = true;
      else if (!isFalse(call.args[0])) facts.customBearer = true;
    } else if (FILTER_ADDERS.has(name)) {
      if (call.args.some((arg) => namesIn(arg).some((part) => BEARER_NAME.test(part)))) {
        facts.tokenFilter = true;
      }
    } else if (name === "securityMatcher" || name === "securityMatchers" || name === "antMatcher") {
      hasSecurityMatcher = true;
    }
  }
  facts.scoped = hasSecurityMatcher;
  for (const form of facts.unsupported) unsupported.add(form);

  for (const fact of facts.csrfDisabled) csrfFinding(facts, fact, findings);
  authorizeFindings(unit, calls, hasSecurityMatcher, selecting, findings);
}

type Customizer = "full" | "conditional" | "none" | "unknown";

/**
 * What a customizer expression does to CSRF protection: disables it, disables it only on some
 * paths of the code (`flag ? withDefaults() : disable`), leaves it on, or cannot be told.
 * A variable is followed to its initializer in the same chain methods.
 */
function classifyCustomizer(expr: Expr, locals: ReadonlyMap<string, Expr>, depth = 0): Customizer {
  if (depth > 4) return "unknown";
  if (isDisableRef(expr)) return "full";
  if (expr.k === "lambda") {
    const state = disableIn(expr);
    return state === "yes" ? "full" : state === "conditional" ? "conditional" : "none";
  }
  if (expr.k === "cond" || expr.k === "alt") {
    const options = expr.k === "cond" ? [expr.a, expr.b] : expr.options;
    const kinds = options.map((option) => classifyCustomizer(option, locals, depth + 1));
    if (kinds.every((kind) => kind === "full")) return "full";
    if (kinds.some((kind) => kind === "full" || kind === "conditional")) return "conditional";
    return kinds.every((kind) => kind === "none") ? "none" : "unknown";
  }
  if (expr.k === "id") {
    const init = locals.get(expr.name);
    return init === undefined ? "unknown" : classifyCustomizer(init, locals, depth + 1);
  }
  if (isCall(expr)) {
    // `Customizer.withDefaults()` keeps the defaults; Kotlin `Customizer { it.disable() }`.
    if (expr.name === "withDefaults") return "none";
    if (expr.name === "Customizer" && expr.recv === null && expr.args[0]?.k === "lambda") {
      return classifyCustomizer(expr.args[0], locals, depth + 1);
    }
  }
  return "unknown";
}

/** Reads one `csrf` call: switched off, off in a branch, exempted for paths, or not readable. */
function csrfFact(
  unit: Unit,
  call: CallExpr,
  parent: CallExpr | null,
  facts: ChainFacts,
  locals: ReadonlyMap<string, Expr>,
): void {
  const line = call.line;
  if (call.args.length === 0) {
    if (parent?.name === "disable") {
      facts.csrfDisabled.push({ line, call, kind: "full", paths: [] });
    } else if (parent !== null && IGNORING.test(parent.name)) {
      const { paths, all } = ignoredPaths(unit, [parent]);
      facts.csrfDisabled.push({ line, call, kind: all ? "full" : "partial", paths });
    }
    return;
  }
  const kinds = call.args.map((arg) => classifyCustomizer(arg, locals));
  if (kinds.includes("full")) {
    facts.csrfDisabled.push({ line, call, kind: "full", paths: [] });
    return;
  }
  if (kinds.includes("conditional")) {
    facts.csrfDisabled.push({ line, call, kind: "conditional", paths: [] });
    return;
  }
  const exempting: CallExpr[] = [];
  const lambdas = call.args.flatMap((arg) => {
    if (arg.k === "lambda") return [arg];
    // A customizer variable or a conditional of lambdas: look at the lambdas it can be.
    const resolved = arg.k === "id" ? locals.get(arg.name) : arg;
    const options =
      resolved?.k === "cond"
        ? [resolved.a, resolved.b]
        : resolved?.k === "alt"
          ? resolved.options
          : [resolved];
    return options.filter(
      (option): option is Extract<Expr, { k: "lambda" }> => option?.k === "lambda",
    );
  });
  for (const lambda of lambdas) {
    walkBody(lambda.body, (inner) => {
      if (IGNORING.test(inner.name)) exempting.push(inner);
    });
  }
  if (exempting.length > 0) {
    const { paths, all } = ignoredPaths(unit, exempting);
    facts.csrfDisabled.push({ line, call, kind: all ? "full" : "partial", paths });
    return;
  }
  if (kinds.includes("unknown")) {
    // `csrf(customizer)`: a customizer this file does not show.
    facts.unsupported.add("a CSRF customizer held in a variable or built by a method");
  }
}

function mergePolicy(
  previous: ChainFacts["policy"],
  next: "stateless" | "session" | "unknown",
): ChainFacts["policy"] {
  // Spring uses the last setter, so the last call wins; an unknown value is unknown.
  void previous;
  return next;
}

function csrfFinding(facts: ChainFacts, fact: Fact, findings: ConfigFinding[]): void {
  const where = "Spring Security CSRF protection is disabled";
  const base = { ruleId: "PG-CSRF-001" as const, line: fact.line };
  const low = (evidence: string, cause = "csrf-disabled"): void => {
    findings.push({
      ...base,
      cause,
      severity: "medium",
      status: "suspected",
      confidence: "low",
      evidence: `${evidence}; inferred`,
    });
  };
  const medium = (evidence: string): void => {
    findings.push({
      ...base,
      cause: "csrf-disabled",
      severity: "medium",
      status: "suspected",
      confidence: "medium",
      evidence,
    });
  };
  if (fact.kind === "conditional") {
    low(`${where} only in a branch of the csrf customizer`, "csrf-conditional");
    return;
  }
  if (fact.kind === "partial") {
    const shown = fact.paths.slice(0, 3).join(", ");
    low(
      `CSRF protection is disabled for ${shown === "" ? "paths this file does not show" : shown}`,
      `csrf-ignoring:${shown}`,
    );
    return;
  }
  const partial = facts.unsupported.size > 0;
  const sessionEvidence = facts.sessionFeature !== null;
  const defaultBearer = facts.bearer && !facts.customBearer;
  if (facts.policy === "stateless") {
    if (sessionEvidence) {
      medium(
        `${where} on a chain that is STATELESS but also configures ${facts.sessionFeature}; the login there is cookie based`,
      );
    } else if (facts.formToken) {
      medium(
        `${where} on a STATELESS chain whose resource server accepts the token in a form-encoded body, which a forged form post can carry`,
      );
    } else if (facts.httpBasic) {
      medium(
        `${where} on a STATELESS chain with httpBasic: the browser sends basic credentials with every request, so a forged request carries them`,
      );
    } else if (defaultBearer) {
      // STATELESS with Spring's default bearer handling: no ambient credential to ride on.
      return;
    } else if (facts.bearer || facts.tokenFilter) {
      low(
        `${where} on a STATELESS chain; the token is read by a custom bearer resolver or a filter that is only known by its name, so it may also come from a cookie`,
      );
    } else {
      low(
        `${where} on a STATELESS chain with no recognised bearer setup (no oauth2ResourceServer); a cookie may still carry the login`,
      );
    }
    return;
  }
  if (facts.policy === "unknown") {
    low(
      `${where}; the session creation policy is not a fixed value, so whether the chain uses cookies is unclear`,
    );
    return;
  }
  if (sessionEvidence || facts.policy === "session") {
    medium(
      `${where} on a session-based chain (${
        facts.sessionFeature !== null
          ? facts.sessionFeature
          : "sessionCreationPolicy is not STATELESS"
      }): a form on another site can make the browser send the session cookie`,
    );
    return;
  }
  if (facts.bearer || facts.tokenFilter) {
    low(
      `${where} on a chain with a token setup but no sessionCreationPolicy(STATELESS); sessions may still be created`,
    );
    return;
  }
  if (partial) {
    low(
      `${where} and the chain sets no STATELESS session policy; the chain is also built by code this file does not show`,
    );
    return;
  }
  medium(
    `${where} and the chain sets no STATELESS session policy (Spring creates sessions by default)`,
  );
}

// ------------------------------------------------------------------------- catch-all and ignoring

function authorizeFindings(
  unit: Unit,
  calls: Array<{ call: CallExpr; parent: CallExpr | null; seq: number }>,
  scoped: boolean,
  selecting: ReadonlySet<CallExpr>,
  findings: ConfigFinding[],
): void {
  type Rule = {
    seq: number;
    line: number;
    catchAll: boolean;
    permit: boolean;
    restrictive: boolean;
  };
  const rules: Rule[] = [];
  for (const { call, parent, seq } of calls) {
    if (selecting.has(call)) continue;
    if (call.name === "authorize") {
      // Kotlin DSL: authorize(matcher, access).
      const matcher = call.args[0];
      const access = call.args[call.args.length - 1];
      if (call.args.length < 2 || matcher === undefined || access === undefined) continue;
      const catchAll =
        (matcher.k === "id" && CATCH_ALL_NAMES.has(matcher.name)) || isWildcardPath(unit, matcher);
      const permit = access.k === "id" && access.name === "permitAll";
      const restrictive =
        (access.k === "id" &&
          ["authenticated", "denyAll", "fullyAuthenticated"].includes(access.name)) ||
        (isCall(access) && RESTRICTIVE.has(access.name));
      rules.push({ seq, line: call.line, catchAll, permit, restrictive });
    } else if (CATCH_ALL_NAMES.has(call.name) || MATCHERS.has(call.name)) {
      if (call.name === "securityMatcher" || call.name === "securityMatchers") continue;
      const catchAll =
        CATCH_ALL_NAMES.has(call.name) || call.args.some((arg) => isWildcardPath(unit, arg));
      // The access call that follows in the chain.
      const permit = parent?.name === "permitAll";
      const restrictive = parent !== null && RESTRICTIVE.has(parent.name);
      rules.push({ seq, line: call.line, catchAll, permit, restrictive });
    }
  }
  rules.sort((a, b) => a.seq - b.seq);
  rules.forEach((rule, index) => {
    if (!rule.catchAll || !rule.permit) return;
    // `/**` followed by more rules: those rules can never be reached; any catch-all is last.
    const later = rules.slice(index + 1);
    if (later.length > 0) return;
    const earlierRestrictive = rules.slice(0, index).some((other) => other.restrictive);
    const lowered = earlierRestrictive || scoped;
    findings.push({
      ruleId: "PG-CONF-001",
      line: rule.line,
      severity: "medium",
      status: "suspected",
      confidence: lowered ? "low" : "medium",
      evidence: `the last authorization rule permits every other request (permitAll on ${
        rule.catchAll ? "a catch-all" : "all paths"
      })${
        earlierRestrictive
          ? "; earlier rules restrict some paths, so this is public-by-default; inferred"
          : scoped
            ? "; the chain is limited by a securityMatcher; inferred"
            : ""
      }`,
      cause: "permit-all-catch-all",
    });
  });
}

function isWildcardPath(unit: Unit, expr: Expr): boolean {
  if (expr.k === "new") return expr.args.some((arg) => isWildcardPath(unit, arg));
  const resolved = resolveStrings(unit, expr);
  return resolved.values.some((value) => value === "/**" || value === "/**/*");
}

function ignoringFindings(unit: Unit, body: readonly Stmt[], findings: ConfigFinding[]): void {
  walkBody(body, (call, _context, parent) => {
    if (call.name !== "ignoring" || call.args.length !== 0 || parent === null) return;
    if (CATCH_ALL_NAMES.has(parent.name)) {
      findings.push({
        ruleId: "PG-CONF-001",
        line: call.line,
        severity: "medium",
        status: "suspected",
        confidence: "medium",
        evidence:
          "web.ignoring().anyRequest() takes every request out of Spring Security (no authentication, no headers, no CSRF)",
        cause: "web-ignoring-any",
      });
      return;
    }
    if (!MATCHERS.has(parent.name)) return;
    const paths: string[] = [];
    let complete = true;
    let staticResources = false;
    for (const arg of parent.args) {
      if (arg.k === "id" && VERBS.has(arg.name)) continue;
      if (arg.k === "member" && arg.obj.k === "id" && arg.obj.name === "HttpMethod") continue;
      if (namesIn(arg).includes("toStaticResources")) {
        staticResources = true;
        continue;
      }
      const target = arg.k === "new" ? (arg.args[0] ?? arg) : arg;
      const resolved = resolveStrings(unit, target);
      paths.push(...resolved.values);
      if (!resolved.complete) complete = false;
    }
    if (parent.args.length > 0 && paths.length === 0 && !complete && !staticResources) {
      findings.push({
        ruleId: "PG-CONF-001",
        line: call.line,
        severity: "medium",
        status: "suspected",
        confidence: "low",
        evidence:
          "web.ignoring() takes paths out of Spring Security and they are not string literals in this file; inferred",
        cause: "web-ignoring-unresolved",
      });
      return;
    }
    const dynamic = paths.filter((path) => !STATIC_PATH.test(path));
    if (dynamic.length === 0) {
      if (!complete) {
        findings.push({
          ruleId: "PG-CONF-001",
          line: call.line,
          severity: "medium",
          status: "suspected",
          confidence: "low",
          evidence:
            "web.ignoring() also takes paths that are not string literals in this file out of Spring Security; inferred",
          cause: "web-ignoring-unresolved",
        });
      }
      return;
    }
    const known = dynamic.every((path) => KNOWN_PUBLIC.test(path));
    findings.push({
      ruleId: "PG-CONF-001",
      line: call.line,
      severity: "medium",
      status: "suspected",
      confidence: known ? "low" : "medium",
      evidence: `web.ignoring() takes ${shorten(dynamic.slice(0, 3).join(", "))} out of Spring Security (no authentication, headers or CSRF); only static resources belong here${
        known ? "; documentation or health endpoint; inferred" : ""
      }`,
      cause: `web-ignoring:${dynamic.slice(0, 3).join(",")}`,
    });
  });
}

// ------------------------------------------------------------------------------------------ CORS

const ORIGIN_SETTERS = new Set([
  "allowedOrigins",
  "allowedOriginPatterns",
  "setAllowedOrigins",
  "setAllowedOriginPatterns",
  "addAllowedOrigin",
  "addAllowedOriginPattern",
]);
const CREDENTIAL_SETTERS = new Set(["allowCredentials", "setAllowCredentials"]);

function corsFindings(unit: Unit, findings: ConfigFinding[]): void {
  for (const { body } of eachBody(unit)) {
    let wildcard: number | null = null;
    let credentials: "yes" | "maybe" | null = null;
    const credentialValue = (value: Expr | undefined): void => {
      if (isTrue(value)) credentials = "yes";
      else if (!isFalse(value) && credentials === null) credentials = "maybe";
    };
    const wildcardValue = (values: Expr[], line: number): void => {
      const resolved = values.map((value) => resolveStrings(unit, value));
      if (resolved.some((entry) => entry.values.includes("*"))) wildcard ??= line;
    };
    walkBody(
      body,
      (call) => {
        if (ORIGIN_SETTERS.has(call.name)) wildcardValue(call.args, call.line);
        else if (CREDENTIAL_SETTERS.has(call.name)) credentialValue(call.args[0]);
      },
      (assign) => {
        const target = assign.target;
        const name = target.k === "member" || target.k === "id" ? target.name : null;
        if (name !== null && ORIGIN_SETTERS.has(name)) wildcardValue([assign.value], assign.line);
        else if (name !== null && CREDENTIAL_SETTERS.has(name)) credentialValue(assign.value);
      },
    );
    if (wildcard !== null && credentials !== null) {
      findings.push({
        ruleId: "PG-CONF-001",
        line: wildcard,
        severity: "medium",
        status: "suspected",
        confidence: credentials === "yes" ? "medium" : "low",
        evidence: `CORS allows every origin ("*") together with ${
          credentials === "yes"
            ? "credentials"
            : "allowCredentials set from a value that is not a literal"
        }: any website can read authenticated responses${credentials === "yes" ? "" : "; inferred"}`,
        cause: "cors-wildcard-credentials",
      });
    }
  }
  // @CrossOrigin on a class and on its methods: the two are combined by Spring.
  for (const cls of [unit.top, ...unit.classes]) {
    const onClass = (cls.annotations ?? []).filter(
      (annotation) => annotation.name === "CrossOrigin",
    );
    const groups: Annotation[][] = [];
    for (const annotation of onClass) groups.push([annotation]);
    for (const method of cls.methods) {
      const own = method.annotations.filter((annotation) => annotation.name === "CrossOrigin");
      for (const annotation of own) groups.push([annotation, ...onClass]);
    }
    for (const group of groups) {
      let wildcard = false;
      let credentials: "yes" | "maybe" | null = null;
      for (const annotation of group) {
        const origins = [
          annotation.value,
          annotation.named.get("origins"),
          annotation.named.get("originPatterns"),
        ];
        for (const origin of origins) {
          if (resolveStrings(unit, origin).values.includes("*")) wildcard = true;
        }
        const allow = annotation.named.get("allowCredentials");
        if (allow !== undefined) {
          const text = literalText(allow);
          if (text === "true" || isTrue(allow)) credentials = "yes";
          else if (text !== "false" && !isFalse(allow) && credentials === null)
            credentials = "maybe";
        }
      }
      if (wildcard && credentials !== null) {
        const line = (group[0] as Annotation).line;
        findings.push({
          ruleId: "PG-CONF-001",
          line,
          severity: "medium",
          status: "suspected",
          confidence: credentials === "yes" ? "medium" : "low",
          evidence: `@CrossOrigin allows every origin ("*") together with ${
            credentials === "yes"
              ? "allowCredentials = true"
              : "allowCredentials from a value that is not a literal"
          }${credentials === "yes" ? "" : "; inferred"}`,
          cause: "cross-origin-wildcard-credentials",
        });
      }
    }
  }
}
