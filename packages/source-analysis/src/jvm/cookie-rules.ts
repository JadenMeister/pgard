import type { Expr, Stmt, Unit } from "./ir.js";
import {
  chainOf,
  eachBody,
  isFalse,
  isTrue,
  isZero,
  lastName,
  literalText,
  namesIn,
  shorten,
  walkBody,
  wordsOf,
  type CallExpr,
  type ConfigFinding,
  type WalkContext,
} from "./config-util.js";

/**
 * PG-COOKIE-001 for Java and Kotlin: a session or auth cookie sent without HttpOnly or Secure.
 *
 * - Servlet `Cookie` (`new Cookie("sid", v)`; Kotlin `Cookie("sid", v)`): `setHttpOnly(true)` and
 *   `setSecure(true)` (or the Kotlin properties, or an `apply { }` block) are the safe values.
 * - Spring `ResponseCookie.from(...)`: `httpOnly(true)`, `secure(true)` and `sameSite(...)`.
 * - A hand-written `Set-Cookie` header string.
 * - Spring Session and the servlet session cookie configuration set to `false`.
 *
 * Only a value that is a literal and safe is silent. A flag set from a variable, set only in a
 * branch, or on a cookie that is handed to another method is reported low and marked inferred.
 * Only cookies that look like session or auth cookies are judged, by the words in the cookie name
 * (or in the expression that makes its value): `sessionId`, `SESSION`, `x-auth`, `jwt`.
 */
type State = "true" | "false" | "unknown" | "unset";
type Kind = "servlet" | "response";

interface Tracked {
  kind: Kind;
  line: number;
  name: Expr | null;
  value: Expr | null;
  httpOnly: State;
  secure: State;
  sameSite: State;
  cleared: boolean;
  used: boolean;
  escaped: boolean;
}

const NAME_WORDS = new Set([
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
  "access",
]);
const NAME_WHOLE =
  /^(?:jsessionid|sessionid|sessid|accesstoken|refreshtoken|authtoken|idtoken|rememberme)$/;
const WEAK_WORDS = new Set(["uid", "userid", "user"]);
const SCOPE_FUNCTIONS = new Set(["apply", "also", "run", "let"]);

const simple = (type: string): string => {
  const bare = type.replace(/<.*>/s, "").trim();
  return bare.slice(bare.lastIndexOf(".") + 1);
};

type Strength = "strong" | "weak" | "none";

function strengthOf(name: Expr | null, value: Expr | null): Strength {
  const pieces: string[] = [];
  const text = literalText(name);
  if (text !== null) pieces.push(...text.split("\u0000"));
  pieces.push(...namesIn(name));
  let weak = false;
  for (const piece of pieces) {
    for (const word of wordsOf(piece)) {
      if (NAME_WORDS.has(word) || NAME_WHOLE.test(word)) return "strong";
      if (WEAK_WORDS.has(word)) weak = true;
    }
  }
  // The value tells when the name does not: a `theme` cookie that holds a `token`.
  for (const piece of namesIn(value)) {
    for (const word of wordsOf(piece)) {
      if (NAME_WORDS.has(word) && word !== "access") return "strong";
    }
  }
  return weak ? "weak" : "none";
}

function setState(
  t: Tracked,
  which: "httpOnly" | "secure" | "sameSite",
  next: State,
  c: WalkContext,
): void {
  // In a branch the other branch leaves the old state: only a state both agree on is certain.
  t[which] = c.conditional ? (t[which] === next ? next : "unknown") : next;
}

function boolState(expr: Expr | undefined): State {
  return isTrue(expr) ? "true" : isFalse(expr) ? "false" : "unknown";
}

function applyAssignment(t: Tracked, name: string, value: Expr, c: WalkContext): void {
  if (name === "isHttpOnly" || name === "httpOnly") setState(t, "httpOnly", boolState(value), c);
  else if (name === "secure" || name === "isSecure") setState(t, "secure", boolState(value), c);
  // Only an unconditional `maxAge(0)` clears the cookie; in a branch it is still sent otherwise.
  else if (name === "maxAge" && isZero(value) && !c.conditional) t.cleared = true;
}

function applyCall(t: Tracked, call: CallExpr, c: WalkContext): void {
  const first = call.args[0];
  switch (call.name) {
    case "setHttpOnly":
    case "httpOnly":
      setState(t, "httpOnly", boolState(first), c);
      break;
    case "setSecure":
    case "secure":
      setState(t, "secure", boolState(first), c);
      break;
    case "sameSite":
      setState(t, "sameSite", first?.k === "str" ? "true" : "unknown", c);
      break;
    case "setMaxAge":
    case "maxAge":
      if (isZero(first) && !c.conditional) t.cleared = true;
      break;
    case "setAttribute": {
      const attribute = (literalText(first) ?? "").toLowerCase();
      if (attribute === "httponly") setState(t, "httpOnly", "true", c);
      else if (attribute === "secure") setState(t, "secure", "true", c);
      else if (attribute === "samesite") setState(t, "sameSite", "true", c);
      break;
    }
    default:
      if (SCOPE_FUNCTIONS.has(call.name)) {
        for (const arg of call.args) {
          if (arg.k === "lambda") applyLambda(t, arg, c);
        }
      }
  }
}

/** `Cookie(...).apply { isHttpOnly = true; secure = true }` and `also { it.setSecure(true) }`. */
function applyLambda(t: Tracked, lambda: Extract<Expr, { k: "lambda" }>, c: WalkContext): void {
  walkBody(
    lambda.body,
    (call, context) => {
      if (call.recv === null || call.recv.k === "id") {
        applyCall(t, call, { conditional: c.conditional || context.conditional });
      }
    },
    (assign, context) => {
      const target = assign.target;
      const name = target.k === "member" || target.k === "id" ? target.name : null;
      if (name !== null) {
        applyAssignment(t, name, assign.value, {
          conditional: c.conditional || context.conditional,
        });
      }
    },
  );
}

/** A cookie made by this expression (and the calls chained onto it), or null. */
function creation(unit: Unit, expr: Expr, context: WalkContext): Tracked | null {
  const servlet = unit.imports.some((name) =>
    /^(?:javax|jakarta)\.servlet\.http\.(?:Cookie|\*)$/.test(name),
  );
  const spring = unit.imports.some((name) =>
    /^org\.springframework\.http\.(?:ResponseCookie|\*)$/.test(name),
  );
  const { root, calls } = chainOf(expr);
  let t: Tracked | null = null;
  let modifiers: CallExpr[] = [];
  if (servlet && root?.k === "new" && simple(root.type) === "Cookie") {
    t = fresh("servlet", root.line, root.args[0] ?? null, root.args[1] ?? null);
    modifiers = calls;
  } else if (servlet && root === null && calls[0]?.name === "Cookie" && calls[0].recv === null) {
    t = fresh("servlet", calls[0].line, calls[0].args[0] ?? null, calls[0].args[1] ?? null);
    modifiers = calls.slice(1);
  } else if (
    spring &&
    root?.k === "id" &&
    root.name === "ResponseCookie" &&
    (calls[0]?.name === "from" || calls[0]?.name === "fromClientResponse")
  ) {
    t = fresh("response", calls[0].line, calls[0].args[0] ?? null, calls[0].args[1] ?? null);
    modifiers = calls.slice(1);
  }
  if (t === null) return null;
  for (const call of modifiers) applyCall(t, call, context);
  return t;
}

function fresh(kind: Kind, line: number, name: Expr | null, value: Expr | null): Tracked {
  return {
    kind,
    line,
    name,
    value,
    httpOnly: "unset",
    secure: "unset",
    sameSite: "unset",
    // `new Cookie("sid", null)` and `Cookie("sid", "")` delete the cookie.
    cleared:
      kind === "servlet" &&
      value !== null &&
      ((value.k === "lit" && value.raw === undefined) || (value.k === "str" && value.text === "")),
    used: kind === "response",
    escaped: false,
  };
}

function judge(t: Tracked, findings: ConfigFinding[]): void {
  if (t.cleared || !t.used) return;
  const strength = strengthOf(t.name, t.value);
  if (strength === "none") return;
  const checked: Array<["HttpOnly" | "Secure" | "SameSite", State]> = [
    ["HttpOnly", t.httpOnly],
    ["Secure", t.secure],
  ];
  if (t.kind === "response") checked.push(["SameSite", t.sameSite]);
  const missing = checked.filter(([, state]) => state === "false" || state === "unset");
  const unsure = checked.filter(([, state]) => state === "unknown");
  if (missing.length === 0 && unsure.length === 0) return;
  const label =
    literalText(t.name)?.replace(/\u0000/g, "") || namesIn(t.name).join(".") || "cookie";
  const api = t.kind === "servlet" ? "Cookie" : "ResponseCookie";
  const inferred = missing.length === 0 || strength === "weak" || t.escaped;
  const why =
    missing.length > 0
      ? `${missing.map(([flag]) => flag).join(" and ")} not set`
      : `${unsure.map(([flag]) => flag).join(" and ")} set from a value that is not a fixed literal or only in a branch`;
  findings.push({
    ruleId: "PG-COOKIE-001",
    line: t.line,
    severity: "medium",
    status: "suspected",
    confidence: inferred ? "low" : "medium",
    evidence: `${api} "${shorten(label, 40)}" looks like a session or auth cookie and has ${why}${
      t.escaped && missing.length > 0
        ? " here (the cookie is passed to another method, which may set it)"
        : ""
    }${strength === "weak" ? " (the name only suggests a user cookie)" : ""}${inferred ? "; inferred" : ""}`,
    cause: `cookie:${t.kind}:${shorten(label, 40)}`,
  });
}

export function analyzeCookies(unit: Unit): ConfigFinding[] {
  const findings: ConfigFinding[] = [];
  for (const { body } of eachBody(unit)) bodyFindings(unit, body, findings);
  return findings;
}

function bodyFindings(unit: Unit, body: readonly Stmt[], findings: ConfigFinding[]): void {
  const vars = new Map<string, Tracked>();
  const all: Tracked[] = [];
  const handled = new Set<Expr>();
  const bind = (name: string, init: Expr, context: WalkContext): void => {
    const t = creation(unit, init, context);
    if (t === null) return;
    handled.add(init);
    vars.set(name, t);
    all.push(t);
  };
  const inline = (expr: Expr, context: WalkContext): void => {
    if (handled.has(expr)) return;
    const t = creation(unit, expr, context);
    if (t === null) return;
    handled.add(expr);
    t.used = true;
    all.push(t);
  };
  const tracked = (expr: Expr | null | undefined): Tracked | null =>
    expr?.k === "id" ? (vars.get(expr.name) ?? null) : null;

  walkBody(
    body,
    (call, context, parent) => {
      // Cookies handed to another method may be changed there; `addCookie` only sends them.
      for (const arg of call.args) {
        const t = tracked(arg);
        if (t !== null) {
          t.used = true;
          if (call.name !== "addCookie") t.escaped = true;
        }
      }
      const rawHeader = rawSetCookie(call);
      if (rawHeader !== null) findings.push(rawHeader);
      const serializer = sessionSettings(call);
      if (serializer !== null) findings.push(serializer);
      if (parent !== null) return;
      // The top of a chain: `c.setSecure(true)`, `v.httpOnly(true).secure(true)`, a new cookie.
      const { root, calls } = chainOf(call);
      const t = tracked(root);
      if (t !== null) {
        for (const item of calls) applyCall(t, item, context);
      } else {
        inline(call, context);
      }
    },
    (assign, context) => {
      const target = assign.target;
      if (target.k === "member") {
        const t = tracked(target.obj);
        if (t !== null) applyAssignment(t, target.name, assign.value, context);
        const text = namesIn(target.obj).join(".");
        if (
          /sessionCookieConfig/i.test(text) &&
          (target.name === "isHttpOnly" ||
            target.name === "httpOnly" ||
            target.name === "secure" ||
            target.name === "isSecure") &&
          isFalse(assign.value)
        ) {
          findings.push(
            sessionConfigFinding(
              assign.line,
              target.name.replace(/^is/, "").toLowerCase() === "httponly" ? "HttpOnly" : "Secure",
            ),
          );
        }
        if (
          (target.name === "useHttpOnlyCookie" || target.name === "useSecureCookie") &&
          isFalse(assign.value)
        ) {
          findings.push(
            sessionConfigFinding(
              assign.line,
              target.name === "useHttpOnlyCookie" ? "HttpOnly" : "Secure",
            ),
          );
        }
      } else if (target.k === "id") {
        if (
          (target.name === "useHttpOnlyCookie" || target.name === "useSecureCookie") &&
          isFalse(assign.value)
        ) {
          findings.push(
            sessionConfigFinding(
              assign.line,
              target.name === "useHttpOnlyCookie" ? "HttpOnly" : "Secure",
            ),
          );
        }
        // `c = Cookie(...)`, and `v = v.httpOnly(true)`.
        const previous = vars.get(target.name);
        const { root, calls } = chainOf(assign.value);
        if (previous !== undefined && tracked(root) === previous) {
          for (const item of calls) applyCall(previous, item, context);
          handled.add(assign.value);
        } else {
          bind(target.name, assign.value, context);
          const stored = tracked(assign.value);
          if (stored !== null) stored.escaped = true;
        }
      }
    },
    (stmt, context) => {
      if (stmt.s === "local" && stmt.init !== null) {
        bind(stmt.name, stmt.init, context);
        const stored = tracked(stmt.init);
        if (stored !== null) {
          stored.escaped = true;
          vars.set(stmt.name, stored);
        }
      } else if (stmt.s === "exit") {
        const t = tracked(stmt.value);
        if (t !== null) {
          t.used = true;
          t.escaped = true;
        }
      }
    },
    (node, context) => inline(node, context),
  );
  for (const t of all) judge(t, findings);
}

function sessionConfigFinding(line: number, flag: "HttpOnly" | "Secure"): ConfigFinding {
  return {
    ruleId: "PG-COOKIE-001",
    line,
    severity: "medium",
    status: "suspected",
    confidence: "medium",
    evidence: `the session cookie is configured without ${flag} (set to false)`,
    cause: `session-cookie-${flag.toLowerCase()}`,
  };
}

/** Spring Session `DefaultCookieSerializer`, `rememberMe().useSecureCookie(false)`, `SessionCookieConfig`. */
function sessionSettings(call: CallExpr): ConfigFinding | null {
  if (!isFalse(call.args[0]) || call.args.length !== 1) return null;
  if (call.name === "setUseHttpOnlyCookie") return sessionConfigFinding(call.line, "HttpOnly");
  if (call.name === "setUseSecureCookie" || call.name === "useSecureCookie") {
    return sessionConfigFinding(call.line, "Secure");
  }
  if (call.name === "setHttpOnly" || call.name === "setSecure") {
    const text = namesIn(call.recv).join(".");
    if (/getSessionCookieConfig|sessionCookieConfig/.test(text)) {
      return sessionConfigFinding(call.line, call.name === "setHttpOnly" ? "HttpOnly" : "Secure");
    }
  }
  return null;
}

/** `response.addHeader("Set-Cookie", "sid=" + id + "; Path=/")`: the cookie is written by hand. */
function rawSetCookie(call: CallExpr): ConfigFinding | null {
  if (!["addHeader", "setHeader", "header", "add", "set"].includes(call.name)) return null;
  const header = call.args[0];
  const isSetCookie =
    (header?.k === "str" && header.text.toLowerCase() === "set-cookie") ||
    lastName(header) === "SET_COOKIE";
  if (!isSetCookie) return null;
  const text = literalText(call.args[1]);
  // A cookie written by hand has a literal `name=` part; `cookie.toString()` has none.
  if (text === null || !text.includes("=")) return null;
  const name = text.slice(0, text.indexOf("=")).replace(/\u0000/g, "");
  const nameExpr: Expr = { k: "str", line: call.line, text: name };
  if (strengthOf(nameExpr, call.args[1] ?? null) !== "strong") return null;
  // Attributes are whole tokens between `;` (`Secure`, `HttpOnly`), not substrings (`NotSecure`).
  const attributes = text
    .split(";")
    .slice(1)
    .map((token) => token.trim().toLowerCase());
  const missing: string[] = [];
  if (!attributes.includes("httponly")) missing.push("HttpOnly");
  if (!attributes.includes("secure")) missing.push("Secure");
  if (missing.length === 0) return null;
  // An attribute part that is built at run time may supply the flag.
  const dynamic = attributes.some((token) => token.includes("\u0000"));
  return {
    ruleId: "PG-COOKIE-001",
    line: call.line,
    severity: "medium",
    status: "suspected",
    confidence: dynamic ? "low" : "medium",
    evidence: `Set-Cookie header for "${shorten(name || "cookie", 40)}" is written by hand without ${missing.join(" and ")}${dynamic ? " (part of the attributes is built at run time); inferred" : ""}`,
    cause: `set-cookie-header:${shorten(name, 40)}`,
  };
}
