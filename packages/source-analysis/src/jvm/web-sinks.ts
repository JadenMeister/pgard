import type { Confidence, FindingStatus, Severity } from "@pgard/findings";
import {
  addLeaves,
  baseType,
  join,
  literalText,
  nonConst,
  sourcesOf,
  value,
  type Context,
  type Leaf,
  type Value,
} from "./flow-values.js";
import type { ClassInfo, Expr, MethodInfo } from "./ir.js";
import { HANDLER_ANNOTATIONS } from "./jvm-names.js";
import {
  APACHE_BUILDERS,
  APACHE_REQUESTS,
  BODY_CLASS_ANNOTATIONS,
  CLIENT_NAME,
  CLIENT_TYPE,
  ESCAPE_ANY_CLASS_NAMES,
  ESCAPE_CLASSES,
  ESCAPE_NAME,
  FLUENT_VERBS,
  HTML_CONTENT,
  HTTP_CLIENT_IMPORTS,
  HTTP_VERBS,
  MODEL_ADDERS,
  MODEL_NAME,
  MODEL_TYPES,
  OTHER_CONTENT,
  REST_NAME,
  REST_TEMPLATE_SHARED,
  REST_TEMPLATE_UNIQUE,
  REST_TYPE,
  TEXT_KEEPERS,
  URL_CONSUMERS,
  URL_KEEPERS,
  URL_OPENERS,
  URL_READERS,
  URL_TYPES,
  WRITER_GETTERS,
  WRITER_MEMBERS,
  WRITER_METHODS,
  WRITER_WRAPPERS,
} from "./web-names.js";

export type WebRuleId = "PG-XSS-004" | "PG-SSRF-002";

/** A finding before the path is attached. */
export interface WebFinding {
  ruleId: WebRuleId;
  line: number;
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  evidence: string;
  cause: string;
}

/** A value put into a template model under a fixed name (`model.addAttribute("name", v)`). */
export interface ModelAttribute {
  name: string;
  /** Request input went into the value. */
  tainted: boolean;
  line: number;
}

export interface WebHost {
  typeOfExpr: (expr: Expr, ctx: Context) => string | null;
  record: (finding: WebFinding, rank: number) => void;
  imports: readonly string[];
}

type CallExpr = Extract<Expr, { k: "call" }>;
type SourceLeaf = Extract<Leaf, { k: "source" }>;
/** What the response's content type is known to be. */
type ContentType = "unset" | "html" | "other" | "dynamic";

type Kind = "tainted" | "helper" | "unknown" | "inferred";
interface Judged {
  kind: Kind;
  tainted: SourceLeaf[];
  helper: string;
  reasons: string[];
  shape: string;
  bare: boolean;
}

const FIXED_BASE = /^\s*(?:https?:)?\/\/[A-Za-z0-9][A-Za-z0-9.-]*(?::\d{1,5})?(?=[/?#])/i;
const CONFIGURED_BASE = /url|uri|base|host|endpoint|api|server|origin/i;
const MARKUP = /<[A-Za-z/!]/;

/** Every string and name in an expression, for reading a content type or a client verb. */
export function exprWords(expr: Expr | null | undefined, depth = 0): string {
  if (expr === null || expr === undefined || depth > 6) return "";
  switch (expr.k) {
    case "str":
      return expr.text;
    case "id":
      return expr.name;
    case "member":
      return `${exprWords(expr.obj, depth + 1)} ${expr.name}`;
    case "call":
      return `${exprWords(expr.recv, depth + 1)} ${expr.name} ${expr.args.map((arg) => exprWords(arg, depth + 1)).join(" ")}`;
    case "bin":
      return `${exprWords(expr.left, depth + 1)} ${exprWords(expr.right, depth + 1)}`;
    case "array":
      return expr.elems.map((elem) => exprWords(elem, depth + 1)).join(" ");
    case "tmpl":
      return expr.parts
        .map((part) => (typeof part === "string" ? part : exprWords(part, depth + 1)))
        .join(" ");
    case "other":
      return expr.kids.map((kid) => exprWords(kid, depth + 1)).join(" ");
    default:
      return "";
  }
}

const contentTypeOf = (expr: Expr | undefined): ContentType => {
  if (expr === undefined) return "dynamic";
  const words = exprWords(expr);
  if (HTML_CONTENT.test(words)) return "html";
  if (OTHER_CONTENT.test(words)) return "other";
  return expr.k === "str" ? "other" : "dynamic";
};

/** The calls of a chain (`a.b().c()`), outermost last. */
function chainOf(expr: Expr | null): CallExpr[] {
  const out: CallExpr[] = [];
  let current: Expr | null = expr;
  for (let hops = 0; current !== null && hops < 30; hops += 1) {
    if (current.k === "call") {
      out.unshift(current);
      current = current.recv;
    } else if (current.k === "member") {
      current = current.obj;
    } else {
      break;
    }
  }
  return out;
}

/** The content type that a response builder chain sets (`.contentType(TEXT_HTML)`), if any. */
function chainContentType(expr: Expr | null): ContentType | null {
  let found: ContentType | null = null;
  for (const call of chainOf(expr)) {
    if (call.name === "contentType" && call.args[0] !== undefined) {
      found = contentTypeOf(call.args[0]);
    } else if (call.name === "header" && /content-?type/i.test(exprWords(call.args[0]))) {
      found = contentTypeOf(call.args[1]);
    }
  }
  return found;
}

const hint = (expr: Expr | null | undefined): string =>
  expr === null || expr === undefined
    ? ""
    : expr.k === "id" || expr.k === "member" || expr.k === "call"
      ? expr.name
      : "";

const demoteEscaped = (leaves: readonly Leaf[]): Leaf[] => {
  const out: Leaf[] = [];
  addLeaves(
    out,
    leaves.map((leaf): Leaf =>
      (leaf.k === "source" || leaf.k === "unknown") && leaf.esc !== undefined
        ? { k: "inferred", why: leaf.esc }
        : leaf,
    ),
  );
  return out;
};

/** The base of a URL when its host is fixed text and only a path or query follows. */
export function fixedBaseOf(leaves: readonly Leaf[]): string | null {
  let text = "";
  for (const leaf of leaves) {
    if (leaf.k !== "const") break;
    text += leaf.text;
  }
  const match = FIXED_BASE.exec(text);
  if (match !== null) return match[0].trim();
  // A base held in a configuration field or a caller's value, then a path: `baseUrl + "/users/" + id`.
  const [first, second] = leaves;
  if (
    first?.k === "unknown" &&
    first.esc === undefined &&
    CONFIGURED_BASE.test(first.name) &&
    second?.k === "const" &&
    /^[/?#]/.test(second.text)
  ) {
    return "a configured base URL";
  }
  return null;
}

export function createWebSinks(host: WebHost) {
  const modelAttributes: ModelAttribute[] = [];
  /** Content type set on the response so far in this method. */
  let contentType: ContentType = "unset";

  const importsAny = (prefixes: readonly string[]): boolean =>
    host.imports.some((name) =>
      prefixes.some((prefix) => name === prefix || name.startsWith(`${prefix}.`)),
    );
  const usesJdk = importsAny(HTTP_CLIENT_IMPORTS.jdk);
  const usesSpring = importsAny(HTTP_CLIENT_IMPORTS.spring);
  const usesOkHttp = importsAny(HTTP_CLIENT_IMPORTS.okhttp);
  const usesApache = importsAny(HTTP_CLIENT_IMPORTS.apache);
  const usesKtor = importsAny(HTTP_CLIENT_IMPORTS.ktor);

  // ---------------------------------------------------------------- judging a value

  function judge(v: Value, composed = v.composed): Judged | null {
    const leaves: Leaf[] = [];
    addLeaves(leaves, demoteEscaped(v.leaves));
    const dynamic = nonConst(leaves);
    if (dynamic.length === 0) return null;
    const callName = v.opaque.replace(/\(\)$/, "");
    const opaque = TEXT_KEEPERS.has(callName) ? "" : v.opaque;
    const tainted = sourcesOf(leaves) as SourceLeaf[];
    const helperLeaf = dynamic.find(
      (leaf) => leaf.k === "unknown" && /\(\)$|^mutable field /.test(leaf.name),
    );
    const helper = opaque !== "" ? opaque : helperLeaf?.k === "unknown" ? helperLeaf.name : "";
    const reasons = [
      ...new Set(dynamic.map((leaf) => (leaf.k === "inferred" ? leaf.why : "")).filter(Boolean)),
    ];
    const shape = v.shape || (composed ? "built value" : "value");
    const base = { tainted, helper, reasons, shape, bare: !composed };
    if (!composed) {
      if (opaque !== "") return { kind: "helper", ...base, tainted: [] };
      if (tainted.length > 0) return { kind: "tainted", ...base };
      if (helper !== "") return { kind: "helper", ...base };
      if (reasons.length > 0 && !dynamic.some((leaf) => leaf.k === "unknown")) {
        return { kind: "inferred", ...base };
      }
      return { kind: "unknown", ...base };
    }
    if (tainted.length > 0) return { kind: "tainted", ...base };
    if (dynamic.some((leaf) => leaf.k === "unknown")) return { kind: "unknown", ...base };
    return { kind: "inferred", ...base };
  }

  const sourceText = (judged: Judged): { text: string; source: SourceLeaf } => {
    const source = (judged.tainted.find((leaf) => leaf.direct) ?? judged.tainted[0]) as SourceLeaf;
    return {
      text: `request input (${source.label})${source.direct ? "" : " via variable"}`,
      source,
    };
  };

  const lowReason = (judged: Judged): string =>
    judged.kind === "helper"
      ? `value from ${judged.helper}, not followed; inferred`
      : judged.kind === "unknown"
        ? judged.bare
          ? "a value with no identified source (such as a parameter) reaches it; callers not followed; inferred"
          : "(no input source identified)"
        : `${judged.reasons.slice(0, 2).join("; ")}; inferred`;

  const rankOf = (kind: Kind): number => (kind === "tainted" ? 3 : kind === "unknown" ? 2 : 1);

  interface Options {
    /** Strongest confidence a request-input finding may have here. */
    top: Confidence;
    /** SSRF: the URL has a fixed base and only a path or query varies. */
    base: string | null;
    /** Why the strongest confidence is lower (XSS: the content type is not known to be HTML). */
    caveat: string;
  }

  function report(
    ruleId: WebRuleId,
    judged: Judged,
    line: number,
    label: string,
    options: Options,
  ): void {
    const base = { ruleId, line, cause: label };
    if (judged.kind === "tainted") {
      const { text, source } = sourceText(judged);
      if (options.base !== null) {
        host.record(
          {
            ...base,
            severity: "medium",
            status: "suspected",
            confidence: "low",
            evidence: `${text} -> ${judged.shape} -> ${label}; fixed base URL (${options.base}), only a path or query comes from request input (path injection); inferred`,
          },
          2,
        );
        return;
      }
      if (options.top === "low") {
        host.record(
          {
            ...base,
            severity: "medium",
            status: "suspected",
            confidence: "low",
            evidence: `${text} -> ${judged.shape} -> ${label}; ${options.caveat}; inferred`,
          },
          3,
        );
        return;
      }
      host.record(
        {
          ...base,
          severity: "high",
          status: source.direct ? "confirmed" : "suspected",
          confidence: options.top,
          evidence: `${text} -> ${judged.shape} -> ${label}${options.caveat === "" ? "" : `; ${options.caveat}`}`,
        },
        3,
      );
      return;
    }
    const joiner = judged.kind === "unknown" && !judged.bare ? " " : "; ";
    host.record(
      {
        ...base,
        severity: judged.kind === "unknown" && judged.bare ? "low" : "medium",
        status: "suspected",
        confidence: "low",
        evidence: `${judged.shape} -> ${label}${joiner}${lowReason(judged)}`,
      },
      rankOf(judged.kind),
    );
  }

  // ---------------------------------------------------------------- XSS

  const NO_CAVEAT: Options = { top: "high", base: null, caveat: "" };

  function xssOptions(type: ContentType): Options | null {
    if (type === "other") return null;
    if (type === "html") return { ...NO_CAVEAT, caveat: "content type text/html" };
    if (type === "unset") {
      return { ...NO_CAVEAT, top: "medium", caveat: "no content type set before the write" };
    }
    return { ...NO_CAVEAT, top: "low", caveat: "content type is not fixed" };
  }

  function xssSink(v: Value, line: number, label: string, type: ContentType, ctx: Context): void {
    if (!ctx.report) return;
    const options = xssOptions(type);
    if (options === null) return;
    const judged = judge(v);
    if (judged === null) return;
    // A value nothing links to request input is told apart from JSON, CSV or plain text only by its
    // surroundings: an HTML content type, or markup in the text around it.
    if (judged.kind !== "tainted" && type !== "html" && !MARKUP.test(literalText(v.leaves))) {
      return;
    }
    report("PG-XSS-004", judged, line, label, options);
  }

  function noteContentType(arg: Expr | undefined): void {
    contentType = contentTypeOf(arg);
  }

  // ---------------------------------------------------------------- SSRF

  function ssrfSink(v: Value, line: number, label: string, ctx: Context): void {
    if (!ctx.report) return;
    const judged = judge(v, v.composed);
    if (judged === null) return;
    const base = judged.kind === "tainted" ? fixedBaseOf(v.leaves) : null;
    report("PG-SSRF-002", judged, line, label, { ...NO_CAVEAT, base, caveat: "" });
  }

  function urlValue(parts: readonly Value[]): Value {
    const leaves: Leaf[] = [];
    for (const part of parts) addLeaves(leaves, part.leaves);
    const first = parts[0];
    return value(leaves, {
      web: "url",
      composed: parts.length > 1 || (first?.composed ?? false),
      shape: first?.shape ?? "",
      opaque: first?.opaque ?? "",
    });
  }

  const isUrlType = (expr: Expr | null, ctx: Context): boolean =>
    expr !== null && URL_TYPES.has(baseType(host.typeOfExpr(expr, ctx)));

  const clientLike = (expr: Expr | null, ctx: Context): boolean => {
    if (expr === null) return false;
    if (CLIENT_TYPE.test(host.typeOfExpr(expr, ctx) ?? "")) return true;
    if (expr.k === "call" && (expr.name === "HttpClient" || expr.name === "newHttpClient"))
      return true;
    return CLIENT_NAME.test(hint(expr));
  };

  const restLike = (expr: Expr | null, ctx: Context): boolean =>
    expr !== null &&
    (REST_TYPE.test(host.typeOfExpr(expr, ctx) ?? "") || REST_NAME.test(hint(expr)));

  // ---------------------------------------------------------------- escaping

  function escapeLabel(name: string, className: string, recvExpr: Expr | null): string | null {
    const byClass = className !== "" && ESCAPE_CLASSES.has(className);
    if (ESCAPE_NAME.test(name)) {
      const generic = name === "clean" || name.startsWith("sanitize");
      if (generic && !byClass && !/sanitiz|jsoup|policy|cleaner/i.test(hint(recvExpr))) return null;
      return `escaped with ${className === "" ? "" : `${className}.`}${name}()`;
    }
    if (ESCAPE_ANY_CLASS_NAMES.has(name)) {
      if (
        byClass ||
        (name === "escape" && chainOf(recvExpr).some((call) => /scaper/.test(call.name)))
      ) {
        return `escaped with ${className === "" ? "" : `${className}.`}${name}()`;
      }
    }
    return null;
  }

  function escaped(arg: Value, why: string): Value {
    const leaves: Leaf[] = [];
    addLeaves(
      leaves,
      arg.leaves.map((leaf): Leaf =>
        leaf.k === "source" || leaf.k === "unknown" ? { ...leaf, esc: `${why}; inferred` } : leaf,
      ),
    );
    return value(leaves, { composed: false, shape: arg.shape });
  }

  // ---------------------------------------------------------------- model attributes

  function noteModel(expr: CallExpr, args: Value[], recv: Value | null, ctx: Context): void {
    if (expr.recv === null || args.length < 2) return;
    const nameArg = expr.args[0];
    if (nameArg?.k !== "str") return;
    const type = baseType(host.typeOfExpr(expr.recv, ctx));
    const typed = MODEL_TYPES.test(type);
    const named = MODEL_NAME.test(hint(expr.recv));
    const ok =
      expr.name === "put"
        ? typed
        : expr.name === "setAttribute"
          ? recv?.req === true
          : typed || named;
    if (!ok) return;
    modelAttributes.push({
      name: nameArg.text,
      tainted: sourcesOf(args[1]?.leaves ?? []).length > 0,
      line: expr.line,
    });
  }

  // ---------------------------------------------------------------- calls

  function call(
    expr: CallExpr,
    recv: Value | null,
    args: Value[],
    typeReceiver: boolean,
    className: string,
    ctx: Context,
  ): Value | null {
    const { name, line } = expr;
    const recvExpr = expr.recv;
    const first = args[0];
    const firstExpr = expr.args[0];
    const firstIsLambda = firstExpr?.k === "lambda";

    const why = escapeLabel(name, className, recvExpr);
    if (why !== null && first !== undefined && !firstIsLambda) return escaped(first, why);

    if (MODEL_ADDERS.has(name) && ctx.report) noteModel(expr, args, recv, ctx);

    // ---- servlet responses ----
    if (recv?.web === "response") {
      if (WRITER_GETTERS.has(name)) return value([], { web: "writer" });
      if (name === "setContentType") noteContentType(firstExpr);
      else if (
        (name === "setHeader" || name === "addHeader") &&
        /content-?type/i.test(exprWords(firstExpr))
      ) {
        noteContentType(expr.args[1]);
      }
      return null;
    }
    if (recv?.web === "writer" && WRITER_METHODS.has(name)) {
      const text = name === "printf" || name === "format" ? join("String.format", ...args) : first;
      if (text !== undefined)
        xssSink(text, line, `${hint(recvExpr) || "response"}.${name}`, contentType, ctx);
      return null;
    }
    if (name === "respondText" && recvExpr !== null && first !== undefined) {
      // Ktor: plain text unless the content type says HTML.
      const type = expr.args.slice(1).some((arg) => HTML_CONTENT.test(exprWords(arg)))
        ? "html"
        : "other";
      xssSink(first, line, "call.respondText", type, ctx);
      return null;
    }
    if (
      (name === "body" || name === "bodyValue" || name === "syncBody") &&
      first !== undefined &&
      chainContentType(recvExpr) === "html"
    ) {
      xssSink(first, line, "response body", "html", ctx);
      return null;
    }

    // ---- URL values ----
    if (
      typeReceiver &&
      URL_TYPES.has(className) &&
      (name === "create" || name === "of") &&
      args.length >= 1
    ) {
      return urlValue(args);
    }
    if (typeReceiver && /^(?:UriComponentsBuilder|UriBuilder|HttpUrl|Uri)$/.test(className)) {
      if (/^(?:from\w*|newInstance|parse|get)$/.test(name) && args.length >= 1 && !firstIsLambda) {
        return urlValue(args);
      }
    }
    if (recv?.web === "url") {
      if (URL_OPENERS.has(name) || URL_READERS.has(name)) {
        ssrfSink(recv, line, `URL.${name}`, ctx);
        return null;
      }
      if (name === "resolve" && first !== undefined) return urlValue([first, recv]);
      if (/^(?:path|pathSegment|replacePath)$/.test(name)) {
        return urlValue([recv, value([{ k: "const", text: "/" }]), ...args]);
      }
      if (/^(?:query|queryParam|queryParams|replaceQuery|replaceQueryParam|fragment)$/.test(name)) {
        return urlValue([recv, value([{ k: "const", text: "?" }]), ...args]);
      }
      if (/^(?:expand|buildAndExpand)$/.test(name)) {
        return urlValue([recv, value([{ k: "const", text: "/" }]), ...args]);
      }
      if (
        URL_KEEPERS.has(name) ||
        (/^(?:build|encode|scheme|port|userInfo|uri)$/.test(name) && name !== "uri")
      ) {
        return urlValue([recv]);
      }
    }
    if (recv !== null && recv.web !== "url" && recvExpr !== null && name === "toHttpUrl") {
      return urlValue([recv]);
    }
    if (
      recvExpr !== null &&
      (URL_OPENERS.has(name) || URL_READERS.has(name)) &&
      recv?.web !== "url" &&
      isUrlType(recvExpr, ctx) &&
      recv !== null
    ) {
      ssrfSink(recv, line, `URL.${name}`, ctx);
      return null;
    }

    // ---- HTTP clients ----
    if (
      typeReceiver &&
      className === "HttpRequest" &&
      name === "newBuilder" &&
      first !== undefined
    ) {
      ssrfSink(first, line, "HttpRequest.newBuilder", ctx);
      return null;
    }
    if (
      name === "uri" &&
      args.length === 1 &&
      first !== undefined &&
      !firstIsLambda &&
      recv?.req !== true
    ) {
      if (usesJdk || usesSpring) {
        const verb = chainOf(recvExpr).some((call) => HTTP_VERBS.has(call.name));
        ssrfSink(
          first,
          line,
          verb && usesSpring ? "WebClient.uri" : "HttpRequest.Builder.uri",
          ctx,
        );
      }
      return null;
    }
    if (
      typeReceiver &&
      (className === "WebClient" || className === "RestClient") &&
      name === "create" &&
      first !== undefined
    ) {
      ssrfSink(first, line, `${className}.create`, ctx);
      return null;
    }
    if (name === "baseUrl" && usesSpring && args.length === 1 && first !== undefined) {
      ssrfSink(first, line, "WebClient.baseUrl", ctx);
      return null;
    }
    if (
      recvExpr !== null &&
      first !== undefined &&
      !firstIsLambda &&
      (REST_TEMPLATE_UNIQUE.has(name) || REST_TEMPLATE_SHARED.has(name)) &&
      (restLike(recvExpr, ctx) || (usesSpring && REST_TEMPLATE_UNIQUE.has(name)))
    ) {
      ssrfSink(first, line, `RestTemplate.${name}`, ctx);
      return null;
    }
    if (
      name === "url" &&
      args.length === 1 &&
      first !== undefined &&
      !firstIsLambda &&
      (usesOkHttp || usesKtor)
    ) {
      ssrfSink(first, line, usesOkHttp ? "OkHttp Request.Builder.url" : "Ktor url", ctx);
      return null;
    }
    if (
      typeReceiver &&
      className === "HttpUrl" &&
      /^(?:parse|get)$/.test(name) &&
      first !== undefined
    ) {
      return urlValue(args);
    }
    if (name === "setUri" && usesApache && first !== undefined && !firstIsLambda) {
      ssrfSink(first, line, "HttpRequest.setUri", ctx);
      return null;
    }
    if (
      typeReceiver &&
      usesApache &&
      first !== undefined &&
      ((className === "Request" && FLUENT_VERBS.has(name)) ||
        (APACHE_BUILDERS.has(className) && HTTP_VERBS.has(name)))
    ) {
      ssrfSink(first, line, `${className}.${name}`, ctx);
      return null;
    }
    if (typeReceiver && className === "Unirest" && HTTP_VERBS.has(name) && first !== undefined) {
      ssrfSink(first, line, `Unirest.${name}`, ctx);
      return null;
    }
    if (typeReceiver && className === "Jsoup" && name === "connect" && first !== undefined) {
      ssrfSink(first, line, "Jsoup.connect", ctx);
      return null;
    }
    if (
      usesKtor &&
      recvExpr !== null &&
      HTTP_VERBS.has(name) &&
      first !== undefined &&
      !firstIsLambda &&
      clientLike(recvExpr, ctx)
    ) {
      ssrfSink(first, line, `Ktor client.${name}`, ctx);
      return null;
    }
    if (first?.web === "url") {
      const consumer = URL_CONSUMERS.find(
        (entry) => typeReceiver && entry.className === className && entry.names.has(name),
      );
      if (consumer !== undefined) {
        ssrfSink(first, line, `${className}.${name}`, ctx);
        return null;
      }
      if ((name === "readValue" || name === "readTree") && recvExpr !== null) {
        ssrfSink(first, line, `ObjectMapper.${name}(URL)`, ctx);
        return null;
      }
    }
    return null;
  }

  // ---------------------------------------------------------------- constructors

  function construct(
    type: string,
    line: number,
    argExprs: Expr[],
    args: Value[],
    ctx: Context,
  ): Value | null {
    const first = args[0];
    if (URL_TYPES.has(type) && args.length >= 1) return urlValue(args);
    if (APACHE_REQUESTS.has(type) && first !== undefined && argExprs[0]?.k !== "lambda") {
      ssrfSink(first, line, `new ${type}`, ctx);
      return null;
    }
    if (
      type === "UrlResource" &&
      first !== undefined &&
      !(first.leaves[0]?.k === "const" && /^\s*file:/i.test(first.leaves[0].text))
    ) {
      ssrfSink(first, line, "UrlResource", ctx);
      return null;
    }
    if (WRITER_WRAPPERS.has(type) && first?.web === "writer") return value([], { web: "writer" });
    if (type === "ModelAndView" && args.length === 3 && argExprs[1]?.k === "str") {
      modelAttributes.push({
        name: argExprs[1].text,
        tainted: sourcesOf(args[2]?.leaves ?? []).length > 0,
        line,
      });
    }
    return null;
  }

  /** `response.writer` / `response.outputStream` (Kotlin property access). */
  function member(name: string, recv: Value): Value | null {
    if (recv.web === "response" && WRITER_MEMBERS.has(name)) return value([], { web: "writer" });
    return null;
  }

  /** `response.contentType = "text/html"` (Kotlin). */
  function assigned(target: Expr, incoming: Expr): void {
    if (target.k === "member" && target.name === "contentType") noteContentType(incoming);
  }

  function startMethod(): void {
    contentType = "unset";
  }

  // ---------------------------------------------------------------- handler return values

  /** `ResponseEntity.ok(x)`, `.body(x)`, `new ResponseEntity<>(x, status)`: the body and a content type set on the way. */
  function entityBody(expr: Expr): { body: Expr; type: ContentType | null } | null {
    if (
      expr.k === "new" &&
      baseType(expr.type) === "ResponseEntity" &&
      expr.args[0] !== undefined
    ) {
      return { body: expr.args[0], type: null };
    }
    if (expr.k === "call") {
      if (expr.recv === null && expr.name === "ResponseEntity" && expr.args[0] !== undefined) {
        return { body: expr.args[0], type: null };
      }
      if ((expr.name === "ok" || expr.name === "body") && expr.args[0] !== undefined) {
        const chain = chainOf(expr.recv);
        const entity =
          expr.name === "ok"
            ? expr.recv?.k === "id" && expr.recv.name === "ResponseEntity"
            : chain.length > 0;
        if (entity) return { body: expr.args[0], type: chainContentType(expr.recv) };
      }
    }
    return null;
  }

  function returned(
    expr: Expr,
    v: Value,
    ctx: Context,
    method: MethodInfo | null,
    cls: ClassInfo | null,
    evalArg: (expr: Expr) => Value,
  ): void {
    if (!ctx.report || method === null) return;
    if (!method.annotations.some((annotation) => HANDLER_ANNOTATIONS.has(annotation.name))) return;
    const body =
      method.annotations.some((annotation) => annotation.name === "ResponseBody") ||
      (cls?.annotations ?? []).some((annotation) => BODY_CLASS_ANNOTATIONS.has(annotation.name));
    if (!body) return;
    const type = (method.returnType ?? "").replace(/\s/g, "");
    const plain = /^(?:String|CharSequence|kotlin\.String)\??$/.test(type);
    const entity = /^ResponseEntity<String\??>$/.test(type);
    if (!plain && !entity) return;
    let setType: ContentType = "unset";
    for (const annotation of method.annotations) {
      const produces = annotation.named.get("produces");
      if (produces !== undefined) setType = contentTypeOf(produces);
    }
    let target = v;
    if (entity) {
      const unwrapped = entityBody(expr);
      if (unwrapped === null) return;
      // The chain-based sink (`.contentType(TEXT_HTML).body(x)`) already reported it.
      if (unwrapped.type === "html") return;
      if (unwrapped.type !== null) setType = unwrapped.type;
      target = evalArg(unwrapped.body);
    } else if (expr.k === "call" || expr.k === "new") {
      // A String handler can still return an object expression the analysis cannot read as text.
      if (expr.k === "new") return;
    }
    if (setType === "other") return;
    const judged = judge(target);
    if (judged === null) return;
    // Only request input that reaches the returned text through string operations is reported: a
    // value that passes through a method call (`render(name)`, `rest.getForObject(url)`) is not followed.
    if (judged.kind !== "tainted") return;
    const markup = MARKUP.test(literalText(target.leaves));
    const options: Options =
      setType === "html"
        ? { ...NO_CAVEAT, caveat: "produces text/html" }
        : setType === "dynamic"
          ? { ...NO_CAVEAT, top: "low", caveat: "content type is not fixed" }
          : markup
            ? {
                ...NO_CAVEAT,
                top: "medium",
                caveat: "HTML text returned as the response body; content type negotiated",
              }
            : {
                ...NO_CAVEAT,
                top: "low",
                caveat: "String response body; plain text unless the client asks for HTML",
              };
    report("PG-XSS-004", judged, expr.line, "response body", options);
  }

  return { call, construct, member, assigned, startMethod, returned, modelAttributes };
}
