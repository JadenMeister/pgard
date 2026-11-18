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
  answersGet,
  fullPaths,
  isTemplatedPath,
  matchesTemplate,
  modelAttributeName,
  normalizePath,
} from "./view-links.js";
import {
  APACHE_BUILDERS,
  APACHE_REQUESTS,
  BODY_CLASS_ANNOTATIONS,
  CLIENT_NAME,
  CLIENT_TYPE,
  ESCAPE_ANY_CLASS_NAMES,
  ESCAPE_CLASSES,
  ESCAPE_NAME,
  NUMBER_WHY,
  SAFE_SERIALIZERS,
  FLUENT_VERBS,
  FLASH_ADDER,
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
  /** Views the method that set it returns (empty when none is a literal). */
  views: string[];
  name: string;
  /** Request input went into the value. */
  tainted: boolean;
  line: number;
  /**
   * `views` is not the whole story: the method (or the controller) also reaches views that were
   * not resolved. A template that is not one of `views` then still gets the name-only match.
   */
  partial?: boolean;
}

/** What one method of a controller returned, kept until the class is complete. */
interface MethodSummary {
  /** A request handler that returns a view name (not a response body). */
  handler: boolean;
  /** A `@ModelAttribute` method: its attributes apply to every view of the controller. */
  classWide: boolean;
  /** Paths it is mapped to (class prefix joined), for `redirect:` targets. */
  paths: string[];
  /** It answers a GET: the request a redirect leads to. */
  get: boolean;
  views: string[];
  partial: boolean;
  redirects: string[];
  attributes: ModelAttribute[];
}

/** More views than this in one controller are not listed: the attributes keep the name-only match. */
const MAX_CLASS_VIEWS = 500;
/** Templated mappings (`/items/{id}`) compared against a redirect target, per controller. */
const MAX_TEMPLATED_MAPPINGS = 200;

export interface WebHost {
  typeOfExpr: (expr: Expr, ctx: Context) => string | null;
  /** The value of a side-effect free expression (a name or a member chain). */
  evaluate: (expr: Expr, ctx: Context) => Value;
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

/** Response builder calls whose body is the page: `.body(x)` only counts after an HTML content type. */
const BODY_SINKS = new Set(["body", "bodyValue", "syncBody", "bodyValueAndAwait"]);
/** The ones of them that only a `ServerResponse` builder has (a WebClient request has `bodyValue` too). */
const FLUENT_BODY_SINKS = new Set(["bodyValue", "syncBody", "bodyValueAndAwait"]);
const SERVER_RESPONSE_STARTS = new Set([
  "ok",
  "created",
  "accepted",
  "status",
  "badRequest",
  "unprocessableEntity",
]);

/** `ServerResponse.ok()...`, or a bare `ok()...` of a Kotlin router. */
function isServerResponseChain(expr: Expr | null): boolean {
  let current: Expr | null = expr;
  for (let hops = 0; current !== null && hops < 30; hops += 1) {
    if (current.k === "call") {
      if (SERVER_RESPONSE_STARTS.has(current.name)) {
        return (
          current.recv === null ||
          (current.recv.k === "id" && current.recv.name === "ServerResponse") ||
          (current.recv.k === "member" && current.recv.name === "ServerResponse")
        );
      }
      current = current.recv;
    } else if (current.k === "member") {
      current = current.obj;
    } else {
      return false;
    }
  }
  return false;
}

const FIXED_BASE = /^\s*(?:https?:)?\/\/[A-Za-z0-9][A-Za-z0-9.-]*(?::\d{1,5})?(?=[/?#])/i;
const CONFIGURED_BASE = /url|uri|base|host|endpoint|api|server|origin/i;
const MARKUP = /<[A-Za-z/!]/;
const COLLECTION_FACTORY_CALL =
  /^(?:listOf|mapOf|setOf|arrayOf|mutableListOf|mutableMapOf|emptyList|emptyMap|of|asList)$/;

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
    } else if (call.args.length === 0 && call.lambdas.length === 0) {
      // Spring Kotlin `ServerResponse.ok().html()` / `.json()`.
      if (call.name === "html") found = "html";
      else if (call.name === "json" || call.name === "xml") found = "other";
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

/**
 * Escaped leaves become "inferred". A leaf that went through a JSON serialiser (`json:...`) is
 * dropped for the XSS rule unless the response is HTML and the serialiser is Jackson, which does
 * not escape `<`.
 */
const demoteEscaped = (leaves: readonly Leaf[], forXss: boolean, html: boolean): Leaf[] => {
  const out: Leaf[] = [];
  addLeaves(
    out,
    leaves.flatMap((leaf): Leaf[] => {
      if ((leaf.k !== "source" && leaf.k !== "unknown") || leaf.esc === undefined) return [leaf];
      if (leaf.esc.startsWith("json:")) {
        if (forXss && !(html && leaf.esc === "json:Jackson")) return [];
        return [{ k: "inferred", why: "JSON-serialised; Jackson does not escape '<'" }];
      }
      return [{ k: "inferred", why: leaf.esc }];
    }),
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
  let methodStart = 0;
  /** Index in `modelAttributes` where the class being read starts. */
  let classStart = 0;
  let views: string[] = [];
  /** The method also returns views that were not resolved (a variable, a call, a forward). */
  let viewsPartial = false;
  /** `redirect:` targets the method returns (literal text after the prefix). */
  let redirects: string[] = [];
  /** Per method of the class being read: what its views and redirects were (#338). */
  let summaries: MethodSummary[] = [];
  /** Model attributes added as flash attributes, and those from a `@ModelAttribute` method. */
  const flashAttributes = new WeakSet<ModelAttribute>();

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

  function judge(v: Value, composed = v.composed, forXss = false, html = false): Judged | null {
    const leaves: Leaf[] = [];
    const escapedAway = demoteEscaped(v.leaves, forXss, html);
    addLeaves(
      leaves,
      forXss
        ? escapedAway.filter((leaf) => !(leaf.k === "inferred" && NUMBER_WHY.test(leaf.why)))
        : escapedAway,
    );
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
    const judged = judge(v, v.composed, true, type === "html");
    if (judged === null) return;
    report("PG-XSS-004", judged, line, label, options);
  }

  /**
   * `ServerResponse.ok().bodyValue(text)` with no content type that is known (WebFlux): plain text
   * unless the client asks for HTML, so low confidence, or medium when the text is markup. A value
   * that is typed and not a String is a serialised object and is left alone.
   */
  function webBodyUnknownType(
    v: Value,
    arg: Expr | undefined,
    line: number,
    type: ContentType | null,
    ctx: Context,
  ): void {
    if (!ctx.report) return;
    const declared = arg === undefined ? null : baseType(host.typeOfExpr(arg, ctx));
    if (declared !== null && declared !== "" && !/^(?:String|CharSequence)$/.test(declared)) return;
    const judged = judge(v, v.composed, true, false);
    if (judged === null) return;
    const markup = MARKUP.test(literalText(v.leaves));
    const options: Options =
      type === "dynamic"
        ? { ...NO_CAVEAT, top: "low", caveat: "content type is not fixed" }
        : markup
          ? {
              ...NO_CAVEAT,
              top: "medium",
              caveat:
                "HTML text in a response body with no content type set; content type negotiated",
            }
          : {
              ...NO_CAVEAT,
              top: "low",
              caveat:
                "text response body with no content type set; plain text unless the client asks for HTML",
            };
    report("PG-XSS-004", judged, line, "response body", options);
  }

  function noteContentType(arg: Expr | undefined, ctx: Context): void {
    const next = contentTypeOf(arg);
    // Set in only some branches (or differently in each): not known.
    contentType = ctx.conditional > 0 && contentType !== next ? "dynamic" : next;
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

  /** The library a JSON serialiser call belongs to, when the receiver or class says so. */
  function serializerOf(
    name: string,
    className: string,
    recvExpr: Expr | null,
    ctx: Context,
  ): "Jackson" | "other" | null {
    const type = recvExpr === null ? "" : baseType(host.typeOfExpr(recvExpr, ctx));
    const word = hint(recvExpr);
    if (name === "writeValueAsString" || name === "writeValueAsBytes") {
      return /^(?:ObjectMapper|ObjectWriter|JsonMapper)$/.test(type) ||
        /mapper|objectWriter/i.test(word)
        ? "Jackson"
        : null;
    }
    if (name === "toJson") return type === "Gson" || /gson/i.test(word) ? "other" : null;
    if (name === "toJSONString") {
      return /^(?:JSON|JSONObject|JSONArray)$/.test(className || type) ? "other" : null;
    }
    if (name === "encodeToString") {
      return className === "Json" || type === "Json" || /^json$/i.test(word) ? "other" : null;
    }
    return null;
  }

  function escaped(arg: Value, why: string): Value {
    const leaves: Leaf[] = [];
    addLeaves(
      leaves,
      arg.leaves.map((leaf): Leaf =>
        leaf.k === "source" || leaf.k === "unknown" ? { ...leaf, esc: why } : leaf,
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
    const attribute: ModelAttribute = {
      views: [],
      name: nameArg.text,
      tainted: sourcesOf(args[1]?.leaves ?? []).length > 0,
      line: expr.line,
    };
    if (expr.name === FLASH_ADDER) flashAttributes.add(attribute);
    modelAttributes.push(attribute);
  }

  // ---------------------------------------------------------------- views of a handler (#338)

  const isPureRef = (expr: Expr, depth = 0): boolean =>
    depth < 6 && (expr.k === "id" || (expr.k === "member" && isPureRef(expr.obj, depth + 1)));

  /**
   * The text of a view name when it is fixed: a literal, a `static final` / `const` String of this
   * file, or a concatenation of those. A variable that holds more than one value is not fixed.
   */
  function viewText(expr: Expr, ctx: Context, depth = 0): string | null {
    if (depth > 6) return null;
    switch (expr.k) {
      case "str":
        return expr.text;
      case "id":
      case "member": {
        if (!isPureRef(expr)) return null;
        const held = host.evaluate(expr, ctx);
        const only = held.leaves.length === 1 ? held.leaves[0] : undefined;
        return only?.k === "const" && held.opaque === "" ? only.text : null;
      }
      case "bin": {
        if (expr.op !== "+") return null;
        const left = viewText(expr.left, ctx, depth + 1);
        const right = left === null ? null : viewText(expr.right, ctx, depth + 1);
        return left === null || right === null ? null : left + right;
      }
      case "tmpl": {
        let text = "";
        for (const part of expr.parts) {
          const piece = typeof part === "string" ? part : viewText(part, ctx, depth + 1);
          if (piece === null) return null;
          text += piece;
        }
        return text;
      }
      default:
        return null;
    }
  }

  /** A view the method gives (null: not fixed). `flag`: an unfixed one makes the views partial. */
  function noteViewText(text: string | null, flag: boolean): void {
    if (text === null) {
      if (flag) viewsPartial = true;
      return;
    }
    const redirect = /^redirect:([^]*)$/.exec(text);
    if (redirect !== null) {
      if (redirects.length < 20) redirects.push(redirect[1] ?? "");
      else viewsPartial = true;
      return;
    }
    if (/^forward:/.test(text)) {
      // The attributes go to the view of another handler: not followed.
      if (flag) viewsPartial = true;
      return;
    }
    if (views.includes(text)) return;
    if (views.length < 100) views.push(text);
    else viewsPartial = true;
  }

  /** A returned value that may be a view name: both branches of a condition count. */
  function collectViews(expr: Expr, ctx: Context, flag: boolean, depth: number): void {
    if (depth > 8) {
      if (flag) viewsPartial = true;
      return;
    }
    if (expr.k === "cond") {
      collectViews(expr.a, ctx, flag, depth + 1);
      collectViews(expr.b, ctx, flag, depth + 1);
    } else if (expr.k === "alt") {
      for (const option of expr.options) collectViews(option, ctx, flag, depth + 1);
    } else if (expr.k !== "lit") {
      noteViewText(viewText(expr, ctx), flag);
    }
  }

  const isModelType = (expr: Expr | null, ctx: Context): boolean =>
    expr !== null &&
    (MODEL_TYPES.test(baseType(host.typeOfExpr(expr, ctx))) || MODEL_NAME.test(hint(expr)));

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

    const serial = SAFE_SERIALIZERS.has(name) ? serializerOf(name, className, recvExpr, ctx) : null;
    if (serial !== null && first !== undefined && !firstIsLambda) {
      const leaves: Leaf[] = [];
      addLeaves(
        leaves,
        first.leaves.map((leaf): Leaf =>
          leaf.k === "source" || leaf.k === "unknown" ? { ...leaf, esc: `json:${serial}` } : leaf,
        ),
      );
      return value(leaves, { shape: first.shape });
    }
    const why = escapeLabel(name, className, recvExpr);
    if (why !== null && first !== undefined && !firstIsLambda) return escaped(first, why);

    if (MODEL_ADDERS.has(name) && ctx.report) noteModel(expr, args, recv, ctx);
    if (
      name === "setViewName" &&
      ctx.report &&
      firstExpr !== undefined &&
      isModelType(recvExpr, ctx)
    ) {
      noteViewText(viewText(firstExpr, ctx), true);
      return null;
    }

    // ---- servlet responses ----
    if (recv?.web === "response") {
      if (WRITER_GETTERS.has(name)) return value([], { web: "writer" });
      if (name === "setContentType") noteContentType(firstExpr, ctx);
      else if (
        (name === "setHeader" || name === "addHeader") &&
        /content-?type/i.test(exprWords(firstExpr))
      ) {
        noteContentType(expr.args[1], ctx);
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
    if (BODY_SINKS.has(name) && first !== undefined && chainContentType(recvExpr) === "html") {
      xssSink(first, line, "response body", "html", ctx);
      return null;
    }
    // WebFlux `ServerResponse.ok().bodyValue(text)` with no content type that is known: low, not silent.
    if (
      FLUENT_BODY_SINKS.has(name) &&
      first !== undefined &&
      firstExpr?.k !== "lambda" &&
      isServerResponseChain(recvExpr)
    ) {
      const type = chainContentType(recvExpr);
      if (type !== "other" && type !== "html")
        webBodyUnknownType(first, firstExpr, line, type, ctx);
      return null;
    }
    // kotlinx.html: `unsafe { +text }` and `unsafe { raw(text) }` write markup as it is.
    if (
      recvExpr === null &&
      ctx.unsafe === true &&
      (name === "unaryPlus" || name === "raw") &&
      first !== undefined
    ) {
      xssSink(first, line, "kotlinx.html unsafe block", "html", ctx);
      return name === "unaryPlus" ? value() : null;
    }
    // Any other `+x` gives no text (as a unary plus on a number did before it was read here).
    if (recvExpr === null && name === "unaryPlus") return value();

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
      if (name === "newInstance" && args.length === 0) return urlValue([]);
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
      // The host, scheme and user info come from the argument: the base is no longer fixed.
      if (/^(?:host|scheme|userInfo|port)$/.test(name)) return urlValue([...args, recv]);
      if (URL_KEEPERS.has(name) || /^(?:build|encode)$/.test(name)) return urlValue([recv]);
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
    // `new URL(context, spec)`: an absolute spec replaces the context, so the spec comes first.
    if (type === "URL" && args.length === 2) return urlValue([args[1] as Value, args[0] as Value]);
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
    if (type === "ModelAndView" && ctx.report && argExprs[0] !== undefined) {
      // A first argument that is not a view name (a `Map`, a `View`) leaves the view unresolved.
      noteViewText(viewText(argExprs[0], ctx), true);
    }
    if (type === "ModelAndView" && args.length === 3 && argExprs[1]?.k === "str") {
      modelAttributes.push({
        views: [],
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
  function assigned(target: Expr, incoming: Expr, ctx: Context): void {
    if (target.k === "member" && target.name === "contentType") noteContentType(incoming, ctx);
    // Kotlin `mav.viewName = "x"`.
    if (
      target.k === "member" &&
      target.name === "viewName" &&
      ctx.report &&
      isModelType(target.obj, ctx)
    ) {
      noteViewText(viewText(incoming, ctx), true);
    }
  }

  /** The method being read, for the summary kept when it ends. */
  let current: {
    method: MethodInfo;
    handler: boolean;
    classWide: boolean;
    paths: string[];
  } | null = null;

  /** A new method starts: its response has no content type yet, and no view or model attribute. */
  function startMethod(method: MethodInfo, cls: ClassInfo | null): void {
    contentType = "unset";
    methodStart = modelAttributes.length;
    views = [];
    viewsPartial = false;
    redirects = [];
    const isBody =
      method.annotations.some((annotation) => annotation.name === "ResponseBody") ||
      (cls?.annotations ?? []).some((annotation) => BODY_CLASS_ANNOTATIONS.has(annotation.name));
    const handler =
      !isBody && method.annotations.some((annotation) => HANDLER_ANNOTATIONS.has(annotation.name));
    current = {
      method,
      handler,
      classWide: method.annotations.some((annotation) => annotation.name === "ModelAttribute"),
      paths: handler ? fullPaths(method, cls) : [],
    };
  }

  /** The method ends: the model attributes it set belong to the views it returned. */
  function endMethod(): void {
    const attributes = modelAttributes.slice(methodStart);
    for (const attribute of attributes) {
      attribute.views = [...views];
      if (viewsPartial) attribute.partial = true;
    }
    if (current !== null && (current.handler || attributes.length > 0)) {
      summaries.push({
        handler: current.handler,
        classWide: current.classWide,
        paths: current.paths,
        get: current.handler && answersGet(current.method, exprWords),
        views: [...views],
        partial: viewsPartial,
        redirects: [...redirects],
        attributes,
      });
    }
    current = null;
  }

  /**
   * The controller is complete (#338): a `@ModelAttribute` attribute applies to every view its
   * handlers return, and a flash attribute to the view of the handler its `redirect:` leads to.
   * Anything that cannot be proven keeps the name-only match (`partial`), so no link hides a finding.
   */
  function endClass(): void {
    const list = summaries;
    summaries = [];
    const start = classStart;
    classStart = modelAttributes.length;
    const wanted = list.some((summary) =>
      summary.attributes.some((attribute) => summary.classWide || flashAttributes.has(attribute)),
    );
    if (!wanted) return;
    let classViews: string[] | null = null;
    const viewsOfClass = (): string[] => {
      if (classViews !== null) return classViews;
      const all = new Set<string>();
      for (const summary of list) {
        if (summary.handler) for (const view of summary.views) all.add(view);
      }
      // Too many to list: none is claimed, so every template keeps the name-only match.
      classViews = all.size > MAX_CLASS_VIEWS ? [] : [...all];
      return classViews;
    };
    // Exact mappings of every handler (a literal path wins over a templated one, whatever the
    // verb); only the ones that answer a GET are a redirect target.
    const exact = new Map<string, MethodSummary[]>();
    const templated: Array<{ path: string; summary: MethodSummary }> = [];
    let indexed = false;
    const index = (): void => {
      if (indexed) return;
      indexed = true;
      for (const summary of list) {
        if (!summary.handler) continue;
        for (const path of summary.paths) {
          if (isTemplatedPath(path)) {
            if (summary.get && templated.length < MAX_TEMPLATED_MAPPINGS) {
              templated.push({ path, summary });
            }
          } else {
            const known = exact.get(path);
            if (known === undefined) exact.set(path, [summary]);
            else known.push(summary);
          }
        }
      }
    };
    const cache = new Map<string, MethodSummary[]>();
    const targets = (redirect: string): MethodSummary[] => {
      const known = cache.get(redirect);
      if (known !== undefined) return known;
      index();
      let result: MethodSummary[] = [];
      // A relative target resolves against the request path: not followed.
      if (redirect.startsWith("/")) {
        const path = normalizePath(redirect);
        const literal = exact.get(path);
        if (literal !== undefined) {
          result = literal.filter((summary) => summary.get);
        } else {
          result = templated
            .filter((entry) => matchesTemplate(entry.path, path))
            .map((entry) => entry.summary);
        }
      }
      cache.set(redirect, result);
      return result;
    };
    for (const summary of list) {
      for (const attribute of summary.attributes) {
        if (summary.classWide) {
          attribute.views = viewsOfClass();
          // Subclasses and handlers in other files are not seen: other templates keep the name match.
          attribute.partial = true;
        } else if (flashAttributes.has(attribute) && summary.redirects.length > 0) {
          const found = new Set(attribute.views);
          let partial = attribute.partial === true;
          for (const redirect of summary.redirects) {
            const hits = targets(redirect);
            if (hits.length === 0) partial = true;
            for (const hit of hits) {
              for (const view of hit.views) found.add(view);
              if (hit.partial || hit.views.length === 0) partial = true;
            }
          }
          if (found.size > MAX_CLASS_VIEWS) {
            attribute.views = [];
            partial = true;
          } else {
            attribute.views = [...found];
          }
          if (partial) attribute.partial = true;
        }
      }
    }
    // One source per (name, taint, views): 2000 `@ModelAttribute("b")` methods or flash attributes
    // that lead to the same views are one link, not 2000 copies for every template to test.
    const joined = new Map<string[], string>();
    const seen = new Set<string>();
    const drop = new Set<ModelAttribute>();
    for (const summary of list) {
      for (const attribute of summary.attributes) {
        let views = joined.get(attribute.views);
        if (views === undefined) {
          views = [...attribute.views].sort().join("\u0001");
          joined.set(attribute.views, views);
        }
        const key = `${attribute.name}\u0000${attribute.tainted}\u0000${attribute.partial === true}\u0000${views}`;
        if (seen.has(key)) drop.add(attribute);
        else seen.add(key);
      }
    }
    if (drop.size > 0) {
      let write = start;
      for (let read = start; read < modelAttributes.length; read += 1) {
        const attribute = modelAttributes[read] as ModelAttribute;
        if (!drop.has(attribute)) modelAttributes[write++] = attribute;
      }
      modelAttributes.length = write;
      classStart = write;
    }
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
    const body =
      method.annotations.some((annotation) => annotation.name === "ResponseBody") ||
      (cls?.annotations ?? []).some((annotation) => BODY_CLASS_ANNOTATIONS.has(annotation.name));
    const modelMethod = method.annotations.find(
      (annotation) => annotation.name === "ModelAttribute",
    );
    if (modelMethod !== undefined) {
      // `@ModelAttribute String banner(...)`: the returned value is a model attribute of every view.
      const name = modelAttributeName(modelMethod, method.returnType);
      if (name !== null) {
        modelAttributes.push({
          views: [],
          name,
          tainted: sourcesOf(v.leaves).length > 0,
          line: expr.line,
          partial: true,
        });
      }
      return;
    }
    const handler = method.annotations.some((annotation) =>
      HANDLER_ANNOTATIONS.has(annotation.name),
    );
    if (!body) {
      const type = baseType(method.returnType ?? "");
      const textual = type === "String" || type === "CharSequence" || type === "";
      // A literal is a view name whatever the method is; an expression is one only in a handler
      // that returns text, and then one that cannot be resolved makes the views partial.
      if (textual || expr.k === "str") collectViews(expr, ctx, handler && textual, 0);
    }
    if (!handler) return;
    if (!body) return;
    // A declared type that is not text (a DTO, a Map, a ResponseEntity of one) is a JSON body. An
    // inferred type (Kotlin expression body) is read from the expression instead.
    const type = (method.returnType ?? "").replace(/\s/g, "");
    const plain = /^(?:String|CharSequence|kotlin\.String)\??$/.test(type);
    const entity = /^ResponseEntity<String\??>$/.test(type);
    const inferredType = type === "";
    if (!plain && !entity && !inferredType) return;
    if (inferredType) {
      // An object, a collection factory or a lambda is not text.
      if (expr.k === "new" || expr.k === "array" || expr.k === "lambda" || expr.k === "lit") return;
      if (expr.k === "call" && COLLECTION_FACTORY_CALL.test(expr.name)) return;
      // With no declared type a call result (`jdbc.queryForList(..)`) may be any object: only text
      // built here (a literal, a template, a concatenation, a variable) is read as a String body.
      if (expr.k === "call" && entityBody(expr) === null) return;
    }
    let setType: ContentType = "unset";
    for (const annotation of method.annotations) {
      const produces = annotation.named.get("produces");
      if (produces !== undefined) setType = contentTypeOf(produces);
    }
    let target = v;
    const unwrapped = entity || inferredType ? entityBody(expr) : null;
    if (entity && unwrapped === null) return;
    if (unwrapped !== null) {
      // The chain-based sink (`.contentType(TEXT_HTML).body(x)`) already reported it.
      if (unwrapped.type === "html") return;
      if (unwrapped.type !== null) setType = unwrapped.type;
      target = evalArg(unwrapped.body);
    } else if (expr.k === "new") {
      return;
    }
    if (setType === "other") return;
    const judged = judge(target, target.composed, true, setType === "html");
    if (judged === null) return;
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

  return {
    call,
    construct,
    member,
    assigned,
    startMethod,
    endMethod,
    endClass,
    returned,
    modelAttributes,
  };
}
