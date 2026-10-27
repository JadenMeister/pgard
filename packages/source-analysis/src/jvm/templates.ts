import type { RawSourceFinding } from "../finding-factory.js";

/**
 * JSP and Thymeleaf templates for the Java/Kotlin XSS rule (PG-XSS-004). Read with patterns and a
 * small tokenizer, never executed. `th:text`, `<c:out>` and `fn:escapeXml` escape their value and
 * are never reported; a raw output (`<%= %>`, `out.print`, `${...}` in template text, `th:utext`,
 * `[( )]`, `<c:out escapeXml="false">`) is judged by where its value can come from.
 */

export const MAX_TEMPLATE_FINDINGS_PER_FILE = 25;

/** A value put into a template model by a controller, found while the Java files were analyzed. */
export interface ModelSource {
  path: string;
  line: number;
  /** Literal view names the method that set it returns; empty when none is known. */
  views: string[];
}

export interface TemplateAnalysis {
  findings: RawSourceFinding[];
  capped: boolean;
  /** The file was read as a template of this kind; `null` when it is not one (a plain HTML file). */
  kind: "jsp" | "thymeleaf" | null;
  /** The file has code forms that are not read (`<jsp:scriptlet>`, `<jsp:expression>`). */
  unread?: boolean;
}

type Class = "tainted" | "escaped" | "unknown" | "fixed";
interface Judgement {
  cls: Class;
  /** Request input is read in the expression itself, not through a variable or model attribute. */
  direct: boolean;
  /** What the evidence says about where the value comes from. */
  detail: string;
}

const RULE = "PG-XSS-004" as const;

const rank = (finding: RawSourceFinding): number =>
  ({ high: 30, medium: 20, low: 10 })[finding.confidence] +
  ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 } as Record<string, number>)[
    finding.severity
  ]!;

/** Request input read in Java code. */
const JAVA_SOURCE =
  /\.\s*(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getQueryString|getRequestURI|getRequestURL|getPathInfo|getServletPath|getCookies|getReader)\s*\(/;
/** Escaping helpers in Java code. */
const JAVA_ESCAPE =
  /^(?:[\w.]+\.)?(?:escapeHtml\d?|escapeXml\d*|escapeEcmaScript|escapeJavaScript|htmlEscape\w*|javaScriptEscape|forHtml\w*|forXml\w*|forJava\w*|encodeFor\w+|sanitize\w*|cleanHtml)\s*\(/;
/** Request input in JSP expression language. */
const EL_SOURCE =
  /(?<![\w.])(?:param|paramValues|header|headerValues|cookie)\s*(?:\.|\[)|pageContext\s*\.\s*request\s*\.\s*(?:queryString|requestURI|requestURL|pathInfo|servletPath|parameterMap|cookies|getParameter\s*\(|getQueryString|getRequestURI|getHeader)/;

function blankKeepLines(text: string, start: number, end: number): string {
  return text.slice(0, start) + text.slice(start, end).replace(/[^\n]/g, " ") + text.slice(end);
}

/** Blanks out comments of one kind, keeping offsets and line breaks. */
function blankComments(text: string, open: string, close: string): string {
  let out = text;
  for (let at = out.indexOf(open); at !== -1; at = out.indexOf(open, at + 1)) {
    const closeAt = out.indexOf(close, at + open.length);
    const end = closeAt === -1 ? out.length : closeAt + close.length;
    out = blankKeepLines(out, at, end);
  }
  return out;
}

function lineStartsOf(text: string): number[] {
  const starts: number[] = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return starts;
}

function lineAtOf(starts: readonly number[]): (offset: number) => number {
  return (offset) => {
    let low = 0;
    let high = starts.length - 1;
    while (low < high) {
      const mid = (low + high + 1) >> 1;
      if ((starts[mid] as number) <= offset) low = mid;
      else high = mid - 1;
    }
    return low + 1;
  };
}

/** Splits at `+` outside quotes and parentheses. */
function splitPlus(text: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote = "";
  let last = 0;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i] as string;
    if (quote !== "") {
      if (char === "\\") i += 1;
      else if (char === quote) quote = "";
    } else if (char === '"' || char === "'") quote = char;
    else if (char === "(" || char === "[" || char === "{") depth += 1;
    else if (char === ")" || char === "]" || char === "}") depth -= 1;
    else if (char === "+" && depth === 0) {
      parts.push(text.slice(last, i));
      last = i + 1;
    }
  }
  parts.push(text.slice(last));
  return parts.map((part) => part.trim()).filter((part) => part !== "");
}

/** The text up to the parenthesis that closes the one at `open`, or -1. */
function closingParen(text: string, open: number): number {
  let depth = 0;
  let quote = "";
  for (let i = open; i < text.length; i += 1) {
    const char = text[i] as string;
    if (quote !== "") {
      if (char === "\\") i += 1;
      else if (char === quote) quote = "";
    } else if (char === '"' || char === "'") quote = char;
    else if (char === "(") depth += 1;
    else if (char === ")") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

// ------------------------------------------------------------------ JSP Java code

const STRING_LITERAL = /^"(?:[^"\\]|\\.)*"$|^'(?:[^'\\]|\\.)*'$|^-?\d+(?:\.\d+)?[lLfFdD]?$/;

/** One term of a Java expression in a scriptlet. */
function javaTerm(term: string, vars: ReadonlyMap<string, Class>): Judgement {
  const text = term.trim().replace(/^\((?:String|Object|CharSequence)\)\s*/, "");
  if (text === "" || STRING_LITERAL.test(text) || /^(?:true|false|null)$/.test(text)) {
    return { cls: "fixed", direct: false, detail: "" };
  }
  if (JAVA_ESCAPE.test(text) || /\.encodeFor\w+\s*\(/.test(text)) {
    const name =
      /(?:escape\w*|htmlEscape\w*|forHtml\w*|forXml\w*|forJava\w*|encodeFor\w+|sanitize\w*|cleanHtml|javaScriptEscape)\s*\(/.exec(
        text,
      )?.[0] ?? "an escaping helper(";
    return {
      cls: "escaped",
      direct: false,
      detail: `escaped with ${name.replace(/\s*\($/, "()")}`,
    };
  }
  if (JAVA_SOURCE.test(text)) {
    const source = /\.\s*(\w+)\s*\(/.exec(JAVA_SOURCE.exec(text)?.[0] ?? "")?.[1] ?? "request";
    return { cls: "tainted", direct: true, detail: `request.${source}` };
  }
  if (/^[A-Za-z_]\w*$/.test(text)) {
    const known = vars.get(text);
    if (known === "tainted") {
      return { cls: "tainted", direct: false, detail: `variable ${text} set from request input` };
    }
    if (known === "escaped")
      return { cls: "escaped", direct: false, detail: `variable ${text} was escaped` };
    if (known === "fixed") return { cls: "fixed", direct: false, detail: "" };
    return { cls: "unknown", direct: false, detail: "" };
  }
  // A call or member on a tainted variable keeps what is in it.
  for (const name of text.match(/[A-Za-z_]\w*/g) ?? []) {
    if (vars.get(name) === "tainted" && new RegExp(`^${name}\\b`).test(text)) {
      return { cls: "tainted", direct: false, detail: `variable ${name} set from request input` };
    }
  }
  return { cls: "unknown", direct: false, detail: "" };
}

/** A Java expression made of terms joined by `+`. */
function javaExpr(text: string, vars: ReadonlyMap<string, Class>): Judgement {
  const terms = splitPlus(text).map((term) => javaTerm(term, vars));
  const pick = (cls: Class): Judgement | undefined => terms.find((term) => term.cls === cls);
  return (
    pick("tainted") ??
    pick("unknown") ??
    pick("escaped") ?? { cls: "fixed", direct: false, detail: "" }
  );
}

/** Variables a scriptlet assigns, in order: tainted, escaped, fixed or unknown. */
function noteAssignments(code: string, vars: Map<string, Class>): void {
  for (const statement of code.split(/[;{}]/)) {
    const match =
      /^\s*(?:final\s+)?(?:[A-Za-z_][\w.<>[\]]*\s+)?([A-Za-z_]\w*)\s*(\+?=)\s*([\s\S]+)$/.exec(
        statement,
      );
    if (match === null) continue;
    const name = match[1] as string;
    const judged = javaExpr(match[3] as string, vars);
    if (match[2] === "+=") {
      if (judged.cls === "tainted") vars.set(name, "tainted");
      continue;
    }
    vars.set(name, judged.cls);
  }
}

// ------------------------------------------------------------------ JSP expression language

/** The `${...}` that starts at `at`: its end offset (after `}`), or -1. */
function elEnd(text: string, at: number): number {
  let depth = 0;
  let quote = "";
  const limit = Math.min(text.length, at + 4000);
  for (let i = at + 1; i < limit; i += 1) {
    const char = text[i] as string;
    if (quote !== "") {
      if (char === "\\") i += 1;
      else if (char === quote) quote = "";
    } else if (char === '"' || char === "'") quote = char;
    else if (char === "{") depth += 1;
    else if (char === "}") {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

/** Replaces every call that `names` matches (with its balanced arguments) by a literal. */
function stripCalls(body: string, names: RegExp): { rest: string; removed: boolean } {
  let rest = body;
  let removed = false;
  for (let hops = 0; hops < 20; hops += 1) {
    const match = new RegExp(names.source).exec(rest);
    if (match === null) break;
    const open = match.index + match[0].length - 1;
    const close = closingParen(rest, open);
    rest = `${rest.slice(0, match.index)}'x'${close === -1 ? "" : rest.slice(close + 1)}`;
    removed = true;
  }
  return { rest, removed };
}

const EL_ESCAPE = /(?<!\w)fn\s*:\s*escapeXml\s*\(/;

function elJudge(body: string, vars: ReadonlyMap<string, Class>): Judgement {
  if (EL_ESCAPE.test(body)) {
    // Only the escaped part is safe: what stays in the expression is judged on its own.
    const { rest } = stripCalls(body, EL_ESCAPE);
    const inner = elJudge(rest, vars);
    return inner.cls === "fixed" ? { cls: "fixed", direct: false, detail: "" } : inner;
  }
  if (EL_SOURCE.test(body)) {
    const source =
      /(param|paramValues|header|headerValues|cookie)\s*(?:\.|\[)/.exec(body)?.[1] ?? "request";
    return { cls: "tainted", direct: true, detail: `\${${source}...}` };
  }
  const root = /^\s*([A-Za-z_]\w*)/.exec(body)?.[1];
  if (root !== undefined && vars.get(root) === "tainted") {
    return {
      cls: "tainted",
      direct: false,
      detail: `variable ${root} set from request input by c:set`,
    };
  }
  if (/^\s*(?:'[^']*'|"[^"]*"|-?\d+(?:\.\d+)?|true|false|null)\s*$/.test(body)) {
    return { cls: "fixed", direct: false, detail: "" };
  }
  return { cls: "unknown", direct: false, detail: "" };
}

// ------------------------------------------------------------------ findings

function make(
  path: string,
  line: number,
  judged: Judgement,
  label: string,
  what: string,
): RawSourceFinding | null {
  if (judged.cls === "fixed") return null;
  const base = { ruleId: RULE, path, line, cause: `${label}:${line}` };
  if (judged.cls === "tainted") {
    return {
      ...base,
      severity: "high",
      status: judged.direct ? "confirmed" : "suspected",
      confidence: "high",
      evidence: `request input (${judged.detail}) -> ${what}`,
    };
  }
  if (judged.cls === "escaped") {
    return {
      ...base,
      severity: "medium",
      status: "suspected",
      confidence: "low",
      evidence: `${what}; ${judged.detail}; inferred`,
    };
  }
  return {
    ...base,
    severity: "low",
    status: "suspected",
    confidence: "low",
    evidence:
      judged.detail === ""
        ? `${what}; the value's source is not followed (no input source identified); inferred`
        : `${what}; ${judged.detail}; inferred`,
  };
}

function limit(findings: RawSourceFinding[]): Omit<TemplateAnalysis, "kind"> {
  // Two outputs on one line keep distinct causes (and so distinct fingerprints).
  const counts = new Map<string, number>();
  const numbered = findings.map((finding) => {
    const count = (counts.get(finding.cause) ?? 0) + 1;
    counts.set(finding.cause, count);
    return count === 1 ? finding : { ...finding, cause: `${finding.cause}#${count}` };
  });
  const sorted = [...numbered].sort((a, b) => rank(b) - rank(a) || a.line - b.line);
  const capped = sorted.length > MAX_TEMPLATE_FINDINGS_PER_FILE;
  return {
    findings: sorted.slice(0, MAX_TEMPLATE_FINDINGS_PER_FILE).sort((a, b) => a.line - b.line),
    capped,
  };
}

// ------------------------------------------------------------------ JSP

/** True for a file that is a JSP by what it contains (taglib or page directive, scriptlet). */
export function looksLikeJsp(text: string): boolean {
  return /<%[@=!\s]|<\s*jsp:|\$\{/.test(text);
}

interface Tag {
  name: string;
  attributes: Array<{ name: string; value: string; valueAt: number }>;
  end: number;
}

/** Reads the tag that starts at `at` (a `<` followed by a name); `end` is just after its `>`. */
function readTag(text: string, at: number): Tag | null {
  const name = /^<([A-Za-z][\w:.-]*)/.exec(text.slice(at, at + 80))?.[1];
  if (name === undefined) return null;
  const attributes: Tag["attributes"] = [];
  let i = at + 1 + name.length;
  const limitAt = Math.min(text.length, at + 20_000);
  while (i < limitAt) {
    const char = text[i] as string;
    if (char === ">") return { name, attributes, end: i + 1 };
    if (/\s|\//.test(char)) {
      i += 1;
      continue;
    }
    const nameMatch = /^[^\s=>/]+/.exec(text.slice(i, i + 200));
    if (nameMatch === null) {
      i += 1;
      continue;
    }
    const attrName = nameMatch[0];
    i += attrName.length;
    while (i < limitAt && /\s/.test(text[i] as string)) i += 1;
    if (text[i] !== "=") {
      attributes.push({ name: attrName, value: "", valueAt: i });
      continue;
    }
    i += 1;
    while (i < limitAt && /\s/.test(text[i] as string)) i += 1;
    const quote = text[i];
    if (quote === '"' || quote === "'") {
      const close = text.indexOf(quote, i + 1);
      const stop = close === -1 ? limitAt : close;
      attributes.push({ name: attrName, value: text.slice(i + 1, stop), valueAt: i + 1 });
      i = stop + 1;
    } else {
      const bare = /^[^\s>]+/.exec(text.slice(i, i + 2000))?.[0] ?? "";
      attributes.push({ name: attrName, value: bare, valueAt: i });
      i += Math.max(bare.length, 1);
    }
  }
  return { name, attributes, end: limitAt };
}

export function analyzeJsp(source: string, path: string): TemplateAnalysis {
  const lineAt = lineAtOf(lineStartsOf(source));
  // Only JSP comments are blanked: an HTML comment is still output, and its scriptlets and EL run.
  let text = blankComments(source, "<%--", "--%>");
  const contentType = /<%@\s*page\b[^%]*\bcontentType\s*=\s*["']([^"']*)["']/.exec(text)?.[1];
  if (contentType !== undefined && !/html/i.test(contentType)) {
    // A JSP that sends JSON, XML or plain text is not an HTML page.
    return { findings: [], capped: false, kind: "jsp" };
  }
  const unread = /<jsp:(?:scriptlet|expression|declaration)\b/.test(text);
  const elIgnored = /<%@\s*page\b[^%]*isELIgnored\s*=\s*["']true["']/.test(text);
  const findings: RawSourceFinding[] = [];
  const vars = new Map<string, Class>();

  // Scriptlets, declarations and expressions, in order.
  let blanked = text;
  for (let at = text.indexOf("<%"); at !== -1; at = text.indexOf("<%", at + 2)) {
    const closeAt = text.indexOf("%>", at + 2);
    const end = closeAt === -1 ? text.length : closeAt + 2;
    const inner = text.slice(at + 2, closeAt === -1 ? text.length : closeAt);
    blanked = blankKeepLines(blanked, at, end);
    const lead = inner[0];
    if (lead === "@") continue;
    if (lead === "=") {
      const judged = javaExpr(inner.slice(1).replace(/;\s*$/, ""), vars);
      const found = make(
        path,
        lineAt(at),
        judged,
        "jsp-expression",
        "JSP <%= %> expression -> HTML output",
      );
      if (found !== null) findings.push(found);
      continue;
    }
    const code = lead === "!" ? inner.slice(1) : inner;
    const codeStart = at + 2 + (lead === "!" ? 1 : 0);
    // `out.print(x)` and friends write to the page; assignments before it decide what `x` is.
    let from = 0;
    const printer = /\bout\s*\.\s*(?:print|println|write|append)\s*\(/g;
    for (let match = printer.exec(code); match !== null; match = printer.exec(code)) {
      noteAssignments(code.slice(from, match.index), vars);
      from = match.index;
      const open = match.index + match[0].length - 1;
      const close = closingParen(code, open);
      const argument = code.slice(open + 1, close === -1 ? code.length : close);
      const judged = javaExpr(argument, vars);
      const found = make(
        path,
        lineAt(codeStart + match.index),
        judged,
        "jsp-out-print",
        "out.print in a scriptlet -> HTML output",
      );
      if (found !== null) findings.push(found);
    }
    noteAssignments(code.slice(from), vars);
  }
  text = blanked;

  if (!elIgnored) {
    const handleEl = (start: number, end: number, label: string, what: string): void => {
      const judged = elJudge(text.slice(start + 2, end - 1), vars);
      const found = make(path, lineAt(start), judged, label, what);
      if (found !== null) findings.push(found);
    };
    const scanEl = (from: number, to: number, what: string): void => {
      for (
        let at = text.indexOf("${", from);
        at !== -1 && at < to;
        at = text.indexOf("${", at + 2)
      ) {
        if (text[at - 1] === "\\") continue;
        const end = elEnd(text, at);
        if (end === -1) continue;
        handleEl(at, end, "jsp-el", what);
      }
    };
    let pos = 0;
    while (pos < text.length) {
      const lt = text.indexOf("<", pos);
      const stop = lt === -1 ? text.length : lt;
      scanEl(pos, stop, "EL ${...} in template text -> HTML output");
      if (lt === -1) break;
      const tag = /^<[A-Za-z]/.test(text.slice(lt, lt + 2)) ? readTag(text, lt) : null;
      if (tag === null) {
        pos = lt + 1;
        continue;
      }
      pos = tag.end;
      const lower = tag.name.toLowerCase();
      if (tag.name.includes(":")) {
        if (lower === "c:out") {
          const off = tag.attributes.find((attr) => attr.name === "escapeXml");
          if (off !== undefined && /^\s*false\s*$/i.test(off.value)) {
            const value = tag.attributes.find((attr) => attr.name === "value");
            if (value !== undefined) {
              const at = value.value.indexOf("${");
              const end = at === -1 ? -1 : elEnd(value.value, at);
              if (at !== -1 && end !== -1) {
                const judged = elJudge(value.value.slice(at + 2, end - 1), vars);
                const found = make(
                  path,
                  lineAt(value.valueAt),
                  judged,
                  "jsp-c-out",
                  'c:out escapeXml="false" -> HTML output',
                );
                if (found !== null) findings.push(found);
              }
            }
          }
        } else if (lower === "c:set") {
          const name = tag.attributes.find((attr) => attr.name === "var")?.value;
          const value = tag.attributes.find((attr) => attr.name === "value")?.value;
          if (name !== undefined && value !== undefined) {
            const at = value.indexOf("${");
            const end = at === -1 ? -1 : elEnd(value, at);
            const cls =
              at === -1 || end === -1 ? "fixed" : elJudge(value.slice(at + 2, end - 1), vars).cls;
            vars.set(name, cls);
          }
        }
        continue;
      }
      for (const attr of tag.attributes) {
        scanEl(
          attr.valueAt,
          attr.valueAt + attr.value.length,
          `EL \${...} in the ${attr.name} attribute -> HTML output`,
        );
      }
      if (lower === "script" || lower === "style") {
        const close = text.toLowerCase().indexOf(`</${lower}`, pos);
        const to = close === -1 ? text.length : close;
        scanEl(pos, to, "EL ${...} in template text -> HTML output");
        pos = to;
      }
    }
  }
  const limited = limit(findings);
  return { ...limited, kind: "jsp", unread };
}

// ------------------------------------------------------------------ Thymeleaf

export function looksLikeThymeleaf(text: string): boolean {
  return /\bxmlns:th\s*=|\b(?:data-)?th[:-][a-z]+\s*=|\[\(\s*[$#*@{]/.test(text);
}

const THYMELEAF_ESCAPE =
  /#strings\.(?:escapeXml|escapeJava|escapeJavaScript|escapeSql)\s*\(|htmlEscape\w*\s*\(|escapeHtml\d?\s*\(|forHtml\w*\s*\(|#\w*\.?sanitize\w*\s*\(/;
const THYMELEAF_SOURCE =
  /\$\{\s*(?:#?(?:request|httpServletRequest)\s*\.\s*(?:getParameter|getHeader|queryString|getQueryString|requestURI|getRequestURI|getRequestURL|parameterMap|getCookies)|param\s*[.[]|#vars\.param|#request\.getParameter)|(?<![\w.])param\s*[.[]\s*['"\w]/;

/** The view name a template file answers to: its path under `templates/`, without the extension. */
function viewOf(path: string): string {
  const at = path.lastIndexOf("templates/");
  const rest = at === -1 ? (path.split("/").pop() ?? path) : path.slice(at + "templates/".length);
  return rest.replace(/\.[^./]+$/, "");
}

const normalizeView = (view: string): string =>
  (view.split("::")[0] ?? view).trim().replace(/^\//, "");

function thymeleafJudge(
  expression: string,
  model: ReadonlyMap<string, ModelSource[]>,
  view: string,
): Judgement {
  const body = expression.trim();
  if (/^#\{[^${}]*\}$/.test(body) || /^'[^']*'$/.test(body) || /^\|[^|$#]*\|$/.test(body)) {
    return { cls: "fixed", direct: false, detail: "" };
  }
  const globalEscape = new RegExp(THYMELEAF_ESCAPE.source);
  if (globalEscape.test(body)) {
    const name =
      /([#\w.]+)\s*\(/.exec(body.slice(body.search(THYMELEAF_ESCAPE)))?.[1] ?? "an escaping helper";
    // The escaped part is inferred safe; request input left outside the helper is still reported.
    const inner = thymeleafJudge(stripCalls(body, THYMELEAF_ESCAPE).rest, model, view);
    if (inner.cls === "tainted") return inner;
    return { cls: "escaped", direct: false, detail: `escaped with ${name}()` };
  }
  if (THYMELEAF_SOURCE.test(body)) {
    return { cls: "tainted", direct: true, detail: "param / request in the expression" };
  }
  let weak: Judgement | null = null;
  for (const match of body.matchAll(/(?:\$\{|\*\{)\s*!?\(?\s*([A-Za-z_]\w*)/g)) {
    const name = match[1] as string;
    const sources = model.get(name) ?? [];
    // The handler that returns this template is the one whose attribute counts.
    const linked = sources.find((source) => source.views.some((v) => normalizeView(v) === view));
    if (linked !== undefined) {
      return {
        cls: "tainted",
        direct: false,
        detail: `model attribute '${name}' is set from request input in ${linked.path}:${linked.line}`,
      };
    }
    const byName = sources.find((source) => source.views.length === 0);
    if (byName !== undefined && weak === null) {
      weak = {
        cls: "unknown",
        direct: false,
        detail: `model attribute '${name}' may be set from request input in ${byName.path}:${byName.line} (view not resolvable, matched by name)`,
      };
    }
  }
  return weak ?? { cls: "unknown", direct: false, detail: "" };
}

export function analyzeThymeleaf(
  source: string,
  path: string,
  model: ReadonlyMap<string, ModelSource[]>,
): TemplateAnalysis {
  const lineAt = lineAtOf(lineStartsOf(source));
  const view = viewOf(path);
  // `<!--/*/ ... /*/-->` is a block that Thymeleaf runs: only its markers are removed.
  const unwrapped = source.replace(/<!--\/\*\/|\/\*\/-->/g, (marker) => " ".repeat(marker.length));
  const text = blankComments(unwrapped, "<!--", "-->");
  const findings: RawSourceFinding[] = [];
  const add = (offset: number, expression: string, label: string, what: string): void => {
    const judged = thymeleafJudge(expression, model, view);
    const found = make(path, lineAt(offset), judged, label, what);
    if (found === null) return;
    // A model value matched by name only is a medium-confidence finding.
    findings.push(
      judged.cls === "tainted" && !judged.direct ? { ...found, confidence: "medium" } : found,
    );
  };
  for (const match of text.matchAll(
    /\b(?:th:utext|data-th-utext)\s*=\s*(?:"([^"]*)"|'([^']*)')/g,
  )) {
    add(
      match.index,
      match[1] ?? match[2] ?? "",
      "th-utext",
      "Thymeleaf th:utext -> unescaped HTML output",
    );
  }
  for (const match of text.matchAll(/\[\(([\s\S]{1,500}?)\)\]/g)) {
    add(
      match.index,
      match[1] ?? "",
      "th-inline",
      "Thymeleaf [( )] inline -> unescaped HTML output",
    );
  }
  const limited = limit(findings);
  return { ...limited, kind: "thymeleaf" };
}
