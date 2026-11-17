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
  /** Expressions that were not judged because the file's work limit was reached (#508). */
  notJudged?: number;
}

type Class = "tainted" | "escaped" | "unknown" | "fixed";
const CLASS_RANK: Record<Class, number> = { tainted: 3, unknown: 2, escaped: 1, fixed: 0 };
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
      /(?<!\w)(?:escape\w*|htmlEscape\w*|forHtml\w*|forXml\w*|forJava\w*|encodeFor\w+|sanitize\w*|cleanHtml|javaScriptEscape)\s*\(/.exec(
        text,
      )?.[0] ?? "an escaping helper(";
    return {
      cls: "escaped",
      direct: false,
      // `name` ends with `(`; `/\s*\($/` would restart at every space of a long whitespace run.
      detail: `escaped with ${name.slice(0, -1).trimEnd()}()`,
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

/** What `elEnd` returns when the file's scan budget ran out before it could tell. */
const EL_NOT_JUDGED = -2;

/**
 * The work one file may spend looking for the end of `${...}` expressions, in characters. An
 * expression of any length is read in full (#508), so a padded expression cannot hide a finding. A
 * hostile file with many openers that never close would make every opener scan to the end of the
 * file; the budget (a few times the file length, so no real template comes near it) keeps that
 * linear. When it runs out, the openers that are left are counted, not judged and not silent.
 */
interface ElBudget {
  left: number;
  /** Expressions that were not judged because the budget ran out. */
  skipped: number;
  /** The file text and where its last `}` is, found once (short attribute values skip this). */
  text: string;
  lastClose: number;
}

// Enough for a few dozen scans that run to the end of a 1 MiB file (an opener that never closes
// does), at most about 150 ms of scanning (measured worst case 143 ms: 36 nested openers, 1 MiB
// of text, 36 closers). Judging the bodies that were found is outside the budget. A file that
// needs more is reported, not skipped.
const EL_BUDGET_FLOOR = 32 * 1024 * 1024;

const elBudgetFor = (text: string): ElBudget => ({
  left: 4 * text.length + EL_BUDGET_FLOOR,
  skipped: 0,
  text,
  lastClose: text.lastIndexOf("}"),
});

/**
 * The `${...}` that starts at `at`: its end offset (after `}`), -1 when it never closes (a broken
 * expression, nothing to judge), or `EL_NOT_JUDGED` when the file's budget ran out first.
 */
function elEnd(text: string, at: number, budget: ElBudget): number {
  // Nothing closes after the last `}`, and no later opener can either: stop without scanning.
  if (text === budget.text && budget.lastClose <= at) return -1;
  let depth = 0;
  let quote = "";
  for (let i = at + 1; i < text.length; i += 1) {
    if (budget.left <= 0) {
      budget.skipped += 1;
      return EL_NOT_JUDGED;
    }
    budget.left -= 1;
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

/**
 * Replaces every call that `names` matches (with its balanced arguments) by a literal, in one
 * left-to-right pass over the body and with one join at the end, so the cost is linear in the body
 * length however many calls it holds (#506). A call whose parenthesis never closes takes the rest
 * of the body with it. No match can start inside a replaced span or straddle it, because the
 * replacement is a quoted literal and no escape pattern contains a quote.
 */
function stripCalls(body: string, names: RegExp): string {
  const scan = new RegExp(names.source, "g");
  const parts: string[] = [];
  let from = 0;
  for (;;) {
    scan.lastIndex = from;
    const match = scan.exec(body);
    if (match === null) break;
    const close = closingParen(body, match.index + match[0].length - 1);
    parts.push(body.slice(from, match.index), "'x'");
    if (close === -1) return parts.join("");
    from = close + 1;
  }
  parts.push(body.slice(from));
  return parts.join("");
}

const EL_ESCAPE = /(?<!\w)fn\s*:\s*escapeXml\s*\(/;

/** Exported for the differential test (#506). */
export function elJudge(input: string, vars: ReadonlyMap<string, Class>): Judgement {
  let body = input;
  let escaped = false;
  // Every pass removes the calls it finds and leaves a shorter body, so this ends.
  while (EL_ESCAPE.test(body)) {
    escaped = true;
    body = stripCalls(body, EL_ESCAPE);
  }
  // Only the escaped part is safe: what stays in the expression is judged on its own.
  const judged = elLeaf(body, vars);
  return escaped && judged.cls === "fixed" ? { cls: "fixed", direct: false, detail: "" } : judged;
}

/** The judgement of a body with no escape call left; exported for the differential test (#506). */
export function elLeaf(body: string, vars: ReadonlyMap<string, Class>): Judgement {
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

const ATTRIBUTE_NAME = /[^\s=>/]+/y;
const BARE_VALUE = /[^\s>]+/y;

/** Reads the tag that starts at `at` (a `<` followed by a name); `end` is just after its `>`. */
function readTag(text: string, at: number): Tag | null {
  const name = /^<([A-Za-z][\w:.-]*)/.exec(text.slice(at, at + 80))?.[1];
  if (name === undefined) return null;
  const attributes: Tag["attributes"] = [];
  let i = at + 1 + name.length;
  // No length limit (#508): a tag padded past any size would otherwise hide what it holds. A tag
  // that never closes ends at the end of the file, and the scan continues from there, so the
  // cost stays linear.
  const limitAt = text.length;
  while (i < limitAt) {
    const char = text[i] as string;
    if (char === ">") return { name, attributes, end: i + 1 };
    if (/\s|\//.test(char)) {
      i += 1;
      continue;
    }
    // Sticky patterns read from `i` with no slice and no length limit (#508).
    ATTRIBUTE_NAME.lastIndex = i;
    const nameMatch = ATTRIBUTE_NAME.exec(text);
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
      BARE_VALUE.lastIndex = i;
      const bare = BARE_VALUE.exec(text)?.[0] ?? "";
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
  const budget = elBudgetFor(text);

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
    // The first `${` at or after `from`. A tag with very many attributes asks for it once per
    // attribute, so the answer is remembered: it holds for every `from` up to the position found.
    let openFrom = 0;
    let openAt = text.indexOf("${");
    const nextOpen = (from: number): number => {
      if (from < openFrom) {
        openFrom = from;
        openAt = text.indexOf("${", from);
      } else if (openAt !== -1 && openAt < from) {
        openFrom = from;
        openAt = text.indexOf("${", from);
      }
      return openAt;
    };
    const scanEl = (from: number, to: number, what: string): void => {
      for (let at = nextOpen(from); at !== -1 && at < to; at = nextOpen(at + 2)) {
        if (text[at - 1] === "\\") continue;
        const end = elEnd(text, at, budget);
        if (end < 0) continue;
        handleEl(at, end, "jsp-el", what);
      }
    };
    // The `${...}` expressions that start in `from..to`, each with its end (`elEnd`); the end may
    // lie past `to` (a single-quoted value that holds `'` inside its expression).
    const expressionsIn = (from: number, to: number): Array<{ at: number; end: number }> => {
      const found: Array<{ at: number; end: number }> = [];
      let at = nextOpen(from);
      while (at !== -1 && at < to) {
        if (text[at - 1] === "\\") {
          at = nextOpen(at + 2);
          continue;
        }
        const end = elEnd(text, at, budget);
        found.push({ at, end });
        at = nextOpen(end > 0 ? Math.max(end, at + 2) : at + 2);
      }
      return found;
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
          // `escapeXml="${...}"` is a runtime value: unless it is the constant true it may be false,
          // so the output is judged as raw (#511 review).
          const rawOutput =
            off !== undefined &&
            (/^\s*false\s*$/i.test(off.value) ||
              (off.value.includes("${") && !/^\s*\$\{\s*true\s*\}\s*$/i.test(off.value)));
          if (rawOutput) {
            // `default` is printed when `value` is null, so it is judged like `value`.
            for (const attr of tag.attributes) {
              if (attr.name !== "value" && attr.name !== "default") continue;
              // Every expression of the value is judged (#511), not only the first.
              for (const { at, end } of expressionsIn(
                attr.valueAt,
                attr.valueAt + attr.value.length,
              )) {
                if (end <= 0) continue;
                const judged = elJudge(text.slice(at + 2, end - 1), vars);
                const found = make(
                  path,
                  lineAt(at),
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
          const value = tag.attributes.find((attr) => attr.name === "value");
          if (name !== undefined && value !== undefined) {
            // The worst of all its expressions; one that was not judged is not known to be fixed.
            let cls: Class = "fixed";
            for (const { at, end } of expressionsIn(
              value.valueAt,
              value.valueAt + value.value.length,
            )) {
              if (end === -1) continue;
              const one: Class =
                end === EL_NOT_JUDGED ? "unknown" : elJudge(text.slice(at + 2, end - 1), vars).cls;
              if (CLASS_RANK[one] > CLASS_RANK[cls]) cls = one;
            }
            vars.set(name, cls);
          }
        }
        continue;
      }
      // The whole tag is template text to the container: EL between the attributes (`<div
      // ${param.q}>`) is evaluated like EL in a value (#511).
      let covered = lt;
      for (const attr of tag.attributes) {
        scanEl(
          covered,
          attr.valueAt,
          "EL ${...} in a tag outside an attribute value -> HTML output",
        );
        scanEl(
          attr.valueAt,
          attr.valueAt + attr.value.length,
          `EL \${...} in the ${attr.name} attribute -> HTML output`,
        );
        covered = Math.max(covered, attr.valueAt + attr.value.length);
      }
      scanEl(covered, tag.end, "EL ${...} in a tag outside an attribute value -> HTML output");
      if (lower === "script" || lower === "style") {
        const close = text.toLowerCase().indexOf(`</${lower}`, pos);
        const to = close === -1 ? text.length : close;
        scanEl(pos, to, "EL ${...} in template text -> HTML output");
        pos = to;
      }
    }
  }
  const limited = limit(findings);
  return { ...limited, kind: "jsp", unread, notJudged: budget.skipped };
}

// ------------------------------------------------------------------ Thymeleaf

export function looksLikeThymeleaf(text: string): boolean {
  // Case-insensitive: Thymeleaf matches attribute names without case in an HTML template.
  return /\bxmlns:th\s*=|\b(?:data-)?th[:-][a-z]+\s*=|\[\(\s*[$#*@{]/i.test(text);
}

// The sanitize forms are `#xsanitizeY(` and `#x.sanitizeY(`. Splitting them, and stopping the first at
// the first `sanitize` in the word, keeps a run like `#sanitizesanitize...` linear (#494).
export const THYMELEAF_ESCAPE =
  /#strings\.(?:escapeXml|escapeJava|escapeJavaScript|escapeSql)\s*\(|(?<!\w)htmlEscape\w*\s*\(|(?<!\w)escapeHtml\d?\s*\(|(?<!\w)forHtml\w*\s*\(|#(?:(?!sanitize)\w)*sanitize\w*\s*\(|#\w*\.sanitize\w*\s*\(/;
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

/** Exported for the differential test (#506). */
export function thymeleafJudge(
  expression: string,
  model: ReadonlyMap<string, ModelSource[]>,
  view: string,
): Judgement {
  let body = expression.trim();
  let name: string | null = null;
  // Each pass removes every escape call it finds and leaves a shorter body, so this ends.
  for (;;) {
    if (/^#\{[^${}]*\}$/.test(body) || /^'[^']*'$/.test(body) || /^\|[^|$#]*\|$/.test(body)) {
      return name === null ? { cls: "fixed", direct: false, detail: "" } : escapedWith(name);
    }
    const at = body.search(THYMELEAF_ESCAPE);
    if (at === -1) break;
    // The lookbehind keeps a start from restarting inside a word (`a.a.a...`): linear.
    name ??= /(?<![#\w.])([#\w.]+)\s*\(/.exec(body.slice(at))?.[1] ?? "an escaping helper";
    body = stripCalls(body, THYMELEAF_ESCAPE).trim();
  }
  // The escaped part is inferred safe; request input left outside the helper is still reported.
  const inner = thymeleafLeaf(body, model, view);
  if (name === null || inner.cls === "tainted") return inner;
  return escapedWith(name);
}

const escapedWith = (name: string): Judgement => ({
  cls: "escaped",
  direct: false,
  detail: `escaped with ${name}()`,
});

/** As `elLeaf`, for Thymeleaf. */
export function thymeleafLeaf(
  body: string,
  model: ReadonlyMap<string, ModelSource[]>,
  view: string,
): Judgement {
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
    /\b(?:th:utext|data-th-utext)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi,
  )) {
    add(
      match.index,
      match[1] ?? match[2] ?? "",
      "th-utext",
      "Thymeleaf th:utext -> unescaped HTML output",
    );
  }
  // `[( ... )]` of any length is read in full (#508). Inlining works on one text node, so the body
  // cannot cross a tag: outside <script> and <style> it stops at the next tag start, inside them at
  // the closing tag. Each opener looks for the first `)]` with one `indexOf`; when there is none, no
  // later opener has one either, so the loop ends. An opener whose body would cross its boundary
  // is skipped and the next one is looked for after the boundary. The cost stays linear, with no
  // length cap to hide behind.
  const rawRanges: Array<[number, number]> = [];
  const rawOpen = /<(?:script|style)\b/gi;
  for (let m = rawOpen.exec(text); m !== null; m = rawOpen.exec(text)) {
    const gt = text.indexOf(">", m.index);
    if (gt === -1) break;
    const name = /^<(\w+)/.exec(m[0])?.[1] ?? "script";
    const closer = new RegExp(`</${name}`, "gi");
    closer.lastIndex = gt + 1;
    const stop = closer.exec(text)?.index ?? text.length;
    rawRanges.push([gt + 1, stop]);
    rawOpen.lastIndex = stop;
  }
  const tagStart = /<[A-Za-z/!]/g;
  let range = 0;
  let cachedClose = 0;
  let cachedTag = 0;
  for (let at = text.indexOf("[("); at !== -1;) {
    while (range < rawRanges.length && (rawRanges[range] as [number, number])[1] <= at) range += 1;
    const inRaw = range < rawRanges.length && (rawRanges[range] as [number, number])[0] <= at;
    let limitAt: number;
    if (inRaw) limitAt = (rawRanges[range] as [number, number])[1];
    else {
      if (cachedTag < at + 2) {
        tagStart.lastIndex = at + 2;
        cachedTag = tagStart.exec(text)?.index ?? text.length;
      }
      limitAt = cachedTag;
    }
    // The first `)]` at or after at + 3; one found for an earlier opener still holds when it is
    // not behind this one, so skipped openers do not each scan to the same far closer.
    if (cachedClose < at + 3) cachedClose = text.indexOf(")]", at + 3);
    const close = cachedClose;
    if (close === -1) break;
    if (limitAt < close + 2) {
      at = text.indexOf("[(", Math.max(limitAt, at + 2));
      continue;
    }
    add(
      at,
      text.slice(at + 2, close),
      "th-inline",
      "Thymeleaf [( )] inline -> unescaped HTML output",
    );
    at = text.indexOf("[(", close + 2);
  }
  const limited = limit(findings);
  return { ...limited, kind: "thymeleaf" };
}
