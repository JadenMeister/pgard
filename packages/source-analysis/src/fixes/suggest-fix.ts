/**
 * Suggested fixes (JSON v1.6 `Finding.fix`): pure text in, a fix out. Nothing here reads a file,
 * runs project code or touches the file system; `attach-fixes.ts` does the reading.
 *
 * A rule is `fixable` only when a finding of it can be repaired by replacing ONE line with ONE
 * other line, mechanically and with the same meaning in that exact context. Each fixer below
 * matches the WHOLE flagged line against a strict pattern and refuses (guidance, no diff) when
 * anything else is on the line. The new line is rebuilt from the pieces the pattern captured, never
 * copied from the old one, and the patterns capture only identifiers, numbers, cookie option names
 * and a few fixed option strings (`path`, `sameSite`), so key material, string values and
 * comments on the line cannot reach a diff. Redaction in `buildLineReplacementDiff` is a second
 * barrier, not the first.
 */
import {
  buildLineReplacementDiff,
  MAX_FIX_LINE_LENGTH,
  type Confidence,
  type Finding,
  type FindingFix,
} from "@pgard/findings";

interface Rewrite {
  newLine: string;
  confidence: Confidence;
}

/** What a fixer needs: the file's text (for imports), the flagged line and what follows it. */
interface FixContext {
  path: string;
  text: string;
  line: string;
  /** The next line that is not blank (`""` at the end of the file). */
  nextLine: string;
  evidence: string;
}

type Fixer = (context: FixContext) => Rewrite | null;

const guidance = (reason: string, confidence: Confidence = "low"): FindingFix => ({
  kind: "guidance",
  confidence,
  reason,
});

function extensionOf(path: string): string {
  const dot = path.lastIndexOf(".");
  return dot < 0 ? "" : path.slice(dot).toLowerCase();
}

const RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };
const lowerOf = (a: Confidence, b: Confidence): Confidence => (RANK[a] <= RANK[b] ? a : b);

// ---------------------------------------------------------------- PG-COOKIE-001: Spring config

const SPRING_FLAG: Record<string, RegExp> = {
  Secure: /^secure$/,
  HttpOnly: /^http-?only$/,
};
/** `<indent><quote?>key<quote?><separator><quote?>off-value<quote?>` and nothing else on the line. */
const SPRING_FLAG_LINE =
  /^( {0,40})(["']?)((?:[\w-]{1,40}\.){0,8}(?:secure|http-?only))\2([ \t]{0,3}[=:][ \t]{0,3})(["']?)(false|off|no|0)\5$/i;
/** The profile of the document: a dev, local or test configuration is probably meant to be insecure. */
const NON_PRODUCTION_FILE =
  /(?:^|[/\\])application[-_.](?:dev|local|test)[\w.-]*\.(?:properties|ya?ml)$/i;
const NON_PRODUCTION_PROFILE =
  /on-profile\s*:\s*["']?(?:dev|local|test)\b|spring\.profiles\s*[:=]\s*["']?(?:dev|local|test)\b/i;

/** `secure` or `httpOnly` of a dotted or nested key, case, hyphen and relaxed binding aside. */
const flagName = (key: string): string =>
  (key.split(".").pop() ?? "").toLowerCase().replace(/[-_]/g, "");

/**
 * `server.servlet.session.cookie.secure=false` (or `http-only`, in a `.properties` or YAML file)
 * becomes `true`. The finding's evidence names the flag and its key, and the line must set exactly
 * that flag to an explicit off value, so nothing else is read as "off" and a line that moved is
 * not rewritten. A person must still check that the site is served over HTTPS (a Secure cookie is
 * not sent over plain HTTP, which also affects local development). In a dev, local or test
 * configuration the setting is probably deliberate, so the confidence is low there.
 */
const fixSpringCookieFlag: Fixer = ({ path, text, line, evidence }) => {
  if (![".properties", ".yml", ".yaml"].includes(extensionOf(path))) return null;
  const parsed =
    /^server\.[\w.-]{1,120}\.cookie\.([\w-]{1,20})=\S{1,20} sends the session cookie without (Secure|HttpOnly)\b/.exec(
      evidence,
    );
  const match = SPRING_FLAG_LINE.exec(line);
  if (parsed === null || match === null) return null;
  const flag = parsed[2] ?? "";
  const [, indent = "", keyQuote = "", key = "", separator = "", valueQuote = ""] = match;
  if (!SPRING_FLAG[flag]?.test(flagName(key))) return null;
  if (flagName(key) !== flagName(parsed[1] ?? "")) return null;
  const isNonProduction = NON_PRODUCTION_FILE.test(path) || NON_PRODUCTION_PROFILE.test(text);
  return {
    newLine: `${indent}${keyQuote}${key}${keyQuote}${separator}${valueQuote}true${valueQuote}`,
    confidence: isNonProduction ? "low" : "high",
  };
};

// ---------------------------------------------------------------- PG-COOKIE-001: Express res.cookie

const IDENT = "[A-Za-z_$][\\w$]{0,40}";
const MEMBER = `${IDENT}(?:\\.${IDENT}){0,4}`;
const COOKIE_VALUE = `${MEMBER}(?:\\((?:${MEMBER}(?: {0,2}, {0,2}${MEMBER}){0,3})?\\))?`;
/** The cookie options of Express, and nothing else: an unknown key is a decision for a person. */
const OPTION_KEYS = [
  "httpOnly",
  "secure",
  "sameSite",
  "maxAge",
  "expires",
  "path",
  "domain",
  "signed",
  "priority",
  "partitioned",
].join("|");
/**
 * An option value: a boolean, a number or a plain name. The only strings are the fixed `sameSite`
 * words and a short route-like `path`; no other string value (a `domain`, a `priority`) is copied.
 */
const OPTION_VALUE = `(?:true|false|-?\\d{1,15}|"(?:lax|strict|none|/[\\w/.-]{0,30})"|'(?:lax|strict|none|/[\\w/.-]{0,30})'|${MEMBER})`;
const OPTION_PAIR = `(?:${OPTION_KEYS}) {0,2}: {0,2}${OPTION_VALUE}`;
const EXPRESS_COOKIE = new RegExp(
  `^( {0,40})((?:return |await )?)(res|response)\\.cookie\\( {0,2}(["'])([\\w.-]{1,64})\\4 {0,2}, {0,2}(${COOKIE_VALUE})(?: {0,2}, {0,2}(?:\\{ {0,2}((?:${OPTION_PAIR}(?: {0,2}, {0,2}${OPTION_PAIR}){0,10}) {0,2},?)? {0,2}\\}))? {0,2}\\)(;?)$`,
);
const OPTION_KEY_VALUE = new RegExp(`(${OPTION_KEYS}) {0,2}: {0,2}(${OPTION_VALUE})`, "g");

/**
 * Adds the missing flags among `httpOnly`, `secure` and `sameSite` to an Express
 * `res.cookie(name, value[, { flat options }])` call written on one line. A flag that is already
 * present with any other value than the safe one is left alone and the fix is refused, as is any
 * options argument that is not a flat literal of known option names (a variable, a spread, a
 * nested object), a call that continues on the next line (`.status(200)`), and a duplicate key:
 * that is a decision for a person. The line ending (`;` or none) is kept. `sameSite: "lax"` is the
 * least disruptive value, but it drops the cookie from cross-site POSTs and iframes (OAuth
 * `form_post`, embeds); `secure: true` means the cookie is not sent over plain HTTP; `httpOnly`
 * hides the cookie from client code that reads it. A person must check all three.
 */
const fixExpressCookie: Fixer = ({ path, line, nextLine, evidence }) => {
  if (![".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"].includes(extensionOf(path))) return null;
  if (!evidence.startsWith("res.cookie(")) return null;
  // `res.cookie(...)\n  .status(200)`: the statement goes on, and a `;` here would end it.
  if (nextLine.trimStart().startsWith(".") || nextLine.trimStart().startsWith("?.")) return null;
  const match = EXPRESS_COOKIE.exec(line);
  if (match === null) return null;
  const [
    ,
    indent = "",
    prefix = "",
    receiver = "res",
    quote = '"',
    name = "",
    value = "",
    body,
    ending = "",
  ] = match;
  const kept: string[] = [];
  const present = new Map<string, string>();
  for (const pair of (body ?? "").matchAll(OPTION_KEY_VALUE)) {
    const [text = "", key = "", optionValue = ""] = pair;
    present.set(key, optionValue);
    kept.push(text);
  }
  const isSafe = (key: string, accepted: (value: string) => boolean): boolean =>
    !present.has(key) || accepted(present.get(key) ?? "");
  const isTrue = (candidate: string) => candidate === "true";
  const isSameSite = (candidate: string) => /^(["'])(?:lax|strict|none)\1$/i.test(candidate);
  if (
    !isSafe("httpOnly", isTrue) ||
    !isSafe("secure", isTrue) ||
    !isSafe("sameSite", isSameSite) ||
    present.size !== kept.length
  ) {
    return null;
  }
  const added = [
    ...(present.has("httpOnly") ? [] : ["httpOnly: true"]),
    ...(present.has("secure") ? [] : ["secure: true"]),
    ...(present.has("sameSite") ? [] : [`sameSite: ${quote}lax${quote}`]),
  ];
  if (added.length === 0) return null;
  const options = `{ ${[...kept, ...added].join(", ")} }`;
  return {
    newLine: `${indent}${prefix}${receiver}.cookie(${quote}${name}${quote}, ${value}, ${options})${ending}`,
    confidence: "medium",
  };
};

// ---------------------------------------------------------------- PG-CRYPTO-003: java.util.Random

const NAME = "[A-Za-z_]\\w{0,40}";
/** `[modifiers] Random name = new Random();` (a field or a local with its type written out). */
const JAVA_DECLARATION = new RegExp(
  `^( {0,40}(?:(?:private|public|protected|static|final) ){0,4}Random ${NAME} = )new Random\\(\\);$`,
);
/** `new Random().nextBytes(name);` */
const JAVA_CALL = new RegExp(
  `^( {0,40})new Random\\(\\)\\.(nextBytes|nextInt|nextLong|nextDouble|nextFloat|nextBoolean)\\((${NAME})?\\);$`,
);
/** Kotlin: `val name = java.util.Random()` (not `var`: a later assignment of another Random would stop compiling). */
const KOTLIN_DECLARATION = new RegExp(
  `^( {0,40}(?:(?:private|internal|public) )?val ${NAME}(?:: java\\.util\\.Random)? = )java\\.util\\.Random\\(\\)$`,
);
const KOTLIN_CALL = new RegExp(
  `^( {0,40})java\\.util\\.Random\\(\\)\\.(nextBytes|nextInt|nextLong|nextDouble|nextFloat|nextBoolean)\\((${NAME})?\\)$`,
);
const IMPORTS_SINGLE_UTIL_RANDOM = /^[ \t]*import[ \t]+java\.util\.Random[ \t]*;[ \t]*$/m;
/** Another single-type import of a `Random` (a wildcard import never beats the explicit one). */
const IMPORTS_OTHER_RANDOM = /^[ \t]*import[ \t]+(?!java\.util\.Random\b)[\w.]+\.Random[ \t]*;/m;
const DECLARES_RANDOM = /\b(?:class|interface|enum|record)[ \t]+Random\b/;

/**
 * `new Random()` (Java) or `java.util.Random()` (Kotlin) on the flagged line becomes the fully
 * qualified `java.security.SecureRandom`, which extends `java.util.Random`, so the type and every
 * call on the value stay valid and no import is needed. The line must be one of four whole-line
 * shapes: a declaration with an explicit `Random` type, or a call of a standard `next*` method on
 * a new generator. So a seed, an anonymous subclass (`new Random() { ... }`, whose overrides would
 * not compile or would keep the weak behaviour), a `var` (a later assignment of another `Random`),
 * a second statement and any other text on the line all give guidance. In Java `Random` must come
 * from a single-type `import java.util.Random;` (a wildcard import can be shadowed by a `Random`
 * class of the same package, which PGARD cannot see, while a single-type import wins over both); an inherited member type named `Random` is
 * not ruled out, so the confidence is medium. SecureRandom can be slower and can block on some
 * systems, and cannot be seeded for a repeatable sequence; a person must review that.
 */
const fixJavaRandom: Fixer = ({ path, text, line, nextLine, evidence }) => {
  if (!evidence.startsWith("non-cryptographic random")) return null;
  if (nextLine.trimStart().startsWith("{")) return null;
  const extension = extensionOf(path);
  if (extension === ".kt") {
    const declaration = KOTLIN_DECLARATION.exec(line);
    if (declaration !== null) {
      return { newLine: `${declaration[1]}java.security.SecureRandom()`, confidence: "high" };
    }
    const call = KOTLIN_CALL.exec(line);
    if (call === null) return null;
    return {
      newLine: `${call[1]}java.security.SecureRandom().${call[2]}(${call[3] ?? ""})`,
      confidence: "high",
    };
  }
  if (extension !== ".java") return null;
  if (
    !IMPORTS_SINGLE_UTIL_RANDOM.test(text) ||
    IMPORTS_OTHER_RANDOM.test(text) ||
    DECLARES_RANDOM.test(text)
  ) {
    return null;
  }
  const declaration = JAVA_DECLARATION.exec(line);
  if (declaration !== null) {
    return { newLine: `${declaration[1]}new java.security.SecureRandom();`, confidence: "medium" };
  }
  const call = JAVA_CALL.exec(line);
  if (call === null) return null;
  return {
    newLine: `${call[1]}new java.security.SecureRandom().${call[2]}(${call[3] ?? ""});`,
    confidence: "medium",
  };
};

// ---------------------------------------------------------------- dispatch

/** The rules that declare `fixable` (see `SOURCE_RULES`) and their fixers, tried in order. */
const FIXERS: Readonly<Record<string, readonly Fixer[]>> = {
  "PG-COOKIE-001": [fixSpringCookieFlag, fixExpressCookie],
  "PG-CRYPTO-003": [fixJavaRandom],
};

/** Rule ids that have a fixer; `rules.ts` must mark exactly these `fixable` (checked by a test). */
export const FIXABLE_RULE_IDS: readonly string[] = Object.keys(FIXERS);

/**
 * Line breaks other than `\n` and `\r\n`. Analyzers count some of them as line ends (a JS parser
 * counts U+2028 and U+2029) and a diff does not, so a file holding one gives line numbers that
 * cannot be trusted and therefore no diff.
 */
const AMBIGUOUS_LINE_BREAK = /[\u2028\u2029]|\r(?!\n)/;

/**
 * The suggested fix of one finding, from the text of the file it points into, or `null` when the
 * finding's rule is not fixable. A fixable rule always gets an answer: a diff when a fixer
 * matches, guidance with a reason otherwise. Deterministic: the same input gives the same output.
 * A finding of low confidence (inferred) never gets a fix of higher confidence than its own.
 */
export function suggestFix(
  finding: Pick<Finding, "ruleId" | "location" | "evidence"> & { confidence?: Confidence },
  text: string,
): FindingFix | null {
  const fixers = FIXERS[finding.ruleId];
  if (fixers === undefined) return null;
  const { path, line } = finding.location;
  if (path === null || line === null) return guidance("context_not_supported");
  if (AMBIGUOUS_LINE_BREAK.test(text)) return guidance("context_not_supported");
  const lines = text.split("\n");
  const flagged = lines[line - 1];
  if (flagged === undefined || flagged.includes("\r")) return guidance("context_not_supported");
  if (flagged.length > MAX_FIX_LINE_LENGTH) return guidance("too_large");
  const nextLine = lines.slice(line).find((candidate) => candidate.trim() !== "") ?? "";
  const context: FixContext = { path, text, line: flagged, nextLine, evidence: finding.evidence };
  for (const fixer of fixers) {
    const rewrite = fixer(context);
    if (rewrite === null) continue;
    const diff = buildLineReplacementDiff({
      path,
      line,
      oldLine: flagged,
      newLine: rewrite.newLine,
    });
    return diff === null
      ? guidance("sensitive_text")
      : {
          kind: "diff",
          diff,
          confidence: lowerOf(rewrite.confidence, finding.confidence ?? "high"),
        };
  }
  return guidance("context_not_supported");
}
