/**
 * Suggested fixes (JSON v1.6 `Finding.fix`): pure text in, a fix out. Nothing here reads a file,
 * runs project code or touches the file system; `attach-fixes.ts` does the reading.
 *
 * A rule is `fixable` only when a finding of it can be repaired by replacing ONE line with ONE
 * other line, mechanically and with the same meaning in that exact context. Each fixer below
 * matches the whole flagged line against a strict pattern and refuses (guidance, no diff) when
 * anything else is on the line: a comment, a second statement, a string literal other than a
 * short name, a spread, a variable where a literal is expected. The patterns accept only
 * identifiers, numbers and short names, so no secret value can be copied into a diff; redaction in
 * `buildLineReplacementDiff` is a second barrier, not the first.
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

/** What a fixer needs: the file's text (for imports), its lines and the flagged line. */
interface FixContext {
  path: string;
  text: string;
  line: string;
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

// ---------------------------------------------------------------- PG-COOKIE-001: Spring config

const SPRING_FLAG: Record<string, RegExp> = {
  Secure: /(?:^|\.)secure$/,
  HttpOnly: /(?:^|\.)(?:http-only|httpOnly)$/,
};
/** `<indent><quote?>key<quote?><separator><quote?>off-value<quote?>` and nothing else on the line. */
const SPRING_FLAG_LINE =
  /^( {0,40})(["']?)((?:[\w-]{1,40}\.){0,8}(?:secure|http-only|httpOnly))\2( {0,3}[=:] {0,3})(["']?)(false|off|no|0)\5$/i;

/**
 * `server.servlet.session.cookie.secure=false` (or `http-only`, in a `.properties` or YAML file)
 * becomes `true`. The finding's evidence names the flag and the line must set exactly that flag to
 * an explicit off value, so nothing else is read as "off". A person must still check that the site
 * is served over HTTPS (a Secure cookie is not sent over plain HTTP, which also affects local
 * development).
 */
const fixSpringCookieFlag: Fixer = ({ path, line, evidence }) => {
  if (![".properties", ".yml", ".yaml"].includes(extensionOf(path))) return null;
  const flag =
    /^server\.[\w.-]{1,120}\.cookie\.[\w-]{1,20}=\S{1,20} sends the session cookie without (Secure|HttpOnly)\b/.exec(
      evidence,
    )?.[1];
  const match = SPRING_FLAG_LINE.exec(line);
  if (flag === undefined || match === null) return null;
  const [, indent = "", keyQuote = "", key = "", separator = "", valueQuote = ""] = match;
  if (!SPRING_FLAG[flag]?.test(key)) return null;
  return {
    newLine: `${indent}${keyQuote}${key}${keyQuote}${separator}${valueQuote}true${valueQuote}`,
    confidence: "high",
  };
};

// ---------------------------------------------------------------- PG-COOKIE-001: Express res.cookie

const IDENT = "[A-Za-z_$][\\w$]{0,40}";
const MEMBER = `${IDENT}(?:\\.${IDENT}){0,4}`;
const COOKIE_VALUE = `${MEMBER}(?:\\((?:${MEMBER}(?: {0,2}, {0,2}${MEMBER}){0,3})?\\))?`;
/** An object literal value: a boolean, a number, a short word-like string or a plain name. */
const OPTION_VALUE = `(?:true|false|-?\\d{1,15}|"[\\w/.:-]{0,64}"|'[\\w/.:-]{0,64}'|${MEMBER})`;
const OPTION_PAIR = `${IDENT} {0,2}: {0,2}${OPTION_VALUE}`;
const EXPRESS_COOKIE = new RegExp(
  `^( {0,40})((?:return |await )?)(res|response)\\.cookie\\( {0,2}(["'])([\\w.-]{1,64})\\4 {0,2}, {0,2}(${COOKIE_VALUE})(?: {0,2}, {0,2}(?:\\{ {0,2}((?:${OPTION_PAIR}(?: {0,2}, {0,2}${OPTION_PAIR}){0,10}) {0,2},?)? {0,2}\\}))? {0,2}\\);?$`,
);
const OPTION_KEY_VALUE = new RegExp(`(${IDENT}) {0,2}: {0,2}(${OPTION_VALUE})`, "g");

/**
 * Adds the missing flags among `httpOnly`, `secure` and `sameSite` to an Express
 * `res.cookie(name, value[, { flat options }])` call written on one line. A flag that is already
 * present with any other value than the safe one is left alone and the fix is refused, as is any
 * options argument that is not a flat literal (a variable, a spread, a nested object): that is a
 * decision for a person. `sameSite: "lax"` is the least disruptive value; `secure: true` means the
 * cookie is not sent over plain HTTP, which a person must check against how the site is served.
 */
const fixExpressCookie: Fixer = ({ path, line, evidence }) => {
  if (![".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"].includes(extensionOf(path))) return null;
  if (!evidence.startsWith("res.cookie(")) return null;
  const match = EXPRESS_COOKIE.exec(line);
  if (match === null) return null;
  const [, indent = "", prefix = "", receiver = "res", quote = '"', name = "", value = "", body] =
    match;
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
    newLine: `${indent}${prefix}${receiver}.cookie(${quote}${name}${quote}, ${value}, ${options});`,
    confidence: "medium",
  };
};

// ---------------------------------------------------------------- PG-CRYPTO-003: java.util.Random

const IMPORTS_UTIL_RANDOM = /^[ \t]*import[ \t]+java\.util\.(?:Random|\*)[ \t]*;?[ \t]*$/m;
const IMPORTS_OTHER_RANDOM = /^[ \t]*import[ \t]+(?!java\.util\.)[\w.]+\.Random[ \t]*;?[ \t]*$/m;
const DECLARES_RANDOM = /\b(?:class|interface|object|enum)[ \t]+Random\b/;

/**
 * `new Random()` (Java) or `java.util.Random()` (Kotlin) written on the flagged line becomes the
 * fully qualified `java.security.SecureRandom`, which extends `java.util.Random`, so the type and
 * every call on the value stay valid and no import is needed. Only a no-argument constructor is
 * rewritten (a seed would make a deterministic sequence, which SecureRandom does not offer) and
 * only when the flagged line itself creates the generator; when the generator is created elsewhere
 * (a field, another method), PGARD does not guess and gives guidance. In Java, `Random` must be
 * `java.util.Random` by the file's imports. SecureRandom can be slower and can block on some
 * systems; a person must review that.
 */
const fixJavaRandom: Fixer = ({ path, text, line, evidence }) => {
  if (!evidence.startsWith("non-cryptographic random")) return null;
  if (/["'`]|\/\/|\/\*|\*\//.test(line)) return null;
  const extension = extensionOf(path);
  if (extension === ".kt") {
    if (
      line.split("java.util.Random()").length !== 2 ||
      /\bRandom\s*\(/.test(line.replace("java.util.Random()", ""))
    ) {
      return null;
    }
    return {
      newLine: line.replace("java.util.Random()", "java.security.SecureRandom()"),
      confidence: "high",
    };
  }
  if (extension !== ".java") return null;
  const construction = line.match(/\bnew[ \t]+Random\(\)/g);
  const anyRandomCall = line.match(/\bRandom[ \t]*\(/g);
  if (construction?.length !== 1 || anyRandomCall?.length !== 1) return null;
  if (
    !IMPORTS_UTIL_RANDOM.test(text) ||
    IMPORTS_OTHER_RANDOM.test(text) ||
    DECLARES_RANDOM.test(text)
  ) {
    return null;
  }
  return {
    newLine: line.replace(/\bnew[ \t]+Random\(\)/, "new java.security.SecureRandom()"),
    confidence: "high",
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
 * The suggested fix of one finding, from the text of the file it points into, or `null` when the
 * finding's rule is not fixable. A fixable rule always gets an answer: a diff when a fixer
 * matches, guidance with a reason otherwise. Deterministic: the same input gives the same output.
 */
export function suggestFix(
  finding: Pick<Finding, "ruleId" | "location" | "evidence">,
  text: string,
): FindingFix | null {
  const fixers = FIXERS[finding.ruleId];
  if (fixers === undefined) return null;
  const { path, line } = finding.location;
  if (path === null || line === null) return guidance("context_not_supported");
  const lines = text.split("\n");
  const flagged = lines[line - 1];
  if (flagged === undefined || flagged.includes("\r")) return guidance("context_not_supported");
  if (flagged.length > MAX_FIX_LINE_LENGTH) return guidance("too_large");
  const context: FixContext = { path, text, line: flagged, evidence: finding.evidence };
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
      : { kind: "diff", diff, confidence: rewrite.confidence };
  }
  return guidance("context_not_supported");
}
