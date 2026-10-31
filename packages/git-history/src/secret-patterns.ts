/**
 * Secret detection for file contents read from Git objects. Matches carry the value only so the
 * caller can compare occurrences in memory; values must never be written to findings.
 */
import { createStringLookup } from "./string-regions.js";

export type DetectedSecretKind =
  | "private_key"
  | "private_key_header"
  | "aws_access_key_id"
  | "aws_secret_access_key"
  | "github_token"
  | "slack_token"
  | "stripe_key"
  | "google_api_key"
  | "generic_credential"
  | "url_credential";

export interface DetectedSecret {
  kind: DetectedSecretKind;
  /** 1-based line of the match. */
  line: number;
  /** In-memory only: used for equality between occurrences, never output. */
  value: string;
  /** A short or simple password in a URL that is still not a placeholder: report it as unsure. */
  weak?: true;
  /** A generic value that looks like code text inside a string literal: report it as unsure. */
  codeText?: true;
}

export const SECRET_KIND_LABEL: Record<DetectedSecretKind, string> = {
  private_key: "private key",
  private_key_header: "private key header without a key body",
  aws_access_key_id: "AWS access key id",
  aws_secret_access_key: "AWS secret access key",
  github_token: "GitHub token",
  slack_token: "Slack token",
  stripe_key: "Stripe secret key",
  google_api_key: "Google API key",
  generic_credential: "credential assignment",
  url_credential: "password in a URL",
};

export interface DetectSecretsOptions {
  /**
   * Repository path of the text. In source code files a string literal is always quoted, so an
   * unquoted value written as code there (an identifier, constant, type or regex) is not a
   * credential value. Without a path, the text is treated like a config file.
   */
  path?: string;
  /**
   * Leave out generic credential assignments, keeping the provider-specific patterns. For a file
   * that is already reported whole as an environment file (PG-SECRET-001), so its lines do not
   * add one generic finding each.
   */
  omitGeneric?: boolean;
}

interface Pattern {
  kind: DetectedSecretKind;
  pattern: RegExp;
  /** Capture group holding the value (0 = whole match, a name for a named group). */
  group: number | string;
}

/** A credential-like key name (`password`, `DB_PASSWORD`, `x-api-key`, `clientSecret`...). */
const CREDENTIAL_KEY =
  "(?<![A-Za-z0-9])[A-Za-z0-9_.-]{0,40}(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)[A-Za-z0-9_.-]{0,40}";
/** A quoted literal value: the quote must close right after the value. */
const QUOTED_VALUE = "(?<valueQuote>[\"'`])(?<value>[^\\s\"'`,;]{8,256})\\k<valueQuote>";

// Bounded quantifiers keep matching linear.
const PATTERNS: Pattern[] = [
  {
    kind: "private_key",
    // The whole (bounded) block is the value, so distinct keys never compare equal just because
    // they share a header line. The value stays in memory only.
    pattern:
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]{0,8192}?-----END [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----|[A-Za-z0-9+/=\s]{0,8192})/g,
    group: 0,
  },
  {
    kind: "aws_access_key_id",
    pattern: /(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])/g,
    group: 0,
  },
  {
    kind: "aws_secret_access_key",
    pattern:
      /aws_?secret_?(?:access_?)?key["']?[ \t]{0,8}[:=][ \t]{0,8}["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi,
    group: 1,
  },
  {
    kind: "github_token",
    pattern: /(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})/g,
    group: 0,
  },
  { kind: "slack_token", pattern: /(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9-]{10,256}/g, group: 0 },
  { kind: "stripe_key", pattern: /(?<![A-Za-z0-9])[sr]k_live_[A-Za-z0-9]{20,256}/g, group: 0 },
  {
    kind: "google_api_key",
    pattern: /(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])/g,
    group: 0,
  },
  {
    kind: "url_credential",
    // `scheme://user:password@host`: the value is the password only.
    pattern:
      /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,31}:\/\/[^\s:/?#@"'`<>]{0,128}:(?<value>[^\s/?#@"'`<>]{1,256})@(?=[A-Za-z0-9[])/g,
    group: "value",
  },
  // The generic patterns come last: a value a specific pattern above already reported is not
  // reported again as a generic credential (see `detectSecrets`).
  {
    kind: "generic_credential",
    // `key = value`, `key: "value"`, `key := "value"`, `headers["x-api-key"] = "value"`.
    pattern: new RegExp(
      `${CREDENTIAL_KEY}(?<keyQuote>["']?)(?<bracket>\\]?)[ \\t]{0,8}(?<separator>:=|[:=])[ \\t]{0,8}(?<valueQuote>["'\`]?)(?<value>[^\\s"'\`,;]{8,256})\\k<valueQuote>`,
      "gi",
    ),
    group: "value",
  },
  {
    kind: "generic_credential",
    // Only with a quoted literal: a typed declaration (`const dbPassword: string = "…"`,
    // `var password string = "…"`) or a literal behind a condition or fallback
    // (`apiKey = isProd ? "…" : …`, `apiKey = process.env.KEY ?? "…"`).
    pattern: new RegExp(
      `${CREDENTIAL_KEY}["']?\\??(?:[ \\t]{0,8}:[ \\t]{0,8}[A-Za-z_$][\\w$.]{0,40}(?:<[^<>\\n]{0,80}>)?(?:\\[\\])?\\??[ \\t]{0,8}(?::=|=(?![=>]))|[ \\t]{1,8}[A-Za-z_*[\\]][\\w$.*[\\]]{0,40}[ \\t]{0,8}=(?![=>])|[ \\t]{0,8}(?::=|=(?![=>]))[ \\t]{0,8}!?[\\w$.!()[\\]]{1,80}[ \\t]{0,8}(?:\\?\\?|\\|\\||\\?(?![.?])))[ \\t]{0,8}${QUOTED_VALUE}`,
      "gi",
    ),
    group: "value",
  },
];

/** A key block needs at least this many base64 characters of body to count as a key. */
const MIN_PRIVATE_KEY_BODY = 16;
const PRIVATE_KEY_HEADER = /^-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----/;
const PRIVATE_KEY_FOOTER = /-----END [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----$/;

/** Extensions of languages where a string value must be quoted. */
const SOURCE_CODE_FILE =
  /\.(?:[cm]?[jt]sx?|vue|svelte|go|py|rb|java|kts?|scala|groovy|cs|php|rs|swift|dart|c|cc|cpp|h|hpp|m|mm)$/i;

/** Values that are clearly not real secrets. */
const PLACEHOLDER =
  /example|sample|changeme|change_me|placeholder|dummy|your[_-]|<[^>]*>|\$\{|\{\{|%\(|process\.env|os\.environ|getenv|xxxx|\*\*\*\*|redacted|todo|fixme|^(true|false|null|none|undefined)$/i;

/**
 * A value of only dictionary-like words: all lowercase letters, three or more words of 2 to 12
 * letters joined by `-`, `_` or `.` (`my-secret-key-value`).
 */
export function isDictionaryWordsValue(value: string): boolean {
  return /^[a-z]{2,12}(?:[-_.][a-z]{2,12}){2,}$/.test(value);
}

/** Words that mark a dictionary-words value as an example (`my-secret-key-value`). */
const EXAMPLE_WORDS = new Set([
  "my",
  "your",
  "secret",
  "key",
  "value",
  "password",
  "token",
  "here",
  "example",
]);

/** A dictionary-words value with an example word in it: a placeholder in a template or doc. */
function isExampleWordsValue(value: string): boolean {
  return isDictionaryWordsValue(value) && value.split(/[-_.]/).some((w) => EXAMPLE_WORDS.has(w));
}

/**
 * A word-shaped value (letters joined by `-`, `_` or `.`, no digits) in which a placeholder word
 * (`replace`, `random`, `generate`, `insert`, `set-me`, `put-your`) is a whole word, at the start
 * or after a separator. `Random2024Xk` or `aZ9k/generateQ7` is not word-shaped, so it is kept.
 */
function isPlaceholderWordValue(value: string): boolean {
  return (
    /^[A-Za-z]+(?:[-_.][A-Za-z]+)*$/.test(value) &&
    /(?:^|[-_.])(?:replace|random|generate|insert|set[-_]?me|put[-_]?your)(?=$|[-_.])/i.test(value)
  );
}

/** Documentation files, where a generic value is usually an example. */
const DOC_FILE = /\.(?:md|mdx|rst|adoc)$/i;
/** `.env` templates, where only a real-looking generic value is reported. */
const ENV_TEMPLATE = /(?:^|\.)env\.(?:example|sample|template|dist)$/i;

export function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

/**
 * Unquoted values that are code, not data: a parameter type (`password: string)`), an arrow
 * function's parameter list (`= (object:`), a generic type (`Record<SecretKind`), or a regex
 * literal (`/pass(word)?|pwd/i`).
 */
const CODE_SHAPED_VALUE = [/^[A-Za-z_$][\w$.]*[)<>[\]]/, /[:(]$/, /^\/.*[\\()[\]|]/];
/**
 * An unquoted value in source code, outside a string, that is the rest of an expression: it
 * starts with `=` (`==e.pass`), or a dotted member access runs into `)`, `}`, `]`, `||` or `&&`
 * (`e.target.value})`, `e.pass)||`). Such a value is rejected only when the key directly follows
 * a code token (see `followsCodeToken`). Comment prose puts a space or a word before the key
 * (`// db password: Xk9)m2`), so a password in a comment is kept wherever the comment starts.
 */
const UNQUOTED_CODE_VALUE = /^=|^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+(?:[)}\]]|\|\||&&)/;
/**
 * Text of the line before `index`, read within `window` characters only (a very long line, such
 * as a minified bundle, is never scanned back to its start). `known` is false when the window
 * cut the line, so its start is not the line's start.
 */
function lineBefore(text: string, index: number, window: number) {
  const from = Math.max(0, index - window);
  const relative = text.slice(from, index).lastIndexOf("\n");
  const start = relative < 0 ? from : from + relative + 1;
  return { start, known: relative >= 0 || from === 0, before: text.slice(start, index) };
}

/**
 * Whether a key sits directly after a code token: `{password:`, `,password:`, `(password:`, or a
 * member access (`t.password==`, the `.` is part of the key text). Minified code has no space
 * there; comment prose has a space or a word before the key. Reads one character, never scans back.
 */
function followsCodeToken(text: string, start: number, matched: string): boolean {
  if (start > 0 && "{,(.".includes(text.charAt(start - 1))) return true;
  const key = /^[^:=\]"']*/.exec(matched)?.[0] ?? "";
  return key.includes(".");
}
/** `ACCESS_TOKEN`: an all-caps constant name used as the value. */
const CONSTANT_NAME = /^[A-Z]+(?:_[A-Z]+)+$/;
const BARE_IDENTIFIER = /^[A-Za-z_$]+$/;
/** `getSecret()`, `hash(input`: a call (cut at `,` or a space). */
const CALL_SHAPED_VALUE = /^[A-Za-z_$][\w$.]*\(/;

/** Code right before a key: a declaration keyword, or an opening `(`/`{`/`[` or `,` separator. */
const CODE_BEFORE_KEY =
  /(?:^|[\s(])(?:const|let|var|val|final|readonly|static|export|public|private|protected|def|func|fn)\s+$|[({[,]\s*$/;
/** Code right after a value: `)`, `,`, `;`, `{` or `=>`. */
const CODE_AFTER_VALUE = /^\s*(?:[),;{]|=>)/;
/** Characters of the line read before a key and after a value to judge whether it is code. */
const CODE_WINDOW = 200;

/**
 * Characters to cut off an unquoted value in a string literal of a source file: from the first
 * `\n` escape (a backslash-n after an odd number of backslashes) to the end. In the source text
 * that escape is a line break, so the value ends there. 0 when the value has no such escape or
 * would be shorter than a value can be (then the value is kept whole).
 */
function escapedNewlineTail(value: string): number {
  for (let index = value.indexOf("n"); index !== -1; index = value.indexOf("n", index + 1)) {
    let backslashes = 0;
    while (backslashes < index && value[index - 1 - backslashes] === "\\") backslashes += 1;
    if (backslashes % 2 === 1) {
      const head = index - 1;
      return head >= MIN_VALUE_LENGTH ? value.length - head : 0;
    }
  }
  return 0;
}

/** Shortest generic value (see the value patterns). */
const MIN_VALUE_LENGTH = 8;

/** Per-text state shared by the matches of one `detectSecrets` call. */
interface DetectContext {
  text: string;
  /** Whether the text is a source code file (string values there must be quoted). */
  isSource: boolean;
  /** Whether the file is a template (`.env.example`): only a real-looking value is reported. */
  isTemplate: boolean;
  /** Whether the file is JavaScript or TypeScript (where `#` starts a private field). */
  isJs: boolean;
  /** Whether the file is a Markdown-like documentation file. */
  isDoc: boolean;
  /** Number of Markdown code fence lines that start before an index (built lazily, once). */
  fencesBefore: (index: number) => number;
  /** Start of the string literal around an index, or -1 (built lazily, once per text). */
  stringStartAt: (index: number) => number;
}

function createContext(text: string, options: DetectSecretsOptions): DetectContext {
  const path = options.path;
  const isSource = path !== undefined && SOURCE_CODE_FILE.test(path);
  const name = path?.split("/").pop() ?? "";
  let lookup: ((index: number) => number) | null = null;
  let fenceStarts: number[] | null = null;
  return {
    text,
    isSource,
    isTemplate: ENV_TEMPLATE.test(name),
    isJs: /\.(?:[cm]?[jt]sx?|vue|svelte)$/i.test(name),
    isDoc: DOC_FILE.test(name),
    fencesBefore: (index) => {
      if (fenceStarts === null) {
        fenceStarts = [];
        let lineStart = 0;
        while (lineStart <= text.length) {
          const end = text.indexOf("\n", lineStart);
          const stop = end === -1 ? text.length : end;
          if (/^[ \t]*(?:```|~~~)/.test(text.slice(lineStart, Math.min(stop, lineStart + 80)))) {
            fenceStarts.push(lineStart);
          }
          if (end === -1) break;
          lineStart = end + 1;
        }
      }
      // Binary search: fences starting before `index`.
      let low = 0;
      let high = fenceStarts.length;
      while (low < high) {
        const middle = (low + high) >> 1;
        if ((fenceStarts[middle] as number) < index) low = middle + 1;
        else high = middle;
      }
      return low;
    },
    stringStartAt: (index) => {
      if (path === undefined) return -1;
      lookup ??= createStringLookup(text, path);
      return lookup(index);
    },
  };
}

/**
 * Whether the match positively looks like code: the key follows a code token on its line
 * (`const password = …`, `f(secret: …`, `{ apiKey: …`, `headers["x-api-key"] = …`), it is a Go
 * short declaration (`token := …`), or the key starts the line as an object property or type
 * member (`key: value`) and the value is followed by code (an object property set to a constant
 * and a trailing comma, or a `string;` type member). The caller has checked that the key is not
 * inside a string literal; anything ambiguous is not treated as code.
 */
function looksLikeCode(
  text: string,
  keyStart: number,
  end: number,
  separator: string,
  stringStart = -1,
): boolean {
  if (separator === ":=") return true;
  // Only a bounded window around the match is read, so a very long line with many matches stays
  // linear. A window cut short of the line start begins with a non-space marker: neither `^`
  // nor an empty `before` can then match at the cut, so a long line is not taken as code there.
  // Inside a string literal (`stringStart` is its opening quote) the judged segment stays within
  // that string, and a `\n` escape is a line break there.
  const inString = stringStart !== -1;
  const lowest = inString ? stringStart + 1 : 0;
  const windowStart = Math.max(lowest, keyStart - CODE_WINDOW);
  const window = text.slice(windowStart, keyStart);
  const escape = inString ? window.lastIndexOf("\\n") : -1;
  // Index of the last character of a line break: a newline, or the `n` of a `\n` escape.
  const newline = Math.max(window.lastIndexOf("\n"), escape === -1 ? -1 : escape + 1);
  const before =
    newline !== -1 ? window.slice(newline + 1) : windowStart > lowest ? `x${window}` : window;
  if (CODE_BEFORE_KEY.test(before)) return true;
  const afterWindow = text.slice(end, end + CODE_WINDOW);
  const lineEnd = afterWindow.indexOf("\n");
  const escapeEnd = inString ? afterWindow.indexOf("\\n") : -1;
  const stop = [lineEnd, escapeEnd].filter((index) => index !== -1);
  const after = stop.length === 0 ? afterWindow : afterWindow.slice(0, Math.min(...stop));
  return separator === ":" && before.trim() === "" && CODE_AFTER_VALUE.test(after);
}

/**
 * Whether a generic `key = value` match is an assignment of a literal value, judged by what
 * surrounds it. Rejects a ternary between two strings (`x ? "API_KEY" : "PG-SECRET-002"`). An
 * unquoted call (`getSecret()`) is rejected when it is complete, or in source code outside a
 * string literal. In source code files, an unquoted value is rejected only when the key is not
 * inside a string literal (judged over the whole file, so multi-line strings count), the line
 * positively looks like code at the match (see `looksLikeCode`), and the value is code-shaped,
 * an all-caps constant name or a bare identifier. Everything else is kept: config files, string
 * literals and ambiguous lines. Erring towards reporting is deliberate.
 */
function isLiteralAssignment(
  context: DetectContext,
  match: RegExpMatchArray,
  cut = 0,
): boolean | "code_text" {
  const groups = match.groups ?? {};
  const keyQuote = groups.keyQuote ?? "";
  const separator = groups.separator ?? "=";
  const valueQuote = groups.valueQuote ?? "";
  const value = groups.value ?? "";
  const { text } = context;
  const start = match.index ?? 0;
  if (
    separator === ":" &&
    keyQuote !== "" &&
    /\?[ \t]*["'`]$/.test(text.slice(Math.max(0, start - 16), start))
  ) {
    return false; // `cond ? "PG-SECRET-003" : "PG-SECRET-002"` is a ternary, not a key
  }
  if (valueQuote !== "") return true;
  // A quoted index key (`headers["x-api-key"] = …`) is a string token of its own: judge the code
  // around its opening quote.
  let keyStart = start;
  let stringStart = context.isSource ? context.stringStartAt(start) : -1;
  if (groups.bracket === "]" && keyQuote !== "" && stringStart === start - 1) {
    keyStart = start - 1;
    stringStart = context.stringStartAt(start - 2);
  }
  const inString = stringStart !== -1;
  // In source code outside a string, a comparison (`password==e.pass`) or a member access that
  // runs into a bracket or operator (`e.target.value})`) is an expression, not a literal. Inside a
  // string, in a comment or in a config file the same characters can be part of a password.
  if (
    context.isSource &&
    !inString &&
    UNQUOTED_CODE_VALUE.test(value) &&
    followsCodeToken(text, start, match[0])
  ) {
    return false;
  }
  if (CALL_SHAPED_VALUE.test(value) && (value.endsWith(")") || (context.isSource && !inString))) {
    return false;
  }
  if (!context.isSource) return true;
  if (inString) {
    // Code text kept in a string (a test fixture, a code generator template) reads like code
    // within its own string segment: code before the key or after the value, and a code-shaped
    // value. It is still reported, demoted to a low-confidence inferred finding, because a real
    // secret can look like that too. A constant-name value counts only with that code context.
    const isCode =
      looksLikeCode(text, keyStart, start + match[0].length - cut, separator, stringStart) &&
      (CODE_SHAPED_VALUE.some((shape) => shape.test(value)) || CONSTANT_NAME.test(value));
    return isCode ? "code_text" : true;
  }
  if (!looksLikeCode(text, keyStart, start + match[0].length - cut, separator)) return true;
  return (
    !CODE_SHAPED_VALUE.some((shape) => shape.test(value)) &&
    !CONSTANT_NAME.test(value) &&
    !BARE_IDENTIFIER.test(value)
  );
}

/** A private key block with fewer base64 body characters than this is only a header. */
function hasPrivateKeyBody(block: string): boolean {
  const body = block.replace(PRIVATE_KEY_HEADER, "").replace(PRIVATE_KEY_FOOTER, "");
  return (body.match(/[A-Za-z0-9+/]/g)?.length ?? 0) >= MIN_PRIVATE_KEY_BODY;
}

/** Generic values must look random enough and not be a code reference or placeholder. */
function isLikelySecretValue(value: string, example = false, template = false): boolean {
  if (PLACEHOLDER.test(value)) return false;
  if (example) return false;
  // A template file reports only what looks like a real secret (see `hasSecretShape`).
  if (template && !hasSecretShape(value)) return false;
  if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(value)) return false; // config.db.password
  if (/^[a-z]+$/.test(value) && value.length < 16) return false; // plain words
  return shannonEntropy(value) >= 3.0;
}

/**
 * Whether a generic match is a placeholder because of its file and shape: a placeholder word in
 * a word-shaped value; in a `.env` template a dictionary-words value with an example word; in a
 * doc the same, but only unquoted or inside a code span or fenced block (a quoted passphrase in
 * prose is kept).
 */
function isExampleValue(context: DetectContext, match: RegExpMatchArray, value: string): boolean {
  // Only in `.env` templates and docs: in a config file `random-tiger-lamp-orbit` is a passphrase.
  if (!context.isTemplate && !context.isDoc) return false;
  if (isPlaceholderWordValue(value)) return true;
  if (!isExampleWordsValue(value)) return false;
  if (context.isTemplate) return true;
  if ((match.groups?.valueQuote ?? "") === "") return true;
  return isInCodeRegion(context, match.index ?? 0);
}

/** Whether `index` is inside a backtick code span on its line or a fenced code block. */
function isInCodeRegion(context: DetectContext, index: number): boolean {
  const { text } = context;
  // A line longer than 2000 characters is read only for its last 2000 (keeps a long line linear).
  const { start, before } = lineBefore(text, index, 2000);
  if (((before.match(/`/g) ?? []).length & 1) === 1) return true;
  return context.fencesBefore(start) % 2 === 1;
}

/**
 * What a value in an `.env` template must look like to be reported: two or more character
 * classes (lowercase, uppercase, digit, other), or a single class with 20+ characters and
 * entropy of 3.5 or more, and entropy of at least 3.0 in any case.
 */
function hasSecretShape(value: string): boolean {
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((test) => test.test(value));
  const entropy = shannonEntropy(value);
  if (entropy < 3.0) return false;
  return classes.length >= 2 || (value.length >= 20 && entropy >= 3.5);
}

/**
 * Passwords in URLs that are template slots shaped like variable names: `$DB_PASSWORD`,
 * `${db_password}`, `{password}`, `%s`, `:password`, `***`. A value that does not read as a name
 * (`$K9X2P7Q4M8`, `{Xk9vLp8Wz4Rt2q}`, `:k9x2p7q4m8z`, `{qwertyuiopasdfgh}`) is a real password.
 */
const URL_SLOT_WORDS = new Set([
  "password",
  "passwd",
  "pass",
  "pwd",
  "pw",
  "secret",
  "token",
  "key",
  "passphrase",
  "credential",
  "credentials",
]);

function isUrlPlaceholder(value: string): boolean {
  if (/^(?:%[sdv]|\*+|\$\{[A-Za-z_]\w*\})$/.test(value)) return true;
  // `$NAME`: a constant-style name, with digits only inside an underscore-separated name.
  if (/^\$[A-Z_][A-Z0-9_]*$/.test(value)) return !/\d/.test(value) || value.includes("_");
  // `{name}` and `:name`: a lowercase name made of letters and underscores that reads as a slot,
  // either snake_case or a plain word from a short list. Digits or a long run of letters is a
  // chosen password.
  const name = /^(?:\{([a-z_]+)\}|:([a-z_]+))$/.exec(value);
  const word = name?.[1] ?? name?.[2];
  return word !== undefined && (word.includes("_") || URL_SLOT_WORDS.has(word));
}

/**
 * Judges the password of a `scheme://user:password@host` match: `null` for a placeholder (see
 * `PLACEHOLDER` and `isUrlPlaceholder`), a plain word (`user:pass`, `postgres:password`) or the
 * user name repeated (`guest:guest`, `postgres:postgres`), or a host and port. A short or simple password that is
 * none of these (`admin:hunter2`) is kept as weak, to be reported with low confidence.
 */
function urlPasswordStrength(match: RegExpMatchArray, value: string): "strong" | "weak" | null {
  if (PLACEHOLDER.test(value) || isUrlPlaceholder(value)) return null;
  if (/^[a-z]+$/.test(value) && value.length < 16) return null;
  const authority = match[0].slice(match[0].indexOf("//") + 2);
  const user = authority.slice(0, authority.indexOf(":"));
  // The user name repeated is a default only when it is a short plain word, lowercase or
  // Capitalized (`guest:guest`, `Guest:Guest`); with digits, symbols, mixed case or a long run
  // of letters (`Svc_Deploy_9f8a`, `QwErTyUiOpAsDfGhJk`) it is a chosen password.
  if (
    /^[A-Z]?[a-z]+$/.test(value) &&
    value.length <= 12 &&
    user.toLowerCase() === value.toLowerCase()
  ) {
    return null;
  }
  // `http://localhost:8080@host`: a host and port, not a user and password.
  if (/^\d{1,5}$/.test(value) && (user.includes(".") || user.toLowerCase() === "localhost")) {
    return null;
  }
  return isLikelySecretValue(value) ? "strong" : "weak";
}

function createLineLookup(text: string): (index: number) => number {
  const newlines: number[] = [];
  for (let cursor = text.indexOf("\n"); cursor !== -1; cursor = text.indexOf("\n", cursor + 1)) {
    newlines.push(cursor);
  }
  return (index) => {
    let low = 0;
    let high = newlines.length;
    while (low < high) {
      const middle = (low + high) >> 1;
      if ((newlines[middle] as number) < index) low = middle + 1;
      else high = middle;
    }
    return low + 1;
  };
}

/**
 * Finds secrets in a file's text. A private key header without a key body is reported as
 * `private_key_header` (never as a confirmed key). Generic credential assignments count only
 * when the value is a literal that looks like a secret (see `isLiteralAssignment`).
 */
export function detectSecrets(text: string, options: DetectSecretsOptions = {}): DetectedSecret[] {
  const lineOfIndex = createLineLookup(text);
  const context = createContext(text, options);
  const results: DetectedSecret[] = [];
  const seen = new Map<string, number>();
  /** `[start, end)` value spans reported by the specific patterns (not weak URL passwords). */
  const claimed: number[] = [];
  /** The same for URL passwords, which also claim a generic value they lie inside. */
  const claimedUrls: number[] = [];
  /** Weak URL passwords: result index and `[start, end)`; a generic match over one replaces it. */
  const weakUrls: { index: number; start: number; end: number }[] = [];
  /** `[start, end)` spans of the generic credentials reported. */
  const genericSpans: number[] = [];
  let isClaimedAt: ((start: number, end: number) => boolean) | null = null;
  let isUrlClaimedAt: ((start: number, end: number) => boolean) | null = null;
  for (const { kind: patternKind, pattern, group } of PATTERNS) {
    if (patternKind === "generic_credential") {
      isClaimedAt ??= createSpanLookup(claimed, MAX_EXTRA_GENERIC);
      isUrlClaimedAt ??= createSpanLookup(claimedUrls);
    }
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      let kind = patternKind;
      let value = (typeof group === "number" ? match[group] : match.groups?.[group]) ?? "";
      if (value.length === 0) continue;
      // The value ends the match (only a closing quote or `@` may follow it).
      const valueStart = (match.index ?? 0) + match[0].lastIndexOf(value);
      const valueEnd = valueStart + value.length;
      // `https://x-access-token:<token>@host`: the URL password, not also a generic credential.
      // A generic value that is a specific match plus more (a key id and a secret) is kept.
      if (
        kind === "generic_credential" &&
        (isUrlClaimedAt?.(valueStart, valueEnd) || isClaimedAt?.(valueStart, valueEnd))
      )
        continue;
      if (kind === "private_key" && !hasPrivateKeyBody(value)) {
        kind = "private_key_header";
        // No key material to compare: keep nearby text so distinct headers stay distinct.
        const start = match.index ?? 0;
        value = text.slice(start, start + value.length + 256);
      }
      let codeText = false;
      let cut = 0;
      if (kind === "generic_credential") {
        // An unquoted value in a string literal of a source file ends at a `\n` escape.
        if (
          context.isSource &&
          match.groups?.valueQuote === "" &&
          context.stringStartAt(match.index ?? 0) !== -1
        ) {
          cut = escapedNewlineTail(value);
          if (cut > 0) value = value.slice(0, value.length - cut);
        }
        if (options.omitGeneric === true) continue;
        if (!isLikelySecretValue(value, isExampleValue(context, match, value), context.isTemplate))
          continue;
        const assignment = isLiteralAssignment(context, match, cut);
        if (assignment === false) continue;
        codeText = assignment === "code_text";
      }
      const strength = kind === "url_credential" ? urlPasswordStrength(match, value) : "strong";
      if (strength === null) continue;
      if ((kind === "aws_access_key_id" || kind === "github_token") && PLACEHOLDER.test(value))
        continue;
      const line = lineOfIndex(match.index ?? 0);
      const key = `${line}:${value}`;
      const duplicate = seen.get(key);
      if (duplicate !== undefined) {
        // A specific pattern already reported this value; a code-text report gives way to a
        // full one for the same value on the same line.
        if (!codeText && results[duplicate]?.codeText === true) {
          const { codeText: _demoted, ...full } = results[duplicate] as DetectedSecret;
          results[duplicate] = full;
        }
        continue;
      }
      seen.set(key, results.length);
      if (strength === "weak")
        weakUrls.push({ index: results.length, start: valueStart, end: valueEnd });
      results.push({
        kind,
        line,
        value,
        ...(strength === "weak" ? { weak: true as const } : {}),
        ...(codeText ? { codeText: true as const } : {}),
      });
      if (kind === "generic_credential") genericSpans.push(valueStart, valueEnd);
      else if (strength !== "weak") {
        (kind === "url_credential" ? claimedUrls : claimed).push(valueStart, valueEnd);
      }
    }
  }
  // A weak URL password inside a reported generic value (a URL assigned to a credential key) is
  // the same finding: keep the generic one, which carries the higher confidence.
  const covered = weakUrls.length > 0 ? createSpanLookup(genericSpans) : null;
  const dropped = new Set(
    weakUrls.filter(({ start, end }) => covered?.(start, end)).map(({ index }) => index),
  );
  return dropped.size > 0 ? results.filter((_, index) => !dropped.has(index)) : results;
}

/**
 * A generic value reaching this many characters beyond a specific match (a key id, then `:` and a secret)
 * holds more than that match, so it is reported too. Shorter tails are trailing punctuation.
 */
const MAX_EXTRA_GENERIC = 4;

/**
 * Whether `[start, end)` overlaps any of the flat `[start, end)` pairs in `spans`. With
 * `maxExtra`, the range must also reach fewer than `maxExtra` characters past that span.
 */
function createSpanLookup(
  spans: number[],
  maxExtra = Infinity,
): (start: number, end: number) => boolean {
  const pairs: [number, number][] = [];
  for (let index = 0; index < spans.length; index += 2) {
    pairs.push([spans[index] as number, spans[index + 1] as number]);
  }
  pairs.sort((a, b) => a[0] - b[0]);
  // Merge into disjoint, sorted spans.
  const merged: [number, number][] = [];
  for (const pair of pairs) {
    const last = merged[merged.length - 1];
    if (last && pair[0] <= last[1]) last[1] = Math.max(last[1], pair[1]);
    else merged.push([pair[0], pair[1]]);
  }
  return (start, end) => {
    // Last span starting before `end`.
    let low = 0;
    let high = merged.length;
    while (low < high) {
      const middle = (low + high) >> 1;
      if ((merged[middle] as [number, number])[0] < end) low = middle + 1;
      else high = middle;
    }
    if (low === 0) return false;
    const [spanStart, spanEnd] = merged[low - 1] as [number, number];
    return spanEnd > start && spanStart - start < maxExtra && end - spanEnd < maxExtra;
  };
}

const ENV_EXAMPLE = /\.(example|sample|template|dist|defaults?)$/i;

/** `.env`, `.env.local`, `prod.env`... but not `.env.example`-style templates. */
export function isEnvironmentFile(filePath: string): boolean {
  const name = filePath.split("/").pop() ?? "";
  if (ENV_EXAMPLE.test(name)) return false;
  return /^\.env(\..+)?$/i.test(name) || /\.env$/i.test(name);
}
