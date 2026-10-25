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
  {
    kind: "url_credential",
    // `scheme://user:password@host`: the value is the password only.
    pattern:
      /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,31}:\/\/[^\s:/?#@"'`<>]{0,128}:(?<value>[^\s/?#@"'`<>]{1,256})@(?=[A-Za-z0-9[])/g,
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

/** Per-text state shared by the matches of one `detectSecrets` call. */
interface DetectContext {
  text: string;
  /** Whether the text is a source code file (string values there must be quoted). */
  isSource: boolean;
  /** Start of the string literal around an index, or -1 (built lazily, once per text). */
  stringStartAt: (index: number) => number;
}

function createContext(text: string, options: DetectSecretsOptions): DetectContext {
  const path = options.path;
  const isSource = path !== undefined && SOURCE_CODE_FILE.test(path);
  let lookup: ((index: number) => number) | null = null;
  return {
    text,
    isSource,
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
function looksLikeCode(text: string, keyStart: number, end: number, separator: string): boolean {
  if (separator === ":=") return true;
  const lineStart = text.lastIndexOf("\n", keyStart - 1) + 1;
  const before = text.slice(lineStart, keyStart);
  if (CODE_BEFORE_KEY.test(before)) return true;
  const lineEnd = text.indexOf("\n", end);
  const after = text.slice(end, lineEnd === -1 ? text.length : lineEnd);
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
function isLiteralAssignment(context: DetectContext, match: RegExpMatchArray): boolean {
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
  if (CALL_SHAPED_VALUE.test(value) && (value.endsWith(")") || (context.isSource && !inString))) {
    return false;
  }
  if (!context.isSource || inString) return true;
  if (!looksLikeCode(text, keyStart, start + match[0].length, separator)) return true;
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
function isLikelySecretValue(value: string): boolean {
  if (PLACEHOLDER.test(value)) return false;
  if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(value)) return false; // config.db.password
  if (/^[a-z]+$/.test(value) && value.length < 16) return false; // plain words
  return shannonEntropy(value) >= 3.0;
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
  const seen = new Set<string>();
  for (const { kind: patternKind, pattern, group } of PATTERNS) {
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      let kind = patternKind;
      let value = (typeof group === "number" ? match[group] : match.groups?.[group]) ?? "";
      if (value.length === 0) continue;
      if (kind === "private_key" && !hasPrivateKeyBody(value)) {
        kind = "private_key_header";
        // No key material to compare: keep nearby text so distinct headers stay distinct.
        const start = match.index ?? 0;
        value = text.slice(start, start + value.length + 256);
      }
      if (
        kind === "generic_credential" &&
        (!isLikelySecretValue(value) || !isLiteralAssignment(context, match))
      )
        continue;
      if (kind === "url_credential" && !isLikelySecretValue(value)) continue;
      if ((kind === "aws_access_key_id" || kind === "github_token") && PLACEHOLDER.test(value))
        continue;
      const line = lineOfIndex(match.index ?? 0);
      const key = `${line}:${value}`;
      if (seen.has(key)) continue; // a specific pattern already reported this value
      seen.add(key);
      results.push({ kind, line, value });
    }
  }
  return results;
}

const ENV_EXAMPLE = /\.(example|sample|template|dist|defaults?)$/i;

/** `.env`, `.env.local`, `prod.env`... but not `.env.example`-style templates. */
export function isEnvironmentFile(filePath: string): boolean {
  const name = filePath.split("/").pop() ?? "";
  if (ENV_EXAMPLE.test(name)) return false;
  return /^\.env(\..+)?$/i.test(name) || /\.env$/i.test(name);
}
