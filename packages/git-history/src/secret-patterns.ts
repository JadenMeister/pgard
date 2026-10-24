/**
 * Secret detection for file contents read from Git objects. Matches carry the value only so the
 * caller can compare occurrences in memory; values must never be written to findings.
 */
export type DetectedSecretKind =
  | "private_key"
  | "private_key_header"
  | "aws_access_key_id"
  | "aws_secret_access_key"
  | "github_token"
  | "slack_token"
  | "stripe_key"
  | "google_api_key"
  | "generic_credential";

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
  /** Capture group holding the value (0 = whole match). */
  group: number;
}

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
    // Groups: 1 quote closing the key, 2 separator, 3 quote opening the value, 4 value.
    pattern:
      /(?<![A-Za-z0-9])[A-Za-z0-9_.-]{0,40}(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)[A-Za-z0-9_.-]{0,40}(["']?)[ \t]{0,8}([:=])[ \t]{0,8}(["']?)([^\s"'`,;]{8,256})\3/gi,
    group: 4,
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

/**
 * Whether `index` sits inside a string literal on its line (`"…;Password=abc"`), judged by the
 * unescaped quotes before it on that line. A stray apostrophe errs towards "inside", which keeps
 * the match.
 */
function isInsideStringLiteral(text: string, index: number): boolean {
  const lineStart = text.lastIndexOf("\n", index - 1) + 1;
  let open: string | null = null;
  for (let cursor = lineStart; cursor < index; cursor += 1) {
    const char = text[cursor];
    if (char === "\\") {
      cursor += 1;
    } else if (open === null) {
      if (char === '"' || char === "'" || char === "`") open = char;
    } else if (char === open) {
      open = null;
    }
  }
  return open !== null;
}

/**
 * Whether a generic `key = value` match is an assignment of a literal value, judged by what
 * surrounds it. Rejects a ternary between two strings (`x ? "API_KEY" : "PG-SECRET-002"`). In
 * source code files, where a literal must be quoted, an unquoted value written as code (outside
 * a string literal) is rejected when it is code-shaped, an all-caps constant name or a bare
 * identifier. Unquoted values in config files (`.env`, YAML, `.properties`) and inside string
 * literals (connection strings) always count, whatever characters they contain.
 */
function isLiteralAssignment(
  text: string,
  match: RegExpMatchArray,
  options: DetectSecretsOptions,
): boolean {
  const [, keyQuote = "", separator = "", valueQuote = "", value = ""] = match;
  const start = match.index ?? 0;
  if (
    separator === ":" &&
    keyQuote !== "" &&
    /\?[ \t]*["']$/.test(text.slice(Math.max(0, start - 16), start))
  ) {
    return false; // `cond ? "PG-SECRET-003" : "PG-SECRET-002"` is a ternary, not a key
  }
  if (valueQuote !== "") return true;
  const isCode =
    options.path !== undefined &&
    SOURCE_CODE_FILE.test(options.path) &&
    !isInsideStringLiteral(text, start);
  if (!isCode) return true;
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

/** Generic assignments must look random enough and not be a code reference or placeholder. */
function isLikelySecretValue(value: string): boolean {
  if (PLACEHOLDER.test(value)) return false;
  if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(value)) return false; // config.db.password
  if (/^[A-Za-z_$][\w$.]*\(/.test(value)) return false; // getSecret()
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
  const results: DetectedSecret[] = [];
  const seen = new Set<string>();
  for (const { kind: patternKind, pattern, group } of PATTERNS) {
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      let kind = patternKind;
      let value = match[group] ?? "";
      if (value.length === 0) continue;
      if (kind === "private_key" && !hasPrivateKeyBody(value)) {
        kind = "private_key_header";
        // No key material to compare: keep nearby text so distinct headers stay distinct.
        const start = match.index ?? 0;
        value = text.slice(start, start + value.length + 256);
      }
      if (
        kind === "generic_credential" &&
        (!isLikelySecretValue(value) || !isLiteralAssignment(text, match, options))
      )
        continue;
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
