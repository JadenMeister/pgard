/**
 * Redaction helpers. Everything rendered by the CLI, local web or reports passes through these,
 * so secret values, tokens, cookies, credentials in URLs and absolute paths never appear in
 * output. Replacements reveal only the kind of secret — never its length, prefix, or a hash.
 *
 * Pure functions with no Node APIs so the browser bundle may import them.
 */
import type { Finding } from "./contract.js";

export type SecretKind =
  | "private_key"
  | "aws_access_key_id"
  | "github_token"
  | "slack_token"
  | "stripe_key"
  | "google_api_key"
  | "jwt"
  | "api_key"
  | "token"
  | "credentials"
  | "cookie"
  | "value";

export function maskSecret(kind: SecretKind): string {
  return `[REDACTED:${kind}]`;
}

interface Rule {
  pattern: RegExp;
  replace: (match: string, ...groups: string[]) => string;
}

// All quantifiers are bounded so matching stays linear in the input length (no ReDoS).
const SENSITIVE_KEY =
  "[\\w.-]{0,64}(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credential|session[_-]?id|auth[_-]?key)[\\w.-]{0,64}";

/**
 * Unquoted values exempt from masking: references through well-known objects
 * (`process.env.X`, `import.meta.env.X`, `req.body.password`, `this.secret`, `config.db.pwd`,
 * `os.environ["X"]`) and well-formed calls (`getSecret()`, `os.getenv("X")`). Anything else after
 * `password=` / `token:` (including `hunter2`, `foo.bar.baz123`, `abc(def`) is treated as a
 * secret.
 */
const REFERENCE_ROOTS =
  "process\\.env|import\\.meta\\.env|os\\.environ|req|request|res|ctx|context|this|self|config|configuration|settings|options|opts|env|params|props|args|body|input|form|values|state";
const CODE_REFERENCE = new RegExp(
  `^(?:(?:${REFERENCE_ROOTS})(?:\\.[A-Za-z_$][\\w$]*|\\[[^\\]\\s]{1,64}\\])+|[A-Za-z_$][\\w$.]{0,128}\\([^()\\s]{0,128}\\))$`,
);
const ALREADY_REDACTED = /^\[REDACTED:/;
const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF]/g;

/**
 * Index of the `@` that ends URL userinfo in `rest` (the text after `scheme://`), or -1.
 * `user:pa@ss/word@host` -> last `@`; `TOKEN@host` -> first `@` before any `/?#`;
 * `host:8080/x?mail=a@b` and `host/path?mail=a@b` -> -1 (no userinfo).
 */
function findUserinfoEnd(rest: string): number {
  const firstDelimiter = rest.search(/[/?#]/);
  const colon = rest.indexOf(":");
  if (colon > 0 && (firstDelimiter < 0 || colon < firstDelimiter)) {
    const at = rest.lastIndexOf("@");
    if (at <= colon) return -1;
    const password = rest.slice(colon + 1, at);
    if (/^\d{1,5}(?:[/?#]|$)/.test(password) || /[?#]/.test(password)) return -1;
    return at;
  }
  const at = rest.indexOf("@");
  return at > 0 && (firstDelimiter < 0 || at < firstDelimiter) ? at : -1;
}

const RULES: Rule[] = [
  {
    // Complete block, or (without an END line) the base64 body that follows the header.
    pattern:
      /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]{0,8192}?-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----|[A-Za-z0-9+/=\s]{0,8192})/g,
    replace: () => maskSecret("private_key"),
  },
  {
    // URL userinfo: everything up to the last `@` of the authority (passwords may contain
    // `@` or `/`), or a user-only token (`https://TOKEN@host`).
    pattern: /([a-z][a-z0-9+.-]{0,31}:\/\/)([^\s"'<>]{1,2048})/gi,
    replace: (match, scheme, rest) => {
      const at = findUserinfoEnd(rest);
      return at > 0 ? `${scheme}${maskSecret("credentials")}${rest.slice(at)}` : match;
    },
  },
  {
    // `Cookie: ...`, `Set-Cookie: ...`, `{"cookie": "..."}`, `cookie='...'`
    pattern:
      /(["']?)\b(set-cookie|cookie)\1([ \t]{0,8}[:=][ \t]{0,8})(?:"[^"\n]{0,4096}"?|'[^'\n]{0,4096}'?|[^\n]{1,4096})/gi,
    replace: (match, quote, name, sep) => {
      const valueStart = match.slice(
        quote.length * 2 + name.length + sep.length,
        quote.length * 2 + name.length + sep.length + 1,
      );
      const wrap = valueStart === '"' || valueStart === "'" ? valueStart : "";
      return `${quote}${name}${quote}${sep}${wrap}${maskSecret("cookie")}${wrap}`;
    },
  },
  {
    pattern: /(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![A-Za-z0-9])/g,
    replace: () => maskSecret("aws_access_key_id"),
  },
  {
    pattern: /(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})/g,
    replace: () => maskSecret("github_token"),
  },
  {
    pattern: /(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9-]{10,256}/g,
    replace: () => maskSecret("slack_token"),
  },
  {
    pattern: /(?<![A-Za-z0-9])[sr]k_(?:live|test)_[A-Za-z0-9]{16,256}/g,
    replace: () => maskSecret("stripe_key"),
  },
  {
    pattern: /(?<![A-Za-z0-9])sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{20,256}/g,
    replace: () => maskSecret("api_key"),
  },
  {
    pattern: /(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}/g,
    replace: () => maskSecret("google_api_key"),
  },
  {
    pattern:
      /(?<![A-Za-z0-9])eyJ[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}/g,
    replace: () => maskSecret("jwt"),
  },
  {
    // Only token-shaped values (digits or token punctuation), so prose such as
    // "Basic authentication" stays readable.
    pattern:
      /(?<![A-Za-z0-9])(bearer|basic)([ \t]{1,8})(?!\[REDACTED)([A-Za-z0-9._~+/=-]{8,4096})/gi,
    replace: (match, scheme, space, value) =>
      /\d|[._~+/=-]/.test(value) ? `${scheme}${space}${maskSecret("token")}` : match,
  },
  {
    // key = "double quoted" | 'single quoted' | `backtick` (a missing closing quote still
    // masks to end of line) | unquoted run up to whitespace or , ; ) } &
    pattern: new RegExp(
      `(\\b${SENSITIVE_KEY}["']?[ \\t]{0,8}[:=][ \\t]{0,8})(?:"([^"\\n]{0,4096})("|$)?|'([^'\\n]{0,4096})('|$)?|\`([^\`\\n]{0,4096})(\`|$)?|([^\\s"'\`,;}&][^\\s,;}&]{0,4095}))`,
      "gim",
    ),
    replace: (match, prefix, dq, dqEnd, sq, sqEnd, bq, bqEnd, bare) => {
      const end = (value: string | undefined) => value ?? "";
      if (dq !== undefined)
        return dq === "" ? match : `${prefix}"${maskSecret("value")}${end(dqEnd)}`;
      if (sq !== undefined)
        return sq === "" ? match : `${prefix}'${maskSecret("value")}${end(sqEnd)}`;
      if (bq !== undefined)
        return bq === "" ? match : `${prefix}\`${maskSecret("value")}${end(bqEnd)}`;
      if (bare === undefined || ALREADY_REDACTED.test(bare) || CODE_REFERENCE.test(bare)) {
        return match;
      }
      return `${prefix}${maskSecret("value")}`;
    },
  },
];

/** Upper bound for text handed to the redaction rules. */
export const MAX_REDACTION_INPUT = 64 * 1024;

/**
 * Cuts `text` to at most `limit` characters. When cut, the trailing partial word is dropped as
 * well, so a secret straddling the cut can never leave an unmatched fragment behind.
 */
export function capText(text: string, limit: number): string {
  if (text.length <= limit) return text;
  const cut = text.slice(0, limit);
  const lastSpace = cut.search(/\s\S*$/);
  return `${lastSpace > 0 ? cut.slice(0, lastSpace) : ""} …`;
}

/** Replaces recognizable secret values in free text with `[REDACTED:<kind>]`. */
export function redactSecrets(text: string): string {
  // Zero-width characters could otherwise split a token so no pattern matches it.
  let output = capText(text, MAX_REDACTION_INPUT).replace(ZERO_WIDTH, "");
  for (const rule of RULES) {
    output = output.replace(rule.pattern, rule.replace as (substring: string) => string);
  }
  return output;
}

export interface RedactEvidenceOptions {
  /** Absolute project root to replace with `.`. */
  projectRoot?: string;
  /** Maximum output length (default 500 characters). */
  maxLength?: number;
}

export const ABSOLUTE_PATH_MASK = "<absolute-path>";
const HOME_PATH_PATTERN =
  /(?:\/(?:Users|home)\/[^\s/'"`]{1,256}|[A-Za-z]:\\Users\\[^\s\\'"`]{1,256})/g;
const FILE_URL_PATTERN = /\bfile:\/\/[^\s'"`<>?#]{0,2048}/gi;
/**
 * Filesystem-looking absolute paths: POSIX paths under well-known roots (route paths such as
 * `/api/login` are not filesystem paths and stay readable) and Windows drive paths.
 */
const ABSOLUTE_PATH_PATTERN =
  /(?<![\w.~/:\\-])\/(?:Users|home|opt|private|tmp|var|etc|usr|root|mnt|srv|Volumes|nix|proc|sys|dev|run|snap|Library|System|Applications|workspaces?|builds|runner|data)(?=[/\s'"`<>|]|$)[^\s'"`<>|]{0,1024}|(?<![A-Za-z0-9])[A-Za-z]:[\\/](?![\\/])[^\s'"`<>|]{0,1024}/g;
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

/**
 * Removes the project root (-> `.`), home directories (-> `~`) and any other absolute
 * filesystem path (-> `<absolute-path>`), including the path in `file://` URLs.
 */
export function scrubAbsolutePaths(text: string, projectRoot?: string): string {
  let output = text;
  if (projectRoot && projectRoot.length > 1) {
    output = output.split(projectRoot).join(".");
  }
  output = output.replace(FILE_URL_PATTERN, `file://${ABSOLUTE_PATH_MASK}`);
  output = output.replace(HOME_PATH_PATTERN, "~");
  return output.replace(ABSOLUTE_PATH_PATTERN, ABSOLUTE_PATH_MASK);
}

/**
 * Prepares analyzer evidence for output: masks secrets, removes the project root, home
 * directories and other absolute paths, strips control characters, collapses whitespace and
 * truncates.
 */
export function redactEvidence(evidence: string, options: RedactEvidenceOptions = {}): string {
  const maxLength = options.maxLength ?? 500;
  // Cap before redacting: redaction cost is bounded by the output size, not the input size.
  let output = redactSecrets(capText(evidence, Math.max(maxLength * 4, 4096)));
  output = scrubAbsolutePaths(output, options.projectRoot);
  output = output.replace(CONTROL_CHARS, "").replace(/\s+/g, " ").trim();
  if (output.length > maxLength) {
    output = `${output.slice(0, Math.max(0, maxLength - 1))}…`;
  }
  return output;
}

/**
 * Location paths are repository-relative: secrets in file names are masked and an absolute
 * path is dropped (`null`) rather than reported.
 */
function redactLocationPath(locationPath: string | null, projectRoot?: string): string | null {
  if (locationPath === null) return null;
  const masked = scrubAbsolutePaths(redactSecrets(locationPath), projectRoot);
  if (
    masked.startsWith("/") ||
    /^[A-Za-z]:[\\/]/.test(masked) ||
    masked.includes(ABSOLUTE_PATH_MASK)
  ) {
    return null;
  }
  return masked;
}

/**
 * Applies `redactEvidence` to every free-text field, and secret/path redaction to
 * `location.path` and `location.url`.
 */
export function redactFinding(finding: Finding, options: RedactEvidenceOptions = {}): Finding {
  const withRoot = options.projectRoot ? { projectRoot: options.projectRoot } : {};
  return {
    ...finding,
    title: redactEvidence(finding.title, { ...withRoot, maxLength: 200 }),
    evidence: redactEvidence(finding.evidence, {
      ...withRoot,
      maxLength: options.maxLength ?? 500,
    }),
    impact: redactEvidence(finding.impact, { ...withRoot, maxLength: 1000 }),
    recommendation: redactEvidence(finding.recommendation, { ...withRoot, maxLength: 1000 }),
    location: {
      ...finding.location,
      path: redactLocationPath(finding.location.path, options.projectRoot),
      url:
        finding.location.url === null
          ? null
          : scrubAbsolutePaths(redactSecrets(finding.location.url), options.projectRoot),
    },
  };
}

/**
 * Session-scoped labels for secret equality ("the same value appears in 3 commits") without
 * exporting the value or a reversible hash. Values stay in this closure's memory only and the
 * labels (`secret-1`, `secret-2`, ...) carry no information about them.
 */
export function createSessionSecretLabeler(): (value: string) => string {
  const labels = new Map<string, string>();
  return (value) => {
    let label = labels.get(value);
    if (label === undefined) {
      label = `secret-${labels.size + 1}`;
      labels.set(value, label);
    }
    return label;
  };
}
