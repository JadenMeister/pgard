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

const SENSITIVE_KEY =
  "[\\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credential|session[_-]?id|auth[_-]?key)[\\w.-]*";

/**
 * Unquoted values exempt from masking: member access or calls (`req.body.password`,
 * `getSecret()`, `process.env.DB_PASSWORD`). Anything else after `password=` / `token:` —
 * including identifier-like words such as `hunter2` — is treated as a secret.
 */
const CODE_REFERENCE = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$|^[A-Za-z_$][\w$.]*\(/;
const ALREADY_REDACTED = /^\[REDACTED:/;

const RULES: Rule[] = [
  {
    pattern:
      /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)/g,
    replace: () => maskSecret("private_key"),
  },
  {
    pattern: /([a-z][a-z0-9+.-]*:\/\/)([^\s:@/]+):([^\s@/]+)@/gi,
    replace: (_m, scheme) => `${scheme}${maskSecret("credentials")}@`,
  },
  {
    pattern: /\b(set-cookie|cookie)(\s*:\s*)[^\n]+/gi,
    replace: (_m, name, sep) => `${name}${sep}${maskSecret("cookie")}`,
  },
  {
    pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    replace: () => maskSecret("aws_access_key_id"),
  },
  {
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b/g,
    replace: () => maskSecret("github_token"),
  },
  {
    pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g,
    replace: () => maskSecret("slack_token"),
  },
  {
    pattern: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    replace: () => maskSecret("stripe_key"),
  },
  {
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    replace: () => maskSecret("google_api_key"),
  },
  {
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    replace: () => maskSecret("jwt"),
  },
  {
    pattern: /\b(Bearer|Basic|token)(\s+)(?!\[REDACTED)[A-Za-z0-9._~+/=-]{8,}/g,
    replace: (_m, scheme, space) => `${scheme}${space}${maskSecret("token")}`,
  },
  {
    // key = "double quoted" | 'single quoted' | `backtick` (a missing closing quote still
    // masks to end of line) | unquoted run up to whitespace or , ; ) } &
    pattern: new RegExp(
      `(\\b${SENSITIVE_KEY}["']?\\s*[:=]\\s*)(?:"([^"\\n]*)("|$)|'([^'\\n]*)('|$)|\`([^\`\\n]*)(\`|$)|([^\\s"'\`,;)}&]+))`,
      "gim",
    ),
    replace: (match, prefix, dq, dqEnd, sq, sqEnd, bq, bqEnd, bare) => {
      if (dq !== undefined) return dq === "" ? match : `${prefix}"${maskSecret("value")}${dqEnd}`;
      if (sq !== undefined) return sq === "" ? match : `${prefix}'${maskSecret("value")}${sqEnd}`;
      if (bq !== undefined) return bq === "" ? match : `${prefix}\`${maskSecret("value")}${bqEnd}`;
      if (bare === undefined || ALREADY_REDACTED.test(bare) || CODE_REFERENCE.test(bare)) {
        return match;
      }
      return `${prefix}${maskSecret("value")}`;
    },
  },
];

/** Replaces recognizable secret values in free text with `[REDACTED:<kind>]`. */
export function redactSecrets(text: string): string {
  let output = text;
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

const HOME_PATH_PATTERN = /(?:\/(?:Users|home)\/[^\s/'"`]+|[A-Za-z]:\\Users\\[^\s\\'"`]+)/g;
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

/**
 * Prepares analyzer evidence for output: masks secrets, removes the project root and home
 * directories, strips control characters, collapses whitespace and truncates.
 */
export function redactEvidence(evidence: string, options: RedactEvidenceOptions = {}): string {
  let output = redactSecrets(evidence);
  if (options.projectRoot && options.projectRoot.length > 1) {
    output = output.split(options.projectRoot).join(".");
  }
  output = output.replace(HOME_PATH_PATTERN, "~");
  output = output.replace(CONTROL_CHARS, "").replace(/\s+/g, " ").trim();
  const maxLength = options.maxLength ?? 500;
  if (output.length > maxLength) {
    output = `${output.slice(0, Math.max(0, maxLength - 1))}…`;
  }
  return output;
}

/** Applies `redactEvidence` to every free-text field and masks credentials in URLs. */
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
      url: finding.location.url === null ? null : redactSecrets(finding.location.url),
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
