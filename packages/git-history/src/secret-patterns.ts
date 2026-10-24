/**
 * Secret detection for file contents read from Git objects. Matches carry the value only so the
 * caller can compare occurrences in memory; values must never be written to findings.
 */
export type DetectedSecretKind =
  | "private_key"
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
  aws_access_key_id: "AWS access key id",
  aws_secret_access_key: "AWS secret access key",
  github_token: "GitHub token",
  slack_token: "Slack token",
  stripe_key: "Stripe secret key",
  google_api_key: "Google API key",
  generic_credential: "credential assignment",
};

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
    pattern:
      /(?<![A-Za-z0-9])[A-Za-z0-9_.-]{0,40}(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)[A-Za-z0-9_.-]{0,40}["']?[ \t]{0,8}[:=][ \t]{0,8}(["']?)([^\s"'`,;]{8,256})\1/gi,
    group: 2,
  },
];

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

export function detectSecrets(text: string): DetectedSecret[] {
  const lineOfIndex = createLineLookup(text);
  const results: DetectedSecret[] = [];
  const seen = new Set<string>();
  for (const { kind, pattern, group } of PATTERNS) {
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      const value = match[group] ?? "";
      if (value.length === 0) continue;
      if (kind === "generic_credential" && !isLikelySecretValue(value)) continue;
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
