/**
 * Why a request never got an answer, reduced to a fixed whitelist. Node's `fetch` rejects with
 * `TypeError: fetch failed` and the real reason (`ENOTFOUND`, `UNABLE_TO_VERIFY_LEAF_SIGNATURE`,
 * ...) sits in `error.cause.code`. Only a code from this list is ever kept or printed; the error's
 * message, address and URL (which can name a proxy with credentials) are never read.
 */
export const TLS_CAUSE_CODES = [
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "ERR_TLS_CERT_ALTNAME_INVALID",
] as const;

export const CONNECTION_CAUSE_CODES = [
  "ENOTFOUND",
  "EAI_AGAIN",
  "ECONNREFUSED",
  "ECONNRESET",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "UND_ERR_CONNECT_TIMEOUT",
] as const;

export type NetworkCauseCode =
  (typeof TLS_CAUSE_CODES)[number] | (typeof CONNECTION_CAUSE_CODES)[number];

const KNOWN: ReadonlySet<string> = new Set<string>([...TLS_CAUSE_CODES, ...CONNECTION_CAUSE_CODES]);
const MAX_CAUSE_DEPTH = 5;

function knownCode(value: unknown): NetworkCauseCode | null {
  return typeof value === "string" && KNOWN.has(value) ? (value as NetworkCauseCode) : null;
}

const MAX_NODES = 16;

function search(
  value: unknown,
  depthLeft: number,
  budget: { nodes: number },
): NetworkCauseCode | null {
  let current: unknown = value;
  for (let depth = depthLeft; depth > 0; depth -= 1) {
    if (typeof current !== "object" || current === null) return null;
    budget.nodes -= 1;
    if (budget.nodes < 0) return null;
    const record = current as { code?: unknown; errors?: unknown; cause?: unknown };
    const own = knownCode(record.code);
    if (own !== null) return own;
    // `AggregateError` (several addresses tried) holds the individual failures.
    if (Array.isArray(record.errors)) {
      for (const inner of record.errors.slice(0, 4)) {
        const found = search(inner, depth - 1, budget);
        if (found !== null) return found;
      }
    }
    current = record.cause;
  }
  return null;
}

/**
 * The whitelisted cause code of a failed request, or `null` when there is none or it is unknown.
 * Bounded (depth and node count) and never throws, even for a self-containing `AggregateError`,
 * a throwing getter or a Proxy.
 */
export function networkCauseCode(error: unknown): NetworkCauseCode | null {
  const budget = { nodes: MAX_NODES };
  try {
    return search(error, MAX_CAUSE_DEPTH, budget);
  } catch {
    // A hostile error (throwing getter, Proxy trap) must never break the caller.
    return null;
  }
}

/** `tls`: a certificate problem (often a TLS-inspecting proxy); `network`: offline, DNS or proxy. */
export type NetworkHintKind = "tls" | "network";

export function networkHintKind(code: string | null): NetworkHintKind {
  return code !== null && (TLS_CAUSE_CODES as readonly string[]).includes(code) ? "tls" : "network";
}

/** ` (ENOTFOUND)` for a known code, otherwise the empty string. */
export function causeSuffix(code: NetworkCauseCode | null): string {
  return code === null ? "" : ` (${code})`;
}

/**
 * The fixed English hint. `codeOnly` adds the pointer to `pgard scan code --code-only` (for sign-in
 * and authorization failures; an advisories download failure has nothing to do with it).
 */
export function networkHintEnglish(code: string | null, options: { codeOnly: boolean }): string {
  const fix =
    networkHintKind(code) === "tls"
      ? "A proxy that inspects TLS may be in the way: set NODE_EXTRA_CA_CERTS=<path to your company CA file> and try again."
      : "Check your internet connection. Behind a proxy, set HTTPS_PROXY and NODE_USE_ENV_PROXY=1 (Node 24 and newer).";
  return options.codeOnly
    ? `${fix} To scan without GitHub, use \`pgard scan code --code-only\`.`
    : fix;
}
