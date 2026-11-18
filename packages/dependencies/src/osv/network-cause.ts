/**
 * The reason a download request got no answer, reduced to a fixed whitelist (same list as
 * `@pgard/github-auth`; a test keeps the two equal). Node's `fetch` rejects with
 * `TypeError: fetch failed` and the real code sits in `error.cause.code`. The message and address
 * are never read: a proxy URL may carry credentials.
 */
export const NETWORK_CAUSE_CODES: readonly string[] = [
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "ENOTFOUND",
  "EAI_AGAIN",
  "ECONNREFUSED",
  "ECONNRESET",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "UND_ERR_CONNECT_TIMEOUT",
];

const MAX_CAUSE_DEPTH = 5;

export function networkCauseCode(error: unknown): string | null {
  let current: unknown = error;
  for (let depth = 0; depth < MAX_CAUSE_DEPTH; depth += 1) {
    if (typeof current !== "object" || current === null) return null;
    const record = current as { code?: unknown; errors?: unknown; cause?: unknown };
    if (typeof record.code === "string" && NETWORK_CAUSE_CODES.includes(record.code)) {
      return record.code;
    }
    if (Array.isArray(record.errors)) {
      for (const inner of record.errors.slice(0, 4)) {
        const found = networkCauseCode(inner);
        if (found !== null) return found;
      }
    }
    current = record.cause;
  }
  return null;
}
