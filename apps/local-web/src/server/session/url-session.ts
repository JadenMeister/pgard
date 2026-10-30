import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * The single-use URL token and the session secret it is exchanged for (#419, design doc section
 * 12). The URL token printed by the launcher is only an invitation: the page's first call,
 * `POST /api/session/exchange`, spends it and gets a session secret back, which every other API
 * call carries in `x-pgard-session`. Both are held only as SHA-256 hashes in this process's
 * memory (never written, never logged) and compared in constant time.
 */

/** An unused URL token stops working after this long. */
export const URL_TOKEN_TTL_MS = 10 * 60 * 1000;
/** The session secret stops working after this long without an API call. */
export const SESSION_IDLE_MS = 30 * 60 * 1000;
/** Random bytes of a session secret. */
export const SESSION_SECRET_BYTES = 32;

export type ExchangeOutcome =
  | { kind: "ok"; secret: string }
  /** The real URL token, already exchanged (a reused link, another tab). */
  | { kind: "token_used" }
  /** The real URL token, never exchanged, older than `URL_TOKEN_TTL_MS`. */
  | { kind: "token_expired" }
  /** Anything else: the answer never tells a guesser that a token once existed. */
  | { kind: "bad_token" };

export type SessionCheck =
  { kind: "ok" } | { kind: "missing" } | { kind: "invalid" } | { kind: "expired" };

export interface UrlSession {
  exchange(token: unknown, now: number): ExchangeOutcome;
  check(secret: string | undefined, now: number): SessionCheck;
}

export interface UrlSessionDeps {
  /** Constant-time comparison of two equal-length hashes; `crypto.timingSafeEqual`. */
  equal?: (a: Buffer, b: Buffer) => boolean;
  /** A new session secret; 32 random bytes, base64url. */
  newSecret?: () => string;
  /** Test hook: a session that already exists (as if exchanged at `createdAt`). */
  presetSecret?: string;
}

const hash = (value: string): Buffer => createHash("sha256").update(value, "utf8").digest();

/** At most this long; a URL token or secret is 43 characters (32 bytes, base64url). */
const MAX_SECRET_LENGTH = 200;

export function createUrlSession(
  token: string,
  createdAt: number,
  deps: UrlSessionDeps = {},
): UrlSession {
  const equal = deps.equal ?? timingSafeEqual;
  const newSecret =
    deps.newSecret ?? (() => randomBytes(SESSION_SECRET_BYTES).toString("base64url"));
  const tokenHash = hash(token);
  let isTokenUsed = false;
  let session: { hash: Buffer; lastUsedAt: number } | null =
    deps.presetSecret === undefined
      ? null
      : { hash: hash(deps.presetSecret), lastUsedAt: createdAt };
  // Both sides are SHA-256 digests, so they always have the same length.
  const matches = (value: string, expected: Buffer): boolean => equal(hash(value), expected);
  return {
    exchange(candidate, now) {
      if (
        typeof candidate !== "string" ||
        candidate.length === 0 ||
        candidate.length > MAX_SECRET_LENGTH ||
        !matches(candidate, tokenHash)
      ) {
        return { kind: "bad_token" };
      }
      if (isTokenUsed) return { kind: "token_used" };
      if (now - createdAt > URL_TOKEN_TTL_MS) return { kind: "token_expired" };
      isTokenUsed = true;
      const secret = newSecret();
      session = { hash: hash(secret), lastUsedAt: now };
      return { kind: "ok", secret };
    },
    check(secret, now) {
      if (secret === undefined || secret.length === 0) return { kind: "missing" };
      if (session === null || secret.length > MAX_SECRET_LENGTH) return { kind: "invalid" };
      if (!matches(secret, session.hash)) return { kind: "invalid" };
      if (now - session.lastUsedAt > SESSION_IDLE_MS) {
        session = null;
        return { kind: "expired" };
      }
      session.lastUsedAt = now;
      return { kind: "ok" };
    },
  };
}
