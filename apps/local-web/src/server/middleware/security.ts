import { timingSafeEqual } from "node:crypto";
import type http from "node:http";
import { SESSION_TOKEN_HEADER } from "../../shared/api-types.js";

export interface RequestCheck {
  isAllowed: boolean;
  status: number;
  code: string;
  message: string;
}

const ALLOWED: RequestCheck = { isAllowed: true, status: 200, code: "ok", message: "" };

function deny(status: number, code: string, message: string): RequestCheck {
  return { isAllowed: false, status, code, message };
}

function single(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? undefined : value;
}

/**
 * DNS-rebinding defence: the Host header must be exactly the address the server printed.
 * `localhost` and any other name are refused.
 */
export function checkHost(request: http.IncomingMessage, port: number): RequestCheck {
  return single(request.headers.host) === `127.0.0.1:${port}`
    ? ALLOWED
    : deny(421, "bad_host", "Unexpected Host header.");
}

/**
 * Cross-origin requests are refused. State-changing API calls must carry our own Origin;
 * reads may omit it (same-origin GET), but a foreign Origin or a cross-site fetch is refused.
 */
export function checkOrigin(
  request: http.IncomingMessage,
  port: number,
  isStateChanging: boolean,
): RequestCheck {
  const origin = single(request.headers.origin);
  const expected = `http://127.0.0.1:${port}`;
  if (origin !== undefined && origin !== expected) {
    return deny(403, "bad_origin", "Cross-origin requests are not allowed.");
  }
  if (isStateChanging && origin !== expected) {
    return deny(403, "missing_origin", "Origin header is required.");
  }
  const fetchSite = single(request.headers["sec-fetch-site"]);
  if (fetchSite !== undefined && fetchSite !== "same-origin" && fetchSite !== "none") {
    return deny(403, "cross_site", "Cross-site requests are not allowed.");
  }
  return ALLOWED;
}

/**
 * Every API call needs the per-session token in a custom header. A custom header cannot be
 * sent cross-origin without a CORS preflight, which this server never approves, so the token
 * also works as CSRF protection.
 */
export function checkSessionToken(request: http.IncomingMessage, token: string): RequestCheck {
  const provided = single(request.headers[SESSION_TOKEN_HEADER]);
  if (provided === undefined) return deny(401, "missing_token", "Session token is required.");
  const expected = Buffer.from(token, "utf8");
  const actual = Buffer.from(provided, "utf8");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    return deny(401, "bad_token", "Session token is invalid.");
  }
  return ALLOWED;
}

/** CSP for the UI: only same-origin scripts/styles, no inline script, no framing. */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

/** Headers on every response, including errors. No CORS headers are ever sent. */
export function applySecurityHeaders(response: http.ServerResponse): void {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Pragma", "no-cache");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);
}
