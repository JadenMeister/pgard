/** Hard limits for local HTTP checks. They are intentionally not user-configurable in the MVP. */
export const MAX_WEB_PAGES = 20;
export const MAX_CRAWL_DEPTH = 2;
export const MAX_REDIRECTS = 5;
export const REQUEST_TIMEOUT_MS = 5000;
export const PROBE_TIMEOUT_MS = 2000;
export const TOTAL_WEB_BUDGET_MS = 60000;
export const MAX_BODY_BYTES = 1_000_000;
export const MAX_PORT_CANDIDATES = 30;
export const MAX_DISPLAY_TEXT_LENGTH = 200;
export const PORT_DISCOVERY_TIMEOUT_MS = 5000;

/** The only IPv4 address PGARD connects to. */
export const LOOPBACK_IPV4 = "127.0.0.1";
export const LOOPBACK_IPV6 = "::1";

export const USER_AGENT = "pgard (local read-only check)";

/** Origin sent once to see whether the service reflects arbitrary origins with credentials. */
export const CORS_PROBE_ORIGIN = "http://pgard-cors-check.invalid";

/**
 * Origin sent in one extra GET, only when the arbitrary-origin probe found nothing, to see
 * whether the service trusts the literal origin `null` (sandboxed iframes, `file:` pages) with
 * credentials.
 */
export const CORS_NULL_ORIGIN = "null";
