import type http from "node:http";
import type { Finding } from "@pgard/findings";
import { buildWebFinding } from "../build-finding.js";
import { CORS_NULL_ORIGIN, CORS_PROBE_ORIGIN } from "../constants.js";
import { WEB_RULES } from "../rules.js";

/**
 * Evaluates the response to a GET sent with `Origin: <probeOrigin>`: `CORS_PROBE_ORIGIN` (an
 * arbitrary origin; its reflection with credentials is the stronger signal) or `CORS_NULL_ORIGIN`
 * (the literal origin `null`, which only the reflect check applies to).
 */
export function checkCors(
  url: string,
  headers: http.IncomingHttpHeaders,
  probeOrigin: string = CORS_PROBE_ORIGIN,
): Finding[] {
  const allowOrigin = headers["access-control-allow-origin"];
  const allowCredentials = headers["access-control-allow-credentials"];
  const hasCredentials =
    typeof allowCredentials === "string" && allowCredentials.trim().toLowerCase() === "true";
  if (!hasCredentials || typeof allowOrigin !== "string") return [];
  const origin = allowOrigin.trim();
  if (probeOrigin === CORS_NULL_ORIGIN) {
    if (origin !== CORS_NULL_ORIGIN) return [];
    return [
      buildWebFinding(
        WEB_RULES.corsReflectedOrigin,
        url,
        "null-origin",
        "A request with Origin: null was answered with Access-Control-Allow-Origin: null and Access-Control-Allow-Credentials: true, so any sandboxed iframe or local file page can read credentialed responses.",
      ),
    ];
  }
  if (origin === probeOrigin) {
    return [
      buildWebFinding(
        WEB_RULES.corsReflectedOrigin,
        url,
        "reflected",
        `A request with an unrelated Origin (${CORS_PROBE_ORIGIN}) was answered with that origin in Access-Control-Allow-Origin and Access-Control-Allow-Credentials: true.`,
      ),
    ];
  }
  if (origin === "*") {
    return [
      buildWebFinding(
        WEB_RULES.corsWildcardWithCredentials,
        url,
        "wildcard",
        "Access-Control-Allow-Origin: * is sent together with Access-Control-Allow-Credentials: true.",
      ),
    ];
  }
  return [];
}
