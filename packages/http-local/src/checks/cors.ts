import type http from "node:http";
import type { Finding } from "@pgard/findings";
import { buildWebFinding } from "../build-finding.js";
import { CORS_PROBE_ORIGIN } from "../constants.js";
import { WEB_RULES } from "../rules.js";

/**
 * Evaluates the response to a GET sent with `Origin: CORS_PROBE_ORIGIN`.
 * Reflection of that arbitrary origin with credentials is the stronger signal.
 */
export function checkCors(url: string, headers: http.IncomingHttpHeaders): Finding[] {
  const allowOrigin = headers["access-control-allow-origin"];
  const allowCredentials = headers["access-control-allow-credentials"];
  const hasCredentials =
    typeof allowCredentials === "string" && allowCredentials.trim().toLowerCase() === "true";
  if (!hasCredentials || typeof allowOrigin !== "string") return [];
  const origin = allowOrigin.trim();
  if (origin === CORS_PROBE_ORIGIN) {
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
