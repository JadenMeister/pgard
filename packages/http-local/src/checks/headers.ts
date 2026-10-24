import type http from "node:http";
import type { Finding } from "@pgard/findings";
import { buildWebFinding } from "../build-finding.js";
import { sanitizeDisplayText } from "../display-text.js";
import { WEB_RULES } from "../rules.js";

function readHeader(headers: http.IncomingHttpHeaders, name: string): string | null {
  const value = headers[name];
  if (value === undefined) return null;
  return Array.isArray(value) ? value.join(", ") : value;
}

/**
 * Security header checks for one HTML response (normally `/`). HSTS is intentionally not checked:
 * it does not apply to plain-http loopback and is recorded in coverage instead.
 */
export function checkSecurityHeaders(url: string, headers: http.IncomingHttpHeaders): Finding[] {
  const findings: Finding[] = [];
  const csp = readHeader(headers, "content-security-policy");
  if (csp === null || csp.trim() === "") {
    findings.push(
      buildWebFinding(
        WEB_RULES.missingCsp,
        url,
        "missing",
        "Response has no Content-Security-Policy header.",
      ),
    );
  }
  const hasFrameAncestors = csp !== null && /(^|;)\s*frame-ancestors\s/i.test(csp);
  const frameOptions = readHeader(headers, "x-frame-options");
  const hasFrameOptions = frameOptions !== null && /^\s*(deny|sameorigin)\s*$/i.test(frameOptions);
  if (!hasFrameAncestors && !hasFrameOptions) {
    findings.push(
      buildWebFinding(
        WEB_RULES.missingFrameProtection,
        url,
        "missing",
        "Neither CSP frame-ancestors nor X-Frame-Options (DENY/SAMEORIGIN) is set.",
      ),
    );
  }
  const noSniff = readHeader(headers, "x-content-type-options");
  if (noSniff === null || noSniff.trim().toLowerCase() !== "nosniff") {
    findings.push(
      buildWebFinding(
        WEB_RULES.missingNoSniff,
        url,
        "missing",
        "X-Content-Type-Options is not set to nosniff.",
      ),
    );
  }
  if (readHeader(headers, "referrer-policy") === null) {
    findings.push(
      buildWebFinding(
        WEB_RULES.missingReferrerPolicy,
        url,
        "missing",
        "Response has no Referrer-Policy header.",
      ),
    );
  }
  return findings;
}

const VERSION_PATTERN = /\d+\.\d+/;

/** Reports `Server` / `X-Powered-By` values that include a version number. */
export function checkVersionDisclosure(url: string, headers: http.IncomingHttpHeaders): Finding[] {
  const findings: Finding[] = [];
  for (const name of ["server", "x-powered-by"]) {
    const value = readHeader(headers, name);
    if (value !== null && VERSION_PATTERN.test(value)) {
      const shown = sanitizeDisplayText(value, 80);
      findings.push(
        buildWebFinding(
          WEB_RULES.versionDisclosure,
          url,
          name,
          `${name === "server" ? "Server" : "X-Powered-By"} header discloses a version: "${shown}".`,
        ),
      );
    }
  }
  return findings;
}
