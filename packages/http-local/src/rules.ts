import type {
  Confidence,
  FindingCategory,
  FindingReferences,
  FindingStatus,
  Severity,
} from "@pgard/findings";

export interface WebRule {
  id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  impact: string;
  recommendation: string;
  references: FindingReferences;
}

const MISCONFIGURATION = "A02:2025";

function rule(definition: WebRule): WebRule {
  return definition;
}

/**
 * Anonymous local HTTP rules. A missing header is reported as informational/suspected and never
 * as proof that the service is vulnerable.
 */
export const WEB_RULES = {
  missingCsp: rule({
    id: "PG-WEB-001",
    title: "Content-Security-Policy header is missing",
    category: "misconfiguration",
    severity: "low",
    status: "informational",
    confidence: "high",
    impact:
      "Without a CSP, an XSS flaw elsewhere is easier to exploit. This alone is not a vulnerability.",
    recommendation:
      "Send a Content-Security-Policy that restricts script sources for HTML responses.",
    references: { cwe: ["CWE-693"], owasp: [MISCONFIGURATION], cve: [] },
  }),
  missingFrameProtection: rule({
    id: "PG-WEB-002",
    title: "Clickjacking protection header is missing",
    category: "misconfiguration",
    severity: "low",
    status: "informational",
    confidence: "high",
    impact:
      "Pages may be framed by other sites, which can enable clickjacking on sensitive actions.",
    recommendation: "Send CSP frame-ancestors (or X-Frame-Options: DENY/SAMEORIGIN).",
    references: { cwe: ["CWE-1021"], owasp: [MISCONFIGURATION], cve: [] },
  }),
  missingNoSniff: rule({
    id: "PG-WEB-003",
    title: "X-Content-Type-Options: nosniff is missing",
    category: "misconfiguration",
    severity: "info",
    status: "informational",
    confidence: "high",
    impact: "Browsers may MIME-sniff responses, which can turn uploaded content into script.",
    recommendation: "Send X-Content-Type-Options: nosniff on all responses.",
    references: { cwe: ["CWE-693"], owasp: [MISCONFIGURATION], cve: [] },
  }),
  missingReferrerPolicy: rule({
    id: "PG-WEB-004",
    title: "Referrer-Policy header is missing",
    category: "misconfiguration",
    severity: "info",
    status: "informational",
    confidence: "high",
    impact:
      "Full URLs (possibly with identifiers) may leak to third parties via the Referer header.",
    recommendation: "Send Referrer-Policy: strict-origin-when-cross-origin or stricter.",
    references: { cwe: ["CWE-200"], owasp: [MISCONFIGURATION], cve: [] },
  }),
  cookieWithoutHttpOnly: rule({
    id: "PG-WEB-005",
    title: "Cookie is set without HttpOnly",
    category: "misconfiguration",
    severity: "low",
    status: "suspected",
    confidence: "medium",
    impact: "If the cookie carries a session, script injected through XSS can read it.",
    recommendation: "Set HttpOnly on session and authentication cookies.",
    references: { cwe: ["CWE-1004"], owasp: [MISCONFIGURATION], cve: [] },
  }),
  cookieWithoutSameSite: rule({
    id: "PG-WEB-006",
    title: "Cookie is set without SameSite",
    category: "csrf",
    severity: "low",
    status: "suspected",
    confidence: "medium",
    impact: "Browser defaults vary; without SameSite, cross-site requests may carry the cookie.",
    recommendation: "Set SameSite=Lax or Strict explicitly on session cookies.",
    references: { cwe: ["CWE-1275"], owasp: [MISCONFIGURATION], cve: [] },
  }),
  cookieWithoutSecure: rule({
    id: "PG-WEB-007",
    title: "Cookie is set without Secure",
    category: "misconfiguration",
    severity: "info",
    status: "informational",
    confidence: "medium",
    impact:
      "Expected on plain-http loopback; make sure production (HTTPS) sets Secure so the cookie is never sent over HTTP.",
    recommendation: "Set Secure on cookies in HTTPS deployments.",
    references: { cwe: ["CWE-614"], owasp: [MISCONFIGURATION], cve: [] },
  }),
  corsWildcardWithCredentials: rule({
    id: "PG-WEB-008",
    title: "CORS allows any origin together with credentials",
    category: "misconfiguration",
    severity: "medium",
    status: "suspected",
    confidence: "medium",
    impact:
      "Indicates a permissive CORS setup; combined with origin reflection it can expose user data.",
    recommendation: "Allow only specific trusted origins when credentials are enabled.",
    references: { cwe: ["CWE-942"], owasp: [MISCONFIGURATION], cve: [] },
  }),
  corsReflectedOrigin: rule({
    id: "PG-WEB-009",
    title: "CORS reflects an arbitrary Origin with credentials",
    category: "access_control",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    impact:
      "Any website a logged-in user visits may read authenticated responses from this service.",
    recommendation:
      "Validate Origin against an allowlist; never echo it back with credentials enabled.",
    references: { cwe: ["CWE-942"], owasp: ["A01:2025"], cve: [] },
  }),
  versionDisclosure: rule({
    id: "PG-WEB-010",
    title: "Server software version is disclosed",
    category: "misconfiguration",
    severity: "low",
    status: "confirmed",
    confidence: "high",
    impact: "Exact versions help attackers pick known exploits.",
    recommendation: "Remove version details from Server / X-Powered-By headers.",
    references: { cwe: ["CWE-200"], owasp: [MISCONFIGURATION], cve: [] },
  }),
  directoryListing: rule({
    id: "PG-WEB-011",
    title: "Directory listing is enabled",
    category: "misconfiguration",
    severity: "medium",
    status: "confirmed",
    confidence: "high",
    impact: "File names and unintended files may be browsed and downloaded.",
    recommendation:
      "Disable automatic directory indexes in the web server or static file middleware.",
    references: { cwe: ["CWE-548"], owasp: [MISCONFIGURATION], cve: [] },
  }),
  exposedEnvFile: rule({
    id: "PG-WEB-012",
    title: "A .env file is served over HTTP",
    category: "secret_exposure",
    severity: "high",
    status: "confirmed",
    confidence: "high",
    impact: "Configuration secrets in .env can be downloaded by anyone who can reach the service.",
    recommendation:
      "Stop serving dotfiles, move .env out of the web root, and rotate any exposed secrets.",
    references: { cwe: ["CWE-538"], owasp: [MISCONFIGURATION], cve: [] },
  }),
  exposedGitDirectory: rule({
    id: "PG-WEB-013",
    title: "The .git directory is served over HTTP",
    category: "secret_exposure",
    severity: "high",
    status: "confirmed",
    confidence: "high",
    impact:
      "Source code and history (including past secrets) can be reconstructed from the .git directory.",
    recommendation:
      "Block access to /.git in the web server and keep the repository out of the web root.",
    references: { cwe: ["CWE-538"], owasp: [MISCONFIGURATION], cve: [] },
  }),
} as const satisfies Record<string, WebRule>;

export const WEB_RULE_LIST: readonly WebRule[] = Object.values(WEB_RULES);
export const WEB_RULE_IDS: readonly string[] = WEB_RULE_LIST.map((entry) => entry.id);
