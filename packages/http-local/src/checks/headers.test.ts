import { describe, expect, it } from "vitest";
import { checkSecurityHeaders } from "./headers.js";

const PAGE_URL = "http://127.0.0.1:3000/";

describe("checkSecurityHeaders", () => {
  it("accepts frame-ancestors from a second, comma-joined CSP header", () => {
    const findings = checkSecurityHeaders(PAGE_URL, {
      "content-security-policy": "default-src 'self', frame-ancestors 'none'",
    });
    expect(findings.map((finding) => finding.ruleId)).not.toContain("PG-WEB-002");
  });

  it("accepts X-Frame-Options as clickjacking protection", () => {
    const findings = checkSecurityHeaders(PAGE_URL, { "x-frame-options": "DENY" });
    expect(findings.map((finding) => finding.ruleId)).not.toContain("PG-WEB-002");
  });

  it("flags missing frame protection", () => {
    const findings = checkSecurityHeaders(PAGE_URL, {
      "content-security-policy": "default-src 'self'",
    });
    expect(findings.map((finding) => finding.ruleId)).toContain("PG-WEB-002");
  });
});
