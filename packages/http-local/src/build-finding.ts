import { createHash } from "node:crypto";
import type { Finding } from "@pgard/findings";
import type { WebRule } from "./rules.js";

/**
 * Builds a contract `Finding` for a URL. `cause` must not contain secret values; it is only
 * used for the stable fingerprint together with the rule id and URL.
 */
export function buildWebFinding(
  rule: WebRule,
  url: string,
  cause: string,
  evidence: string,
): Finding {
  const id = createHash("sha256").update(`${rule.id}\n${url}\n${cause}`).digest("hex").slice(0, 32);
  return {
    id,
    ruleId: rule.id,
    title: rule.title,
    category: rule.category,
    severity: rule.severity,
    status: rule.status,
    confidence: rule.confidence,
    location: { kind: "url", path: null, line: null, url, commit: null },
    evidence,
    impact: rule.impact,
    recommendation: rule.recommendation,
    references: {
      cwe: [...rule.references.cwe],
      owasp: [...rule.references.owasp],
      cve: [...rule.references.cve],
    },
    sources: ["web"],
  };
}
