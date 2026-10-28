import {
  createFindingFingerprint,
  directCertIdsForPath,
  redactEvidence,
  type Confidence,
  type Finding,
  type FindingStatus,
  type Severity,
} from "@pgard/findings";
import { getRule, type SourceRuleId } from "./rules.js";

export interface RawSourceFinding {
  ruleId: SourceRuleId;
  /** Repository-relative POSIX path. */
  path: string;
  line: number;
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  /** Short description of the flow, e.g. "request input -> template literal -> pool.query". */
  evidence: string;
  /** Stable, value-free cause used for the fingerprint (e.g. callee name). */
  cause: string;
}

/** Builds a contract `Finding` from rule metadata. Evidence is redacted again here. */
export function createSourceFinding(raw: RawSourceFinding): Finding {
  const rule = getRule(raw.ruleId);
  const location = {
    kind: "file" as const,
    path: raw.path,
    line: raw.line,
    url: null,
    commit: null,
  };
  const cert = directCertIdsForPath(rule.metadata.standards, raw.path);
  return {
    id: createFindingFingerprint({ ruleId: raw.ruleId, location, cause: raw.cause }),
    ruleId: raw.ruleId,
    title: rule.title,
    category: rule.category,
    severity: raw.severity,
    status: raw.status,
    confidence: raw.confidence,
    location,
    evidence: redactEvidence(raw.evidence, { maxLength: 300 }),
    impact: rule.impact,
    recommendation: rule.recommendation,
    references: {
      cwe: [...rule.cwe],
      owasp: [...rule.owasp],
      cve: [],
      ...(cert.length > 0 ? { cert } : {}),
    },
    sources: ["code"],
  };
}
