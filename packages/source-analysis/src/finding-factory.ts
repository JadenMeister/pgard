import {
  createFindingFingerprint,
  directCertIdsForPath,
  type CertCause,
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
  /** Set by the analyzer for rules whose direct CERT reference depends on it (PG-PATH-002). */
  certCause?: CertCause;
}

/**
 * The causes of a finding, for the direct CERT references that cover only part of a rule:
 * - PG-CRYPTO-003: the analyzer's own cause of a weak random source is `weak-random:*` (MSC02-J);
 *   weak cipher and fixed IV findings have other causes and get none.
 * - PG-PATH-002: the analyzer sets `certCause` from the source of the path (an archive entry name
 *   is `archive-entry`, IDS04-J); a finding without it is `other-than-archive-entry` (FIO16-J).
 * Nothing is read from the evidence text.
 */
export function certCausesOf(ruleId: string, cause: string, certCause?: CertCause): CertCause[] {
  if (ruleId === "PG-CRYPTO-003") return cause.startsWith("weak-random:") ? ["weak-random"] : [];
  if (ruleId === "PG-PATH-002") return [certCause ?? "other-than-archive-entry"];
  return [];
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
  const cert = directCertIdsForPath(
    rule.metadata.standards,
    raw.path,
    certCausesOf(raw.ruleId, raw.cause, raw.certCause),
  );
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
