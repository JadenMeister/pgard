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
}

/**
 * The cause of a finding, for the direct CERT references that cover only part of a rule. It is read
 * from the evidence text that the analyzers build, which starts with the kind of source or sink:
 * - PG-CRYPTO-003 "non-cryptographic random ..." is a weak random source (MSC02-J). Fixed IVs and
 *   weak or ECB ciphers have other evidence and get no MSC02-J.
 * - PG-PATH-002 "archive entry name ..." is a zip slip (IDS04-J); every other path finding is
 *   not (FIO16-J). Evidence of a tainted path always starts with the source label.
 * The corpus check (tests/corpus) and `finding-factory.test.ts` pin both.
 */
export function certCausesOf(ruleId: string, evidence: string): CertCause[] {
  if (ruleId === "PG-CRYPTO-003") {
    return evidence.startsWith("non-cryptographic random") ? ["weak-random"] : [];
  }
  if (ruleId === "PG-PATH-002") {
    return evidence.startsWith("archive entry name")
      ? ["archive-entry"]
      : ["other-than-archive-entry"];
  }
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
    certCausesOf(raw.ruleId, raw.evidence),
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
