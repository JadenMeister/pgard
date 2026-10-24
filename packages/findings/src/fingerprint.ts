import {
  SCAN_SCOPES,
  type Confidence,
  type Finding,
  type FindingLocation,
  type FindingStatus,
  type ScanScope,
  type Severity,
} from "./contract.js";

const FNV_OFFSET = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;
const MASK_64 = 0xffffffffffffffffn;

function fnv1a64(input: string, seed: bigint): string {
  let hash = FNV_OFFSET ^ seed;
  for (const byte of new TextEncoder().encode(input)) {
    hash ^= BigInt(byte);
    hash = (hash * FNV_PRIME) & MASK_64;
  }
  return hash.toString(16).padStart(16, "0");
}

export interface FingerprintInput {
  ruleId: string;
  location: Pick<FindingLocation, "kind" | "path" | "line" | "url" | "commit">;
  /**
   * Short description of the cause (e.g. `template-literal->pool.query`). Must never contain a
   * secret value: callers pass the secret kind, not the secret.
   */
  cause: string;
}

/**
 * Stable 128-bit (hex) identifier of rule + location + cause. Deterministic across runs and
 * machines so CLI and local web produce identical ids. Non-cryptographic by design; inputs are
 * already non-secret.
 */
export function createFindingFingerprint(input: FingerprintInput): string {
  const { location } = input;
  const canonical = [
    input.ruleId,
    location.kind,
    location.path ?? "",
    location.line ?? "",
    location.url ?? "",
    location.commit ?? "",
    input.cause,
  ].join("\u001f");
  return `${fnv1a64(canonical, 0n)}${fnv1a64(canonical, 0x9e3779b97f4a7c15n)}`;
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};
const CONFIDENCE_RANK: Record<Confidence, number> = { high: 2, medium: 1, low: 0 };
const STATUS_RANK: Record<FindingStatus, number> = {
  confirmed: 2,
  suspected: 1,
  informational: 0,
};

/**
 * Merges findings that share an id (same rule, location and cause). Sources are unioned in
 * canonical order so code+HTTP evidence is preserved; the strongest severity, status and
 * confidence win; distinct evidence strings are joined. First-seen order is kept.
 */
export function mergeFindings(findings: readonly Finding[]): Finding[] {
  const merged = new Map<string, Finding>();
  for (const finding of findings) {
    const existing = merged.get(finding.id);
    if (!existing) {
      merged.set(finding.id, { ...finding, sources: canonicalSources(finding.sources) });
      continue;
    }
    const evidence =
      existing.evidence === finding.evidence || existing.evidence.includes(finding.evidence)
        ? existing.evidence
        : `${existing.evidence} | ${finding.evidence}`;
    merged.set(finding.id, {
      ...existing,
      severity:
        SEVERITY_RANK[finding.severity] > SEVERITY_RANK[existing.severity]
          ? finding.severity
          : existing.severity,
      status:
        STATUS_RANK[finding.status] > STATUS_RANK[existing.status]
          ? finding.status
          : existing.status,
      confidence:
        CONFIDENCE_RANK[finding.confidence] > CONFIDENCE_RANK[existing.confidence]
          ? finding.confidence
          : existing.confidence,
      evidence,
      references: {
        cwe: union(existing.references.cwe, finding.references.cwe),
        owasp: union(existing.references.owasp, finding.references.owasp),
        cve: union(existing.references.cve, finding.references.cve),
      },
      sources: canonicalSources([...existing.sources, ...finding.sources]),
    });
  }
  return [...merged.values()];
}

function union(a: readonly string[], b: readonly string[]): string[] {
  return [...new Set([...a, ...b])];
}

function canonicalSources(sources: readonly ScanScope[]): ScanScope[] {
  return SCAN_SCOPES.filter((scope) => sources.includes(scope));
}
