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

/** Maximum length of merged evidence (same as the default evidence cap). */
export const MERGED_EVIDENCE_MAX = 500;

function verdictRank(finding: Finding): number {
  return (
    SEVERITY_RANK[finding.severity] * 100 +
    STATUS_RANK[finding.status] * 10 +
    CONFIDENCE_RANK[finding.confidence]
  );
}

/**
 * Joins distinct evidence strings (exact duplicates removed) within `MERGED_EVIDENCE_MAX`.
 * Parts that do not fit are counted, never silently dropped: `… (+2 more)`.
 */
function joinEvidence(parts: string[]): string {
  const distinct = [...new Set(parts)];
  let output = "";
  for (let index = 0; index < distinct.length; index += 1) {
    const part = distinct[index] as string;
    const candidate = output === "" ? part : `${output} | ${part}`;
    const remaining = distinct.length - index - 1;
    const suffix = remaining > 0 ? ` | … (+${remaining} more)` : "";
    if (candidate.length + suffix.length > MERGED_EVIDENCE_MAX) {
      const omitted = distinct.length - index;
      const note = ` | … (+${omitted} more)`;
      if (output === "") {
        return `${part.slice(0, Math.max(0, MERGED_EVIDENCE_MAX - note.length - 1))}…${omitted > 1 ? ` (+${omitted - 1} more)` : ""}`;
      }
      return `${output}${note}`;
    }
    output = candidate;
  }
  return output;
}

/**
 * Merges findings that share an id (same rule, location and cause).
 * - severity/status/confidence come together from the single strongest finding (ranked by
 *   severity, then status, then confidence); they are never combined across findings.
 * - sources and references are unioned (canonical source order), so code+HTTP evidence for one
 *   issue keeps both sources.
 * - distinct evidence strings are joined and capped; omitted parts are counted.
 * First-seen order of ids is kept.
 */
export function mergeFindings(findings: readonly Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const group = groups.get(finding.id);
    if (group) group.push(finding);
    else groups.set(finding.id, [finding]);
  }
  return [...groups.values()].map((group) => {
    const first = group[0] as Finding;
    if (group.length === 1) {
      return { ...first, sources: canonicalSources(first.sources) };
    }
    const strongest = group.reduce((best, candidate) =>
      verdictRank(candidate) > verdictRank(best) ? candidate : best,
    );
    return {
      ...first,
      severity: strongest.severity,
      status: strongest.status,
      confidence: strongest.confidence,
      evidence: joinEvidence(group.map((finding) => finding.evidence)),
      references: {
        cwe: union(...group.map((finding) => finding.references.cwe)),
        owasp: union(...group.map((finding) => finding.references.owasp)),
        cve: union(...group.map((finding) => finding.references.cve)),
        ...(group.some((finding) => finding.references.cert !== undefined)
          ? { cert: union(...group.map((finding) => finding.references.cert ?? [])) }
          : {}),
      },
      sources: canonicalSources(group.flatMap((finding) => finding.sources)),
    };
  });
}

function union(...lists: (readonly string[])[]): string[] {
  return [...new Set(lists.flat())];
}

function canonicalSources(sources: readonly ScanScope[]): ScanScope[] {
  return SCAN_SCOPES.filter((scope) => sources.includes(scope));
}
