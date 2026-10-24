import {
  SEVERITIES,
  type Coverage,
  type Finding,
  type OverallStatus,
  type ScanScope,
  type Severity,
} from "./contract.js";

export type SeverityCounts = Record<Severity, number>;

/** Finding counts per severity, always containing every severity key (for charts). */
export function summarizeBySeverity(findings: readonly Finding[]): SeverityCounts {
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0])) as SeverityCounts;
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}

export interface OverallStatusInput {
  decision: "allowed" | "blocked";
  requestedScopes: readonly ScanScope[];
  coverage: readonly Coverage[];
}

/**
 * - blocked authorization ⇒ `blocked`.
 * - any requested scope with `partial`/`not_tested` coverage, or with no coverage entry at all,
 *   ⇒ `partial` (e.g. `scan all` without a confirmed web target).
 * - `not_selected` entries never make a scan partial.
 */
export function deriveOverallStatus(input: OverallStatusInput): OverallStatus {
  if (input.decision !== "allowed") {
    return "blocked";
  }
  for (const scope of input.requestedScopes) {
    const entries = input.coverage.filter((entry) => entry.scope === scope);
    if (entries.length === 0) {
      return "partial";
    }
    if (entries.some((entry) => entry.status === "partial" || entry.status === "not_tested")) {
      return "partial";
    }
    if (entries.every((entry) => entry.status === "not_selected")) {
      return "partial";
    }
  }
  return "completed";
}
