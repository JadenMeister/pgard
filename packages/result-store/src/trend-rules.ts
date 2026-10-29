import { SCHEMA_VERSION, type Finding, type Severity } from "@pgard/findings";

/**
 * Rules shared by every reader of the stored history (the CLI trend panel, the dashboard Trend
 * view) and by retention, so they cannot drift apart.
 */

/** A result written by a newer minor of the schema than this build understands. */
export function isNewerSchemaMinor(sourceVersion: string): boolean {
  const [major = 0, minor = 0] = sourceVersion.split(".").map(Number);
  const [currentMajor = 0, currentMinor = 0] = SCHEMA_VERSION.split(".").map(Number);
  return major > currentMajor || (major === currentMajor && minor > currentMinor);
}

/**
 * A scan dated after `now` (clock skew or tampering) cannot be a real scan yet. The same strict
 * rule retention uses when it prunes, so a file prune treats as future is never shown as history.
 */
export function isFutureDated(savedAtMs: number, nowMs: number): boolean {
  return savedAtMs > nowMs;
}

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export interface FindingStateCounts {
  /** Active findings by severity: not ignored by a suppression and not in the baseline. */
  severity: Record<Severity, number>;
  /** The severity counts added up. */
  total: number;
  /** Findings matched by a `pgard.config.json` suppression. */
  ignored: number;
  /** Findings in the saved baseline (and not ignored). */
  baselined: number;
}

/** The one way history counts findings: active by severity, ignored and baselined apart. */
export function countFindingStates(findings: readonly Finding[]): FindingStateCounts {
  const severity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let ignored = 0;
  let baselined = 0;
  for (const finding of findings) {
    if (finding.suppression !== undefined) ignored += 1;
    else if (finding.inBaseline === true) baselined += 1;
    else if (SEVERITIES.includes(finding.severity)) severity[finding.severity] += 1;
  }
  return {
    severity,
    total: SEVERITIES.reduce((sum, name) => sum + severity[name], 0),
    ignored,
    baselined,
  };
}
