import type { Severity } from "@pgard/findings";
import { en } from "../../i18n/en";

export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** English labels; components use the active catalog's `severity` map. */
export const SEVERITY_LABELS: Record<Severity, string> = en.severity;

/**
 * Severity colours are CSS custom properties (`--severity-*` in tokens.css), applied through
 * `sev-<severity>` classes so nothing needs an inline style under the dashboard's CSP. Severity is
 * ordinal: the loud warm end is critical and high, the quiet end low and info. Labels and counts
 * always accompany the colour.
 */
export function severityClass(severity: Severity): string {
  return `sev-${severity}`;
}
