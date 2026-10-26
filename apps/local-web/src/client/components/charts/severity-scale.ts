import type { Severity } from "@pgard/findings";
import { en } from "../../i18n/en";

export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** English labels; components use the active catalog's `severity` map. */
export const SEVERITY_LABELS: Record<Severity, string> = en.severity;

/**
 * Severity is ordinal, so it uses one hue (blue) from light to dark, validated with the
 * dataviz palette checker (--ordinal) on both surfaces. Colors are CSS variables so dark mode
 * gets its own validated steps; labels and counts always accompany the color.
 */
export const SEVERITY_COLOR_VARS: Record<Severity, string> = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
  info: "var(--severity-info)",
};
