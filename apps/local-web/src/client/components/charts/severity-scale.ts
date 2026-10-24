import type { Severity } from "@pgard/findings";

export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

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
