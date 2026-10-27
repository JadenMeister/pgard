import type { Finding, ScanScope, Severity } from "@pgard/findings";
import type { Filters } from "./types.js";

/** Keys 1 to 5 pick these severities, most severe first. */
export const SEVERITY_KEYS: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
const AREAS: readonly ScanScope[] = ["code", "history", "web"];

export function hasFilters(filters: Filters): boolean {
  return (
    filters.severity !== null ||
    filters.area !== null ||
    filters.rule !== null ||
    filters.text !== ""
  );
}

function matchesText(finding: Finding, needle: string): boolean {
  const place = finding.location.path ?? finding.location.url ?? "";
  return [finding.title, finding.ruleId, place].some((field) =>
    field.toLowerCase().includes(needle),
  );
}

/** The findings that pass every active filter, in their order. Pure. */
export function applyFilters(findings: readonly Finding[], filters: Filters): Finding[] {
  const needle = filters.text.trim().toLowerCase();
  return findings.filter(
    (finding) =>
      (filters.severity === null || finding.severity === filters.severity) &&
      (filters.area === null || finding.sources.includes(filters.area)) &&
      (filters.rule === null || finding.ruleId === filters.rule) &&
      (needle === "" || matchesText(finding, needle)),
  );
}

/** The areas some finding came from, in a fixed order (what the area key cycles through). */
export function areasOf(findings: readonly Finding[]): ScanScope[] {
  return AREAS.filter((area) => findings.some((finding) => finding.sources.includes(area)));
}

/** The rule ids of the findings, in order of first appearance. */
export function rulesOf(findings: readonly Finding[]): string[] {
  return [...new Set(findings.map((finding) => finding.ruleId))];
}

/** The value after `current` in `values`, then `null` (no filter), then the first again. */
export function cycle<T>(values: readonly T[], current: T | null): T | null {
  if (values.length === 0) return null;
  if (current === null) return values[0] ?? null;
  const index = values.indexOf(current);
  return index < 0 ? (values[0] ?? null) : (values[index + 1] ?? null);
}
