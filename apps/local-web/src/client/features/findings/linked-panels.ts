import type { Finding, FindingCategory, Severity } from "@pgard/findings";
import {
  countBySeverity,
  areaMatcher,
  countByCategory,
  filterFindings,
  partitionFindings,
  splitByContext,
  type AreaRules,
  type FindingFilters,
} from "./filter-findings";

/** What each linked panel shows: every panel is counted with the other panels' filters applied. */
export interface LinkedCounts {
  /** Regular findings before any filter. */
  total: number;
  /** Regular findings that match every active filter, sorted. */
  matched: Finding[];
  /** Severity counts without the severity filter, so the bar still offers the other severities. */
  severity: Record<Severity, number>;
  /** Category counts without the category filter. */
  categories: Array<{ category: FindingCategory; count: number }>;
  /** Findings per coverage area without the area filter. */
  areas: ReadonlyMap<string, number>;
}

/**
 * Cross-filtering as in a dashboard: the clicked panel keeps showing its own distribution (so
 * another value can be picked) but counts only what the other filters leave; every other panel
 * and the table show the findings that match all filters. Regular code only, like the headline
 * counts; test, vendored, suppressed and baseline groups stay separate.
 */
export function buildLinkedCounts(
  findings: readonly Finding[],
  filters: FindingFilters,
  areaRules: AreaRules,
): LinkedCounts {
  const regular = splitByContext(partitionFindings(findings).rest).primary;
  const without = (patch: Partial<FindingFilters>): Finding[] =>
    filterFindings(regular, { ...filters, ...patch }, areaRules);
  const areas = new Map<string, number>();
  const outsideArea = without({ area: null });
  for (const area of areaRules.keys()) {
    const inArea = areaMatcher(area, areaRules);
    areas.set(area, inArea === null ? 0 : outsideArea.filter(inArea).length);
  }
  return {
    total: regular.length,
    matched: filterFindings(regular, filters, areaRules),
    severity: countBySeverity(without({ severity: null })),
    categories: countByCategory(without({ category: null })),
    areas,
  };
}
