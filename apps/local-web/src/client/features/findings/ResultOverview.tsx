import { useMemo, type MouseEvent, type ReactNode } from "react";
import { coverageNoteText, type FindingStatus, type ScanResult } from "@pgard/findings";
import type { RuleTextsResponse } from "../../../shared/api-types";
import { SeverityBar } from "../../components/charts/SeverityBar";
import { Badge } from "../../components/ui/Badge";
import { EmptyState } from "../../components/ui/EmptyState";
import { Section } from "../../components/ui/Section";
import { useI18n } from "../../i18n/I18nProvider";
import {
  buildAreaRules,
  buildFindingsView,
  isAreaFilterable,
  EMPTY_FILTERS,
  formatSeverityBreakdown,
  partitionFindings,
  toggleFilter,
  type FindingFilters,
} from "./filter-findings";
import { FilterBar } from "./FilterBar";
import { hasActiveFilters } from "./filter-url";
import { FindingTable } from "./FindingTable";
import { buildLinkedCounts } from "./linked-panels";
import { statusLine } from "./result-summary";
import { localizeFindingText } from "./rule-texts";

const TOP_COUNT = 5;

interface OverviewProps {
  /** Scan progress and scan notices, shown at the top of the summary. */
  lead?: ReactNode;
  /** The authorization and local web service sections, beside the result. */
  aside: ReactNode;
  result: ScanResult | null;
  ruleTexts?: RuleTextsResponse | null;
  /** What to show in the summary when there is no result yet. */
  emptyText: string | null;
  /** The active cross-filters (kept in the address by the app). */
  filters?: FindingFilters;
  /** Changes filters; every linked panel and the table below re-render for the filtered set. */
  onFilter: (patch: Partial<FindingFilters>) => void;
  /** Removes every filter. */
  onClearFilters?: () => void;
  /** Opens the Findings view (it keeps the filters). */
  onOpenFindings?: () => void;
  /** Opens the Coverage view. */
  onCoverage: () => void;
}

/** The status meanings, one short line each, so the counts read without opening any help. */
function StatusMeanings() {
  const { m } = useI18n();
  return (
    <ul className="meaning-list">
      <li>{m.overview.statusMeaning.confirmed}</li>
      <li>{m.overview.statusMeaning.suspected}</li>
      <li>{m.overview.statusMeaning.informational}</li>
    </ul>
  );
}

/**
 * The Overview view: separated panels in a two-column grid on wide screens. Summary (status line,
 * counts, severity bar) beside the per-area coverage, then the top five findings, then the
 * breakdown by category beside authorization and the local web service. One column on phones.
 *
 * The panels are linked filters: a severity chip or bar segment, a coverage area, a category row,
 * and the rule and file of a finding each toggle a filter. All of them read one filter state, so
 * the counts, the lists and the table always describe the same filtered set; the filter bar shows
 * what is active and removes it. Everything is computed here from the result already loaded.
 */
export function ResultOverview({
  lead,
  aside,
  result,
  ruleTexts = null,
  emptyText,
  filters = EMPTY_FILTERS,
  onFilter,
  onClearFilters = () => onFilter(EMPTY_FILTERS),
  onOpenFindings = () => undefined,
  onCoverage,
}: OverviewProps) {
  const { m, language } = useI18n();
  const findings = useMemo(
    () =>
      result === null
        ? []
        : result.findings.map((finding) => localizeFindingText(finding, ruleTexts, language)),
    [result, ruleTexts, language],
  );
  const areaRules = useMemo(
    () => (result === null ? new Map() : buildAreaRules(result.coverage, result.ruleStats)),
    [result],
  );
  const view = useMemo(() => buildFindingsView(findings, EMPTY_FILTERS, m), [findings, m]);
  const linked = useMemo(
    () => buildLinkedCounts(findings, filters, areaRules),
    [findings, filters, areaRules],
  );
  const matched = linked.matched;
  const statusCounts = useMemo(() => {
    const counts: Record<FindingStatus, number> = { confirmed: 0, suspected: 0, informational: 0 };
    for (const finding of matched) counts[finding.status] += 1;
    return counts;
  }, [matched]);
  // The selected category stays in the list (count 0) when the other filters leave none of it.
  const categories =
    filters.category !== null &&
    linked.total > 0 &&
    !linked.categories.some((row) => row.category === filters.category)
      ? [...linked.categories, { category: filters.category, count: 0 }]
      : linked.categories;
  const isBlocked = result?.overallStatus === "blocked";
  const link =
    (action: () => void) =>
    (event: MouseEvent<HTMLAnchorElement>): void => {
      event.preventDefault();
      action();
    };
  const toggle = (patch: Partial<FindingFilters>): void => onFilter(toggleFilter(filters, patch));

  const context =
    result === null
      ? []
      : [
          ...(view.contextNote === "" ? [] : [view.contextNote]),
          ...(result.baseline === undefined
            ? []
            : [
                m.findings.baselineCount(
                  result.baseline.matched,
                  result.baseline.new,
                  formatSeverityBreakdown(partitionFindings(result.findings).baseline, m),
                ),
              ]),
        ];
  // [label, matching the filters, all]: with a filter the tiles read "10 / 240", never a bare
  // filtered number beside unfiltered text.
  const stats: Array<[string, number, number]> = [
    [m.overview.stats.findings, matched.length, view.total],
    [m.overview.stats.confirmed, statusCounts.confirmed, view.statusCounts.confirmed],
    [m.overview.stats.suspected, statusCounts.suspected, view.statusCounts.suspected],
    [m.overview.stats.informational, statusCounts.informational, view.statusCounts.informational],
  ];
  const statusLabels: Record<string, string> = m.status;
  const maxCategory = Math.max(1, ...categories.map((row) => row.count));
  const hasFilters = hasActiveFilters(filters);

  return (
    // Without a result (or with a blocked one) authorization and the web service sit side by side
    // under the summary instead of in a column beside it.
    <div
      className={`overview-grid${result === null ? " is-empty" : ""}${result === null || isBlocked ? " is-flat" : ""}`}
    >
      {result !== null && !isBlocked && (linked.total > 0 || hasFilters) && (
        <div className="span-full">
          <FilterBar
            filters={filters}
            shown={matched.length}
            total={linked.total}
            onRemove={onFilter}
            onClear={onClearFilters}
            showHint={linked.total > 0}
          />
        </div>
      )}
      <Section
        title={m.overview.summaryTitle}
        className={result === null ? "panel span-full" : "panel"}
      >
        {lead}
        {result === null ? (
          emptyText !== null && <p className="muted">{emptyText}</p>
        ) : (
          <>
            <p className={`status-line overall-${result.overallStatus}`}>
              <span className="status-dot" aria-hidden="true" />
              {statusLine(result, m)}
            </p>
            {!isBlocked && (
              <>
                <dl className="stats">
                  {stats.map(([label, value, all]) => (
                    <div key={label} className="stat">
                      <dt>{label}</dt>
                      <dd className="num">
                        {value}
                        {hasFilters && (
                          <>
                            <span className="stat-of" aria-hidden="true">
                              {" "}
                              / {all}
                            </span>
                            <span className="sr-only"> {m.linked.ofTotal(all)}</span>
                          </>
                        )}
                      </dd>
                    </div>
                  ))}
                </dl>
                <StatusMeanings />
                <SeverityBar
                  counts={linked.severity}
                  selected={filters.severity}
                  onSelect={(severity) => onFilter({ severity })}
                />
                {context.length > 0 && (
                  <ul className="context-list">
                    {context.map((entry) => (
                      <li key={entry}>{entry}</li>
                    ))}
                  </ul>
                )}
              </>
            )}
          </>
        )}
      </Section>
      {result !== null && (
        <Section
          title={m.overview.coverageTitle}
          className="panel"
          actions={
            <a href="#coverage" onClick={link(onCoverage)}>
              {m.overview.coverageLink}
            </a>
          }
        >
          <ul className="area-list">
            {result.coverage.map((entry) => {
              const count = linked.areas.get(entry.area) ?? 0;
              const isSelected = filters.area === entry.area;
              const isFilterable = isAreaFilterable(entry.area, areaRules);
              const isDisabled = !isSelected && (!isFilterable || count === 0);
              const areaLabel = !isFilterable
                ? m.linked.areaUndistinguishable(entry.area)
                : count === 0 && !isSelected
                  ? m.linked.areaNone(entry.area)
                  : m.linked.filterArea(entry.area, count);
              return (
                <li key={entry.area}>
                  {isBlocked ? (
                    <code className="area-name">{entry.area}</code>
                  ) : (
                    <button
                      type="button"
                      className="area-pick"
                      aria-pressed={isSelected}
                      // A disabled button leaves the tab order and says why in its name.
                      disabled={isDisabled}
                      aria-label={areaLabel}
                      title={isDisabled ? areaLabel : undefined}
                      onClick={() => toggle({ area: entry.area })}
                    >
                      <code className="area-name">{entry.area}</code>
                      {isFilterable && <span className="num area-count">{count}</span>}
                    </button>
                  )}
                  <Badge kind={entry.status}>{statusLabels[entry.status] ?? entry.status}</Badge>
                  {entry.note !== null && entry.note !== "" && (
                    <span className="area-note" title={coverageNoteText(entry, language) ?? ""}>
                      {coverageNoteText(entry, language)}
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
          <p className="muted small">{m.overview.partialMeaning}</p>
        </Section>
      )}
      {result !== null &&
        !isBlocked &&
        (matched.length > 0 || (hasFilters && linked.total > 0)) && (
          <Section
            title={m.overview.topTitle}
            className="panel span-full"
            actions={
              <a href="#findings" onClick={link(onOpenFindings)}>
                {m.overview.allFindings(matched.length)}
              </a>
            }
          >
            {matched.length === 0 ? (
              <EmptyState title={m.linked.noMatch} />
            ) : (
              <FindingTable
                label={m.overview.topTitle}
                findings={matched.slice(0, TOP_COUNT)}
                ruleTexts={ruleTexts}
                isNew={result.baseline !== undefined}
                linked={{ filters, toggle }}
              />
            )}
          </Section>
        )}
      {result !== null && !isBlocked && (
        <Section title={m.overview.categoryTitle} className="panel">
          {categories.length === 0 ? (
            <p className="muted">{m.overview.categoryEmpty}</p>
          ) : (
            <table className="category-table">
              <caption className="sr-only">{m.overview.categoryTitle}</caption>
              <thead className="sr-only">
                <tr>
                  <th scope="col">{m.table.category}</th>
                  <th scope="col">{m.overview.stats.findings}</th>
                </tr>
              </thead>
              <tbody>
                {categories.map(({ category, count }) => (
                  <tr key={category}>
                    <th scope="row">
                      <button
                        type="button"
                        className="category-pick"
                        aria-pressed={filters.category === category}
                        aria-label={m.linked.filterCategory(m.categories[category], count)}
                        onClick={() => toggle({ category })}
                      >
                        {m.categories[category]}
                      </button>
                    </th>
                    <td className="num">{count}</td>
                    <td className="category-bar-cell" aria-hidden="true">
                      <svg
                        className="category-bar"
                        viewBox="0 0 100 6"
                        preserveAspectRatio="none"
                        width="100%"
                        height="6"
                      >
                        <rect x="0" y="0" width={(count / maxCategory) * 100} height="6" />
                      </svg>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Section>
      )}
      <div className="overview-stack">{aside}</div>
    </div>
  );
}
