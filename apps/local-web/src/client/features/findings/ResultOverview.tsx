import { useMemo, type MouseEvent, type ReactNode } from "react";
import type { ScanResult } from "@pgard/findings";
import type { RuleTextsResponse } from "../../../shared/api-types";
import { SeverityBar } from "../../components/charts/SeverityBar";
import { Badge } from "../../components/ui/Badge";
import { Section } from "../../components/ui/Section";
import { useI18n } from "../../i18n/I18nProvider";
import {
  buildFindingsView,
  countByCategory,
  EMPTY_FILTERS,
  formatSeverityBreakdown,
  partitionFindings,
  type FindingFilters,
} from "./filter-findings";
import { FindingTable } from "./FindingTable";
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
  /** Opens the Findings view filtered by a severity or a category. */
  onFilter: (patch: Partial<FindingFilters>) => void;
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
 */
export function ResultOverview({
  lead,
  aside,
  result,
  ruleTexts = null,
  emptyText,
  onFilter,
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
  const view = useMemo(() => buildFindingsView(findings, EMPTY_FILTERS, m), [findings, m]);
  const categories = useMemo(() => countByCategory(view.visible), [view.visible]);
  const isBlocked = result?.overallStatus === "blocked";
  const link =
    (action: () => void) =>
    (event: MouseEvent<HTMLAnchorElement>): void => {
      event.preventDefault();
      action();
    };

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
  const stats: Array<[string, number]> = [
    [m.overview.stats.findings, view.total],
    [m.overview.stats.confirmed, view.statusCounts.confirmed],
    [m.overview.stats.suspected, view.statusCounts.suspected],
    [m.overview.stats.informational, view.statusCounts.informational],
  ];
  const statusLabels: Record<string, string> = m.status;

  return (
    // Without a result (or with a blocked one) authorization and the web service sit side by side
    // under the summary instead of in a column beside it.
    <div
      className={`overview-grid${result === null ? " is-empty" : ""}${result === null || isBlocked ? " is-flat" : ""}`}
    >
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
                  {stats.map(([label, value]) => (
                    <div key={label} className="stat">
                      <dt>{label}</dt>
                      <dd className="num">{value}</dd>
                    </div>
                  ))}
                </dl>
                <StatusMeanings />
                <SeverityBar counts={view.counts} onSelect={(severity) => onFilter({ severity })} />
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
            {result.coverage.map((entry) => (
              <li key={entry.area}>
                <code className="area-name">{entry.area}</code>
                <Badge kind={entry.status}>{statusLabels[entry.status] ?? entry.status}</Badge>
                {entry.note !== null && entry.note !== "" && (
                  <span className="area-note" title={entry.note}>
                    {entry.note}
                  </span>
                )}
              </li>
            ))}
          </ul>
          <p className="muted small">{m.overview.partialMeaning}</p>
        </Section>
      )}
      {result !== null && !isBlocked && view.visible.length > 0 && (
        <Section
          title={m.overview.topTitle}
          className="panel span-full"
          actions={
            <a href="#findings" onClick={link(() => onFilter({}))}>
              {m.overview.allFindings(view.total)}
            </a>
          }
        >
          <FindingTable
            label={m.overview.topTitle}
            findings={view.visible.slice(0, TOP_COUNT)}
            ruleTexts={ruleTexts}
            isNew={result.baseline !== undefined}
          />
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
                      <a
                        href="#findings"
                        title={m.overview.categoryLink(count, m.categories[category])}
                        onClick={link(() => onFilter({ category }))}
                      >
                        {m.categories[category]}
                      </a>
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
                        <rect
                          x="0"
                          y="0"
                          width={(count / (categories[0]?.count ?? 1)) * 100}
                          height="6"
                        />
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
