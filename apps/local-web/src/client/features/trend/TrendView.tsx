import { useState } from "react";
import type { Severity } from "@pgard/findings";
import type { TrendPointDto, TrendResponse } from "../../../shared/api-types";
import { SEVERITY_ORDER } from "../../components/charts/severity-scale";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { EmptyState } from "../../components/ui/EmptyState";
import { Notice } from "../../components/ui/Notice";
import { Section } from "../../components/ui/Section";
import { useI18n } from "../../i18n/I18nProvider";
import type { FindingFilters } from "../findings/filter-findings";
import { hasActiveFilters } from "../findings/filter-url";
import { ChangeTrendChart, SeverityTrendChart, breakdownText, coverageText } from "./TrendCharts";
import {
  countIncomplete,
  formatDayTime,
  isChangeUncertain,
  isIncomplete,
  type ReadyTrend,
} from "./trend-model";
import { useTrend, type TrendState } from "./use-trend";

/**
 * The view as the app mounts it: reads the saved scans when it opens (each visit reads again, so
 * a scan saved from a terminal meanwhile shows up) and keeps nothing across a project change.
 */
export function TrendPage(props: Omit<TrendViewProps, "state" | "onReload">) {
  const [state, reload] = useTrend();
  return <TrendView {...props} state={state} onReload={reload} />;
}

interface TrendViewProps {
  state: TrendState;
  onReload: () => void;
  /** The shared M8-2 filters; only the severity applies to the trend. */
  filters: FindingFilters;
  onFilter: (patch: Partial<FindingFilters>) => void;
  /** Whether this dashboard has a scan result the Findings view could list. */
  hasCurrentScan: boolean;
  onOpenFindings: () => void;
}

/**
 * The Trend view: this repository's saved CLI scans over time. It says plainly where the data
 * comes from and why there is none when the store is off, the project is not verified, the
 * history is too short or unreadable. It never shows an empty chart.
 */
export function TrendView({
  state,
  onReload,
  filters,
  onFilter,
  hasCurrentScan,
  onOpenFindings,
}: TrendViewProps) {
  const { m } = useI18n();
  return (
    <Section
      title={m.trend.title}
      helpLabel={m.trend.help.label}
      help={m.trend.help.lines.map((line) => (
        <p key={line}>{line}</p>
      ))}
    >
      <p className="trend-source">{m.trend.source}</p>
      <TrendBody
        state={state}
        onReload={onReload}
        filters={filters}
        onFilter={onFilter}
        hasCurrentScan={hasCurrentScan}
        onOpenFindings={onOpenFindings}
      />
    </Section>
  );
}

/** Common reasons for an empty trend, under the reason for this one. */
function EmptyCases({ off = true }: { off?: boolean }) {
  const { m } = useI18n();
  return (
    <div className="trend-cases">
      <p>{m.trend.cases.intro}</p>
      <ol>
        {m.trend.cases.items.slice(0, off ? 3 : 2).map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ol>
    </div>
  );
}

function TrendBody(props: TrendViewProps) {
  const { m } = useI18n();
  const { state, onReload } = props;
  if (state.status === "loading") {
    return (
      <p className="trend-loading" role="status">
        {m.trend.loading}
      </p>
    );
  }
  if (state.status === "failed") {
    return (
      <>
        <Notice tone="error">{m.trend.loadFailed}</Notice>
        <Button onClick={onReload}>{m.trend.reload}</Button>
      </>
    );
  }
  const data: TrendResponse = state.data;
  switch (data.kind) {
    case "disabled":
      return (
        <>
          <Notice tone="info">{m.trend.disabled}</Notice>
          <EmptyCases off={false} />
        </>
      );
    case "unavailable":
      return (
        <>
          <Notice tone={data.why === "unreadable" ? "error" : "info"}>
            {data.why === "not-verified"
              ? m.trend.notVerified
              : data.why === "no-store-dir"
                ? m.trend.noStoreDir
                : m.trend.unreadable}
          </Notice>
          <Button onClick={onReload}>{m.trend.reload}</Button>
        </>
      );
    case "ready":
      return <ReadyTrendView {...props} data={data} />;
  }
}

function SkipNotes({ data }: { data: ReadyTrend }) {
  const { m } = useI18n();
  const notes = [
    data.skipped > 0 ? m.trend.skipped(data.skipped) : null,
    data.newerSkipped > 0 ? m.trend.newerSkipped(data.newerSkipped) : null,
    data.futureSkipped > 0 ? m.trend.futureSkipped(data.futureSkipped) : null,
    data.unread > 0 ? m.trend.unread(data.unread) : null,
  ].filter((note): note is string => note !== null);
  if (notes.length === 0) return null;
  return (
    <ul className="trend-notes">
      {notes.map((note) => (
        <li key={note}>{note}</li>
      ))}
    </ul>
  );
}

function ReadyTrendView({
  data,
  filters,
  onFilter,
  hasCurrentScan,
  onOpenFindings,
}: TrendViewProps & { data: ReadyTrend }) {
  const { m, language } = useI18n();
  const { points } = data;
  const [selectedState, setSelected] = useState<number | null>(null);
  const selected = Math.min(points.length - 1, selectedState ?? points.length - 1);
  if (points.length < 2) {
    return (
      <>
        <Notice tone="info">{m.trend.tooFew(points.length)}</Notice>
        <EmptyCases />
        <SkipNotes data={data} />
        {points.length === 1 && <TrendTable points={points} />}
      </>
    );
  }
  const incomplete = countIncomplete(points);
  const point = points[selected] as TrendPointDto;
  const otherFilters = hasActiveFilters({ ...filters, severity: null });
  const toggleSeverity = (severity: Severity): void =>
    onFilter({ severity: filters.severity === severity ? null : severity });
  return (
    <>
      <SkipNotes data={data} />
      <p className={incomplete > 0 ? "trend-coverage-note is-partial" : "trend-coverage-note"}>
        {incomplete > 0 ? m.trend.partialWarning(incomplete, points.length) : m.trend.allComplete}
      </p>

      <h3 className="trend-subtitle">{m.trend.severityTitle}</h3>
      <ul className="trend-key">
        <li className="trend-key-hatch">{m.trend.legendHatch}</li>
        <li className="trend-key-flag">{m.trend.legendFlag}</li>
      </ul>
      <SeverityTrendChart
        points={points}
        selected={selected}
        onSelect={setSelected}
        highlight={filters.severity}
      />
      <ul className="sev-legend" aria-label={m.trend.legendLabel}>
        {SEVERITY_ORDER.map((severity) => (
          <li key={severity}>
            <button
              type="button"
              className={`sev-chip sev-${severity}`}
              aria-pressed={filters.severity === severity}
              onClick={() => toggleSeverity(severity)}
            >
              {m.severityInline[severity]}
            </button>
          </li>
        ))}
      </ul>
      <p className="trend-hint">{m.trend.legendHint}</p>
      {otherFilters && <p className="trend-hint">{m.trend.otherFilters}</p>}
      {filters.severity !== null && (
        <p className="trend-hint">
          {hasCurrentScan ? (
            <button type="button" className="link-button" onClick={onOpenFindings}>
              {m.trend.showFindings}
            </button>
          ) : (
            m.trend.noCurrentScan
          )}
        </p>
      )}

      <div className="trend-selected" aria-live="off">
        <h4 className="trend-selected-title">
          {m.trend.selectedTitle}: {formatDayTime(point.savedAt, language)}
        </h4>
        <p className="trend-selected-line">
          {m.trend.columns.coverage}: <Badge kind={point.coverage}>{coverageText(point, m)}</Badge>
        </p>
        <p className="trend-selected-line">
          {m.trend.activeLine(point.total, breakdownText(point, m))}
        </p>
        <p className="trend-selected-line">
          {point.change === null
            ? m.trend.noChange
            : m.trend.changeSummary(
                point.change.new,
                point.change.noLongerReported,
                point.change.unchanged,
                point.change.notComparable,
              )}
        </p>
        {isChangeUncertain(points, selected) && (
          <p className="trend-selected-line is-partial">{m.trend.changeUncertainNote}</p>
        )}
        <p className="trend-selected-hint">{m.trend.selectedHint}</p>
      </div>

      <h3 className="trend-subtitle">{m.trend.changeTitle}</h3>
      <ul className="trend-key">
        <li className="trend-key-new">{m.trend.legendNew}</li>
        <li className="trend-key-gone">{m.trend.legendGone}</li>
        <li className="trend-key-hatch">{m.trend.legendUncertain}</li>
      </ul>
      <ChangeTrendChart points={points} />
      <p className="trend-hint">{m.trend.changeNote}</p>
      <p className="trend-hint">{m.trend.changeCountsNote}</p>

      <h3 className="trend-subtitle">{m.trend.tableTitle}</h3>
      <p className="trend-hint">{m.trend.ignoredBaselined}</p>
      <TrendTable points={points} highlight={filters.severity} />
      {points.some((_, index) => isChangeUncertain(points, index)) && (
        <p className="trend-hint">* {m.trend.changeUncertainNote}</p>
      )}
    </>
  );
}

/**
 * The data table behind both charts: every value, as text, for screen readers and for anyone who
 * prefers numbers. One row per saved scan, oldest first.
 */
export function TrendTable({
  points,
  highlight = null,
}: {
  points: readonly TrendPointDto[];
  highlight?: Severity | null;
}) {
  const { m, language } = useI18n();
  const c = m.trend.columns;
  return (
    <div className="trend-table-wrap">
      <table className="table trend-table">
        <caption className="sr-only">{m.trend.tableCaption}</caption>
        <thead>
          <tr>
            <th scope="col">{c.scan}</th>
            <th scope="col">{c.coverage}</th>
            {SEVERITY_ORDER.map((severity) => (
              <th
                scope="col"
                key={severity}
                className={`num${highlight === severity ? " is-highlight" : ""}`}
              >
                {m.severityInline[severity]}
              </th>
            ))}
            <th scope="col" className="num">
              {c.total}
            </th>
            <th scope="col" className="num">
              {c.ignored}
            </th>
            <th scope="col" className="num">
              {c.baselined}
            </th>
            <th scope="col" className="num">
              {c.new}
            </th>
            <th scope="col" className="num">
              {c.gone}
            </th>
            <th scope="col" className="num">
              {c.unchanged}
            </th>
            <th scope="col" className="num">
              {c.notComparable}
            </th>
          </tr>
        </thead>
        <tbody>
          {points.map((point, index) => {
            const dash = "-";
            return (
              <tr key={index} className={isIncomplete(point) ? "is-partial" : undefined}>
                <th scope="row" data-label={c.scan}>
                  {formatDayTime(point.savedAt, language)}
                </th>
                <td data-label={c.coverage}>
                  <Badge kind={point.coverage}>{coverageText(point, m)}</Badge>
                </td>
                {SEVERITY_ORDER.map((severity) => (
                  <td
                    key={severity}
                    className={`num${highlight === severity ? " is-highlight" : ""}`}
                    data-label={m.severityInline[severity]}
                  >
                    {point.severity[severity]}
                  </td>
                ))}
                <td className="num" data-label={c.total}>
                  {point.total}
                </td>
                <td className="num" data-label={c.ignored}>
                  {point.ignored}
                </td>
                <td className="num" data-label={c.baselined}>
                  {point.baselined}
                </td>
                <td className="num" data-label={c.new}>
                  {point.change?.new ?? dash}
                </td>
                <td className="num" data-label={c.gone}>
                  {point.change?.noLongerReported ?? dash}
                  {point.change !== null && isChangeUncertain(points, index) ? " *" : ""}
                </td>
                <td className="num" data-label={c.unchanged}>
                  {point.change?.unchanged ?? dash}
                </td>
                <td className="num" data-label={c.notComparable}>
                  {point.change?.notComparable ?? dash}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
