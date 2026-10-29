import type { KeyboardEvent } from "react";
import type { Severity } from "@pgard/findings";
import type { TrendPointDto } from "../../../shared/api-types";
import { useI18n } from "../../i18n/I18nProvider";
import type { Messages } from "../../i18n/types";
import {
  CHART_HEIGHT,
  formatDay,
  isChangeUncertain,
  isIncomplete,
  maxChange,
  maxTotal,
  segmentsOf,
  SLOT,
} from "./trend-model";
import { SEVERITY_ORDER } from "../../components/charts/severity-scale";

/** Strip under the bars where a scan that did not cover everything is flagged. */
const FLAG_HEIGHT = 6;
const VIEW_HEIGHT = CHART_HEIGHT + FLAG_HEIGHT;

/** The hatch is defined once per chart and referenced by id (an SVG pattern, no inline style). */
function Hatch({ id }: { id: string }) {
  return (
    <defs>
      <pattern
        id={id}
        width="3"
        height="3"
        patternUnits="userSpaceOnUse"
        patternTransform="rotate(45)"
      >
        <line className="trend-hatch-line" x1="0" y1="0" x2="0" y2="3" />
      </pattern>
    </defs>
  );
}

export function coverageText(point: TrendPointDto, m: Messages): string {
  return m.trend.coverageDetail(m.trend.coverageValue[point.coverage], point.incompleteAreas);
}

export function breakdownText(point: TrendPointDto, m: Messages): string {
  return SEVERITY_ORDER.map(
    (severity) => `${point.severity[severity]} ${m.severityInline[severity]}`,
  ).join(", ");
}

interface SeverityChartProps {
  points: readonly TrendPointDto[];
  selected: number;
  onSelect: (index: number) => void;
  /** The severity the shared filter is set to: the other segments are dimmed. */
  highlight: Severity | null;
}

/**
 * Stacked bars of active findings by severity, one bar per saved scan, oldest first. The picture
 * has no text of its own (text inside a stretched SVG would distort): the axis and dates are
 * HTML next to it. Each bar is a keyboard stop (roving tab index, left and right arrows) whose
 * label reads the date, the total, the severity breakdown and the coverage. A scan that did not
 * cover everything is hatched and flagged below the bars, so a lower bar never reads as progress.
 * The data table under the chart holds every value.
 */
export function SeverityTrendChart({ points, selected, onSelect, highlight }: SeverityChartProps) {
  const { m, language } = useI18n();
  const max = maxTotal(points);
  const first = points[0];
  const last = points[points.length - 1];
  const onKeyDown = (event: KeyboardEvent<SVGSVGElement>): void => {
    const step = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    const target =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? points.length - 1
          : Math.min(points.length - 1, Math.max(0, selected + step));
    if (step === 0 && event.key !== "Home" && event.key !== "End") return;
    event.preventDefault();
    onSelect(target);
    const columns = event.currentTarget.querySelectorAll<SVGGElement>("[data-column]");
    columns[target]?.focus();
  };
  return (
    <div className="trend-plot">
      <div className="trend-axis" aria-hidden="true">
        <span className="num">{m.trend.axisMax(max)}</span>
        <span className="num">{m.trend.axisZero}</span>
      </div>
      <div className="trend-canvas">
        <svg
          className="trend-svg"
          viewBox={`0 0 ${points.length * SLOT} ${VIEW_HEIGHT}`}
          preserveAspectRatio="none"
          width="100%"
          height="180"
          role="group"
          aria-label={
            first === undefined || last === undefined
              ? ""
              : m.trend.chartLabel(
                  formatDay(first.savedAt, language),
                  formatDay(last.savedAt, language),
                  points.length,
                )
          }
          onKeyDown={onKeyDown}
        >
          <Hatch id="trend-hatch-severity" />
          <line className="trend-grid" x1="0" x2={points.length * SLOT} y1="0" y2="0" />
          <line
            className="trend-grid"
            x1="0"
            x2={points.length * SLOT}
            y1={CHART_HEIGHT}
            y2={CHART_HEIGHT}
          />
          {points.map((point, index) => {
            const x = index * SLOT;
            const segments = segmentsOf(point, max);
            const top = CHART_HEIGHT - (point.total / max) * CHART_HEIGHT;
            return (
              <g
                key={index}
                data-column=""
                className={`trend-column${index === selected ? " is-selected" : ""}`}
                tabIndex={index === selected ? 0 : -1}
                role="img"
                aria-label={m.trend.columnLabel(
                  formatDay(point.savedAt, language),
                  point.total,
                  breakdownText(point, m),
                  coverageText(point, m),
                )}
                onClick={() => onSelect(index)}
                onFocus={() => onSelect(index)}
              >
                <rect className="trend-hit" x={x} y="0" width={SLOT} height={VIEW_HEIGHT} />
                {point.total === 0 && (
                  <rect
                    className="trend-zero"
                    x={x + 1.5}
                    y={CHART_HEIGHT - 0.8}
                    width={SLOT - 3}
                    height="0.8"
                  />
                )}
                {segments.map((segment) => (
                  <rect
                    key={segment.severity}
                    className={`trend-seg sev-${segment.severity}${highlight !== null && highlight !== segment.severity ? " is-dimmed" : ""}`}
                    x={x + 1.5}
                    y={segment.y}
                    width={SLOT - 3}
                    height={segment.height}
                  />
                ))}
                {isIncomplete(point) && (
                  <>
                    {point.total > 0 && (
                      <rect
                        className="trend-hatch"
                        x={x + 1.5}
                        y={top}
                        width={SLOT - 3}
                        height={CHART_HEIGHT - top}
                        fill="url(#trend-hatch-severity)"
                      />
                    )}
                    <rect
                      className="trend-flag"
                      x={x + 1.5}
                      y={CHART_HEIGHT + 3}
                      width={SLOT - 3}
                      height={FLAG_HEIGHT - 3}
                    />
                  </>
                )}
              </g>
            );
          })}
        </svg>
        <div className="trend-dates" aria-hidden="true">
          <span>{first === undefined ? "" : formatDay(first.savedAt, language)}</span>
          <span>{last === undefined ? "" : formatDay(last.savedAt, language)}</span>
        </div>
      </div>
    </div>
  );
}

/**
 * Paired bars per scan: findings new since the scan before, and findings no longer reported
 * (left and right of each slot). Hatched when either scan of the pair did not cover everything.
 * Decorative next to the table, which holds the numbers, so it is one labelled image.
 */
export function ChangeTrendChart({ points }: { points: readonly TrendPointDto[] }) {
  const { m } = useI18n();
  const max = maxChange(points);
  const half = (SLOT - 3) / 2;
  return (
    <div className="trend-plot">
      <div className="trend-axis" aria-hidden="true">
        <span className="num">{m.trend.axisMax(max)}</span>
        <span className="num">{m.trend.axisZero}</span>
      </div>
      <div className="trend-canvas">
        <svg
          className="trend-svg trend-svg-change"
          viewBox={`0 0 ${points.length * SLOT} ${VIEW_HEIGHT}`}
          preserveAspectRatio="none"
          width="100%"
          height="120"
          role="img"
          aria-label={m.trend.changeChartLabel(Math.max(0, points.length - 1))}
        >
          <Hatch id="trend-hatch-change" />
          <line className="trend-grid" x1="0" x2={points.length * SLOT} y1="0" y2="0" />
          <line
            className="trend-grid"
            x1="0"
            x2={points.length * SLOT}
            y1={CHART_HEIGHT}
            y2={CHART_HEIGHT}
          />
          {points.map((point, index) => {
            if (point.change === null) return null;
            const x = index * SLOT + 1.5;
            const added = (point.change.new / max) * CHART_HEIGHT;
            const gone = (point.change.noLongerReported / max) * CHART_HEIGHT;
            const uncertain = isChangeUncertain(points, index);
            return (
              <g key={index}>
                <rect
                  className="trend-new"
                  x={x}
                  y={CHART_HEIGHT - added}
                  width={half}
                  height={added}
                />
                <rect
                  className="trend-gone"
                  x={x + half}
                  y={CHART_HEIGHT - gone}
                  width={half}
                  height={gone}
                />
                {uncertain && (
                  <>
                    <rect
                      className="trend-hatch"
                      x={x}
                      y={CHART_HEIGHT - added}
                      width={half}
                      height={added}
                      fill="url(#trend-hatch-change)"
                    />
                    <rect
                      className="trend-hatch"
                      x={x + half}
                      y={CHART_HEIGHT - gone}
                      width={half}
                      height={gone}
                      fill="url(#trend-hatch-change)"
                    />
                    <rect
                      className="trend-flag"
                      x={x}
                      y={CHART_HEIGHT + 3}
                      width={SLOT - 3}
                      height={FLAG_HEIGHT - 3}
                    />
                  </>
                )}
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
