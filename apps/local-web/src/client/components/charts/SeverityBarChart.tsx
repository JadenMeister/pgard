import type { Severity } from "@pgard/findings";
import { useI18n } from "../../i18n/I18nProvider";
import { SEVERITY_ORDER, severityClass } from "./severity-scale";

const ROW_HEIGHT = 34;
const LABEL_WIDTH = 74;
const VALUE_WIDTH = 40;
// Close to the rendered width on a phone, so 14-unit text never drops below 13px.
const WIDTH = 300;
const BAR_HEIGHT = 10;

interface SeverityBarChartProps {
  counts: Record<Severity, number>;
  activeSeverity: Severity | null;
  onSelect: (severity: Severity | null) => void;
}

/** Horizontal bars, one per severity, direct-labeled with counts; click filters the list. */
export function SeverityBarChart({ counts, activeSeverity, onSelect }: SeverityBarChartProps) {
  const { m } = useI18n();
  const maxCount = Math.max(1, ...SEVERITY_ORDER.map((severity) => counts[severity]));
  const barSpace = WIDTH - LABEL_WIDTH - VALUE_WIDTH;
  return (
    <svg
      className="chart"
      viewBox={`0 0 ${WIDTH} ${SEVERITY_ORDER.length * ROW_HEIGHT}`}
      role="img"
      aria-label={m.charts.barAria(
        SEVERITY_ORDER.map((s) => `${m.severity[s]} ${counts[s]}`).join(", "),
      )}
    >
      {SEVERITY_ORDER.map((severity, index) => {
        const y = index * ROW_HEIGHT;
        const count = counts[severity];
        const width = count === 0 ? 0 : Math.max(4, Math.round((count / maxCount) * barSpace));
        const isDimmed = activeSeverity !== null && activeSeverity !== severity;
        const barY = y + (ROW_HEIGHT - BAR_HEIGHT) / 2;
        return (
          <g
            key={severity}
            className={`bar-row${isDimmed ? " is-dimmed" : ""}`}
            onClick={() => onSelect(activeSeverity === severity ? null : severity)}
          >
            <title>{m.charts.barTitle(m.severity[severity], count)}</title>
            {/* Hit target spans the whole row, larger than the bar. */}
            <rect x={0} y={y} width={WIDTH} height={ROW_HEIGHT} rx={6} className="hit-target" />
            <text x={0} y={y + ROW_HEIGHT / 2 + 5} className="chart-label">
              {m.severity[severity]}
            </text>
            <rect
              x={LABEL_WIDTH}
              y={barY}
              width={barSpace}
              height={BAR_HEIGHT}
              rx={BAR_HEIGHT / 2}
              className="bar-track"
            />
            {width > 0 && (
              <rect
                x={LABEL_WIDTH}
                y={barY}
                width={width}
                height={BAR_HEIGHT}
                rx={BAR_HEIGHT / 2}
                className={`bar-fill ${severityClass(severity)}`}
              />
            )}
            <text x={WIDTH} y={y + ROW_HEIGHT / 2 + 5} textAnchor="end" className="chart-value">
              {count}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
