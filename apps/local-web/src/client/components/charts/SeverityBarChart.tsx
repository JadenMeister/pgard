import type { Severity } from "@pgard/findings";
import { SEVERITY_COLOR_VARS, SEVERITY_LABELS, SEVERITY_ORDER } from "./severity-scale";

const ROW_HEIGHT = 30;
const LABEL_WIDTH = 72;
const VALUE_WIDTH = 36;
const WIDTH = 420;
const BAR_HEIGHT = 14;

interface SeverityBarChartProps {
  counts: Record<Severity, number>;
  activeSeverity: Severity | null;
  onSelect: (severity: Severity | null) => void;
}

/** Horizontal bars, one per severity, direct-labeled with counts; click filters the list. */
export function SeverityBarChart({ counts, activeSeverity, onSelect }: SeverityBarChartProps) {
  const maxCount = Math.max(1, ...SEVERITY_ORDER.map((severity) => counts[severity]));
  const barSpace = WIDTH - LABEL_WIDTH - VALUE_WIDTH;
  return (
    <svg
      className="chart"
      viewBox={`0 0 ${WIDTH} ${SEVERITY_ORDER.length * ROW_HEIGHT}`}
      role="img"
      aria-label={`Findings by severity: ${SEVERITY_ORDER.map((s) => `${SEVERITY_LABELS[s]} ${counts[s]}`).join(", ")}`}
    >
      {SEVERITY_ORDER.map((severity, index) => {
        const y = index * ROW_HEIGHT;
        const count = counts[severity];
        const width = count === 0 ? 0 : Math.max(4, Math.round((count / maxCount) * barSpace));
        const isDimmed = activeSeverity !== null && activeSeverity !== severity;
        return (
          <g
            key={severity}
            className={`bar-row${isDimmed ? " is-dimmed" : ""}`}
            onClick={() => onSelect(activeSeverity === severity ? null : severity)}
          >
            <title>{`${SEVERITY_LABELS[severity]}: ${count} finding(s)`}</title>
            {/* Hit target spans the whole row, larger than the bar. */}
            <rect x={0} y={y} width={WIDTH} height={ROW_HEIGHT} className="hit-target" />
            <text x={0} y={y + ROW_HEIGHT / 2 + 4} className="chart-label">
              {SEVERITY_LABELS[severity]}
            </text>
            {width > 0 && (
              <rect
                x={LABEL_WIDTH}
                y={y + (ROW_HEIGHT - BAR_HEIGHT) / 2}
                width={width}
                height={BAR_HEIGHT}
                rx={4}
                fill={SEVERITY_COLOR_VARS[severity]}
              />
            )}
            <text x={LABEL_WIDTH + width + 6} y={y + ROW_HEIGHT / 2 + 4} className="chart-value">
              {count}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
