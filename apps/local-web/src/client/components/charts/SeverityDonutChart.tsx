import type { Severity } from "@pgard/findings";
import { useI18n } from "../../i18n/I18nProvider";
import { SEVERITY_COLOR_VARS, SEVERITY_ORDER } from "./severity-scale";

const SIZE = 180;
const RADIUS = 70;
const STROKE = 22;
const GAP_RADIANS = 0.02;

interface SeverityDonutChartProps {
  counts: Record<Severity, number>;
}

function arcPath(startAngle: number, endAngle: number): string {
  const center = SIZE / 2;
  const start = {
    x: center + RADIUS * Math.sin(startAngle),
    y: center - RADIUS * Math.cos(startAngle),
  };
  const end = { x: center + RADIUS * Math.sin(endAngle), y: center - RADIUS * Math.cos(endAngle) };
  const isLargeArc = endAngle - startAngle > Math.PI ? 1 : 0;
  return `M ${start.x} ${start.y} A ${RADIUS} ${RADIUS} 0 ${isLargeArc} 1 ${end.x} ${end.y}`;
}

/** Share of findings per severity with the total in the middle and a labeled legend. */
export function SeverityDonutChart({ counts }: SeverityDonutChartProps) {
  const { m } = useI18n();
  const total = SEVERITY_ORDER.reduce((sum, severity) => sum + counts[severity], 0);
  const present = SEVERITY_ORDER.filter((severity) => counts[severity] > 0);
  let angle = 0;
  return (
    <figure className="donut">
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} role="img" aria-label={m.charts.donutAria(total)}>
        {total === 0 ? (
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={RADIUS}
            className="donut-empty"
            strokeWidth={STROKE}
            fill="none"
          />
        ) : present.length === 1 ? (
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={RADIUS}
            fill="none"
            strokeWidth={STROKE}
            stroke={SEVERITY_COLOR_VARS[present[0] as Severity]}
          >
            <title>{m.charts.donutSingleTitle(m.severity[present[0] as Severity], total)}</title>
          </circle>
        ) : (
          present.map((severity) => {
            const sweep = (counts[severity] / total) * Math.PI * 2;
            const start = angle + GAP_RADIANS;
            const end = angle + sweep - GAP_RADIANS;
            angle += sweep;
            return (
              <path
                key={severity}
                d={arcPath(start, Math.max(start, end))}
                fill="none"
                strokeWidth={STROKE}
                stroke={SEVERITY_COLOR_VARS[severity]}
              >
                <title>{m.charts.donutTitle(m.severity[severity], counts[severity], total)}</title>
              </path>
            );
          })
        )}
        <text x={SIZE / 2} y={SIZE / 2 - 2} textAnchor="middle" className="donut-total">
          {total}
        </text>
        <text x={SIZE / 2} y={SIZE / 2 + 18} textAnchor="middle" className="chart-label">
          {m.charts.findings}
        </text>
      </svg>
      <figcaption>
        <ul className="legend">
          {SEVERITY_ORDER.map((severity) => (
            <li key={severity}>
              <span
                className="swatch"
                style={{ background: SEVERITY_COLOR_VARS[severity] }}
                aria-hidden="true"
              />
              {m.severity[severity]} <span className="muted">{counts[severity]}</span>
            </li>
          ))}
        </ul>
      </figcaption>
    </figure>
  );
}
