import type { Severity } from "@pgard/findings";
import { useI18n } from "../../i18n/I18nProvider";
import { SEVERITY_ORDER } from "./severity-scale";

interface SeverityBarProps {
  counts: Record<Severity, number>;
  /** The severity the findings list is filtered to, marked pressed in the legend. */
  selected?: Severity | null;
  /** Called with a severity, or `null` when the selected one is chosen again. */
  onSelect: (severity: Severity | null) => void;
}

/**
 * One stacked bar of findings per severity, with the counts in a legend under it. The legend
 * items are toggle buttons (keyboard and screen readers); the bar segments do the same on click
 * for the pointer. The bar is an image whose text alternative lists every count.
 *
 * Drawn in SVG with percentage geometry, so it needs no inline style under the strict CSP.
 */
export function SeverityBar({ counts, selected = null, onSelect }: SeverityBarProps) {
  const { m } = useI18n();
  const total = SEVERITY_ORDER.reduce((sum, severity) => sum + counts[severity], 0);
  const summary = SEVERITY_ORDER.map(
    (severity) => `${counts[severity]} ${m.severityInline[severity]}`,
  ).join(", ");
  const toggle = (severity: Severity): void => onSelect(selected === severity ? null : severity);
  let offset = 0;
  return (
    <div className="sev-bar-block">
      <svg
        className="sev-bar"
        role="img"
        aria-label={m.overview.severityBar(summary)}
        viewBox="0 0 100 10"
        preserveAspectRatio="none"
        width="100%"
        height="10"
      >
        <rect className="sev-bar-track" x="0" y="0" width="100" height="10" />
        {total > 0 &&
          SEVERITY_ORDER.filter((severity) => counts[severity] > 0).map((severity) => {
            const width = (counts[severity] / total) * 100;
            const x = offset;
            offset += width;
            return (
              <rect
                key={severity}
                className={`sev-seg sev-${severity}${selected !== null && selected !== severity ? " is-dimmed" : ""}`}
                x={x}
                y="0"
                width={width}
                height="10"
                onClick={() => toggle(severity)}
              >
                <title>{`${counts[severity]} ${m.severityInline[severity]}`}</title>
              </rect>
            );
          })}
      </svg>
      <ul className="sev-legend" aria-label={m.table.severityFilter}>
        {SEVERITY_ORDER.map((severity) => (
          <li key={severity}>
            <button
              type="button"
              className={`sev-chip sev-${severity}`}
              aria-pressed={selected === severity}
              onClick={() => toggle(severity)}
            >
              <span className="num">{counts[severity]}</span> {m.severityInline[severity]}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
