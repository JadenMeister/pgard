import { useEffect, useState } from "react";
import type { ScanScope } from "@pgard/findings";
import type { ScanProgressDto } from "../../../shared/api-types";
import { useI18n } from "../../i18n/I18nProvider";
import { describeScanProgress, formatElapsed, type ProgressArea } from "./scan-progress";

/** Seconds since `isRunning` became true, updated every second; 0 while not running. */
export function useElapsedSeconds(isRunning: boolean): number {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (!isRunning) return undefined;
    const startedAt = Date.now();
    setElapsed(0);
    const timer = window.setInterval(
      () => setElapsed(Math.floor((Date.now() - startedAt) / 1000)),
      1000,
    );
    return () => window.clearInterval(timer);
  }, [isRunning]);
  return elapsed;
}

interface ScanProgressProps {
  scopes: readonly ScanScope[];
  events: readonly ScanProgressDto[];
  elapsedSeconds: number;
}

/**
 * What a running scan is doing, per area: the authorization gate, then each selected scope.
 * scan-core reports when an area starts and finishes (and pages for the web check), not how much
 * is left, so the bar is indeterminate. Screen readers hear each area's change once; the elapsed
 * clock is not announced.
 */
export function ScanProgress({ scopes, events, elapsedSeconds }: ScanProgressProps) {
  const { m } = useI18n();
  const text = m.scan.progress;
  const rows = describeScanProgress(scopes, events);
  const areaLabel = (area: ProgressArea): string =>
    area === "authorization" ? text.authorization : m.scan.scopes[area].label;
  const current = [...rows].reverse().find((row) => row.state !== "waiting") ?? rows[0];
  return (
    <section className="scan-progress" aria-labelledby="scan-progress-title" aria-busy="true">
      <div className="scan-progress-head">
        <h3 id="scan-progress-title" className="scan-progress-title">
          {text.title}
        </h3>
        <span className="scan-progress-elapsed">{text.elapsed(formatElapsed(elapsedSeconds))}</span>
      </div>
      <div className="progress-track" aria-hidden="true" />
      <p className="sr-only" role="status" aria-live="polite">
        {current === undefined
          ? ""
          : text.announce(areaLabel(current.area), text.states[current.state])}
      </p>
      <ol className="progress-areas" aria-label={text.areasLabel}>
        {rows.map((row) => (
          <li key={row.area} className={`progress-area state-${row.state}`}>
            <span className="area-marker" aria-hidden="true" />
            <span>
              <span className="progress-area-name">{areaLabel(row.area)}</span>
              {row.pagesVisited === null ? null : (
                <span className="progress-area-detail">{text.pages(row.pagesVisited)}</span>
              )}
            </span>
            <span className="progress-area-state">{text.states[row.state]}</span>
          </li>
        ))}
      </ol>
      <p className="muted small">{text.note}</p>
      <ActivityLog events={events} />
    </section>
  );
}

/** The latest raw progress events (server text, English), collapsed. */
export function ActivityLog({ events }: { events: readonly ScanProgressDto[] }) {
  const { m } = useI18n();
  if (events.length === 0) return null;
  return (
    <details className="activity-log">
      <summary>{m.scan.progress.log}</summary>
      <ol>
        {events.slice(-8).map((event, index) => (
          <li key={`${index}-${event.stage}-${event.status}`}>
            <code>{event.stage}</code> {event.status}
            {event.message ? ` - ${event.message}` : ""}
          </li>
        ))}
      </ol>
    </details>
  );
}
