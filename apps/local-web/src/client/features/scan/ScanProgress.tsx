import { useEffect, useState } from "react";
import type { ScanScope } from "@pgard/findings";
import type { ScanProgressDto } from "../../../shared/api-types";
import { useI18n } from "../../i18n/I18nProvider";
import {
  describeScanProgress,
  formatElapsed,
  type AreaState,
  type ProgressArea,
} from "./scan-progress";

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
  /** The scan was cancelled or failed: the areas stay visible, frozen where it stopped. */
  isStopped?: boolean;
}

/**
 * What a scan is doing, per area: the authorization gate, then each selected scope. scan-core
 * reports when an area starts and finishes (and pages for the web check), not how much is left,
 * so the bar is indeterminate. Screen readers hear the current area's change once; the elapsed
 * clock is not announced. After a cancel or failure the same list stays, with the area that was
 * running marked as stopped and the activity log open.
 */
export function ScanProgress({
  scopes,
  events,
  elapsedSeconds,
  isStopped = false,
}: ScanProgressProps) {
  const { m } = useI18n();
  const text = m.scan.progress;
  const rows = describeScanProgress(scopes, events);
  const areaLabel = (area: ProgressArea): string =>
    area === "authorization" ? text.authorization : m.scan.scopes[area].label;
  const isFrozen = (state: AreaState): boolean => isStopped && state === "running";
  const stateLabel = (state: AreaState): string =>
    isFrozen(state) ? text.states.stopped : text.states[state];
  const current = [...rows].reverse().find((row) => row.state !== "waiting") ?? rows[0];
  return (
    <section className="scan-progress" aria-labelledby="scan-progress-title">
      <div className="scan-progress-head">
        <h3 id="scan-progress-title" className="scan-progress-title">
          {isStopped ? text.stoppedTitle : text.title}
        </h3>
        {isStopped ? null : (
          <span className="scan-progress-elapsed">
            {text.elapsed(formatElapsed(elapsedSeconds))}
          </span>
        )}
      </div>
      {isStopped ? null : <div className="progress-track" aria-hidden="true" />}
      <p className="sr-only" role="status" aria-live="polite">
        {current === undefined
          ? ""
          : text.announce(areaLabel(current.area), stateLabel(current.state))}
      </p>
      <ol className="progress-areas" aria-label={text.areasLabel}>
        {rows.map((row) => (
          <li
            key={row.area}
            className={`progress-area state-${isFrozen(row.state) ? "stopped" : row.state}`}
          >
            <span className="area-marker" aria-hidden="true" />
            <span>
              <span className="progress-area-name">{areaLabel(row.area)}</span>
              {row.pagesVisited === null ? null : (
                <span className="progress-area-detail">{text.pages(row.pagesVisited)}</span>
              )}
            </span>
            <span className="progress-area-state">{stateLabel(row.state)}</span>
          </li>
        ))}
      </ol>
      <p className="muted small">{text.note}</p>
      <ActivityLog events={events} isOpen={isStopped} />
    </section>
  );
}

/** The latest raw progress events (server text, English); open after a cancel or failure. */
export function ActivityLog({
  events,
  isOpen = false,
}: {
  events: readonly ScanProgressDto[];
  isOpen?: boolean;
}) {
  const { m } = useI18n();
  if (events.length === 0) return null;
  return (
    <details className="activity-log" open={isOpen}>
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
