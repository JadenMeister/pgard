import type { ScanScope } from "@pgard/findings";
import type { ScanProgressDto } from "../../../shared/api-types";

export type ProgressArea = "authorization" | ScanScope;
export type AreaState = "waiting" | "running" | "done" | "failed" | "skipped";

export interface AreaProgress {
  area: ProgressArea;
  state: AreaState;
  /** Pages the web check has visited so far, when it reported any. */
  pagesVisited: number | null;
}

/** The order scan-core runs areas in: the gate first, then the selected scopes. */
const SCOPE_ORDER: readonly ScanScope[] = ["code", "history", "web"];

const STATE_BY_STATUS: Record<string, AreaState> = {
  started: "running",
  completed: "done",
  failed: "failed",
  skipped: "skipped",
};

/** "12 page(s) checked", the text the server writes for web progress. */
const PAGES_PATTERN = /^(\d+) page\(s\) checked$/;

/**
 * Per-area state from the progress events `GET /api/scan` returns (the scan-core `onProgress`
 * events the server already keeps). Areas run one after another, so an area with no event of its
 * own is finished once a later area has started: the server keeps only the latest events, and
 * the early ones may have been dropped.
 */
export function describeScanProgress(
  scopes: readonly ScanScope[],
  events: readonly ScanProgressDto[],
): AreaProgress[] {
  const areas: ProgressArea[] = [
    "authorization",
    ...SCOPE_ORDER.filter((scope) => scopes.includes(scope)),
  ];
  const rows = areas.map((area): AreaProgress => {
    let state: AreaState = "waiting";
    let pagesVisited: number | null = null;
    for (const event of events) {
      if (event.stage !== area) continue;
      state = STATE_BY_STATUS[event.status] ?? state;
      const pages = PAGES_PATTERN.exec(event.message);
      if (pages !== null) pagesVisited = Number(pages[1]);
    }
    return { area, state, pagesVisited };
  });
  // A later area that has started means every earlier one has finished.
  let hasLaterActivity = false;
  for (let index = rows.length - 1; index >= 0; index -= 1) {
    const row = rows[index] as AreaProgress;
    if (hasLaterActivity && (row.state === "waiting" || row.state === "running")) {
      row.state = "done";
    }
    if (row.state !== "waiting") hasLaterActivity = true;
  }
  return rows;
}

/** "0:07", "12:40", "1:02:03". */
export function formatElapsed(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = String(seconds % 60).padStart(2, "0");
  return hours > 0 ? `${hours}:${String(minutes).padStart(2, "0")}:${rest}` : `${minutes}:${rest}`;
}
