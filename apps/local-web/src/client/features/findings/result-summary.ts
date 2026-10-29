import type { Coverage, ScanResult } from "@pgard/findings";
import { en } from "../../i18n/en";
import type { Messages } from "../../i18n/types";

export interface CoverageCounts {
  completed: number;
  partial: number;
  notTested: number;
}

/** Requested areas by outcome; areas of scopes that were not selected are left out. */
export function coverageCounts(coverage: readonly Coverage[]): CoverageCounts {
  const counts: CoverageCounts = { completed: 0, partial: 0, notTested: 0 };
  for (const entry of coverage) {
    if (entry.status === "completed") counts.completed += 1;
    else if (entry.status === "partial") counts.partial += 1;
    else if (entry.status === "not_tested") counts.notTested += 1;
  }
  return counts;
}

/**
 * The one-line status of a result: "Completed", "Partial · 2 areas did not finish",
 * "Blocked · no analysis ran", "Failed · an internal error stopped the scan".
 */
export function statusLine(result: ScanResult, m: Messages = en): string {
  const text = m.overview;
  switch (result.overallStatus) {
    case "completed":
      return text.status.completed;
    case "partial": {
      const counts = coverageCounts(result.coverage);
      const unfinished = counts.partial + counts.notTested;
      return unfinished === 0
        ? text.status.partial
        : `${text.status.partial} · ${text.unfinished(unfinished)}`;
    }
    case "blocked":
      return `${text.status.blocked} · ${text.blockedDetail}`;
    case "failed":
      return `${text.status.failed} · ${text.failedDetail}`;
    default:
      return text.status.unknown;
  }
}
