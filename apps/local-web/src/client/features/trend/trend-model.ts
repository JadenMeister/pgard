import type { Severity } from "@pgard/findings";
import type { TrendPointDto, TrendResponse } from "../../../shared/api-types";
import { LOCALES } from "../../i18n/format";
import type { Language } from "../../i18n/types";

/** Slot width of one scan in the chart's own coordinate system, and the drawn height. */
export const SLOT = 10;
export const CHART_HEIGHT = 100;

/** Stack order from the bottom: the quiet end first, so the loud end sits on top. */
export const STACK_ORDER: readonly Severity[] = ["info", "low", "medium", "high", "critical"];

export type ReadyTrend = Extract<TrendResponse, { kind: "ready" }>;

/** A point whose scan did not cover everything it was asked to check. */
export const isIncomplete = (point: TrendPointDto): boolean => point.coverage !== "completed";

/**
 * The comparison with the earlier scan is only a clean "no longer reported" reading when both
 * scans were complete; otherwise the chart draws it hatched and the text says why.
 */
export function isChangeUncertain(points: readonly TrendPointDto[], index: number): boolean {
  const point = points[index];
  const previous = points[index - 1];
  if (point === undefined || previous === undefined) return false;
  return isIncomplete(point) || isIncomplete(previous);
}

/** The largest stacked total (at least 1, so an all-zero history still draws a baseline). */
export function maxTotal(points: readonly TrendPointDto[]): number {
  return Math.max(1, ...points.map((point) => point.total));
}

/** The largest single change count (new or no longer reported), at least 1. */
export function maxChange(points: readonly TrendPointDto[]): number {
  return Math.max(
    1,
    ...points.map((point) => Math.max(point.change?.new ?? 0, point.change?.noLongerReported ?? 0)),
  );
}

export interface Segment {
  severity: Severity;
  y: number;
  height: number;
}

/** The stacked segments of one bar, bottom first, scaled to `max`. Zero counts draw nothing. */
export function segmentsOf(point: TrendPointDto, max: number): Segment[] {
  let used = 0;
  const segments: Segment[] = [];
  for (const severity of STACK_ORDER) {
    const count = point.severity[severity];
    if (count <= 0) continue;
    const height = (count / max) * CHART_HEIGHT;
    used += height;
    segments.push({ severity, y: CHART_HEIGHT - used, height });
  }
  return segments;
}

/** A calendar date in the dashboard language ("2026. 10. 28." / "10/28/2026"). */
export function formatDay(epochMs: number, language: Language): string {
  return new Date(epochMs).toLocaleDateString(LOCALES[language], {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  });
}

/** Date and time of a scan, to the minute. */
export function formatDayTime(epochMs: number, language: Language): string {
  return new Date(epochMs).toLocaleString(LOCALES[language], {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** How many points did not cover everything. */
export const countIncomplete = (points: readonly TrendPointDto[]): number =>
  points.filter(isIncomplete).length;
