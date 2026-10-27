import type { Finding, RuleLocale, ScanResult } from "@pgard/findings";

/**
 * The panels of the full-screen view, in tab order. M6-4 (trend) adds an id here and a case in
 * `layout.ts`; nothing else enumerates the panels.
 */
export const PANEL_IDS = ["overview", "charts", "coverage", "findings"] as const;
export type PanelId = (typeof PANEL_IDS)[number];

export interface Size {
  columns: number;
  rows: number;
}

/** Below this the view shows only a "terminal too small" message. */
export const MIN_SIZE: Size = { columns: 40, rows: 10 };
/** At or below this many columns the layout is the narrow one (no bars, shorter rows). */
export const NARROW_COLUMNS = 60;
/** Lines around the body: title, tab bar, footer. */
export const CHROME_ROWS = 3;

/**
 * What covers the panels. M6-3 adds `"filter"` (a `/` input line) and `"detail"` (one finding
 * opened with Enter) here; `reduce` and `renderFrame` each have one switch to extend.
 */
export type Overlay = "none" | "help" | "confirm-cancel";

/** How the view ended: Esc (`back`) or a confirmed Ctrl+C (`cancel`, exit 130). */
export type PanelsExit = "back" | "cancel";

export interface PanelsState {
  /** The completed scan, rule texts already in the terminal language. Never mutated. */
  readonly result: ScanResult;
  readonly locale: RuleLocale;
  /** Every finding, in the order of the text result (severity first). M6-3 filters this. */
  readonly findings: readonly Finding[];
  readonly panel: PanelId;
  /** Top line per panel. For `findings` it is the first visible row of the list. */
  readonly scroll: Readonly<Record<PanelId, number>>;
  /** Selected row of the findings list. */
  readonly selected: number;
  /** Top line of the help overlay. */
  readonly helpScroll: number;
  readonly overlay: Overlay;
  readonly size: Size;
  /** Set when the view should close; the controller reads it after every key. */
  readonly exit: PanelsExit | null;
}
