import type {
  Finding,
  RuleLocale,
  RuleTextCatalog,
  ScanResult,
  ScanScope,
  Severity,
} from "@pgard/findings";

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
 * What covers the panels: the help text, the cancel question, the `/` search input (`filter`) and
 * one finding opened with Enter (`detail`). `reduce` and `renderFrame` each have one switch.
 */
export type Overlay = "none" | "help" | "confirm-cancel" | "filter" | "detail";

/** The list filters. `null` / empty means "not filtering by this". */
export interface Filters {
  readonly severity: Severity | null;
  /** The scan area a finding came from (code, history or web). */
  readonly area: ScanScope | null;
  readonly rule: string | null;
  /** Case-insensitive text searched in the title, rule id and path. */
  readonly text: string;
}

export const NO_FILTERS: Filters = { severity: null, area: null, rule: null, text: "" };

/** Longest search text; more is ignored. */
export const MAX_SEARCH_LENGTH = 80;

/** How the view ended: Esc (`back`) or a confirmed Ctrl+C (`cancel`, exit 130). */
/** `terminated` is SIGTERM: the caller exits 143. */
export type PanelsExit = "back" | "cancel" | "terminated";

export interface PanelsState {
  /** The completed scan, rule texts already in the terminal language. Never mutated. */
  readonly result: ScanResult;
  readonly locale: RuleLocale;
  /** Rule catalog, for the standards links in the detail view. Optional (hand-built results). */
  readonly ruleTexts: RuleTextCatalog | undefined;
  /** Every finding, in the order of the text result (severity first). Never filtered. */
  readonly findings: readonly Finding[];
  readonly filters: Filters;
  /** The findings that pass `filters`, same order. The list shows these; charts use `findings`. */
  readonly visible: readonly Finding[];
  readonly panel: PanelId;
  /** Top line per panel. For `findings` it is the first visible row of the list. */
  readonly scroll: Readonly<Record<PanelId, number>>;
  /** Selected row of the findings list (an index into `visible`). */
  readonly selected: number;
  /** Top line of the help overlay. */
  readonly helpScroll: number;
  /** Top line of the detail overlay. */
  readonly detailScroll: number;
  /** The overlay the cancel question returns to when it is answered "no". */
  readonly cancelFrom: Overlay;
  readonly overlay: Overlay;
  readonly size: Size;
  /** Set when the view should close; the controller reads it after every key. */
  readonly exit: PanelsExit | null;
}
