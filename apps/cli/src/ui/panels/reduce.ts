import type { RuleLocale, RuleTextCatalog, ScanResult } from "@pgard/findings";
import type { Key } from "../../adapters/terminal.js";
import { sortBySeverity } from "../formatters/result-groups.js";
import { applyFilters, areasOf, cycle, rulesOf, SEVERITY_KEYS } from "./filter.js";
import { bodyHeight, isTooSmall, listHeight, panelLength } from "./layout.js";
import {
  MAX_SEARCH_LENGTH,
  NO_FILTERS,
  NO_TREND,
  PANEL_IDS,
  type Filters,
  type PanelId,
  type PanelsState,
  type Size,
  type TrendData,
} from "./types.js";

const SHIFT_TAB = "\u001b[Z";

export function createPanelsState(
  result: ScanResult,
  locale: RuleLocale,
  size: Size,
  ruleTexts?: RuleTextCatalog,
  trend: TrendData = NO_TREND,
): PanelsState {
  const findings = sortBySeverity(result.findings);
  return {
    result,
    locale,
    ruleTexts,
    trend,
    findings,
    filters: NO_FILTERS,
    visible: findings,
    panel: "overview",
    scroll: { overview: 0, charts: 0, coverage: 0, trend: 0, findings: 0 },
    selected: 0,
    helpScroll: 0,
    detailScroll: 0,
    cancelFrom: "none",
    overlay: "none",
    size,
    exit: null,
  };
}

function clamp(value: number, max: number): number {
  return Math.max(0, Math.min(value, max));
}

/** Brings scroll positions and the selection back inside their ranges (after a resize). */
function normalize(state: PanelsState): PanelsState {
  const height = bodyHeight(state.size);
  const listRows = listHeight(state, state.size);
  const scroll = { ...state.scroll };
  for (const id of PANEL_IDS) {
    const length =
      id === "findings"
        ? state.visible.length
        : panelLength({ ...state, panel: id, overlay: "none" }, state.size);
    scroll[id] = clamp(scroll[id], Math.max(0, length - (id === "findings" ? listRows : height)));
  }
  const selected = clamp(state.selected, Math.max(0, state.visible.length - 1));
  if (selected < scroll.findings) scroll.findings = selected;
  if (selected >= scroll.findings + listRows) scroll.findings = selected - listRows + 1;
  const helpLength = panelLength({ ...state, overlay: "help" }, state.size);
  const detailLength = panelLength({ ...state, overlay: "detail" }, state.size);
  return {
    ...state,
    scroll,
    selected,
    helpScroll: clamp(state.helpScroll, Math.max(0, helpLength - height)),
    detailScroll: clamp(state.detailScroll, Math.max(0, detailLength - height)),
  };
}

/** The terminal changed size (SIGWINCH). */
export function resize(state: PanelsState, size: Size): PanelsState {
  return normalize({ ...state, size });
}

function movePanel(state: PanelsState, step: number): PanelsState {
  const index = PANEL_IDS.indexOf(state.panel);
  const next = PANEL_IDS[(index + step + PANEL_IDS.length) % PANEL_IDS.length] as PanelId;
  return { ...state, panel: next };
}

/** Moves the viewport (or, in the findings list, the selection) by `delta` lines. */
function scrollBy(state: PanelsState, delta: number): PanelsState {
  if (state.overlay === "help") {
    return normalize({ ...state, helpScroll: state.helpScroll + delta });
  }
  if (state.overlay === "detail") {
    return normalize({ ...state, detailScroll: state.detailScroll + delta });
  }
  if (state.panel === "findings") {
    return normalize({ ...state, selected: state.selected + delta });
  }
  return normalize({
    ...state,
    scroll: { ...state.scroll, [state.panel]: state.scroll[state.panel] + delta },
  });
}

function scrollTo(state: PanelsState, edge: "start" | "end"): PanelsState {
  const huge = edge === "start" ? -Number.MAX_SAFE_INTEGER : Number.MAX_SAFE_INTEGER;
  if (state.overlay === "help") return normalize({ ...state, helpScroll: huge });
  if (state.overlay === "detail") return normalize({ ...state, detailScroll: huge });
  if (state.panel === "findings") return normalize({ ...state, selected: huge });
  return normalize({ ...state, scroll: { ...state.scroll, [state.panel]: huge } });
}

/**
 * Applies new filters. The selection stays on the same finding when it is still listed, else it
 * goes to the first row.
 */
function refilter(state: PanelsState, filters: Filters): PanelsState {
  const keptId = state.visible[state.selected]?.id;
  const visible = applyFilters(state.findings, filters);
  const index = visible.findIndex((finding) => finding.id === keptId);
  return normalize({
    ...state,
    filters,
    visible,
    selected: Math.max(0, index),
    scroll: { ...state.scroll, findings: 0 },
  });
}

/** Text typed into the `/` search. A control sequence (arrow, Tab, ...) is not text. */
function typedText(key: Key): string | null {
  const sequence = key.sequence;
  if (key.ctrl || sequence === undefined || sequence === "") return null;
  return /^[^\u0000-\u001f\u007f-\u009f]+$/u.test(sequence) ? sequence : null;
}

/** Keys while the `/` input line is open: everything printable is text. */
function reduceSearch(state: PanelsState, key: Key): PanelsState {
  if (key.name === "escape") {
    return { ...refilter(state, { ...state.filters, text: "" }), overlay: "none" };
  }
  if (key.name === "return" || key.name === "enter") return { ...state, overlay: "none" };
  if (key.name === "backspace") {
    const text = Array.from(state.filters.text).slice(0, -1).join("");
    return refilter(state, { ...state.filters, text });
  }
  const typed = typedText(key);
  if (typed === null) return state;
  const text = Array.from(state.filters.text + typed)
    .slice(0, MAX_SEARCH_LENGTH)
    .join("");
  return refilter(state, { ...state.filters, text });
}

/** Keys of the findings list that change what it shows or open a finding. */
function reduceListKey(state: PanelsState, key: Key): PanelsState {
  if (key.name === "return" || key.name === "enter") {
    return state.visible.length === 0 ? state : { ...state, overlay: "detail", detailScroll: 0 };
  }
  const { filters } = state;
  const digit = key.ctrl ? undefined : key.sequence;
  if (digit === "/") return { ...state, overlay: "filter" };
  if (digit !== undefined && /^[1-5]$/.test(digit)) {
    const severity = SEVERITY_KEYS[Number(digit) - 1] ?? null;
    return refilter(state, {
      ...filters,
      severity: filters.severity === severity ? null : severity,
    });
  }
  if (digit === "0") return refilter(state, { ...filters, severity: null });
  switch (key.name) {
    case "s":
      return refilter(state, { ...filters, severity: cycle(SEVERITY_KEYS, filters.severity) });
    case "a":
      return refilter(state, { ...filters, area: cycle(areasOf(state.findings), filters.area) });
    case "r":
      return refilter(state, { ...filters, rule: cycle(rulesOf(state.findings), filters.rule) });
    case "c":
      return refilter(state, NO_FILTERS);
    default:
      return state;
  }
}

/** Ctrl+D is end of input: it leaves the view like Esc. */
function isCtrlD(key: Key): boolean {
  return key.ctrl && key.name === "d";
}

function isCtrlC(key: Key): boolean {
  return key.ctrl && key.name === "c";
}

/**
 * Pure: the state after one key. Unknown keys change nothing. Extension point: M6-5 adds an
 * export key the way `reduceListKey` adds the filter keys.
 */
export function reduce(state: PanelsState, key: Key): PanelsState {
  if (state.exit !== null) return state;
  // Two Esc presses that arrive in one read are two presses, not one.
  if (key.name === "escape" && key.sequence === "\u001b\u001b") {
    const single: Key = { ...key, sequence: "\u001b" };
    return reduce(reduce(state, single), single);
  }
  if (state.overlay === "confirm-cancel") {
    if (key.name === "y" || isCtrlC(key)) return { ...state, exit: "cancel" };
    return { ...state, overlay: state.cancelFrom, cancelFrom: "none" };
  }
  if (isCtrlC(key)) return { ...state, overlay: "confirm-cancel", cancelFrom: state.overlay };
  if (isCtrlD(key)) return { ...state, exit: "back" };
  // The "terminal too small" screen says Esc leaves, whatever is open underneath.
  if (key.name === "escape" && isTooSmall(state.size)) return { ...state, exit: "back" };
  if (state.overlay === "filter") return reduceSearch(state, key);
  const height =
    state.panel === "findings" && state.overlay === "none"
      ? listHeight(state, state.size)
      : bodyHeight(state.size);
  if (key.name === "q") return { ...state, exit: "back" };
  const isHelp = key.sequence === "?";
  if (state.overlay === "help") {
    if (isHelp || key.name === "escape" || key.name === "return" || key.name === "enter") {
      return { ...state, overlay: "none", helpScroll: 0 };
    }
    // Only scrolling reaches the help text; panel switches wait until it is closed.
  } else if (state.overlay === "detail") {
    if (key.name === "escape" || key.name === "return" || key.name === "enter") {
      return { ...state, overlay: "none", detailScroll: 0 };
    }
  } else {
    if (isHelp) return { ...state, overlay: "help", helpScroll: 0 };
    if (key.name === "escape") {
      // On the findings list an active search is cleared first; the next Esc leaves.
      if (state.panel === "findings" && state.filters.text !== "") {
        return refilter(state, { ...state.filters, text: "" });
      }
      return { ...state, exit: "back" };
    }
  }
  switch (key.name) {
    case "up":
    case "k":
      return scrollBy(state, -1);
    case "down":
    case "j":
      return scrollBy(state, 1);
    case "pageup":
      return scrollBy(state, -Math.max(1, height - 1));
    case "pagedown":
      return scrollBy(state, Math.max(1, height - 1));
    case "home":
      return scrollTo(state, "start");
    case "end":
      return scrollTo(state, "end");
  }
  if (state.overlay === "help" || state.overlay === "detail") return state;
  if (state.panel === "findings") {
    const next = reduceListKey(state, key);
    if (next !== state) return next;
  }
  switch (key.name) {
    case "tab":
      return movePanel(state, key.sequence === SHIFT_TAB ? -1 : 1);
    case "right":
      return movePanel(state, 1);
    case "left":
      return movePanel(state, -1);
    default:
      return state;
  }
}
