import type { RuleLocale, ScanResult } from "@pgard/findings";
import type { Key } from "../../adapters/terminal.js";
import { sortBySeverity } from "../formatters/result-groups.js";
import { bodyHeight, panelLength } from "./layout.js";
import { PANEL_IDS, type PanelId, type PanelsState, type Size } from "./types.js";

const SHIFT_TAB = "\u001b[Z";

export function createPanelsState(result: ScanResult, locale: RuleLocale, size: Size): PanelsState {
  return {
    result,
    locale,
    findings: sortBySeverity(result.findings),
    panel: "overview",
    scroll: { overview: 0, charts: 0, coverage: 0, findings: 0 },
    selected: 0,
    helpScroll: 0,
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
  const scroll = { ...state.scroll };
  for (const id of PANEL_IDS) {
    const length =
      id === "findings"
        ? state.findings.length
        : panelLength({ ...state, panel: id, overlay: "none" }, state.size);
    scroll[id] = clamp(scroll[id], Math.max(0, length - height));
  }
  const selected = clamp(state.selected, Math.max(0, state.findings.length - 1));
  if (selected < scroll.findings) scroll.findings = selected;
  if (selected >= scroll.findings + height) scroll.findings = selected - height + 1;
  const helpLength = panelLength({ ...state, overlay: "help" }, state.size);
  return {
    ...state,
    scroll,
    selected,
    helpScroll: clamp(state.helpScroll, Math.max(0, helpLength - height)),
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
  if (state.panel === "findings") return normalize({ ...state, selected: huge });
  return normalize({ ...state, scroll: { ...state.scroll, [state.panel]: huge } });
}

/** Ctrl+D is end of input: it leaves the view like Esc. */
function isCtrlD(key: Key): boolean {
  return key.ctrl && key.name === "d";
}

function isCtrlC(key: Key): boolean {
  return key.ctrl && key.name === "c";
}

/**
 * Pure: the state after one key. Unknown keys change nothing. Extension points: M6-3 adds
 * overlays (`filter`, `detail`) before the panel keys below and gives Enter a meaning; M6-5 adds
 * an export key the same way.
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
    return { ...state, overlay: "none" };
  }
  if (isCtrlC(key)) return { ...state, overlay: "confirm-cancel" };
  if (isCtrlD(key)) return { ...state, exit: "back" };
  const height = bodyHeight(state.size);
  if (key.name === "q") return { ...state, exit: "back" };
  const isHelp = key.sequence === "?";
  if (state.overlay === "help") {
    if (isHelp || key.name === "escape" || key.name === "return" || key.name === "enter") {
      return { ...state, overlay: "none", helpScroll: 0 };
    }
    // Only scrolling reaches the help text; panel switches wait until it is closed.
  } else {
    if (isHelp) return { ...state, overlay: "help", helpScroll: 0 };
    if (key.name === "escape") return { ...state, exit: "back" };
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
  if (state.overlay === "help") return state;
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
