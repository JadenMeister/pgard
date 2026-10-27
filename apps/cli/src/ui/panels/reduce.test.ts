import { describe, expect, it } from "vitest";
import type { Key } from "../../adapters/terminal.js";
import { panelsFixtureResult } from "../../test-support.js";
import { createPanelsState, reduce, resize } from "./reduce.js";
import type { PanelsState, Size } from "./types.js";

const key = (name: string, extra: Partial<Key> = {}): Key => ({
  name,
  sequence: name.length === 1 ? name : undefined,
  ctrl: false,
  ...extra,
});
const ctrlC = key("c", { ctrl: true, sequence: "\u0003" });
const SIZE: Size = { columns: 80, rows: 12 };

function fresh(size: Size = SIZE): PanelsState {
  return createPanelsState(panelsFixtureResult(), "en", size);
}

function press(state: PanelsState, ...keys: Key[]): PanelsState {
  return keys.reduce(reduce, state);
}

describe("reduce", () => {
  it("starts on the overview with findings in severity order", () => {
    const state = fresh();
    expect(state.panel).toBe("overview");
    expect(state.findings[0]?.severity).toBe("critical");
    expect(state.exit).toBeNull();
  });

  it("does not mutate the state it is given", () => {
    const state = fresh();
    const frozen = JSON.stringify({ ...state, result: undefined });
    press(state, key("tab"), key("down"), key("?"));
    expect(JSON.stringify({ ...state, result: undefined })).toBe(frozen);
  });

  it("moves between panels with Tab, Shift+Tab and the side arrows, wrapping around", () => {
    let state = fresh();
    state = press(state, key("tab"));
    expect(state.panel).toBe("charts");
    state = press(state, key("right"), key("right"));
    expect(state.panel).toBe("findings");
    state = press(state, key("tab"));
    expect(state.panel).toBe("overview");
    state = press(state, key("tab", { sequence: "\u001b[Z" }));
    expect(state.panel).toBe("findings");
    state = press(state, key("left"));
    expect(state.panel).toBe("coverage");
  });

  it("scrolls a panel and stops at both ends", () => {
    let state = press(fresh({ columns: 80, rows: 10 }), key("tab"), key("tab"));
    expect(state.panel).toBe("coverage");
    state = press(state, key("up"));
    expect(state.scroll.coverage).toBe(0);
    state = press(state, key("end"));
    const bottom = state.scroll.coverage;
    expect(bottom).toBeGreaterThan(0);
    state = press(state, key("down"), key("pagedown"));
    expect(state.scroll.coverage).toBe(bottom);
    state = press(state, key("pageup"));
    expect(state.scroll.coverage).toBeLessThan(bottom);
    state = press(state, key("home"));
    expect(state.scroll.coverage).toBe(0);
  });

  it("moves the findings selection and keeps it in view", () => {
    let state = press(fresh(), key("left"));
    expect(state.panel).toBe("findings");
    state = press(state, key("down"), key("j"));
    expect(state.selected).toBe(2);
    state = press(state, key("end"));
    expect(state.selected).toBe(state.findings.length - 1);
    expect(state.scroll.findings).toBeGreaterThan(0);
    const visible = SIZE.rows - 3 - 1;
    expect(state.selected).toBeLessThan(state.scroll.findings + visible);
    state = press(state, key("down"));
    expect(state.selected).toBe(state.findings.length - 1);
    state = press(state, key("home"));
    expect(state.selected).toBe(0);
    expect(state.scroll.findings).toBe(0);
    state = press(state, key("pagedown"));
    expect(state.selected).toBe(SIZE.rows - 3 - 1 - 1);
  });

  it("opens and closes help with ? and Esc, and Esc then leaves", () => {
    let state = press(fresh(), key("?"));
    expect(state.overlay).toBe("help");
    state = press(state, key("tab"));
    expect(state.panel).toBe("overview");
    state = press(state, key("escape"));
    expect(state.overlay).toBe("none");
    expect(state.exit).toBeNull();
    state = press(state, key("?"), key("?"));
    expect(state.overlay).toBe("none");
    state = press(state, key("escape"));
    expect(state.exit).toBe("back");
  });

  it("scrolls the help text on its own", () => {
    const small: Size = { columns: 40, rows: 10 };
    let state = press(fresh(small), key("?"), key("end"));
    expect(state.helpScroll).toBeGreaterThan(0);
    expect(state.scroll.overview).toBe(0);
    state = press(state, key("?"));
    expect(state.helpScroll).toBe(0);
  });

  it("leaves at once with q, and reads two Esc in one read as two presses", () => {
    expect(press(fresh(), key("q")).exit).toBe("back");
    expect(press(press(fresh(), key("?")), key("q")).exit).toBe("back");
    const both = key("escape", { sequence: "\u001b\u001b" });
    // Help open: the first closes it, the second leaves.
    expect(press(press(fresh(), key("?")), both).exit).toBe("back");
    expect(press(fresh(), both).exit).toBe("back");
    expect(press(press(fresh(), key("?")), key("escape")).exit).toBeNull();
  });

  it("asks before Ctrl+C cancels; only y (or Ctrl+C again) confirms", () => {
    let state = press(fresh(), ctrlC);
    expect(state.overlay).toBe("confirm-cancel");
    expect(state.exit).toBeNull();
    state = press(state, key("n"));
    expect(state.overlay).toBe("none");
    expect(state.exit).toBeNull();
    expect(press(state, ctrlC, key("y")).exit).toBe("cancel");
    expect(press(state, ctrlC, ctrlC).exit).toBe("cancel");
    expect(press(state, ctrlC, key("escape")).exit).toBeNull();
  });

  it("asks for confirmation even while help is open", () => {
    const state = press(fresh(), key("?"), ctrlC);
    expect(state.overlay).toBe("confirm-cancel");
  });

  it("ignores Enter and unknown keys, and anything after the view ended", () => {
    const state = fresh();
    expect(press(state, key("return"), key("x"), key("f1"))).toEqual(state);
    const ended = press(state, key("escape"));
    expect(press(ended, key("tab"))).toBe(ended);
  });

  it("clamps scroll and selection when the terminal shrinks or grows", () => {
    let state = press(fresh({ columns: 80, rows: 40 }), key("left"), key("end"));
    expect(state.selected).toBe(11);
    expect(state.scroll.findings).toBe(0);
    state = resize(state, { columns: 60, rows: 10 });
    expect(state.selected).toBe(11);
    expect(state.scroll.findings).toBe(11 - (10 - 3 - 1) + 1);
    state = resize(state, { columns: 80, rows: 40 });
    expect(state.scroll.findings).toBe(0);
  });

  it("re-flows panel scroll limits at a new width", () => {
    let state = press(fresh({ columns: 80, rows: 10 }), key("tab"), key("tab"), key("end"));
    const wide = state.scroll.coverage;
    state = resize(state, { columns: 40, rows: 10 });
    expect(state.scroll.coverage).toBeGreaterThanOrEqual(wide);
    state = resize(state, { columns: 120, rows: 60 });
    expect(state.scroll.coverage).toBe(0);
  });
});
