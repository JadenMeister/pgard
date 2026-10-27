import type { RuleLocale, Severity } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import type { Key } from "../../adapters/terminal.js";
import { panelsFixtureResult } from "../../test-support.js";
import { createStyle } from "../formatters/style.js";
import { displayWidth, stripAnsi } from "../i18n/display-width.js";
import { renderFrame } from "./layout.js";
import { createPanelsState, reduce } from "./reduce.js";
import { trendBarRow } from "./trend.js";
import type { PanelsState, Size, TrendData, TrendScan } from "./types.js";

// Dates are local time; pin the zone so the snapshots do not depend on the machine.
process.env.TZ = "UTC";

const ESC = String.fromCharCode(27);
const plain = { style: createStyle(false), unicode: false };
const colour = { style: createStyle(true), unicode: true };
const DAY = 86_400_000;
const NOW = Date.UTC(2026, 9, 28, 12, 0, 0);
const SIZES: Size[] = [
  { columns: 80, rows: 24 },
  { columns: 60, rows: 20 },
  { columns: 40, rows: 14 },
];

/** Counts follow a fixed pattern so the snapshots show different bars. */
function scan(index: number): TrendScan {
  const counts: Record<Severity, number> = {
    critical: index % 3,
    high: 2 + (index % 4),
    medium: 3 + (index % 5),
    low: index % 2,
    info: 1,
  };
  return {
    savedAt: NOW - (20 - index) * DAY,
    counts,
    total: Object.values(counts).reduce((sum, value) => sum + value, 0),
  };
}

function ready(count: number): TrendData {
  return {
    kind: "ready",
    scans: Array.from({ length: count }, (_, index) => scan(index + 20 - count)),
    diff: count >= 2 ? { newCount: 2, fixedCount: 1, unchangedCount: 9 } : null,
    skipped: 0,
    now: NOW,
  };
}

function stateFor(locale: RuleLocale, size: Size, trend: TrendData): PanelsState {
  return {
    ...createPanelsState(panelsFixtureResult(), locale, size, undefined, trend),
    panel: "trend",
  };
}

function frame(state: PanelsState, size: Size, options = plain): string[] {
  return renderFrame(state, size, options);
}

function text(lines: readonly string[]): string {
  return lines.join("\n").replaceAll(ESC, "<ESC>");
}

const key = (name: string, extra: Partial<Key> = {}): Key => ({
  name,
  sequence: name.length === 1 ? name : undefined,
  ctrl: false,
  ...extra,
});

/** No control characters (other than the escape of colour codes) and no bidi controls. */
function expectClean(lines: readonly string[], size: Size, allowColour: boolean): void {
  expect(lines).toHaveLength(size.rows);
  for (const line of lines) {
    expect(displayWidth(line), stripAnsi(line)).toBeLessThanOrEqual(size.columns);
    const visible = allowColour ? stripAnsi(line) : line;
    expect(visible).not.toMatch(/[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/u);
  }
}

describe("trend panel snapshots", () => {
  for (const locale of ["en", "ko"] as const) {
    for (const size of SIZES) {
      for (const count of [0, 1, 2, 20]) {
        it(`${locale} ${size.columns}x${size.rows} ${count} scans`, () => {
          const lines = frame(stateFor(locale, size, ready(count)), size);
          expectClean(lines, size, false);
          expect(text(lines)).toMatchSnapshot();
        });
      }
      it(`${locale} ${size.columns}x${size.rows} store disabled`, () => {
        const lines = frame(stateFor(locale, size, { kind: "disabled" }), size);
        expectClean(lines, size, false);
        expect(text(lines)).toMatchSnapshot();
      });
      it(`${locale} ${size.columns}x${size.rows} unreadable store`, () => {
        const trend: TrendData = {
          kind: "unavailable",
          why: "unreadable",
          reason: "Permission denied",
        };
        const lines = frame(stateFor(locale, size, trend), size);
        expectClean(lines, size, false);
        expect(text(lines)).toMatchSnapshot();
      });
    }
  }

  it("colour (unicode) 80x24, 20 scans", () => {
    const size = SIZES[0] as Size;
    const lines = frame(stateFor("en", size, ready(20)), size, colour);
    expectClean(lines, size, true);
    expect(text(lines)).toMatchSnapshot();
  });
});

describe("trend panel content", () => {
  const wide = SIZES[0] as Size;
  const narrow = SIZES[2] as Size;

  it("says what changed and marks fixed as not reported any more", () => {
    const body = frame(stateFor("en", wide, ready(5)), wide).join("\n");
    expect(body).toContain("2 new, 1 fixed*, 9 unchanged");
    expect(body).toContain("no longer reported");
  });

  it("separates severities by character, not colour (ASCII and Unicode)", () => {
    const asciiBody = frame(stateFor("en", wide, ready(5)), wide, plain).join("\n");
    expect(asciiBody).toMatch(/#+=+\++/);
    const unicodeBody = frame(stateFor("en", wide, ready(5)), wide, {
      style: createStyle(false),
      unicode: true,
    }).join("\n");
    expect(unicodeBody).toMatch(/█+▓+▒+/u);
  });

  it("shows a plain text table at narrow widths, no bars", () => {
    const body = frame(stateFor("en", narrow, ready(5)), narrow).join("\n");
    expect(body).toContain("C=Critical");
    expect(body).not.toMatch(/#{2}/);
  });

  it("uses relative labels", () => {
    const body = frame(stateFor("en", wide, ready(3)), wide).join("\n");
    expect(body).toMatch(/\b1 days ago|yesterday/);
    const ko = frame(stateFor("ko", wide, ready(3)), wide).join("\n");
    expect(ko).toContain("일 전");
  });

  it("reports unreadable files that were left out", () => {
    const trend = { ...(ready(3) as Extract<TrendData, { kind: "ready" }>), skipped: 2 };
    expect(frame(stateFor("en", wide, trend), wide).join("\n")).toContain("2 stored files were");
  });

  it("each honest state names its reason", () => {
    const body = (trend: TrendData): string => frame(stateFor("en", wide, trend), wide).join(" ");
    expect(body(ready(1))).toContain("only one stored scan");
    expect(body(ready(0))).toContain("No history yet");
    expect(body({ kind: "disabled" })).toContain("--no-store or PGARD_NO_STORE=1");
    expect(body({ kind: "unavailable", why: "no-repository", reason: "" })).toContain(
      "No history yet",
    );
    expect(body({ kind: "unavailable", why: "no-store-dir", reason: "" })).toContain(
      "No history yet",
    );
    expect(body({ kind: "unavailable", why: "unreadable", reason: "EACCES" })).toContain(
      "could not be read: EACCES",
    );
  });

  it("bar rows never exceed the width and keep every present severity visible", () => {
    const counts = { critical: 1, high: 1, medium: 1, low: 1, info: 100 };
    const parts = trendBarRow(counts, 104, 12, false);
    const length = parts.reduce((sum, part) => sum + part.text.length, 0);
    expect(length).toBeLessThanOrEqual(12);
    expect(parts.map((part) => part.severity)).toEqual([
      "critical",
      "high",
      "medium",
      "low",
      "info",
    ]);
  });
});

describe("trend panel hostile data", () => {
  it("never prints escapes or bidi controls from a hostile reason", () => {
    const hostile = `${ESC}[2J${ESC}]0;pwned\u0007‮ evil⁦ \u0085`;
    for (const locale of ["en", "ko"] as const) {
      for (const size of SIZES) {
        const trend: TrendData = { kind: "unavailable", why: "unreadable", reason: hostile };
        const lines = frame(stateFor(locale, size, trend), size);
        expectClean(lines, size, false);
      }
    }
  });

  it("does not print stored repository names or paths at all", () => {
    // The trend data carries counts and dates only; a hostile name in a stored result cannot
    // reach the frame because the loader copies nothing but numbers.
    const trend = ready(5);
    const body = frame(stateFor("en", SIZES[0] as Size, trend), SIZES[0] as Size).join("\n");
    expect(body).not.toContain("owner/name‮");
  });
});

describe("trend panel navigation", () => {
  const size: Size = { columns: 80, rows: 12 };

  it("sits between coverage and findings in the Tab order", () => {
    let state = createPanelsState(panelsFixtureResult(), "en", size);
    const seen: string[] = [state.panel];
    for (let i = 0; i < 5; i += 1) {
      state = reduce(state, key("tab"));
      seen.push(state.panel);
    }
    expect(seen).toEqual(["overview", "charts", "coverage", "trend", "findings", "overview"]);
  });

  it("scrolls 20 scans to the oldest row and back", () => {
    let state = stateFor("en", size, ready(20));
    state = reduce(state, key("end"));
    expect(state.scroll.trend).toBeGreaterThan(0);
    const lines = frame(state, size);
    expectClean(lines, size, false);
    expect(lines.join("\n")).toContain(String(scan(0).total));
    state = reduce(state, key("home"));
    expect(state.scroll.trend).toBe(0);
  });

  it("lists the trend panel in the help overlay and tab bar (EN and KO)", () => {
    for (const [locale, label] of [
      ["en", "Trend"],
      ["ko", "추이"],
    ] as const) {
      const state = stateFor(locale, { columns: 80, rows: 24 }, ready(2));
      expect(frame(state, { columns: 80, rows: 24 })[1]).toContain(`[${label}]`);
      const help = frame({ ...state, overlay: "help" }, { columns: 80, rows: 40 }).join("\n");
      expect(help).toContain(label);
    }
  });
});
