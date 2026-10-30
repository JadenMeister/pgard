import type { RuleLocale, Severity } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import type { Key } from "../../adapters/terminal.js";
import { codeOnlyTestResult, panelsFixtureResult } from "../../test-support.js";
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
    newerSkipped: 0,
    isCurrentStored: true,
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
    expect(body).toContain("2 new, 1 no longer reported, 9 unchanged");
    expect(body).not.toContain("fixed");
    const ko = frame(stateFor("ko", wide, ready(5)), wide).join("\n");
    expect(ko).toContain("신규 2건, 더 이상 보고되지 않음 1건, 변화 없음 9건");
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

  it("notes a scan that was not stored and scans skipped for a newer version", () => {
    const base = ready(3) as Extract<TrendData, { kind: "ready" }>;
    const trend = { ...base, newerSkipped: 2, isCurrentStored: false };
    const body = frame(stateFor("en", wide, trend), wide).join("\n");
    expect(body).toContain("This scan was not stored.");
    expect(body).toContain("2 scans from a newer PGARD version were skipped.");
    const ko = frame(stateFor("ko", wide, trend), wide).join("\n");
    expect(ko).toContain("이 검사는 저장되지 않았습니다.");
  });

  it("puts the not-stored note and a stored-scans heading on the first screen (80x24, 20 scans)", () => {
    const base = ready(20) as Extract<TrendData, { kind: "ready" }>;
    const trend = { ...base, isCurrentStored: false };
    const size = SIZES[0] as Size;
    const lines = frame(stateFor("en", size, trend), size);
    const first = lines.slice(2, 8).join("\n");
    expect(first).toContain("This scan was not stored.");
    expect(first).toContain("The two newest stored scans");
    const ko = frame(stateFor("ko", size, trend), size)
      .slice(2, 8)
      .join("\n");
    expect(ko).toContain("이 검사는 저장되지 않았습니다.");
    // The other empty and single states carry it too.
    for (const count of [0, 1]) {
      const small = {
        ...(ready(count) as Extract<TrendData, { kind: "ready" }>),
        isCurrentStored: false,
      };
      expect(frame(stateFor("en", size, small), size).join("\n")).toContain("not stored");
    }
  });

  it("shows the date, not 'just now', for a scan dated after the read", () => {
    const base = ready(3) as Extract<TrendData, { kind: "ready" }>;
    const last = base.scans.at(-1) as TrendScan;
    const future = { ...last, savedAt: NOW + 30 * DAY };
    const trend = { ...base, scans: [...base.scans.slice(0, -1), future] };
    for (const size of [SIZES[0] as Size, SIZES[2] as Size]) {
      const body = frame(stateFor("en", size, trend), size).join("\n");
      expect(body).not.toContain("just now");
      expect(body).toContain("11-27");
    }
  });

  it("words an unreadable store without a doubled period and keeps the KO sentence whole", () => {
    const trend: TrendData = {
      kind: "unavailable",
      why: "unreadable",
      reason: "Permission denied.",
    };
    const en = frame(stateFor("en", SIZES[0] as Size, trend), SIZES[0] as Size)
      .slice(2)
      .join(" ");
    expect(en).toContain("(reason: Permission denied). The scan");
    expect(en).not.toContain("..");
    const ko = frame(stateFor("ko", SIZES[0] as Size, trend), SIZES[0] as Size).join(" ");
    expect(ko).toContain("(원인: Permission denied)");
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
      "could not be read (reason: EACCES)",
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

describe("trend panel empty states and help marker", () => {
  const unavailable = (why: "no-repository" | "no-store-dir" | "unreadable"): TrendData => ({
    kind: "unavailable",
    why,
    reason: "Permission denied",
  });
  const codeOnlyState = (locale: RuleLocale, size: Size, trend: TrendData): PanelsState => ({
    ...createPanelsState(codeOnlyTestResult(), locale, size, undefined, trend),
    panel: "trend",
  });
  const joined = (lines: readonly string[]): string => lines.join(" ").replace(/\s+/gu, " ");
  const EXPECT = {
    en: {
      codeOnly: "a code-only scan does not store its result, so no trend builds up",
      intro: "Trend is empty in one of three cases:",
      cases: [
        "1. A code-only scan: results are not stored. Run `pgard scan` with GitHub approval.",
        "2. Only one stored scan: scan again later to compare.",
        "3. Storing is off: `--no-store` or `PGARD_NO_STORE=1`.",
      ],
    },
    ko: {
      codeOnly: "코드 전용 검사는 결과를 저장하지 않아 추이가 쌓이지 않습니다.",
      intro: "기록이 없는 경우는 셋 중 하나입니다:",
      cases: [
        "1. 코드 전용 검사: 결과가 저장되지 않습니다. GitHub 승인으로 `pgard scan`을 실행하세요.",
        "2. 저장된 검사가 1건뿐: 나중에 다시 검사해 비교하세요.",
        "3. 저장이 꺼져 있음: `--no-store` 또는 `PGARD_NO_STORE=1`.",
      ],
    },
  } as const;
  const tall = (columns: number): Size => ({ columns, rows: 40 });

  for (const locale of ["en", "ko"] as const) {
    it(`${locale}: a code-only result names its own reason, then the three cases`, () => {
      const size = tall(80);
      const all = joined(frame(codeOnlyState(locale, size, unavailable("no-repository")), size));
      expect(all).toContain(EXPECT[locale].codeOnly);
      expect(all).not.toContain(
        locale === "en" ? "not tied to a GitHub" : "GitHub 저장소와 연결되지",
      );
      expect(all).toContain(EXPECT[locale].intro);
      for (const line of EXPECT[locale].cases) expect(all).toContain(line);
    });

    it(`${locale}: other reasons stay first and the cases follow`, () => {
      const size = tall(80);
      const noRepo = joined(frame(stateFor(locale, size, unavailable("no-repository")), size));
      expect(noRepo).toContain(
        locale === "en" ? "not tied to a GitHub repository" : "GitHub 저장소와 연결되지 않아",
      );
      const store = joined(frame(stateFor(locale, size, unavailable("no-store-dir")), size));
      expect(store).toContain(locale === "en" ? "no app-data directory" : "앱 데이터 폴더");
      const unreadable = joined(frame(stateFor(locale, size, unavailable("unreadable")), size));
      expect(unreadable).toContain("Permission denied");
      const disabled = joined(frame(stateFor(locale, size, { kind: "disabled" }), size));
      expect(disabled).toContain("PGARD_NO_STORE=1");
      for (const all of [
        noRepo,
        store,
        unreadable,
        disabled,
        joined(frame(stateFor(locale, size, ready(1)), size)),
      ]) {
        expect(all).toContain(EXPECT[locale].intro);
        for (const line of EXPECT[locale].cases) expect(all).toContain(line);
      }
    });

    for (const columns of [40, 80]) {
      it(`${locale}: shows (?) and never exceeds ${columns} columns`, () => {
        const size = tall(columns);
        const trends: TrendData[] = [
          unavailable("no-repository"),
          unavailable("unreadable"),
          { kind: "disabled" },
          ready(0),
          ready(1),
          ready(2),
          ready(20),
        ];
        for (const trend of trends) {
          for (const state of [stateFor(locale, size, trend), codeOnlyState(locale, size, trend)]) {
            const lines = frame(state, size);
            expectClean(lines, size, false);
            expect(joined(lines)).toContain("(?)");
          }
        }
      });
    }

    it(`${locale}: ? on the trend tab opens the help at the trend section`, () => {
      const size: Size = { columns: 80, rows: 14 };
      const state = reduce(stateFor(locale, size, ready(2)), key("?"));
      expect(state.overlay).toBe("help");
      expect(state.helpScroll).toBeGreaterThan(0);
      const lines = frame(state, size);
      expectClean(lines, size, false);
      const title = locale === "en" ? "Trend panel" : "추이 패널";
      expect(joined(lines)).toContain(title);
      expect(joined(lines)).toContain("pgard scan");
      expect(reduce(state, key("?")).overlay).toBe("none");
    });

    it(`${locale}: ? on another tab still opens the help at the top`, () => {
      const size: Size = { columns: 80, rows: 14 };
      const state = reduce(
        { ...stateFor(locale, size, ready(2)), panel: "overview" as const },
        key("?"),
      );
      expect(state.overlay).toBe("help");
      expect(state.helpScroll).toBe(0);
    });
  }

  it("the help fits at 40 columns", () => {
    const size: Size = { columns: 40, rows: 14 };
    const state = reduce(stateFor("ko", size, ready(2)), key("?"));
    expectClean(frame(state, size), size, false);
  });
});
