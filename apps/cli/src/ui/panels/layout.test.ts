import type { RuleLocale } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { panelsFixtureResult, testResult } from "../../test-support.js";
import { createStyle } from "../formatters/style.js";
import { displayWidth, stripAnsi } from "../i18n/display-width.js";
import { renderFrame } from "./layout.js";
import { createPanelsState, reduce } from "./reduce.js";
import { PANEL_IDS, type PanelId, type PanelsState, type Size } from "./types.js";

const ESC = String.fromCharCode(27);
const plain = { style: createStyle(false), unicode: false };
const colour = { style: createStyle(true), unicode: true };

function stateFor(locale: RuleLocale, size: Size, panel: PanelId): PanelsState {
  return { ...createPanelsState(panelsFixtureResult(), locale, size), panel };
}

function text(lines: readonly string[]): string {
  return lines.join("\n").replaceAll(ESC, "<ESC>");
}

const SIZES: Size[] = [
  { columns: 80, rows: 24 },
  { columns: 60, rows: 20 },
  { columns: 40, rows: 14 },
];

describe("renderFrame snapshots", () => {
  for (const locale of ["en", "ko"] as const) {
    for (const size of SIZES) {
      for (const panel of PANEL_IDS) {
        it(`${locale} ${size.columns}x${size.rows} ${panel} (NO_COLOR)`, () => {
          const lines = renderFrame(stateFor(locale, size, panel), size, plain);
          expect(text(lines)).toMatchSnapshot();
        });
      }
      for (const panel of ["overview", "findings"] as const) {
        it(`${locale} ${size.columns}x${size.rows} ${panel} (colour)`, () => {
          const lines = renderFrame(stateFor(locale, size, panel), size, colour);
          expect(text(lines)).toMatchSnapshot();
        });
      }
    }
  }
});

describe("renderFrame invariants", () => {
  const sizes: Size[] = [
    { columns: 120, rows: 40 },
    ...SIZES,
    { columns: 45, rows: 12 },
    { columns: 40, rows: 10 },
  ];
  for (const locale of ["en", "ko"] as const) {
    for (const size of sizes) {
      for (const panel of PANEL_IDS) {
        for (const overlay of ["none", "help", "confirm-cancel"] as const) {
          for (const options of [plain, colour]) {
            it(`${locale} ${size.columns}x${size.rows} ${panel} ${overlay} fits the terminal`, () => {
              const state = { ...stateFor(locale, size, panel), overlay };
              const lines = renderFrame(state, size, options);
              expect(lines).toHaveLength(size.rows);
              for (const line of lines) {
                expect(displayWidth(line), stripAnsi(line)).toBeLessThanOrEqual(size.columns);
              }
              if (!options.style.enabled) {
                expect(lines.join("")).not.toContain(ESC);
              }
            });
          }
        }
      }
    }
  }

  it("shows only a message below the minimum size, in the chosen language", () => {
    const small: Size = { columns: 30, rows: 8 };
    const en = renderFrame(stateFor("en", small, "overview"), small, plain);
    expect(en.join("\n")).toContain("Terminal too small (30x8)");
    expect(en.join("\n")).not.toContain("Summary");
    const ko = renderFrame(stateFor("ko", small, "overview"), small, plain);
    expect(ko.join("\n")).toContain("터미널이 너무 작습니다 (30x8)");
  });

  it("uses block bars with colour and # bars without", () => {
    const size = SIZES[0] as Size;
    const withColour = renderFrame(stateFor("en", size, "overview"), size, colour).join("\n");
    const without = renderFrame(stateFor("en", size, "overview"), size, plain).join("\n");
    expect(withColour).toContain("█");
    expect(without).toContain("#");
    expect(without).not.toContain("█");
  });

  it("drops bars and titles in the narrow layout", () => {
    const narrow = SIZES[1] as Size;
    const overview = renderFrame(stateFor("en", narrow, "overview"), narrow, plain).join("\n");
    expect(overview).not.toContain("#");
    const findings = renderFrame(stateFor("en", narrow, "findings"), narrow, plain).join("\n");
    expect(findings).not.toContain("Fixture finding");
    expect(findings).toContain("src/module1/handler.ts:11");
  });

  it("lists findings in severity order with file:line and status", () => {
    const size = SIZES[0] as Size;
    const body = renderFrame(stateFor("en", size, "findings"), size, plain);
    expect(body[2]).toContain("12 of 12");
    expect(body[3]).toMatch(/^> \[CRITICAL\] confirmed {1,}src\/module1\/handler\.ts:11/);
    expect(body[4]).toMatch(/^ {2}\[HIGH\] +suspected +config\/\.env/);
    expect(body.join("\n")).toContain("(suppressed)");
  });

  it("keeps Korean rows aligned by display width", () => {
    const size = SIZES[0] as Size;
    const lines = renderFrame(stateFor("ko", size, "findings"), size, plain);
    const widths = lines.slice(2, 8).map((line) => displayWidth(line));
    expect(Math.max(...widths)).toBeLessThanOrEqual(size.columns);
  });

  it("never prints evidence, impact or fixes", () => {
    const secret = "ghp_REDACTED_EVIDENCE_MARKER";
    const result = panelsFixtureResult();
    const leaky = {
      ...result,
      findings: result.findings.map((finding) => ({
        ...finding,
        evidence: secret,
        impact: secret,
        recommendation: secret,
      })),
    };
    const size = { columns: 120, rows: 60 };
    for (const panel of PANEL_IDS) {
      const state = { ...createPanelsState(leaky, "en", size), panel };
      expect(renderFrame(state, size, plain).join("\n")).not.toContain(secret);
    }
  });

  it("strips control characters from text that comes from the repository", () => {
    const result = testResult({
      coverage: [
        {
          area: `source:evil${ESC}[31m`,
          scope: "code",
          status: "partial",
          ruleIds: [],
          note: `note${ESC}]0;title\u0007`,
        },
      ],
    });
    const size = { columns: 80, rows: 24 };
    const state = { ...createPanelsState(result, "en", size), panel: "coverage" as const };
    expect(renderFrame(state, size, plain).join("\n")).not.toContain(ESC);
  });

  it("renders an empty result", () => {
    const size = SIZES[0] as Size;
    const empty = testResult({ findings: [], coverage: [] });
    for (const panel of PANEL_IDS) {
      const state = { ...createPanelsState(empty, "en", size), panel };
      const lines = renderFrame(state, size, plain);
      expect(lines).toHaveLength(size.rows);
    }
    const findings = renderFrame(
      { ...createPanelsState(empty, "en", size), panel: "findings" },
      size,
      plain,
    );
    expect(findings.join("\n")).toContain("(no findings)");
  });

  it("scrolls the findings list with the selection and shows the window position", () => {
    const size: Size = { columns: 80, rows: 12 };
    let state = stateFor("en", size, "findings");
    for (let i = 0; i < 11; i += 1)
      state = reduce(state, { name: "down", sequence: undefined, ctrl: false });
    const lines = renderFrame(state, size, plain);
    expect(lines.join("\n")).toContain("> ");
    expect(lines.at(-1)).toContain("5-12/12");
  });
});

describe("hostile text from the repository", () => {
  // ESC/CSI, OSC, BEL, C1 (CSI 0x9b, NEL 0x85) and a right-to-left override, around a marker.
  const hostile = (name: string): string =>
    `${name}\u001b[31m\u001b]0;pwned\u0007\u009b31m\u0085‮${name}`;
  const FORBIDDEN = ["\u001b", "\u0007", "\u009b", "\u0085", "‮"];
  const size: Size = { columns: 120, rows: 60 };

  function hostileState(locale: RuleLocale, panel: PanelId, overlay: "none" | "help"): PanelsState {
    const base = panelsFixtureResult();
    const at = (index: number, patch: Partial<(typeof base.findings)[number]>) => ({
      ...(base.findings[index] as (typeof base.findings)[number]),
      ...patch,
    });
    const findings = [
      at(0, {
        title: hostile("title"),
        location: { kind: "file", path: hostile("path"), line: 3, url: null, commit: null },
      }),
      at(1, {
        location: { kind: "url", path: null, line: null, url: hostile("url"), commit: null },
      }),
      at(2, {
        location: { kind: "commit", path: null, line: null, url: null, commit: hostile("commit") },
      }),
      ...base.findings.slice(3),
    ];
    const result = {
      ...base,
      target: { ...base.target, repo: hostile("repo"), revision: hostile("rev") },
      findings,
    };
    return { ...createPanelsState(result, locale, size), panel, overlay };
  }

  for (const locale of ["en", "ko"] as const) {
    for (const panel of PANEL_IDS) {
      for (const overlay of ["none", "help"] as const) {
        it(`${locale} ${panel} ${overlay}: nothing but our own colour codes reaches the terminal`, () => {
          const state = hostileState(locale, panel, overlay);
          const noColour = renderFrame(state, size, plain);
          for (const line of noColour) {
            for (const bad of FORBIDDEN) expect(line).not.toContain(bad);
          }
          // With colour, removing our own SGR codes must give the very same text: any
          // injected sequence would survive as an extra character or code.
          const coloured = renderFrame(state, size, { style: createStyle(true), unicode: false });
          expect(coloured.map((line) => stripAnsi(line).trimEnd())).toEqual(
            noColour.map((line) => line.trimEnd()),
          );
          for (const line of coloured) {
            const withoutOurs = line.replace(new RegExp(`${ESC}\\[[0-9;]*m`, "g"), "");
            for (const bad of FORBIDDEN) expect(withoutOurs).not.toContain(bad);
          }
        });
      }
    }
  }

  it("still shows the visible part of each hostile field", () => {
    const text = (panel: PanelId): string =>
      renderFrame(hostileState("en", panel, "none"), size, plain).join("\n");
    expect(text("overview")).toContain("repo");
    expect(text("findings")).toContain("title");
    const list = text("findings");
    for (const marker of ["path", "url", "commit"]) expect(list).toContain(marker);
  });

  it("keeps the suppressed flag in the narrow layout", () => {
    const narrow: Size = { columns: 60, rows: 20 };
    const state = {
      ...createPanelsState(panelsFixtureResult(), "en", narrow),
      panel: "findings" as const,
    };
    const text = renderFrame(state, narrow, plain).join("\n");
    expect(text).toContain("(suppressed) src/module4");
    expect(text).toContain("(baseline) src/module7");
  });
});

describe("footer with the export key", () => {
  const exportable = (locale: RuleLocale, size: Size, panel: PanelId): PanelsState => ({
    ...createPanelsState(panelsFixtureResult(), locale, size, undefined, undefined, true),
    panel,
  });

  it("lists e after the help hint, in English and Korean, on every panel", () => {
    const size: Size = { columns: 80, rows: 24 };
    for (const panel of PANEL_IDS) {
      const en = renderFrame(exportable("en", size, panel), size, plain).at(-1) ?? "";
      expect(en, panel).toContain("?: help  e: export");
      const ko = renderFrame(exportable("ko", size, panel), size, plain).at(-1) ?? "";
      expect(ko, panel).toContain("?: 도움말  e: 내보내기");
    }
  });

  it("still fits at 40 columns and keeps the export hint there", () => {
    const size: Size = { columns: 40, rows: 14 };
    for (const locale of ["en", "ko"] as const) {
      for (const panel of PANEL_IDS) {
        const lines = renderFrame(exportable(locale, size, panel), size, plain);
        expect(lines, `${locale} ${panel}`).toHaveLength(14);
        for (const line of lines) expect(displayWidth(stripAnsi(line))).toBeLessThanOrEqual(40);
        // Whole hints are dropped from the end when the position indicator takes the room.
        const last = lines.at(-1) ?? "";
        if (!/\d+-\d+\/\d+/.test(last)) {
          expect(last).toContain(locale === "en" ? "e: export" : "e: 내보내기");
        }
      }
    }
  });

  it("is not shown when exporting is not possible, and the help text always names it", () => {
    const size: Size = { columns: 80, rows: 24 };
    const plainState = stateFor("en", size, "overview");
    expect(renderFrame(plainState, size, plain).at(-1)).not.toContain("e: export");
    const help = renderFrame(
      reduce(exportable("en", size, "overview"), {
        name: "?",
        sequence: "?",
        ctrl: false,
      }),
      size,
      plain,
    ).join("\n");
    expect(help).toContain("e: save a report");
  });
});
