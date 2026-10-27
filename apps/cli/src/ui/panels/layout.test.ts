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
    expect(body[2]).toMatch(/^> \[CRITICAL\] confirmed {1,}src\/module1\/handler\.ts:11/);
    expect(body[3]).toMatch(/^ {2}\[HIGH\] +suspected +config\/\.env/);
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
    expect(lines.at(-1)).toContain("4-12/12");
  });
});
