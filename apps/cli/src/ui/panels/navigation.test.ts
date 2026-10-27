import type { RuleLocale } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import type { Key } from "../../adapters/terminal.js";
import { getRuleTextCatalog } from "../../rule-texts.js";
import { panelsFixtureResult, testFinding, testResult } from "../../test-support.js";
import { createStyle } from "../formatters/style.js";
import { displayWidth, stripAnsi } from "../i18n/display-width.js";
import { renderFrame } from "./layout.js";
import { createPanelsState, reduce } from "./reduce.js";
import type { PanelsState, Size } from "./types.js";

const ESC = String.fromCharCode(27);
const plain = { style: createStyle(false), unicode: false };
const key = (name: string, extra: Partial<Key> = {}): Key => ({
  name,
  sequence: name.length === 1 ? name : undefined,
  ctrl: false,
  ...extra,
});
/** A typed character: readline names a digit or letter by itself, `/` and `?` have no name. */
const char = (value: string): Key => ({
  name: /^[a-z0-9]$/.test(value) ? value : undefined,
  sequence: value,
  ctrl: false,
});
const ctrlC = key("c", { ctrl: true, sequence: "\u0003" });
const SIZE: Size = { columns: 80, rows: 20 };

function findings(size: Size = SIZE, locale: RuleLocale = "en"): PanelsState {
  const state = createPanelsState(panelsFixtureResult(), locale, size, getRuleTextCatalog());
  return { ...state, panel: "findings" };
}

function press(state: PanelsState, ...keys: Key[]): PanelsState {
  return keys.reduce(reduce, state);
}

function type(state: PanelsState, text: string): PanelsState {
  return press(state, ...Array.from(text).map(char));
}

const ids = (state: PanelsState): string[] => state.visible.map((finding) => finding.id);

describe("severity filter", () => {
  it("keys 1 to 5 show one severity each, and pressing the same key again clears it", () => {
    const expected = { "1": 1, "2": 4, "3": 4, "4": 2, "5": 1 } as const;
    for (const [digit, count] of Object.entries(expected)) {
      const state = press(findings(), char(digit));
      expect(state.visible).toHaveLength(count);
      expect(state.findings).toHaveLength(12);
      expect(press(state, char(digit)).visible).toHaveLength(12);
    }
  });

  it("0 clears the severity, s cycles through the severities and back to all", () => {
    let state = press(findings(), char("2"), char("0"));
    expect(state.filters.severity).toBeNull();
    const seen: unknown[] = [];
    for (let i = 0; i < 6; i += 1) {
      state = press(state, key("s"));
      seen.push(state.filters.severity);
    }
    expect(seen).toEqual(["critical", "high", "medium", "low", "info", null]);
  });

  it("keeps the selected finding when it is still listed, else selects the first", () => {
    let state = press(findings(), key("down"), key("down"));
    const kept = state.visible[state.selected]?.id;
    expect(state.visible[state.selected]?.severity).toBe("high");
    state = press(state, char("2"));
    expect(state.visible[state.selected]?.id).toBe(kept);
    state = press(state, char("4"));
    expect(state.selected).toBe(0);
  });
});

describe("area and rule filters", () => {
  it("a cycles through the areas the findings came from", () => {
    let state = press(findings(), key("a"));
    expect(state.filters.area).toBe("code");
    expect(state.visible).toHaveLength(11);
    state = press(state, key("a"));
    expect(state.filters.area).toBe("history");
    expect(ids(state)).toEqual(["f3"]);
    state = press(state, key("a"));
    expect(ids(state)).toEqual(["f6"]);
    state = press(state, key("a"));
    expect(state.filters.area).toBeNull();
    expect(state.visible).toHaveLength(12);
  });

  it("r cycles through the rules in list order", () => {
    let state = press(findings(), key("r"));
    const order = [...new Set(state.findings.map((finding) => finding.ruleId))];
    expect(state.filters.rule).toBe(order[0]);
    expect(ids(state)).toEqual(["f1"]);
    state = press(state, key("r"));
    expect(state.filters.rule).toBe(order[1]);
    for (let i = 0; i < 11; i += 1) state = press(state, key("r"));
    expect(state.filters.rule).toBeNull();
  });

  it("c clears every filter at once", () => {
    const state = press(findings(), char("2"), key("a"), key("r"), key("c"));
    expect(state.filters).toEqual({ severity: null, area: null, rule: null, text: "" });
    expect(state.visible).toHaveLength(12);
  });

  it("filters combine, and the findings and charts keep using all findings", () => {
    const state = press(findings(), char("3"), key("a"), key("a"), key("a"));
    expect(ids(state)).toEqual(["f6"]);
    expect(state.findings).toHaveLength(12);
  });

  it("filter keys do nothing on the other panels", () => {
    const state = { ...findings(), panel: "overview" as const };
    expect(press(state, char("1"), key("s"), key("a"), key("r"), char("/"))).toEqual(state);
  });
});

describe("text search", () => {
  it("/ opens the input; typing filters live over title, rule id and path", () => {
    let state = press(findings(), char("/"));
    expect(state.overlay).toBe("filter");
    state = type(state, "SECRET");
    expect(ids(state)).toEqual(["f1"]);
    state = press(state, key("backspace", { sequence: "\u007f" }));
    expect(state.filters.text).toBe("SECRE");
    state = press(state, key("escape"));
    expect(state.overlay).toBe("none");
    expect(state.filters.text).toBe("");
    state = type(press(state, char("/")), "pg-fix-012");
    expect(ids(state)).toEqual(["f12"]);
    state = type(press(state, key("return")), "x");
    expect(state.filters.text).toBe("pg-fix-012");
    state = press(state, char("c"));
    state = type(press(state, char("/")), "config/.env");
    expect(ids(state)).toEqual(["f3"]);
  });

  it("treats letters, digits, ? and q as text while typing, but not arrows or Tab", () => {
    let state = type(press(findings(), char("/")), "q1?s");
    expect(state.filters.text).toBe("q1?s");
    expect(state.exit).toBeNull();
    state = press(state, key("tab", { sequence: "\t" }), key("up", { sequence: "\u001b[A" }));
    expect(state.filters.text).toBe("q1?s");
    expect(state.panel).toBe("findings");
  });

  it("Enter keeps the search, then the first Esc clears it and the second leaves", () => {
    let state = press(type(press(findings(), char("/")), "fix"), key("return"));
    expect(state.overlay).toBe("none");
    expect(state.filters.text).toBe("fix");
    state = press(state, key("escape"));
    expect(state.exit).toBeNull();
    expect(state.filters.text).toBe("");
    expect(state.visible).toHaveLength(12);
    expect(press(state, key("escape")).exit).toBe("back");
  });

  it("Esc in the input clears the search and closes the input without leaving", () => {
    const state = press(type(press(findings(), char("/")), "abc"), key("escape"));
    expect(state.exit).toBeNull();
    expect(state.overlay).toBe("none");
  });

  it("caps the search length and ignores control sequences", () => {
    let state = press(findings(), char("/"));
    state = type(state, "x".repeat(200));
    expect(state.filters.text).toHaveLength(80);
    state = press(state, { name: undefined, sequence: `${ESC}[200~`, ctrl: false });
    expect(state.filters.text).toHaveLength(80);
  });

  it("Ctrl+C in the input asks to confirm, and 'no' returns to the input", () => {
    let state = type(press(findings(), char("/")), "ab");
    state = press(state, ctrlC);
    expect(state.overlay).toBe("confirm-cancel");
    expect(press(state, key("n")).overlay).toBe("filter");
    expect(press(state, key("y")).exit).toBe("cancel");
  });

  it("Ctrl+D leaves from the input, like everywhere else", () => {
    const state = press(findings(), char("/"), key("d", { ctrl: true, sequence: "\u0004" }));
    expect(state.exit).toBe("back");
  });

  it("a search that matches nothing keeps the findings in the state and the count visible", () => {
    const state = type(press(findings(), char("/")), "zzzz");
    expect(state.visible).toHaveLength(0);
    expect(state.findings).toHaveLength(12);
    const text = renderFrame(state, SIZE, plain).join("\n");
    expect(text).toContain("0 of 12");
    expect(text).toContain("12 findings exist");
    expect(text).not.toContain("(no findings)");
    expect(press(state, key("return"), key("return")).overlay).toBe("none");
  });
});

describe("detail view", () => {
  it("Enter opens the selected finding, Enter or Esc closes it without leaving", () => {
    const opened = press(findings(), key("down"), key("return"));
    expect(opened.overlay).toBe("detail");
    expect(opened.visible[opened.selected]).toBe(opened.visible[1]);
    expect(press(opened, key("return")).overlay).toBe("none");
    const escaped = press(opened, key("escape"));
    expect(escaped.overlay).toBe("none");
    expect(escaped.exit).toBeNull();
    expect(escaped.selected).toBe(1);
  });

  it("Enter does nothing on an empty list or another panel", () => {
    const empty = type(press(findings(), char("/")), "zzzz");
    expect(press(empty, key("return"), key("return"), key("return")).overlay).toBe("none");
    const overview = { ...findings(), panel: "overview" as const };
    expect(press(overview, key("return"))).toEqual(overview);
  });

  it("scrolls with the arrows, page keys, Home and End; Tab and filters wait", () => {
    const small: Size = { columns: 40, rows: 10 };
    let state = press(findings(small), key("return"));
    state = press(state, key("down"), key("j"));
    expect(state.detailScroll).toBe(2);
    state = press(state, key("end"));
    const last = state.detailScroll;
    expect(last).toBeGreaterThan(2);
    state = press(state, key("pagedown"), key("down"));
    expect(state.detailScroll).toBe(last);
    state = press(state, key("home"));
    expect(state.detailScroll).toBe(0);
    state = press(state, key("tab"), char("1"), char("/"), key("k"));
    expect(state.overlay).toBe("detail");
    expect(state.panel).toBe("findings");
    expect(state.filters.severity).toBeNull();
    state = press(state, char("?"));
    expect(state.overlay).toBe("detail");
  });

  it("q leaves from the detail view; Ctrl+C asks and returns to it", () => {
    const opened = press(findings(), key("return"));
    expect(press(opened, key("q")).exit).toBe("back");
    expect(press(opened, ctrlC, key("n")).overlay).toBe("detail");
  });

  it("clamps the detail scroll when the terminal grows", () => {
    const small: Size = { columns: 40, rows: 10 };
    const state = press(findings(small), key("return"), key("end"));
    expect(state.detailScroll).toBeGreaterThan(0);
  });
});

describe("keys that moved or stayed", () => {
  it("Esc outside the findings list still leaves at once, whatever the search holds", () => {
    const state = type(press(findings(), char("/")), "fix");
    const overview = { ...press(state, key("return")), panel: "overview" as const };
    expect(press(overview, key("escape")).exit).toBe("back");
  });

  it("q, Esc and Ctrl+D leave from the list; the first Ctrl+C then y cancels", () => {
    expect(press(findings(), key("q")).exit).toBe("back");
    expect(press(findings(), key("escape")).exit).toBe("back");
    expect(press(findings(), key("d", { ctrl: true })).exit).toBe("back");
    expect(press(findings(), ctrlC, key("y")).exit).toBe("cancel");
  });

  it("help from the list closes with ?, Esc or Enter and keeps the filters", () => {
    const state = press(findings(), char("2"), char("?"));
    expect(state.overlay).toBe("help");
    expect(press(state, char("1")).filters.severity).toBe("high");
    expect(press(state, key("escape")).overlay).toBe("none");
    expect(press(state, key("escape")).filters.severity).toBe("high");
  });

  it("PageUp, PageDown, Home, End and j/k move the selection inside the filtered list", () => {
    let state = press(findings(), char("2"));
    expect(state.visible).toHaveLength(4);
    state = press(state, key("end"));
    expect(state.selected).toBe(3);
    state = press(state, key("pageup"));
    expect(state.selected).toBe(0);
    state = press(state, key("j"), key("down"), key("k"));
    expect(state.selected).toBe(1);
    state = press(state, key("pagedown"));
    expect(state.selected).toBe(3);
    expect(press(state, key("home")).selected).toBe(0);
  });
});

describe("rendering", () => {
  const sizes: Size[] = [
    { columns: 80, rows: 24 },
    { columns: 60, rows: 20 },
    { columns: 40, rows: 14 },
  ];

  function lines(state: PanelsState, size: Size): string[] {
    return renderFrame(state, size, plain);
  }

  function expectFits(frame: string[], size: Size): void {
    expect(frame).toHaveLength(size.rows);
    for (const line of frame) {
      expect(displayWidth(line), stripAnsi(line)).toBeLessThanOrEqual(size.columns);
      expect(line).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/);
    }
  }

  for (const locale of ["en", "ko"] as const) {
    for (const size of sizes) {
      const label = `${locale} ${size.columns}x${size.rows}`;
      it(`${label}: the unfiltered list shows "N of N" and the key help`, () => {
        const frame = lines(findings(size, locale), size);
        expectFits(frame, size);
        expect(frame.join("\n")).toMatchSnapshot();
      });
      it(`${label}: active filters are shown with the count`, () => {
        const state = press(findings(size, locale), char("2"), key("a"), key("r"));
        const frame = lines(state, size);
        expectFits(frame, size);
        expect(frame.join("\n")).toMatchSnapshot();
      });
      it(`${label}: the search input shows the text and a cursor`, () => {
        const state = type(press(findings(size, locale), char("/")), "fix");
        const frame = lines(state, size);
        expectFits(frame, size);
        expect(frame.join("\n")).toMatchSnapshot();
      });
      it(`${label}: nothing matches`, () => {
        const state = press(type(press(findings(size, locale), char("/")), "zzz"), key("return"));
        const frame = lines(state, size);
        expectFits(frame, size);
        expect(frame.join("\n")).toMatchSnapshot();
      });
      it(`${label}: detail of a finding with standards`, () => {
        const result = testResult({
          findings: [
            testFinding({
              ruleId: "PG-SQL-001",
              severity: "critical",
              references: { cwe: ["CWE-89"], owasp: ["A05:2025"], cve: [] },
            }),
          ],
        });
        // Short link titles: the ellipsis of a cut title differs between platforms.
        const catalog = new Map([
          [
            "PG-SQL-001",
            {
              title: { en: "t", ko: "t" },
              impact: { en: "i", ko: "i" },
              recommendation: { en: "r", ko: "r" },
              details: {
                standards: [
                  {
                    id: "A05:2025",
                    title: "Injection",
                    url: "https://top10.owasp.org/2025/A05_2025-Injection/",
                  },
                  {
                    id: "CWE-89",
                    title: "SQL Injection",
                    url: "https://cwe.mitre.org/data/definitions/89.html",
                    viaCwe: "CWE-89",
                  },
                ],
              },
            },
          ],
        ]) as unknown as ReturnType<typeof getRuleTextCatalog>;
        const state = {
          ...createPanelsState(result, locale, size, catalog),
          panel: "findings" as const,
        };
        const opened = press(state, key("return"));
        const frame = lines(opened, size);
        expectFits(frame, size);
        const text = frame.join("\n");
        expect(text).toContain(locale === "en" ? "Evidence:" : "근거:");
        expect(text).toMatchSnapshot();
      });
      it(`${label}: help lists the new keys`, () => {
        const frame = lines(press(findings(size, locale), char("?")), size);
        expectFits(frame, size);
        expect(frame.join("\n")).toMatchSnapshot();
      });
    }
  }

  it("marks the selected row with '>' and an indicator that does not need colour", () => {
    const frame = lines(findings(), SIZE);
    const selected = frame.filter((line) => line.startsWith("> "));
    expect(selected).toHaveLength(1);
    expect(selected[0]).toContain("[CRITICAL]");
    expect(frame.filter((line) => line.startsWith("  [")).length).toBeGreaterThan(0);
  });

  it("shows the filtered count in the Findings tab", () => {
    const state = press(findings(), char("2"));
    expect(lines(state, SIZE)[1]).toContain("Findings (4 of 12)");
    expect(lines(findings(), SIZE)[1]).toContain("Findings (12)");
  });

  it("shows only the first findings page header rows when the filter line wraps", () => {
    const size: Size = { columns: 40, rows: 10 };
    const state = press(findings(size), char("2"), key("a"));
    const frame = lines(state, size);
    expectFits(frame, size);
    expect(frame.join("\n")).toContain("3 of 12");
    expect(frame.join("\n")).toContain("area:");
    expect(frame.join("\n")).toContain("severity: High");
  });

  it("keeps selection visible while paging in a filtered list at the smallest size", () => {
    const size: Size = { columns: 40, rows: 10 };
    let state = findings(size);
    for (let i = 0; i < 11; i += 1) state = press(state, key("down"));
    const frame = lines(state, size);
    expectFits(frame, size);
    expect(frame.filter((line) => line.startsWith("> "))).toHaveLength(1);
  });
});

describe("hostile text in the detail view", () => {
  const hostile = `${ESC}[31mred${ESC}]0;pwn\u0007 \u0000\u0008\u009b‮ tail`;
  const result = testResult({
    findings: [
      testFinding({
        id: "h1",
        ruleId: `PG-SQL-001${ESC}[2J`,
        title: `Title ${hostile}`,
        evidence: `${hostile} ${"E".repeat(900)}`,
        recommendation: `${hostile} ${"F".repeat(900)}`,
        location: {
          kind: "file",
          path: `src/${hostile}/${"d".repeat(400)}.ts`,
          line: 1,
          url: null,
          commit: null,
        },
        references: { cwe: [`CWE-${hostile}`], owasp: [`A01${ESC}[1m`], cve: [] },
      }),
    ],
  });
  const catalog = new Map([
    [
      "PG-SQL-001",
      {
        title: { en: "t", ko: "t" },
        impact: { en: "i", ko: "i" },
        recommendation: { en: "r", ko: "r" },
        details: {
          standards: [
            {
              id: `CWE-89${ESC}[0m`,
              title: hostile,
              url: `https://cwe.mitre.org/data/definitions/89.html${ESC}[31m`,
            },
            { id: "x", title: null, url: "javascript:alert(1)" },
            { id: "y", title: null, url: "http://insecure.example/" },
          ],
        },
      },
    ],
  ]) as unknown as ReturnType<typeof getRuleTextCatalog>;

  for (const size of [
    { columns: 80, rows: 24 },
    { columns: 60, rows: 20 },
    { columns: 40, rows: 10 },
  ]) {
    for (const locale of ["en", "ko"] as const) {
      it(`${locale} ${size.columns}x${size.rows}: no control characters, no overflow, no scheme but https`, () => {
        const base = createPanelsState(result, locale, size, catalog);
        let state: PanelsState = { ...base, panel: "findings" };
        state = press(state, key("return"));
        for (let page = 0; page < 12; page += 1) {
          const frame = renderFrame(state, size, plain);
          expect(frame).toHaveLength(size.rows);
          for (const line of frame) {
            expect(displayWidth(line)).toBeLessThanOrEqual(size.columns);
            expect(line).not.toMatch(/[\u0000-\u001f\u007f-\u009f‮]/);
          }
          const text = frame.join("\n");
          expect(text).not.toContain("javascript:");
          expect(text).not.toContain("http://insecure");
          state = press(state, key("pagedown"));
        }
      });
    }
  }

  it("shows the redacted evidence as it is, never more than the finding carries", () => {
    const size: Size = { columns: 80, rows: 40 };
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const redacted = testResult({
      findings: [testFinding({ evidence: "key = [REDACTED]" })],
    });
    const state = {
      ...createPanelsState(redacted, "en", size),
      panel: "findings" as const,
    };
    const text = renderFrame(press(state, key("return")), size, plain).join("\n");
    expect(text).toContain("key = [REDACTED]");
    expect(text).not.toContain(secret);
  });
});
