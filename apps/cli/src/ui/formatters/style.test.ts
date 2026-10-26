import { describe, expect, it } from "vitest";
import { isUnicodeTerminal, shouldUseColor, toTerminalText } from "./style.js";

describe("shouldUseColor", () => {
  it("needs a TTY and respects NO_COLOR and TERM=dumb", () => {
    expect(shouldUseColor({ isTTY: true }, {})).toBe(true);
    expect(shouldUseColor({ isTTY: false }, {})).toBe(false);
    expect(shouldUseColor({ isTTY: true }, { NO_COLOR: "1" })).toBe(false);
    expect(shouldUseColor({ isTTY: true }, { NO_COLOR: "" })).toBe(true);
    expect(shouldUseColor({ isTTY: true }, { TERM: "dumb" })).toBe(false);
  });
});

describe("Unicode fallback", () => {
  it("assumes Unicode on Unix terminals except the Linux console", () => {
    expect(isUnicodeTerminal({ TERM: "xterm" }, "darwin")).toBe(true);
    expect(isUnicodeTerminal({ TERM: "linux" }, "linux")).toBe(false);
  });

  it("requires a known modern host on Windows", () => {
    expect(isUnicodeTerminal({}, "win32")).toBe(false);
    expect(isUnicodeTerminal({ WT_SESSION: "x" }, "win32")).toBe(true);
    expect(isUnicodeTerminal({ TERM_PROGRAM: "vscode" }, "win32")).toBe(true);
  });

  it("replaces punctuation with ASCII only where Unicode is not expected", () => {
    const text = "cut … — “q” ’";
    expect(toTerminalText(text, {}, "win32")).toBe('cut ... - "q" \'');
    expect(toTerminalText(text, { WT_SESSION: "x" }, "win32")).toBe(text);
    expect(toTerminalText(text, { TERM: "xterm" }, "linux")).toBe(text);
  });
});
