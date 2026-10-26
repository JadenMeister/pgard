import { describe, expect, it } from "vitest";
import {
  charWidth,
  displayWidth,
  maxDisplayWidth,
  padEndWidth,
  padStartWidth,
  stripAnsi,
  truncateWidth,
} from "./display-width.js";

describe("display width", () => {
  it("counts Hangul and other wide characters as two columns", () => {
    expect(displayWidth("abc")).toBe(3);
    expect(displayWidth("검사")).toBe(4);
    expect(displayWidth("PGARD 검사 결과")).toBe(5 + 1 + 4 + 1 + 4);
    expect(displayWidth("가나다 abc")).toBe(10);
    expect(charWidth("́")).toBe(0);
    expect(charWidth("​")).toBe(0);
  });

  it("ignores colour codes", () => {
    const colored = "\u001b[31m치명적\u001b[39m";
    expect(stripAnsi(colored)).toBe("치명적");
    expect(displayWidth(colored)).toBe(6);
  });

  it("pads by columns, so Korean and English labels end in the same column", () => {
    const labels = ["영역", "규칙", "대상 크기", "Areas"];
    const widest = maxDisplayWidth(labels);
    const padded = labels.map((label) => `${padEndWidth(label, widest)}|`);
    expect(new Set(padded.map((line) => displayWidth(line))).size).toBe(1);
    expect(padStartWidth("검사", 6)).toBe("  검사");
  });

  it("never cuts a wide character in half when truncating", () => {
    const cut = truncateWidth("가나다라마바사", 9);
    expect(displayWidth(cut)).toBeLessThanOrEqual(9);
    expect(cut.endsWith("...")).toBe(true);
    expect(truncateWidth("짧음", 9)).toBe("짧음");
  });
});
