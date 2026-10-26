import { describe, expect, it } from "vitest";
import { displayWidth } from "../i18n/display-width.js";
import { renderChart } from "./charts.js";

const rows = [
  { label: "Critical", count: 4 },
  { label: "High", count: 2 },
  { label: "Low", count: 0 },
];

describe("renderChart", () => {
  it("draws # bars without colour and scales to the widest count", () => {
    const lines = renderChart(rows, { width: 80, isColor: false });
    expect(lines).toHaveLength(3);
    expect(lines[0]).toMatch(/^ {2}Critical #{30} 4$/);
    expect(lines[1]).toMatch(/^ {2}High {5}#{15} 2$/);
    expect(lines[2]).toBe("  Low      0");
  });

  it("uses block bars with colour", () => {
    const lines = renderChart(rows, { width: 80, isColor: true, unicode: true });
    expect(lines[0]).toContain("█".repeat(30));
    expect(lines.join("")).not.toContain("#");
  });

  it("falls back to ASCII bars when the terminal has no Unicode", () => {
    const lines = renderChart(rows, { width: 80, isColor: true, unicode: false });
    expect(lines[0]).toContain("#");
  });

  it("shrinks bars when long labels leave less room", () => {
    const long = [
      { label: "A05 Software or Data Integrity Failures", count: 9 },
      { label: "A01", count: 3 },
    ];
    const lines = renderChart(long, { width: 60, isColor: false });
    for (const line of lines) expect(displayWidth(line)).toBeLessThanOrEqual(60);
    expect(lines[0]?.split("#").length).toBeLessThan(30);
  });

  it("is plain count lines below 60 columns", () => {
    const lines = renderChart(rows, { width: 59, isColor: true, unicode: true });
    expect(lines.join("\n")).not.toMatch(/[#█]/);
    expect(lines).toEqual(["  Critical 4", "  High     2", "  Low      0"]);
  });

  it("aligns Korean labels by display width", () => {
    const korean = [
      { label: "치명적", count: 3 },
      { label: "높음", count: 1 },
      { label: "정보", count: 0 },
    ];
    const lines = renderChart(korean, { width: 80, isColor: false });
    // The bar starts in the same column on every row that has one.
    const starts = lines
      .filter((line) => line.includes("#"))
      .map((line) => displayWidth(line.slice(0, line.indexOf("#"))));
    expect(new Set(starts).size).toBe(1);
    const narrow = renderChart(korean, { width: 40, isColor: false });
    expect(
      new Set(narrow.map((line) => displayWidth(line.slice(0, line.lastIndexOf(" "))))).size,
    ).toBe(1);
  });

  it("cuts a long label to the room it has", () => {
    const lines = renderChart([{ label: "A".repeat(80), count: 1 }], { width: 60, isColor: false });
    expect(displayWidth(lines[0] ?? "")).toBeLessThanOrEqual(60);
    expect(lines[0]).toContain("...");
  });

  it("is empty without rows", () => {
    expect(renderChart([], { width: 80, isColor: false })).toEqual([]);
  });
});
