/// <reference types="node" />
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const tokens = readFileSync(new URL("./tokens.css", import.meta.url), "utf8");
const app = readFileSync(new URL("./app.css", import.meta.url), "utf8");

/** `--name: #hex` pairs of one CSS block. */
function colours(block: string): Record<string, string> {
  return Object.fromEntries(
    [...block.matchAll(/--(color-[a-z-]+):\s*(#[0-9a-f]{6})/gi)].map((match) => [
      match[1] as string,
      (match[2] as string).toLowerCase(),
    ]),
  );
}

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((offset) => {
    const value = parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (light + 0.05) / (dark + 0.05);
}

const darkStart = tokens.indexOf("@media (prefers-color-scheme: dark)");
const light = colours(tokens.slice(0, darkStart));
const dark = { ...light, ...colours(tokens.slice(darkStart)) };

describe.each([
  ["light", light],
  ["dark", dark],
])("%s theme tokens", (_name, theme) => {
  const text = ["color-ink", "color-muted", "color-accent", "color-danger", "color-warning"];

  it.each(text)("%s meets WCAG AA (4.5:1) on the page and on subtle fills", (token) => {
    expect(contrast(theme[token] as string, theme["color-page"] as string)).toBeGreaterThanOrEqual(
      4.5,
    );
    expect(contrast(theme[token] as string, theme["color-fill"] as string)).toBeGreaterThanOrEqual(
      4.5,
    );
  });

  it("gives controls a 3:1 outline and primary buttons readable text", () => {
    expect(
      contrast(theme["color-control"] as string, theme["color-page"] as string),
    ).toBeGreaterThanOrEqual(3);
    // Primary buttons are ink on page colour, inverted.
    expect(
      contrast(theme["color-page"] as string, theme["color-ink"] as string),
    ).toBeGreaterThanOrEqual(7);
  });
});

describe("type scale", () => {
  it("never sets text below 13px", () => {
    const sizes = [
      ...[...tokens.matchAll(/--text-[a-z0-9]+:\s*([0-9.]+)rem/g)].map((m) => Number(m[1]) * 16),
      ...[...app.matchAll(/font(?:-size)?:[^;]*?\b([0-9.]+)px/g)].map((m) => Number(m[1])),
      ...[...app.matchAll(/font-size:\s*([0-9.]+)rem/g)].map((m) => Number(m[1]) * 16),
    ];
    expect(sizes.length).toBeGreaterThan(5);
    expect(Math.min(...sizes)).toBeGreaterThanOrEqual(13);
  });

  it("uses no gradients, glows or heavy shadows", () => {
    expect(app).not.toMatch(/gradient\(|box-shadow|text-shadow|filter:/);
  });
});
