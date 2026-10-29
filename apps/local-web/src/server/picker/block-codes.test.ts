import { describe, expect, it } from "vitest";
import { BLOCK_TEXT } from "./candidates.js";
import { PICKER_BLOCK_CODES } from "./protocol.js";

describe("block codes", () => {
  it("have a fixed server text, and nothing else", () => {
    expect(Object.keys(BLOCK_TEXT).sort()).toEqual([...PICKER_BLOCK_CODES].sort());
    expect(PICKER_BLOCK_CODES).toHaveLength(15);
  });

  it("every code has a reason and a fix", () => {
    for (const code of PICKER_BLOCK_CODES) {
      expect(BLOCK_TEXT[code].reason.length).toBeGreaterThan(10);
      expect(BLOCK_TEXT[code].fix.length).toBeGreaterThan(10);
    }
  });
});
