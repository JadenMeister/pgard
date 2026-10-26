import { describe, expect, it } from "vitest";
import { SOURCE_RULES } from "./rules.js";

describe("source rule metadata", () => {
  it("keeps every rationale within 500 characters in both languages", () => {
    for (const rule of SOURCE_RULES) {
      for (const language of ["en", "ko"] as const) {
        expect(rule.rationale[language].length, `${rule.id} ${language}`).toBeLessThanOrEqual(500);
      }
    }
  });
});
