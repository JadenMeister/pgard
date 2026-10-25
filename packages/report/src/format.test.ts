import { describe, expect, it } from "vitest";
import {
  formatContextCounts,
  formatFindingSummary,
  formatOutsideContexts,
  formatVendoredSuggestions,
} from "./format.js";
import { finding } from "./test-fixtures.js";

const vendored = (severity: "critical" | "high" | "medium" | "low" | "info") =>
  finding({ id: `v-${severity}`, severity, context: "vendored", confidence: "low" });

describe("vendored suggestion wording", () => {
  it("adds the critical and high counts only when there are any", () => {
    expect(formatVendoredSuggestions([vendored("medium")])).toBe("1 suggestion in vendored code");
    expect(formatVendoredSuggestions([vendored("critical")])).toBe(
      "1 suggestion in vendored code (1 critical)",
    );
    expect(
      formatVendoredSuggestions([
        vendored("high"),
        vendored("info"),
        vendored("critical"),
        vendored("high"),
      ]),
    ).toBe("4 suggestions in vendored code (1 critical, 2 high)");
  });

  it("builds the headline addition from the test count and the vendored findings", () => {
    expect(formatContextCounts({ test: 0, vendored: [] })).toBe("");
    expect(formatContextCounts({ test: 2, vendored: [] })).toBe("plus 2 in test or fixture code");
    expect(formatContextCounts({ test: 1, vendored: [vendored("info"), vendored("high")] })).toBe(
      "plus 1 in test or fixture code, 2 suggestions in vendored code (1 high)",
    );
    expect(formatOutsideContexts({ test: 1, vendored: 1 })).toBe(
      " outside test, fixture or vendored code",
    );
  });

  it("uses the same wording in the report summary", () => {
    expect(formatFindingSummary([finding({}), vendored("critical")])).toBe(
      "1 finding(s): 0 confirmed, 1 suspected, 0 informational. 1 suggestion in vendored code (1 critical), listed last.",
    );
  });
});
