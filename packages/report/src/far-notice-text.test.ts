import { describe, expect, it } from "vitest";
import { REPORT_TEXT } from "./report-text.js";

describe("merged far-expiry notice text (#249)", () => {
  const far = REPORT_TEXT.ko.notices?.far;

  it("names the count and the latest date for several entries", () => {
    const text = far?.("", "", "9999-12-31", 5) ?? "";
    expect(text).toContain("5개");
    expect(text).toContain("9999-12-31");
    expect(text).not.toContain("PG-");
  });

  it("keeps the per-entry text for one entry or an older result without a count", () => {
    for (const count of [1, 0]) {
      const text = far?.("PG-SQL-001", "scripts/**", "2999-01-01", count) ?? "";
      expect(text).toContain("PG-SQL-001");
      expect(text).toContain("2999-01-01");
    }
    expect(far?.("PG-SQL-001", "a", "2999-01-01", 2)).not.toContain("PG-SQL-001");
  });
});
