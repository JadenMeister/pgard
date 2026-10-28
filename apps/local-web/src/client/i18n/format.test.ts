import { describe, expect, it } from "vitest";
import { formatTime } from "./format";

// 10:35:58 local time, whatever the machine's time zone.
const time = new Date(2026, 9, 28, 10, 35, 58).getTime();

describe("formatTime", () => {
  it("uses the dashboard language, not the system locale", () => {
    const english = formatTime(time, "en");
    expect(english).toMatch(/10:35:58\s?AM/);
    expect(english).not.toMatch(/[가-힣]/);
    const korean = formatTime(time, "ko");
    expect(korean).toContain("오전");
    expect(korean).toContain("10:35:58");
  });
});
