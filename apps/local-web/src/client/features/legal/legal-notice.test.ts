import { describe, expect, it } from "vitest";
import { LEGAL_POINTS } from "./LegalNotice";

const text = LEGAL_POINTS.join("\n");

describe("dashboard privacy notice", () => {
  it("does not promise advisory updates that do not exist", () => {
    expect(text).not.toMatch(/updat\w* advisory|advisory data, when you choose/i);
    expect(text).toContain("PGARD_ADVISORY_DB");
    expect(text).toMatch(/no advisory update command/i);
  });

  it("lists the network traffic described in the README", () => {
    expect(text).toContain("device-flow sign-in on github.com");
    expect(text).toContain("GitHub API calls");
    expect(text).toContain("SHAs of local commits");
    expect(text).toContain("pgard doctor");
    expect(text).toContain("api.github.com");
    expect(text).toMatch(/after authorization passes.*127\.0\.0\.1/i);
  });
});
