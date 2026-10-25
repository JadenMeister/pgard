import { describe, expect, it } from "vitest";
import { LEGAL_POINTS } from "./LegalNotice";

const text = LEGAL_POINTS.join("\n");

describe("dashboard privacy notice", () => {
  it("says PGARD has no vulnerability database and analysis is code-based", () => {
    expect(text).not.toMatch(/advisory/i);
    expect(text).not.toContain("PGARD_ADVISORY_DB");
    expect(text).toContain(
      "PGARD does not ship or query a vulnerability database. Findings come from the code itself (query statements, server code, configuration), Git history and, if selected, local HTTP checks. Dependency versions are not checked against known vulnerabilities.",
    );
  });

  it("says the GitHub sign-in is kept in the OS keychain, not memory only and not in a file", () => {
    expect(text).toContain("saved in the OS keychain");
    expect(text).toMatch(/never in a file/);
    expect(text).toMatch(/never sent to the browser/);
    expect(text).toContain("pgard logout");
    expect(text).not.toMatch(/GitHub sign-in live only in memory/);
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
