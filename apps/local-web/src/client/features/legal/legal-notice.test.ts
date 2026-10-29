import { describe, expect, it } from "vitest";
import { ko } from "../../i18n/ko";
import { LEGAL_POINTS } from "./LegalNotice";

const text = LEGAL_POINTS.join("\n");

describe("dashboard privacy notice", () => {
  it("says PGARD ships no vulnerability database and what the dependency match means", () => {
    expect(text).not.toMatch(/advisory/i);
    expect(text).not.toContain("PGARD_ADVISORY_DB");
    expect(text).toContain(
      "PGARD does not ship a vulnerability database and a scan never downloads or queries one. Findings come from the code itself (query statements, server code, configuration), Git history, if selected local HTTP checks and, for npm and Go lockfiles, a version match against the OSV data you downloaded with pgard advisories update (not proof that the vulnerable code is reachable or exploitable).",
    );
  });

  it("names the OSV download host as the only other destination and what it never sends", () => {
    expect(text).toContain(
      "The only other external destination is osv-vulnerabilities.storage.googleapis.com, and only when you run pgard advisories update in a terminal: it downloads public OSV vulnerability data over https and uploads nothing (no package names, no lockfile contents, no GitHub sign-in).",
    );
    expect(text).toContain("Scans, SBOM generation and this dashboard never start that download");
    expect(text).toContain("never send your code, lockfiles or results anywhere");
    expect(text).not.toContain("The only external network traffic is to GitHub");
  });

  it("is mirrored in Korean with the same destinations", () => {
    const korean = ko.legal.points.join("\n");
    for (const needle of [
      "api.github.com",
      "osv-vulnerabilities.storage.googleapis.com",
      "pgard advisories update",
      "SBOM",
    ]) {
      expect(korean).toContain(needle);
    }
    expect(korean).not.toContain("GitHub로만");
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
