import { describe, expect, it } from "vitest";
import { getHelpText } from "./help.js";
import { CLI_TEXT } from "./ui/i18n/cli-text.js";

/**
 * The external-communication notices of the CLI, pinned so they cannot drift from the README
 * section "Privacy and network traffic" and from what the code really sends.
 */
describe("external-communication notices", () => {
  it("the main help names every destination and says scans and sbom upload nothing", () => {
    const text = getHelpText("main");
    expect(text).toContain("processed locally and never uploaded");
    expect(text).toContain("scans and pgard sbom contact GitHub for");
    expect(text).toContain("github.com, api.github.com");
    expect(text).toContain("osv-vulnerabilities.storage.googleapis.com");
    expect(text).toContain("only when\nyou run pgard advisories update");
    expect(text).not.toMatch(/GitHub for sign-in and repository metadata only/);
  });

  it("the advisories help states the source, integrity checks, storage and that nothing is sent", () => {
    const text = getHelpText("advisories update");
    expect(text).toContain(
      "https://osv-vulnerabilities.storage.googleapis.com/ (https only, that host only)",
    );
    expect(text).toContain("PGARD's data directory on this computer");
    expect(text).toContain("It runs\nonly when you run this command, never during a scan");
    expect(text).toContain("no package names, no project data\nand no sign-in");
    expect(text).toContain("per-record checksums");
  });

  it("the scan help says dependencies are matched against the downloaded data only", () => {
    const text = getHelpText("scan");
    expect(text).toContain("Scans never download advisory data and");
    expect(text).toContain("never query a vulnerability database");
    expect(text).not.toMatch(/dependenc[a-z]* (are|is) not (checked|scanned)/i);
  });

  it("the doctor help lists the advisory data status and its only request", () => {
    const text = getHelpText("doctor");
    expect(text).toContain("present or missing, age, stale after 7 days, data version, store path");
    expect(text).toContain("unauthenticated HEAD to\napi.github.com");
  });

  it("the login help names the two GitHub hosts", () => {
    const text = getHelpText("login");
    expect(text).toContain("Login contacts only\ngithub.com and api.github.com");
    expect(text).toContain("your code and results are never sent");
  });

  it("the sign-in prompts say where the sign-in goes, in English and Korean", () => {
    const en = CLI_TEXT.en.commands;
    const ko = CLI_TEXT.ko.commands;
    const device = en.signIn.deviceCode("https://github.com/login/device", "ABCD-1234", 15);
    expect(device).toContain(
      "Sign-in talks to github.com and api.github.com only; your code and results are never sent.",
    );
    expect(ko.signIn.deviceCode("https://github.com/login/device", "ABCD-1234", 15)).toContain(
      "로그인은 github.com과 api.github.com하고만 통신하며 코드와 결과는 전송하지 않습니다.",
    );
    expect(en.firstRun.notSignedIn).toContain("github.com and api.github.com only");
    expect(en.firstRun.notSignedIn).toContain("never leave this computer");
    expect(ko.firstRun.notSignedIn).toContain("github.com과 api.github.com하고만 통신");
  });
});
