import { describe, expect, it } from "vitest";
import { parseCommandLine, UsageError } from "./options.js";

describe("parseCommandLine", () => {
  it("parses every documented command", () => {
    expect(parseCommandLine([])).toEqual({ kind: "menu" });
    expect(parseCommandLine(["--help"])).toEqual({ kind: "help", topic: "main" });
    expect(parseCommandLine(["--version"])).toEqual({ kind: "version" });
    expect(parseCommandLine(["project", "verify"])).toEqual({
      kind: "project-verify",
      noBrowser: false,
    });
    expect(parseCommandLine(["scan"])).toEqual({
      kind: "scan",
      variant: "default",
      port: null,
      report: null,
      noBrowser: false,
    });
    expect(parseCommandLine(["scan", "code"])).toMatchObject({ variant: "code" });
    expect(parseCommandLine(["scan", "history"])).toMatchObject({ variant: "history" });
    expect(parseCommandLine(["scan", "web", "--port", "3000"])).toMatchObject({
      variant: "web",
      port: 3000,
    });
    expect(parseCommandLine(["scan", "all", "--port=8080"])).toMatchObject({
      variant: "all",
      port: 8080,
    });
    expect(parseCommandLine(["dashboard", "--target-port", "5173"])).toEqual({
      kind: "dashboard",
      targetPort: 5173,
      noBrowser: false,
    });
    expect(parseCommandLine(["rules", "list", "--language", "go"])).toEqual({
      kind: "rules-list",
      language: "go",
    });
    expect(parseCommandLine(["doctor"])).toEqual({ kind: "doctor" });
  });

  it("accepts --no-browser for scan, project verify, login and dashboard only", () => {
    expect(parseCommandLine(["scan", "--no-browser"])).toMatchObject({ noBrowser: true });
    expect(parseCommandLine(["scan", "web", "--port", "3000", "--no-browser"])).toMatchObject({
      variant: "web",
      port: 3000,
      noBrowser: true,
    });
    expect(parseCommandLine(["project", "verify", "--no-browser"])).toEqual({
      kind: "project-verify",
      noBrowser: true,
    });
    expect(parseCommandLine(["login", "--no-browser"])).toEqual({ kind: "login", noBrowser: true });
    expect(parseCommandLine(["dashboard", "--no-browser"])).toEqual({
      kind: "dashboard",
      targetPort: null,
      noBrowser: true,
    });
    for (const argv of [
      ["--no-browser"],
      ["doctor", "--no-browser"],
      ["logout", "--no-browser"],
      ["rules", "list", "--no-browser"],
    ]) {
      expect(() => parseCommandLine(argv)).toThrow("--no-browser is not available");
    }
    expect(() => parseCommandLine(["scan", "--no-browser", "--no-browser"])).toThrow(
      "more than once",
    );
    expect(() => parseCommandLine(["scan", "--no-browser=1"])).toThrow("Unknown option");
  });

  it("shows command help", () => {
    expect(parseCommandLine(["scan", "--help"])).toEqual({ kind: "help", topic: "scan" });
    expect(parseCommandLine(["project", "verify", "-h"])).toEqual({
      kind: "help",
      topic: "project verify",
    });
    expect(parseCommandLine(["rules", "list", "--help"])).toEqual({
      kind: "help",
      topic: "rules list",
    });
  });

  it("requires --report and --output-dir together and validates the format", () => {
    expect(
      parseCommandLine(["scan", "--report", "both", "--output-dir", "/tmp/out"]),
    ).toMatchObject({
      report: { format: "both", outputDir: "/tmp/out" },
    });
    expect(() => parseCommandLine(["scan", "--report", "html"])).toThrow(UsageError);
    expect(() => parseCommandLine(["scan", "--output-dir", "/tmp"])).toThrow(UsageError);
    expect(() => parseCommandLine(["scan", "--report", "docx", "--output-dir", "/tmp"])).toThrow(
      UsageError,
    );
  });

  it.each([
    [["unknown"]],
    [["scan", "remote"]],
    [["scan", "dependencies"]],
    [["scan", "code", "--port", "3000"]],
    [["scan", "--port", "3000"]],
    [["scan", "web", "--port", "0"]],
    [["scan", "web", "--port", "65536"]],
    [["scan", "web", "--port", "3000.5"]],
    [["scan", "web", "--port", "-1"]],
    [["scan", "web", "--port", "0x50"]],
    [["scan", "web", "--port"]],
    [["scan", "web", "--port", "3000", "--port", "3001"]],
    [["scan", "--path", "/etc"]],
    [["scan", "--host", "example.com"]],
    [["scan", "--url", "http://example.com"]],
    [["scan", "--force"]],
    [["scan", "--skip-auth"]],
    [["dashboard", "--port", "3000"]],
    [["scan", "web", "--target-port", "3000"]],
    [["rules", "list", "--language", "python"]],
    [["rules"]],
    [["project"]],
    [["project", "verify", "extra"]],
    [["doctor", "--language", "go"]],
    [["scan", "--version"]],
    [["--", "scan"]],
  ])("rejects %j before doing anything", (argv) => {
    expect(() => parseCommandLine(argv)).toThrow(UsageError);
  });

  it("parses --no-store for scan only and history clear with --all or --repo", () => {
    expect(parseCommandLine(["scan", "code", "--no-store"])).toMatchObject({
      kind: "scan",
      variant: "code",
      noStore: true,
    });
    expect(parseCommandLine(["scan"])).not.toHaveProperty("noStore");
    for (const argv of [
      ["doctor", "--no-store"],
      ["project", "verify", "--no-store"],
      ["scan", "--no-store", "--no-store"],
      ["scan", "--all"],
    ]) {
      expect(() => parseCommandLine(argv), argv.join(" ")).toThrow(UsageError);
    }
    expect(parseCommandLine(["history", "clear"])).toEqual({ kind: "history-clear", repo: null });
    expect(parseCommandLine(["history", "clear", "--all"])).toEqual({
      kind: "history-clear",
      repo: null,
    });
    expect(parseCommandLine(["history", "clear", "--repo", "Owner/name.js"])).toEqual({
      kind: "history-clear",
      repo: "Owner/name.js",
    });
    for (const argv of [
      ["history"],
      ["history", "list"],
      ["history", "clear", "--repo", "noslash"],
      ["history", "clear", "--repo", "a/b", "--all"],
      ["history", "clear", "extra"],
      ["history", "clear", "--port", "1"],
    ]) {
      expect(() => parseCommandLine(argv), argv.join(" ")).toThrow(UsageError);
    }
    expect(parseCommandLine(["history", "clear", "--help"])).toEqual({
      kind: "help",
      topic: "history clear",
    });
  });
});
