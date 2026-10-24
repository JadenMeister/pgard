import { describe, expect, it } from "vitest";
import { parseCommandLine, UsageError } from "./options.js";

describe("parseCommandLine", () => {
  it("parses every documented command", () => {
    expect(parseCommandLine([])).toEqual({ kind: "menu" });
    expect(parseCommandLine(["--help"])).toEqual({ kind: "help", topic: "main" });
    expect(parseCommandLine(["--version"])).toEqual({ kind: "version" });
    expect(parseCommandLine(["project", "verify"])).toEqual({ kind: "project-verify" });
    expect(parseCommandLine(["scan"])).toEqual({
      kind: "scan",
      variant: "default",
      port: null,
      report: null,
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
    });
    expect(parseCommandLine(["rules", "list", "--language", "go"])).toEqual({
      kind: "rules-list",
      language: "go",
    });
    expect(parseCommandLine(["doctor"])).toEqual({ kind: "doctor" });
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
});
