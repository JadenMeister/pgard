import { describe, expect, it } from "vitest";
import { parseCommandLine, UsageError } from "./options.js";

describe("parseCommandLine precommit", () => {
  it("parses the check, install, uninstall and snippet", () => {
    expect(parseCommandLine(["precommit"])).toEqual({ kind: "precommit", action: "run" });
    expect(parseCommandLine(["precommit", "install"])).toEqual({
      kind: "precommit",
      action: "install",
    });
    expect(parseCommandLine(["precommit", "uninstall"])).toEqual({
      kind: "precommit",
      action: "uninstall",
    });
    expect(parseCommandLine(["precommit", "snippet", "--lang", "ko"])).toEqual({
      kind: "precommit",
      action: "snippet",
      lang: "ko",
    });
    expect(parseCommandLine(["precommit", "--help"])).toEqual({ kind: "help", topic: "precommit" });
    expect(parseCommandLine(["precommit", "install", "--help"])).toEqual({
      kind: "help",
      topic: "precommit",
    });
  });

  it("rejects unknown subcommands, extra arguments and options of other commands", () => {
    expect(() => parseCommandLine(["precommit", "bogus"])).toThrow(UsageError);
    expect(() => parseCommandLine(["precommit", "install", "x"])).toThrow(UsageError);
    for (const option of ["--no-store", "--full", "--no-browser", "--force", "--all-findings"]) {
      expect(() => parseCommandLine(["precommit", option])).toThrow(UsageError);
    }
    expect(() => parseCommandLine(["precommit", "--format", "json"])).toThrow(UsageError);
    expect(() => parseCommandLine(["precommit", "--port", "3000"])).toThrow(UsageError);
  });
});
