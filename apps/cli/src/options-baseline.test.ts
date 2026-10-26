import { describe, expect, it } from "vitest";
import { getHelpText } from "./help.js";
import { UsageError, parseCommandLine } from "./options.js";

describe("pgard baseline", () => {
  it.each(["set", "show", "clear"] as const)("parses baseline %s", (action) => {
    expect(parseCommandLine(["baseline", action])).toEqual({
      kind: "baseline",
      action,
      fromCurrent: false,
    });
  });

  it("parses --from-current for set only", () => {
    expect(parseCommandLine(["baseline", "set", "--from-current"])).toEqual({
      kind: "baseline",
      action: "set",
      fromCurrent: true,
    });
    for (const action of ["show", "clear"]) {
      expect(() => parseCommandLine(["baseline", action, "--from-current"])).toThrow(UsageError);
    }
    expect(() => parseCommandLine(["scan", "--from-current"])).toThrow(UsageError);
  });

  it("needs a known subcommand and nothing else", () => {
    expect(() => parseCommandLine(["baseline"])).toThrow(/Missing subcommand/);
    expect(() => parseCommandLine(["baseline", "remove"])).toThrow(/Unknown subcommand/);
    expect(() => parseCommandLine(["baseline", "set", "extra"])).toThrow(/Unexpected argument/);
    expect(() => parseCommandLine(["baseline", "set", "--from-current", "--from-current"])).toThrow(
      /more than once/,
    );
  });

  it("does not accept --no-store (the environment variable is the opt-out)", () => {
    expect(() => parseCommandLine(["baseline", "show", "--no-store"])).toThrow(/only available/);
  });

  it("has help that names the opt-outs and history clear", () => {
    expect(parseCommandLine(["baseline", "--help"])).toEqual({ kind: "help", topic: "baseline" });
    const help = getHelpText("baseline");
    expect(help).toContain("PGARD_NO_STORE=1");
    expect(help).toContain("--no-store");
    expect(help).toContain("history clear");
    expect(getHelpText("main")).toContain("pgard baseline set");
  });
});
