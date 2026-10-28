import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { getHelpText } from "./help.js";
import { ALL_OPTION_NAMES, HELP_TOPICS, parseCommandLine, UsageError } from "./options.js";

/** Sample values that are valid for the value options, so only "is it accepted" is probed. */
const SAMPLE_VALUES: Record<string, string> = {
  "--port": "3000",
  "--target-port": "3000",
  "--report": "html",
  "--output-dir": "out",
  "--language": "go",
  "--format": "html",
  "--repo": "owner/name",
  "--lang": "en",
  "--report-lang": "en",
};

/** Every command path the parser has, as the argv that reaches it. */
const COMMANDS: readonly string[][] = [
  ["scan"],
  ["scan", "code"],
  ["scan", "history"],
  ["scan", "web"],
  ["scan", "all"],
  ["report"],
  ["dashboard"],
  ["project", "verify"],
  ["rules", "list"],
  ["history", "clear"],
  ["baseline", "set"],
  ["baseline", "show"],
  ["baseline", "clear"],
  ["advisories", "update"],
  ["doctor"],
  ["login"],
  ["logout"],
];

/** The options the parser accepts for `base`, found by asking the parser itself. */
function acceptedOptions(base: readonly string[]): string[] {
  return ALL_OPTION_NAMES.filter((name) => {
    const value = SAMPLE_VALUES[name];
    try {
      parseCommandLine([...base, name, ...(value === undefined ? [] : [value])]);
      return true;
    } catch (error) {
      if (!(error instanceof UsageError)) throw error;
      // Rejected as an option of another command; any other error means it was accepted.
      return !/not available|only available|Unknown option/.test(error.message);
    }
  });
}

function helpOf(path: readonly string[]): string {
  const parsed = parseCommandLine([...path, "--help"]);
  if (parsed.kind !== "help") throw new Error(`${path.join(" ")} --help is not help`);
  return getHelpText(parsed.topic);
}

function mentions(text: string, option: string): boolean {
  return new RegExp(`${option}(?![-\\w])`).test(text);
}

describe("command help lists every accepted option", () => {
  for (const path of COMMANDS) {
    it(`pgard ${path.join(" ")} --help`, () => {
      const text = helpOf(path);
      for (const option of acceptedOptions(path)) {
        expect(mentions(text, option), `${option} missing from help of ${path.join(" ")}`).toBe(
          true,
        );
      }
    });
  }

  it("the accepted options are really found (the probe is not vacuous)", () => {
    expect(acceptedOptions(["project", "verify"])).toEqual(["--no-browser"]);
    expect(acceptedOptions(["rules", "list"])).toEqual(["--language", "--lang"]);
    expect(acceptedOptions(["advisories", "update"])).toEqual(["--force"]);
    expect(acceptedOptions(["scan", "web"])).toContain("--port");
    expect(acceptedOptions(["scan", "code"])).not.toContain("--port");
  });

  it("a command group's help covers the options of its subcommands", () => {
    for (const group of ["project", "rules", "history", "baseline", "advisories"]) {
      const text = helpOf([group]);
      for (const path of COMMANDS.filter((entry) => entry[0] === group)) {
        for (const option of acceptedOptions(path)) {
          expect(mentions(text, option), `${option} missing from pgard ${group} --help`).toBe(true);
        }
      }
    }
  });

  it("the main help names every option of every command", () => {
    const text = getHelpText("main");
    for (const path of COMMANDS) {
      for (const option of acceptedOptions(path)) {
        expect(mentions(text, option), `${option} missing from pgard --help`).toBe(true);
      }
    }
  });

  it("every option string in the parser source is in the checked list", () => {
    const source = readFileSync(new URL("./options.ts", import.meta.url), "utf8");
    const found = optionStringsIn(source);
    expect(found.length).toBeGreaterThan(10);
    for (const name of found) expect(ALL_OPTION_NAMES).toContain(name);
  });

  it("the source scan sees single-quoted, template and short-alias option strings", () => {
    const mutant = [
      "if (arg === `--quiet`) {}",
      "if (arg === '--loud') {}",
      'if (arg === "-q") {}',
      'const ok = "--help"; const v = "-V"; const sep = "--";',
    ].join("\n");
    expect(optionStringsIn(mutant).sort()).toEqual(["--loud", "--quiet", "-q"]);
  });
});

/** Quoted option-like strings (double, single or template quotes, long or short) in `source`. */
function optionStringsIn(source: string): string[] {
  const ignored = new Set(["--help", "-h", "--version", "-V"]);
  return [...source.matchAll(/["'`](--?[a-zA-Z][\w-]*)["'`]/g)]
    .map((match) => match[1] ?? "")
    .filter((name) => !ignored.has(name));
}

describe("pgard help", () => {
  it("is an alias for <command> --help", () => {
    expect(parseCommandLine(["help"])).toEqual({ kind: "help", topic: "main" });
    expect(parseCommandLine(["help", "scan"])).toEqual({ kind: "help", topic: "scan" });
    expect(parseCommandLine(["help", "scan", "code"])).toEqual({ kind: "help", topic: "scan" });
    expect(parseCommandLine(["help", "rules", "list"])).toEqual({
      kind: "help",
      topic: "rules list",
    });
    expect(parseCommandLine(["help", "baseline", "set"])).toEqual({
      kind: "help",
      topic: "baseline",
    });
    expect(parseCommandLine(["help", "report"])).toEqual({ kind: "help", topic: "report" });
  });

  it("help help prints the main help; help takes no options", () => {
    expect(parseCommandLine(["help", "help"])).toEqual({ kind: "help", topic: "main" });
    for (const argv of [
      ["help", "scan", "--no-store"],
      ["help", "scan", "--full"],
      ["help", "--port", "3"],
      ["help", "history", "--all"],
    ]) {
      expect(() => parseCommandLine(argv)).toThrow("pgard help takes no options.");
    }
  });

  it("rejects unknown commands and extra arguments", () => {
    expect(() => parseCommandLine(["help", "nope"])).toThrow(UsageError);
    expect(() => parseCommandLine(["help", "scan", "bogus"])).toThrow(UsageError);
    expect(() => parseCommandLine(["help", "scan", "code", "x"])).toThrow(UsageError);
    expect(() => parseCommandLine(["help", "scan", "--port", "3"])).toThrow(UsageError);
  });

  it("resolves every help topic", () => {
    for (const topic of HELP_TOPICS) expect(getHelpText(topic).length).toBeGreaterThan(20);
    for (const path of COMMANDS) expect(helpOf(path)).toContain("pgard");
  });

  it("documents what a plain pgard scan does", () => {
    const text = getHelpText("scan");
    expect(text).toContain("With no options");
    expect(text).toContain("Git");
  });
});
