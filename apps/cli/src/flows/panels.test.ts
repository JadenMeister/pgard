import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { ReportWriteError, writeReports } from "@pgard/report";
import { afterAll, describe, expect, it, vi } from "vitest";
import { main } from "../app.js";
import type { CliDeps } from "../deps.js";
import { runScanCommand } from "../commands/scan/index.js";
import { runReportExport } from "./export-report.js";
import { getRuleTextCatalog } from "../rule-texts.js";
import { parseCommandLine, UsageError } from "../options.js";
import {
  createTestContext,
  createSignedInCredentialStore,
  createTestDeps,
  createTestIo,
  noInterrupts,
  panelsFixtureResult,
  scriptedKeys,
  testFinding,
  testResult,
} from "../test-support.js";
import { UserCancelledError } from "../ui/components/prompts.js";
import { offerPanels, PANELS_ONCE_ENV } from "./panels.js";

const ENTER = "\u001b[?1049h";
const LEAVE = "\u001b[?1049l";
/** The fixture is a partial scan: exit code 4, whatever the view does. */
const PARTIAL = 4;

function deps(runScan = vi.fn(async (_request: unknown) => panelsFixtureResult())) {
  return { runScan, deps: createTestDeps({ runScan }) };
}

describe("--panels option", () => {
  it("is accepted by pgard scan and by every scan type", () => {
    expect(parseCommandLine(["scan", "--panels"])).toMatchObject({ kind: "scan", panels: true });
    expect(parseCommandLine(["scan", "code", "--panels", "--format", "text"])).toMatchObject({
      panels: true,
    });
    expect(parseCommandLine(["scan", "code"])).not.toHaveProperty("panels");
  });

  it("is a usage error with --format json or sarif, and for other commands", () => {
    expect(() => parseCommandLine(["scan", "--panels", "--format", "json"])).toThrow(UsageError);
    expect(() => parseCommandLine(["scan", "--format=sarif", "--panels"])).toThrow(
      /cannot be combined with --format sarif/,
    );
    expect(() => parseCommandLine(["doctor", "--panels"])).toThrow(/only available for pgard scan/);
    expect(() => parseCommandLine(["scan", "--panels", "--panels"])).toThrow(/more than once/);
  });

  it("is rejected before authorization, any scan or any network call", async () => {
    const { runScan, deps: testDeps } = deps();
    const findGitRoot = vi.fn(async () => "/work/repo");
    const captured = createTestIo({ isTTY: true });
    const code = await main(["scan", "--panels", "--format", "json"], captured.io, {
      deps: { ...testDeps, findGitRoot },
      interrupts: noInterrupts,
    });
    expect(code).toBe(2);
    expect(findGitRoot).not.toHaveBeenCalled();
    expect(runScan).not.toHaveBeenCalled();
    expect(captured.stderr()).toContain("--panels cannot be combined with --format json");
    expect(captured.stdout()).toBe("");
  });

  it("is documented in scan help and kept apart from the web dashboard", async () => {
    const captured = createTestIo();
    await main(["scan", "--help"], captured.io, {
      deps: createTestDeps(),
      interrupts: noInterrupts,
    });
    expect(captured.stdout()).toContain("--panels");
    expect(captured.stdout().replace(/\s+/g, " ")).toContain("pgard dashboard is the");
  });
});

describe("non-interactive output", () => {
  it("never enters the full-screen view when stdout is not a terminal", async () => {
    const { deps: testDeps } = deps();
    const captured = createTestIo({ isTTY: false });
    const code = await main(["scan", "--panels"], captured.io, {
      deps: testDeps,
      interrupts: noInterrupts,
    });
    expect(code).toBe(PARTIAL);
    expect(captured.stdout()).not.toContain(ENTER);
    expect(captured.stdout()).not.toContain("\u001b[?25l");
    expect(captured.stdout()).toContain("PGARD scan result");
    expect(captured.stderr()).toContain("--panels needs a terminal");
  });

  it("also stays out when only stdin is not a terminal", async () => {
    const { deps: testDeps } = deps();
    const captured = createTestIo({ isTTY: true });
    (captured.io.stdin as unknown as { isTTY: boolean }).isTTY = false;
    const code = await main(["scan", "--panels"], captured.io, {
      deps: testDeps,
      interrupts: noInterrupts,
    });
    expect(code).toBe(PARTIAL);
    expect(captured.stdout()).not.toContain(ENTER);
  });

  it("prints the text result unchanged without --panels", async () => {
    const { deps: testDeps } = deps();
    const withFlag = createTestIo({ isTTY: false });
    const without = createTestIo({ isTTY: false });
    await main(["scan"], without.io, { deps: testDeps, interrupts: noInterrupts });
    await main(["scan", "--panels"], withFlag.io, { deps: testDeps, interrupts: noInterrupts });
    expect(withFlag.stdout()).toBe(without.stdout());
    expect(without.stderr()).not.toContain("--panels");
  });

  it("keeps --format json output untouched", async () => {
    const { deps: testDeps } = deps();
    const captured = createTestIo({ isTTY: false });
    await main(["scan", "--format", "json"], captured.io, {
      deps: testDeps,
      interrupts: noInterrupts,
    });
    expect(() => JSON.parse(captured.stdout())).not.toThrow();
  });
});

describe("render-once path (also run on windows-latest by the normal test suite)", () => {
  it("prints one frame after the text result, with no screen-control codes and no key reads", async () => {
    const { deps: testDeps } = deps();
    const captured = createTestIo({
      isTTY: false,
      env: { [PANELS_ONCE_ENV]: "1", COLUMNS: "80", LINES: "24", PGARD_LANG: "en" },
    });
    const code = await main(["scan", "--panels"], captured.io, {
      deps: testDeps,
      interrupts: noInterrupts,
    });
    expect(code).toBe(PARTIAL);
    const out = captured.stdout();
    const frame = out.slice(out.lastIndexOf("PGARD panels"));
    expect(frame).toContain("[Overview]");
    expect(frame).toContain("Findings (12)");
    expect(frame).not.toContain("\u001b");
    expect(out).not.toContain(ENTER);
  });

  it("renders Korean chrome with --lang ko", async () => {
    const { deps: testDeps } = deps();
    const captured = createTestIo({ isTTY: false, env: { [PANELS_ONCE_ENV]: "1" } });
    await main(["scan", "--panels", "--lang", "ko"], captured.io, {
      deps: testDeps,
      interrupts: noInterrupts,
    });
    expect(captured.stdout()).toContain("PGARD 패널");
    expect(captured.stdout()).toContain("[개요]");
  });

  it("is ignored without --panels", async () => {
    const { deps: testDeps } = deps();
    const captured = createTestIo({ isTTY: false, env: { [PANELS_ONCE_ENV]: "1" } });
    await main(["scan"], captured.io, { deps: testDeps, interrupts: noInterrupts });
    expect(captured.stdout()).not.toContain("PGARD panels");
  });
});

describe("offerPanels", () => {
  function terminal() {
    const captured = createTestIo({ isTTY: true });
    (captured.io.stdout as unknown as { columns: number; rows: number }).columns = 80;
    (captured.io.stdout as unknown as { columns: number; rows: number }).rows = 24;
    return captured;
  }

  it("opens the view for --panels in a terminal and returns on Esc", async () => {
    const captured = terminal();
    const context = createTestContext(captured, createTestDeps(), scriptedKeys(["tab", "escape"]));
    await offerPanels(context, panelsFixtureResult(), true);
    expect(captured.stdout()).toContain(ENTER);
    expect(captured.stdout().endsWith(LEAVE)).toBe(true);
  });

  it("shows the Trend panel from the loaded history, and survives a loader that throws", async () => {
    const captured = terminal();
    const context = createTestContext(
      captured,
      createTestDeps(),
      scriptedKeys(["tab", "tab", "tab", "escape"]),
    );
    await offerPanels(context, panelsFixtureResult(), true, true, async () => ({
      kind: "disabled",
    }));
    expect(captured.stdout()).toContain("storing is off");
    expect(captured.stdout().endsWith(LEAVE)).toBe(true);

    const second = terminal();
    const again = createTestContext(second, createTestDeps(), scriptedKeys(["tab", "escape"]));
    await offerPanels(again, panelsFixtureResult(), true, true, async () => {
      throw new Error("store exploded");
    });
    expect(second.stdout()).toContain(ENTER);
    expect(second.stderr()).not.toContain("store exploded");
  });

  it("renders the one-frame path even when the history loader throws", async () => {
    const captured = createTestIo({ isTTY: false, env: { [PANELS_ONCE_ENV]: "1" } });
    const context = createTestContext(captured, createTestDeps());
    await offerPanels(context, panelsFixtureResult(), true, true, async () => {
      throw new Error("store exploded");
    });
    expect(captured.stdout()).toContain("PGARD panels");
    expect(captured.stdout()).not.toContain("store exploded");
  });

  it("ends as a cancellation (exit 130 at the top level) after a confirmed Ctrl+C", async () => {
    const captured = terminal();
    const context = createTestContext(
      captured,
      createTestDeps(),
      scriptedKeys([{ name: "c", sequence: "\u0003", ctrl: true }, "y"]),
    );
    await expect(offerPanels(context, panelsFixtureResult(), true)).rejects.toBeInstanceOf(
      UserCancelledError,
    );
    expect(captured.stdout().endsWith(LEAVE)).toBe(true);
  });

  async function menuRun(env: Record<string, string>) {
    const captured = terminal();
    const context = createTestContext(captured, createTestDeps(), scriptedKeys(["escape"]), true);
    context.io.env = env;
    await offerPanels(context, panelsFixtureResult(), false);
    return captured;
  }

  it("opens by itself in the menu in a terminal", async () => {
    const captured = await menuRun({});
    expect(captured.stdout()).toContain(ENTER);
    expect(captured.stdout().endsWith(LEAVE)).toBe(true);
    expect(captured.stderr()).toBe("");
  });

  it("does not open in the menu without a terminal", async () => {
    const captured = createTestIo({ isTTY: false });
    const context = createTestContext(captured, createTestDeps(), null, true);
    await offerPanels(context, panelsFixtureResult(), false);
    expect(captured.stdout()).toBe("");
    expect(captured.stderr()).toBe("");
  });

  it("is turned off in the menu by PGARD_PANELS=off, 0, false or no in any case", async () => {
    for (const value of ["off", "OFF", "0", "false", "False", "no", " No "]) {
      const captured = await menuRun({ PGARD_PANELS: value });
      expect(captured.stdout(), value).not.toContain(ENTER);
      expect(captured.stderr(), value).toBe("");
    }
  });

  it("keeps the default on for on-like values and says so for unknown ones", async () => {
    for (const value of ["on", "1", "true", "yes", ""]) {
      const captured = await menuRun({ PGARD_PANELS: value });
      expect(captured.stdout(), value).toContain(ENTER);
      expect(captured.stderr(), value).toBe("");
    }
    const captured = await menuRun({ PGARD_PANELS: "maybe" });
    expect(captured.stdout()).toContain(ENTER);
    expect(captured.stderr()).toContain("PGARD_PANELS is not off, 0, false or no");
    const ko = createTestIo({ isTTY: true, env: { PGARD_PANELS: "maybe" } });
    const koContext = createTestContext(ko, createTestDeps(), scriptedKeys(["escape"]), true);
    koContext.ruleLocale = "ko";
    await offerPanels(koContext, panelsFixtureResult(), false);
    expect(ko.stderr()).toContain("PGARD_PANELS 값이");
  });

  it("lets --panels win over PGARD_PANELS=off", async () => {
    const captured = terminal();
    captured.io.env = { PGARD_PANELS: "off" };
    const context = createTestContext(captured, createTestDeps(), scriptedKeys(["escape"]));
    await offerPanels(context, panelsFixtureResult(), true);
    expect(captured.stdout()).toContain(ENTER);
  });

  it("opens for a plain pgard scan command in a terminal, like the menu", async () => {
    const captured = terminal();
    const context = createTestContext(captured, createTestDeps(), scriptedKeys(["escape"]));
    await offerPanels(context, panelsFixtureResult(), false);
    expect(captured.stdout()).toContain(ENTER);
    expect(captured.stdout().endsWith(LEAVE)).toBe(true);
    expect(captured.stderr()).toBe("");
  });

  it("stays closed for a plain pgard scan command with PGARD_PANELS=off", async () => {
    const captured = terminal();
    captured.io.env = { PGARD_PANELS: "off" };
    const context = createTestContext(captured, createTestDeps(), scriptedKeys([]));
    await offerPanels(context, panelsFixtureResult(), false);
    expect(captured.stdout()).toBe("");
    expect(captured.stderr()).toBe("");
  });

  it("does not open for a plain pgard scan command without a terminal", async () => {
    const captured = createTestIo({ isTTY: false });
    const context = createTestContext(captured, createTestDeps(), scriptedKeys([]));
    await offerPanels(context, panelsFixtureResult(), false);
    expect(captured.stdout()).toBe("");
    expect(captured.stderr()).toBe("");
  });
});

describe("menu scan, end to end", () => {
  async function runMenu(env: Record<string, string>) {
    const captured = createTestIo({ isTTY: true, env });
    const { stdin } = captured;
    stdin.setRawMode = () => undefined;
    const running = main([], captured.io, {
      deps: createTestDeps({
        runScan: async () => panelsFixtureResult(),
        createSessionProvider: () => (async () => ({})) as never,
        credentialStore: createSignedInCredentialStore(),
      }),
      interrupts: noInterrupts,
    });
    const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
    const press = async (sequence: string, after = 15): Promise<void> => {
      await wait(after);
      stdin.write(sequence);
    };
    await press("\u001b[B");
    await press("\u001b[B");
    await press("\r"); // "Scan code"
    await wait(250);
    return { captured, running, press, wait };
  }

  it("shows the text result, then the panels, then asks the report question", async () => {
    const { captured, running, press, wait } = await runMenu({});
    await press("\u001b"); // Esc leaves the panels (readline waits ~500 ms to know it is Esc)
    await wait(800);
    await press("\u001b"); // Esc: no report
    await wait(800);
    await press("x"); // any key back to the menu
    await press("\u001b"); // quit
    await running;
    const out = captured.stdout();
    const text = out.indexOf("PGARD scan result");
    const enter = out.indexOf(ENTER);
    const leave = out.indexOf(LEAVE);
    const question = out.indexOf("Save a report?");
    expect(text).toBeGreaterThan(-1);
    expect(enter).toBeGreaterThan(text);
    expect(leave).toBeGreaterThan(enter);
    expect(question).toBeGreaterThan(leave);
  }, 15_000);

  it("asks the report question straight away with PGARD_PANELS=off", async () => {
    const { captured, running, press, wait } = await runMenu({ PGARD_PANELS: "off" });
    await press("\u001b");
    await wait(800);
    await press("x");
    await press("\u001b");
    await running;
    expect(captured.stdout()).not.toContain(ENTER);
    expect(captured.stdout()).toContain("Save a report?");
  }, 15_000);
});

describe("panel view edge cases", () => {
  function terminal() {
    const captured = createTestIo({ isTTY: true });
    const stdout = captured.io.stdout as unknown as { columns: number; rows: number };
    stdout.columns = 80;
    stdout.rows = 24;
    return captured;
  }

  it("does not auto-open in the menu after a failed scan, but does for completed and partial", async () => {
    for (const [status, opens] of [
      ["failed", false],
      ["completed", true],
      ["partial", true],
    ] as const) {
      const captured = terminal();
      const context = createTestContext(captured, createTestDeps(), scriptedKeys(["escape"]), true);
      await offerPanels(context, { ...panelsFixtureResult(), overallStatus: status }, false);
      expect(captured.stdout().includes(ENTER), status).toBe(opens);
    }
  });

  it("still opens for a failed scan when --panels is given", async () => {
    const captured = terminal();
    const context = createTestContext(captured, createTestDeps(), scriptedKeys(["escape"]));
    await offerPanels(context, { ...panelsFixtureResult(), overallStatus: "failed" }, true);
    expect(captured.stdout()).toContain(ENTER);
  });

  it("restores the terminal, says so on stderr and does not throw when the view itself fails", async () => {
    const captured = terminal();
    const keys = {
      readKey: async (): Promise<never> => {
        throw new Error("view broke");
      },
      suspend: () => undefined,
      close: () => undefined,
    };
    const context = createTestContext(captured, createTestDeps(), keys);
    await expect(offerPanels(context, panelsFixtureResult(), true)).resolves.toBe(true);
    expect(captured.stdout().endsWith(LEAVE)).toBe(true);
    expect(captured.stderr()).toContain("The panel view failed");
    expect(captured.stderr()).not.toContain("view broke");
  });

  it("gives the view the rule catalog, so the opened finding shows its standards links", async () => {
    const captured = terminal();
    const context = createTestContext(
      captured,
      createTestDeps(),
      scriptedKeys(["left", "return", "escape", "escape"]),
    );
    context.ruleTexts = getRuleTextCatalog();
    const result = testResult({ findings: [testFinding({ ruleId: "PG-SQL-001" })] });
    await offerPanels(context, result, true);
    expect(captured.stdout()).toContain("https://cwe.mitre.org/data/definitions/89.html");
  });

  it("pauses the cancel controller's SIGINT handling while the view is open", async () => {
    const captured = terminal();
    const calls: string[] = [];
    const context = createTestContext(captured, createTestDeps(), scriptedKeys(["escape"]));
    context.suspendInterrupts = () => {
      calls.push("suspend");
      return () => calls.push("resume");
    };
    await offerPanels(context, panelsFixtureResult(), true);
    expect(calls).toEqual(["suspend", "resume"]);
  });

  it("notes on stderr that --panels did not open on a blocked scan", async () => {
    const captured = createTestIo({ isTTY: false });
    const code = await main(["scan", "--panels"], captured.io, {
      deps: createTestDeps({
        runScan: async () => ({ ...panelsFixtureResult(), overallStatus: "blocked" }),
      }),
      interrupts: noInterrupts,
    });
    expect(code).toBe(3);
    expect(captured.stderr()).toContain("not opened because the scan was blocked");
    expect(captured.stdout()).not.toContain(ENTER);
  });

  it("ends the command with 143 after SIGTERM in the view, 130 after SIGINT", async () => {
    for (const [signal, expected] of [
      ["SIGTERM", 143],
      ["SIGINT", 130],
    ] as const) {
      const captured = terminal();
      captured.stdin.setRawMode = () => undefined;
      // Capture the view's own signal listener instead of signalling the test process.
      const listeners: Record<string, () => void> = {};
      const original = process.on.bind(process) as (event: string, listener: unknown) => unknown;
      const spy = vi.spyOn(process, "on").mockImplementation(((
        event: string,
        listener: (...args: never[]) => void,
      ) => {
        if (event === "SIGTERM" || event === "SIGINT") listeners[event] = listener as () => void;
        else original(event, listener);
        return process;
      }) as never);
      try {
        const running = main(["scan", "--panels"], captured.io, {
          deps: createTestDeps({
            runScan: async () => ({ ...panelsFixtureResult(), overallStatus: "completed" }),
          }),
          interrupts: noInterrupts,
        });
        for (let waited = 0; waited < 60 && listeners[signal] === undefined; waited += 1) {
          await new Promise((resolve) => setTimeout(resolve, 50));
        }
        listeners[signal]?.();
        expect(await running, signal).toBe(expected);
      } finally {
        spy.mockRestore();
      }
      expect(captured.stdout().endsWith(LEAVE), signal).toBe(true);
    }
  }, 15_000);
});

describe("automatic opening stays off in automation", () => {
  function terminalWith(env: Record<string, string>) {
    const captured = createTestIo({ isTTY: true, env });
    const stdout = captured.io.stdout as unknown as { columns: number; rows: number };
    stdout.columns = 80;
    stdout.rows = 24;
    return captured;
  }

  async function auto(env: Record<string, string>, isRequested = false, isAutoAllowed = true) {
    const captured = terminalWith(env);
    const context = createTestContext(captured, createTestDeps(), scriptedKeys(["escape"]));
    await offerPanels(context, panelsFixtureResult(), isRequested, isAutoAllowed);
    return captured;
  }

  it("does not open when CI is set to anything but empty, 0 or false", async () => {
    for (const value of ["true", "1", "yes", "TRUE", "anything"]) {
      const captured = await auto({ CI: value });
      expect(captured.stdout(), value).toBe("");
      expect(captured.stderr(), value).toBe("");
    }
    for (const value of ["", "0", "false", "False"]) {
      expect((await auto({ CI: value })).stdout(), value).toContain(ENTER);
    }
  });

  it("does not open under GitHub Actions, Buildkite, Azure Pipelines or Jenkins", async () => {
    for (const name of ["GITHUB_ACTIONS", "BUILDKITE", "TF_BUILD", "JENKINS_URL"]) {
      expect((await auto({ [name]: "x" })).stdout(), name).toBe("");
    }
  });

  it("does not open with TERM=dumb, and --panels says why instead of drawing", async () => {
    expect((await auto({ TERM: "dumb" })).stdout()).toBe("");
    const forced = await auto({ TERM: "dumb" }, true);
    expect(forced.stdout()).toBe("");
    expect(forced.stderr()).toContain("TERM=dumb");
  });

  it("opens in CI only when asked: --panels, or PGARD_PANELS=on", async () => {
    expect((await auto({ CI: "true" }, true)).stdout()).toContain(ENTER);
    expect((await auto({ CI: "true", PGARD_PANELS: "on" })).stdout()).toContain(ENTER);
    // An empty or unset PGARD_PANELS does not override the automation check.
    expect((await auto({ CI: "true", PGARD_PANELS: "" })).stdout()).toBe("");
  });

  it("does not open for a command that only uses the scan (baseline set --from-current)", async () => {
    expect((await auto({}, false, false)).stdout()).toBe("");
    // The explicit flag still works.
    expect((await auto({}, true, false)).stdout()).toContain(ENTER);
  });

  it("goes through the real scan command: baseline set --from-current never opens the view", async () => {
    const captured = terminalWith({});
    captured.stdin.setRawMode = () => undefined;
    const code = await main(["baseline", "set", "--from-current"], captured.io, {
      deps: createTestDeps({
        runScan: async () => panelsFixtureResult(),
        createSessionProvider: () => (async () => ({})) as never,
      }),
      interrupts: noInterrupts,
    });
    expect(typeof code).toBe("number");
    expect(captured.stdout()).not.toContain(ENTER);
  }, 15_000);

  it("does not hang when input has ended: the view is left like Esc", async () => {
    const captured = terminalWith({});
    const { UserCancelledError: Cancelled } = await import("../ui/components/prompts.js");
    const context = createTestContext(captured, createTestDeps(), {
      readKey: () => Promise.reject(new Cancelled()),
      suspend: () => undefined,
      close: () => undefined,
    });
    await offerPanels(context, panelsFixtureResult(), false);
    expect(captured.stdout()).toContain(ENTER);
    expect(captured.stdout().endsWith(LEAVE)).toBe(true);
  });
});

describe("e: export from the panel view", () => {
  // Only an empty directory is made; every write goes through an injected writeReports.
  const outputDir = mkdtempSync(path.join(os.tmpdir(), "pgard-panel-export-"));
  afterAll(() => rmSync(outputDir, { recursive: true, force: true }));

  const chars = (text: string): string[] => Array.from(text);
  const HTML = ["down", "return"];
  const DIR = [...chars(outputDir), "return"];

  function terminal() {
    const captured = createTestIo({ isTTY: true });
    const stdout = captured.io.stdout as unknown as { columns: number; rows: number };
    stdout.columns = 80;
    stdout.rows = 24;
    return captured;
  }

  async function open(
    keys: (string | { name: string; sequence?: string; ctrl: boolean })[],
    overrides: Parameters<typeof createTestDeps>[0] = {},
  ) {
    const captured = terminal();
    const writeReports = vi.fn(async () => [{ format: "html" as const, filePath: "/out/r.html" }]);
    const testDeps = createTestDeps({ writeReports, ...overrides });
    const context = createTestContext(captured, testDeps, scriptedKeys(keys as never[]));
    const result = panelsFixtureResult();
    const outcomes: string[] = [];
    const savedPaths = new Set<string>();
    const isOk = offerPanels(context, result, true, true, undefined, async () => {
      const outcome = await runReportExport(context, result, "/work/repo", savedPaths);
      outcomes.push(outcome);
      return outcome;
    });
    return { captured, writeReports: overrides.writeReports ?? writeReports, isOk, outcomes };
  }

  it("runs the menu's format, directory and save steps, then resumes the panel", async () => {
    const run = await open(["tab", "e", ...HTML, ...DIR, "x", "q"]);
    expect(await run.isOk).toBe(true);
    expect(run.outcomes).toEqual(["saved"]);
    expect(run.writeReports).toHaveBeenCalledTimes(1);
    expect(run.writeReports).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ format: "html", outputDir }),
    );
    const out = run.captured.stdout();
    expect(out).toContain("Save a report?");
    expect(out).toContain("Saved HTML report: /out/r.html");
    expect(out.split(ENTER)).toHaveLength(3);
    // The panel that comes back is the one that was left (the Charts tab).
    expect(out.split(ENTER)[2]).toContain("[Charts]");
  });

  it("returns to the panel on Esc at the format question, writing nothing", async () => {
    const run = await open(["e", "escape", "q"]);
    expect(await run.isOk).toBe(true);
    expect(run.outcomes).toEqual(["cancelled"]);
    expect(run.writeReports).not.toHaveBeenCalled();
    expect(run.captured.stdout().split(ENTER)).toHaveLength(3);
  });

  it("returns to the panel on Esc at the directory question", async () => {
    const run = await open(["e", ...HTML, "escape", "q"]);
    expect(await run.isOk).toBe(true);
    expect(run.writeReports).not.toHaveBeenCalled();
  });

  it("asks before writing inside the repository and writes nothing on no", async () => {
    const run = await open(["e", ...HTML, ...DIR, "n", "escape", "q"], {
      isPathInsideDirectory: async () => true,
    });
    expect(await run.isOk).toBe(true);
    expect(run.captured.stderr()).toContain("output directory is inside");
    expect(run.writeReports).not.toHaveBeenCalled();
  });

  it("shows a write failure, resumes the panel and reports the failure to the caller", async () => {
    const writeReports = vi.fn(async () => {
      throw new ReportWriteError("write_failed", "disk full");
    });
    const run = await open(["e", ...HTML, ...DIR, "x", "q"], { writeReports });
    expect(await run.isOk).toBe(false);
    expect(run.outcomes).toEqual(["failed"]);
    expect(run.captured.stderr()).toContain("Report not saved: disk full");
    expect(run.captured.stdout().split(ENTER)).toHaveLength(3);
    expect(run.captured.stdout().endsWith(LEAVE)).toBe(true);
  });

  const failing = () =>
    vi.fn(async () => {
      throw new ReportWriteError("write_failed", "disk full");
    });

  it("keeps a failure when the next export is cancelled with Esc or answered No", async () => {
    const byEsc = await open(["e", ...HTML, ...DIR, "x", "e", "escape", "q"], {
      writeReports: failing(),
    });
    expect(await byEsc.isOk).toBe(false);
    expect(byEsc.outcomes).toEqual(["failed", "cancelled"]);
    // "No" is the first choice of the format question.
    const byNo = await open(["e", ...HTML, ...DIR, "x", "e", "return", "q"], {
      writeReports: failing(),
    });
    expect(await byNo.isOk).toBe(false);
    expect(byNo.outcomes).toEqual(["failed", "cancelled"]);
  });

  describe("with the real writeReports (temp directories only)", () => {
    const dirs: string[] = [];
    afterAll(() => {
      for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
    });
    const freshDir = (): string => {
      const dir = mkdtempSync(path.join(os.tmpdir(), "pgard-panel-export-real-"));
      dirs.push(dir);
      return dir;
    };
    const CHOICE = {
      html: ["down", "return"],
      pdf: ["down", "down", "return"],
      both: ["down", "down", "down", "return"],
    };
    const exportKeys = (format: keyof typeof CHOICE, dir: string): string[] => [
      "e",
      ...CHOICE[format],
      ...Array.from(dir),
      "return",
      "x",
    ];
    const files = (dir: string): string[] => readdirSync(dir).sort();

    it("html then both: the PDF is written, the HTML is reported as already saved", async () => {
      const dir = freshDir();
      const run = await open([...exportKeys("html", dir), ...exportKeys("both", dir), "q"], {
        writeReports,
      });
      expect(await run.isOk).toBe(true);
      expect(run.outcomes).toEqual(["saved", "saved"]);
      expect(files(dir).map((name) => path.extname(name))).toEqual([".html", ".pdf"]);
      expect(run.captured.stdout()).toContain("This report was already saved to");
      expect(run.captured.stdout()).toContain("Saved PDF report");
      expect(run.captured.stderr()).not.toContain("not saved");
    }, 30_000);

    it("both then html: already saved, nothing new written", async () => {
      const dir = freshDir();
      const run = await open([...exportKeys("both", dir), ...exportKeys("html", dir), "q"], {
        writeReports,
      });
      expect(await run.isOk).toBe(true);
      expect(files(dir)).toHaveLength(2);
      expect(run.captured.stdout()).toContain("This report was already saved to");
    }, 30_000);

    it("html then pdf writes the PDF as a new file", async () => {
      const dir = freshDir();
      const run = await open([...exportKeys("html", dir), ...exportKeys("pdf", dir), "q"], {
        writeReports,
      });
      expect(await run.isOk).toBe(true);
      expect(files(dir).map((name) => path.extname(name))).toEqual([".html", ".pdf"]);
      expect(run.captured.stdout()).not.toContain("already saved");
    }, 30_000);

    it("still refuses a file that existed before the session (a failure)", async () => {
      const dir = freshDir();
      const result = panelsFixtureResult();
      await writeReports(result, { format: "html", outputDir: dir });
      const before = readdirSync(dir);
      const run = await open(exportKeys("html", dir).concat("q"), { writeReports });
      expect(await run.isOk).toBe(false);
      expect(run.outcomes).toEqual(["failed"]);
      expect(run.captured.stderr()).toContain("Refusing to overwrite");
      expect(readdirSync(dir)).toEqual(before);
    }, 30_000);

    it("end to end through the scan command: html then both exits 0 and writes both files", async () => {
      const dir = freshDir();
      const captured = createTestIo({ isTTY: true });
      const stdout = captured.io.stdout as unknown as { columns: number; rows: number };
      stdout.columns = 80;
      stdout.rows = 24;
      const keys = scriptedKeys([...exportKeys("html", dir), ...exportKeys("both", dir), "q"]);
      const context = {
        ...createTestContext(
          captured,
          createTestDeps({
            runScan: async () => ({ ...panelsFixtureResult(), overallStatus: "completed" }),
            writeReports,
          }),
          keys,
        ),
        ruleLocale: "en" as const,
      };
      const code = await runScanCommand(context, {
        variant: "code",
        port: null,
        report: null,
        panels: true,
      });
      expect(code).toBe(0);
      expect(files(dir).map((name) => path.extname(name))).toEqual([".html", ".pdf"]);
    }, 30_000);
  });

  it("still fails for a file this session did not save", async () => {
    const other = path.join(outputDir, "other.html");
    const writeReports = vi.fn(async () => {
      throw new ReportWriteError(
        "file_exists",
        `Refusing to overwrite existing file: ${other}`,
        other,
      );
    });
    const run = await open(["e", ...HTML, ...DIR, "x", "q"], { writeReports });
    expect(await run.isOk).toBe(false);
    expect(run.captured.stderr()).toContain("Refusing to overwrite");
  });

  it("lets a later successful export win over an earlier failed one", async () => {
    let calls = 0;
    const writeReports = vi.fn(async () => {
      calls += 1;
      if (calls === 1) throw new ReportWriteError("write_failed", "disk full");
      return [{ format: "html" as const, filePath: "/out/r.html" }];
    });
    const run = await open(["e", ...HTML, ...DIR, "x", "e", ...HTML, ...DIR, "x", "q"], {
      writeReports,
    });
    expect(await run.isOk).toBe(true);
    expect(run.outcomes).toEqual(["failed", "saved"]);
  });

  it("ends as a cancellation after Ctrl+C and y inside the export prompts", async () => {
    const ctrlC = { name: "c", sequence: "\u0003", ctrl: true };
    const run = await open(["e", ctrlC, "y"]);
    await expect(run.isOk).rejects.toBeInstanceOf(UserCancelledError);
    // The screen was given back before the prompts and never taken again.
    expect(run.captured.stdout().split(ENTER)).toHaveLength(2);
    expect(run.captured.stdout()).toContain(LEAVE);
    expect(run.writeReports).not.toHaveBeenCalled();
  });

  it("does nothing on e without an export (no terminal case never opens the view at all)", async () => {
    const captured = terminal();
    const context = createTestContext(captured, createTestDeps(), scriptedKeys(["e", "q"]));
    await offerPanels(context, panelsFixtureResult(), true);
    expect(captured.stdout().split(ENTER)).toHaveLength(2);
    const piped = createTestIo({ isTTY: false });
    const pipedContext = createTestContext(piped, createTestDeps(), scriptedKeys(["e"]));
    await offerPanels(pipedContext, panelsFixtureResult(), true, true, undefined, async () => {
      throw new Error("must not run");
    });
    expect(piped.stdout()).not.toContain(ENTER);
  });
});

describe("e: export from the panel view, end to end through main (exit codes)", () => {
  const outputDir = mkdtempSync(path.join(os.tmpdir(), "pgard-panel-export-e2e-"));
  afterAll(() => rmSync(outputDir, { recursive: true, force: true }));
  const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  async function session(
    writeReports: CliDeps["writeReports"],
    steps: string[],
  ): Promise<{ code: number; stdout: string; stderr: string }> {
    const captured = createTestIo({ isTTY: true });
    const stdout = captured.io.stdout as unknown as { columns: number; rows: number };
    stdout.columns = 80;
    stdout.rows = 24;
    captured.stdin.setRawMode = () => undefined;
    const running = main(["scan", "--panels"], captured.io, {
      deps: createTestDeps({
        runScan: async () => ({ ...panelsFixtureResult(), overallStatus: "completed" }),
        createSessionProvider: () => (async () => ({})) as never,
        credentialStore: createSignedInCredentialStore(),
        writeReports,
      }),
      interrupts: noInterrupts,
    });
    await wait(250);
    for (const step of steps) {
      await wait(step === "\u001b" ? 700 : 80);
      captured.stdin.write(step);
    }
    const code = await running;
    return { code, stdout: captured.stdout(), stderr: captured.stderr() };
  }

  const toDir = [`${outputDir}\r`];
  const SAVE = ["e", "\u001b[B", "\r", ...toDir, "x"];

  it("keeps exit 0 after a saved export and q", async () => {
    const writeReports = vi.fn(async () => [{ format: "html" as const, filePath: "/out/r.html" }]);
    const run = await session(writeReports as never, [...SAVE, "q"]);
    expect(run.code).toBe(0);
    expect(writeReports).toHaveBeenCalledTimes(1);
    expect(run.stdout).toContain("Saved HTML report");
  }, 20_000);

  it("exits 4 (partial) after a failed write, like the menu's failed export", async () => {
    const writeReports = vi.fn(async () => {
      throw new ReportWriteError("write_failed", "disk full");
    });
    const run = await session(writeReports as never, [...SAVE, "q"]);
    expect(run.code).toBe(4);
    expect(run.stderr).toContain("Report not saved: disk full");
  }, 20_000);

  it("exits 130 after Ctrl+C and y inside the export prompts", async () => {
    const writeReports = vi.fn();
    const run = await session(writeReports as never, ["e", "\u0003", "y"]);
    expect(run.code).toBe(130);
    expect(writeReports).not.toHaveBeenCalled();
    expect(
      run.stdout.endsWith("\u001b[?25h\u001b[?1049l") || run.stdout.includes("\u001b[?1049l"),
    ).toBe(true);
  }, 20_000);
});

describe("menu scan: panel export failure then No at the menu question", () => {
  it("exits 4 for an otherwise ok scan", async () => {
    const outputDir = mkdtempSync(path.join(os.tmpdir(), "pgard-panel-export-menu-"));
    try {
      const captured = createTestIo({ isTTY: true });
      const stdout = captured.io.stdout as unknown as { columns: number; rows: number };
      stdout.columns = 80;
      stdout.rows = 24;
      const writeReports = vi.fn(async () => {
        throw new ReportWriteError("write_failed", "disk full");
      });
      const keys = scriptedKeys([
        "e",
        "down",
        "return",
        ...Array.from(outputDir),
        "return",
        "x",
        "q", // leaves the panel; the menu's report question follows
        "return", // "No"
      ]);
      const context = {
        ...createTestContext(
          captured,
          createTestDeps({
            runScan: async () => ({ ...panelsFixtureResult(), overallStatus: "completed" }),
            writeReports,
          }),
          keys,
          true,
        ),
        ruleLocale: "en" as const,
      };
      const code = await runScanCommand(context, { variant: "code", port: null, report: null });
      expect(code).toBe(4);
      expect(writeReports).toHaveBeenCalledTimes(1);
    } finally {
      rmSync(outputDir, { recursive: true, force: true });
    }
  });
});
