import { describe, expect, it, vi } from "vitest";
import { main } from "../app.js";
import { parseCommandLine, UsageError } from "../options.js";
import {
  createTestContext,
  createTestDeps,
  createTestIo,
  noInterrupts,
  panelsFixtureResult,
  scriptedKeys,
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
    expect(captured.stdout()).toContain("pgard dashboard is the");
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

  it("does not open for a plain scan command, whatever PGARD_PANELS says", async () => {
    const captured = terminal();
    const context = createTestContext(captured, createTestDeps(), scriptedKeys([]));
    await offerPanels(context, panelsFixtureResult(), false);
    expect(captured.stdout()).toBe("");
  });

  it("does nothing outside the menu without --panels", async () => {
    const captured = terminal();
    const context = createTestContext(captured, createTestDeps(), scriptedKeys([]));
    await offerPanels(context, testResult(), false);
    expect(captured.stdout()).toBe("");
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
