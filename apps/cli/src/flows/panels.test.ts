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

  it("asks in the menu and opens only on y", async () => {
    const yes = terminal();
    await offerPanels(
      createTestContext(yes, createTestDeps(), scriptedKeys(["y", "escape"]), true),
      panelsFixtureResult(),
      false,
    );
    expect(yes.stdout()).toContain("Open the full-screen panel view? [y/N]");
    expect(yes.stdout()).toContain(ENTER);
    const no = terminal();
    await offerPanels(
      createTestContext(no, createTestDeps(), scriptedKeys(["n"]), true),
      panelsFixtureResult(),
      false,
    );
    expect(no.stdout()).not.toContain(ENTER);
  });

  it("does nothing outside the menu without --panels", async () => {
    const captured = terminal();
    const context = createTestContext(captured, createTestDeps(), scriptedKeys([]));
    await offerPanels(context, testResult(), false);
    expect(captured.stdout()).toBe("");
  });
});
