import { describe, expect, it } from "vitest";
import { main } from "../../app.js";
import { createTestDeps, createTestIo, noInterrupts } from "../../test-support.js";
import { displayWidth, stripAnsi } from "../../ui/i18n/display-width.js";
import { realRepoResult } from "../../ui/formatters/result-fixture.js";

const ENTER = "\u001b[?1049h";
const LEAVE = "\u001b[?1049l";
const PARTIAL = 4;

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function deps() {
  return createTestDeps({
    runScan: async () => realRepoResult(),
    createSessionProvider: () => (async () => ({})) as never,
  });
}

function terminalIo(env: Record<string, string> = {}) {
  const captured = createTestIo({ isTTY: true, env: { COLUMNS: "80", ...env } });
  captured.stdin.setRawMode = () => undefined;
  const stdout = captured.io.stdout as unknown as { columns: number; rows: number };
  stdout.columns = 80;
  stdout.rows = 30;
  return captured;
}

/** Runs `pgard scan ...` in a terminal; `leave` presses Esc once the panel view is up. */
async function scanInTerminal(args: string[], env: Record<string, string> = {}) {
  const captured = terminalIo(env);
  const running = main(args, captured.io, { deps: deps(), interrupts: noInterrupts });
  for (let waited = 0; waited < 4000 && !captured.stdout().includes(ENTER); waited += 25) {
    await wait(25);
    if (env.PGARD_PANELS === "off" && captured.stdout().includes("Next:")) break;
  }
  if (captured.stdout().includes(ENTER)) {
    await wait(25);
    captured.stdin.write("\u001b");
  }
  return { captured, code: await running };
}

describe("pgard scan in a terminal", () => {
  it("prints the compact text result, then opens the panels by itself, and keeps the text", async () => {
    const { captured, code } = await scanInTerminal(["scan"]);
    expect(code).toBe(PARTIAL);
    const out = captured.stdout();
    const text = out.indexOf("PGARD scan result");
    const next = out.indexOf("Next:");
    const enter = out.indexOf(ENTER);
    expect(text).toBeGreaterThan(-1);
    expect(next).toBeGreaterThan(text);
    // The text result is printed before the panels open and stays on the main screen.
    expect(enter).toBeGreaterThan(next);
    expect(out.endsWith(LEAVE)).toBe(true);
    expect(out).toContain("more findings");
    expect(out).not.toContain("Evidence:");
  }, 15_000);

  it("does not open the panels with PGARD_PANELS=off, and still prints the compact result", async () => {
    const { captured, code } = await scanInTerminal(["scan"], { PGARD_PANELS: "off" });
    expect(code).toBe(PARTIAL);
    expect(captured.stdout()).not.toContain(ENTER);
    expect(captured.stdout()).toContain("Next:");
    expect(captured.stdout()).toContain("more findings");
  }, 15_000);

  it("lets --panels win over PGARD_PANELS=off", async () => {
    const { captured } = await scanInTerminal(["scan", "--panels"], { PGARD_PANELS: "off" });
    expect(captured.stdout()).toContain(ENTER);
  }, 15_000);

  it("prints the full form with --all-findings, summary last, and still opens the panels", async () => {
    const { captured } = await scanInTerminal(["scan", "--all-findings"]);
    const out = captured.stdout();
    expect(out).toContain("Evidence:");
    expect(out).not.toContain("more findings");
    expect(out.indexOf("Evidence:")).toBeLessThan(out.indexOf("Findings by severity"));
    expect(out.indexOf("Next:")).toBeLessThan(out.indexOf(ENTER));
  }, 15_000);

  it("keeps every line within the terminal width, except URLs", async () => {
    const { captured } = await scanInTerminal(["scan"], { PGARD_PANELS: "off" });
    for (const line of stripAnsi(captured.stdout()).split("\n")) {
      if (line.includes("https://")) continue;
      expect(displayWidth(line), line).toBeLessThanOrEqual(80);
    }
  }, 15_000);

  it("never opens the panels for --format json or sarif, and the document is unchanged", async () => {
    const reference = createTestIo({ isTTY: false });
    await main(["scan", "--format", "json"], reference.io, {
      deps: deps(),
      interrupts: noInterrupts,
    });
    for (const format of ["json", "sarif"]) {
      const captured = terminalIo();
      const code = await main(["scan", "--format", format], captured.io, {
        deps: deps(),
        interrupts: noInterrupts,
      });
      expect(code).toBe(PARTIAL);
      expect(captured.stdout()).not.toContain(ENTER);
      expect(captured.stderr()).not.toContain(ENTER);
      expect(() => JSON.parse(captured.stdout())).not.toThrow();
      if (format === "json") expect(captured.stdout()).toBe(reference.stdout());
    }
  }, 15_000);
});

describe("pgard scan without a terminal", () => {
  it("never opens the panels and prints the stable full form, summary first", async () => {
    const captured = createTestIo({ isTTY: false });
    const code = await main(["scan"], captured.io, { deps: deps(), interrupts: noInterrupts });
    expect(code).toBe(PARTIAL);
    const out = captured.stdout();
    expect(out).not.toContain(ENTER);
    expect(out).toContain("Evidence:");
    expect(out).not.toContain("Next:");
    expect(out).not.toContain("more findings");
    expect(out.indexOf("Summary")).toBeLessThan(out.indexOf("Findings ("));
    // Even with PGARD_PANELS forced on: a pipe is never a terminal.
    const forced = createTestIo({ isTTY: false, env: { PGARD_PANELS: "on" } });
    await main(["scan"], forced.io, { deps: deps(), interrupts: noInterrupts });
    expect(forced.stdout()).toBe(out);
  });
});
