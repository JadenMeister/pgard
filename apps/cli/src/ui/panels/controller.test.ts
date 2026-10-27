import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import type { Key, KeyReader } from "../../adapters/terminal.js";
import { getRuleTextCatalog } from "../../rule-texts.js";
import { panelsFixtureResult, testFinding, testResult } from "../../test-support.js";
import { UserCancelledError } from "../components/prompts.js";
import { renderPanelsOnce, runPanelsScreen } from "./controller.js";

const ENTER = "\u001b[?1049h\u001b[?25l";
const LEAVE = "\u001b[?25h\u001b[?1049l";
const ctrlC: Key = { name: "c", sequence: "\u0003", ctrl: true };
const press = (name: string): Key => ({
  name,
  sequence: name.length === 1 ? name : undefined,
  ctrl: false,
});

function fakeStdout(columns = 80, rows = 24) {
  const stream = new PassThrough() as PassThrough & {
    isTTY: boolean;
    columns: number;
    rows: number;
  };
  stream.isTTY = true;
  stream.columns = columns;
  stream.rows = rows;
  let written = "";
  stream.on("data", (chunk: Buffer) => {
    written += chunk.toString();
  });
  return { stream, written: () => written };
}

/** Keys come from `next()`; a rejected key read stands for a failing terminal. */
function keysOf(next: () => Promise<Key>): KeyReader {
  return { readKey: next, suspend: () => undefined, close: () => undefined };
}

function scripted(...keys: Key[]): KeyReader {
  const queue = [...keys];
  return keysOf(async () => {
    const entry = queue.shift();
    if (entry === undefined) throw new Error("no more keys");
    return entry;
  });
}

const EMPTY_ENV = {};

describe("runPanelsScreen", () => {
  it("enters the alternate screen, draws, and restores the terminal when Esc leaves", async () => {
    const out = fakeStdout();
    const processEvents = new EventEmitter();
    const exit = await runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys: scripted(press("tab"), press("escape")),
      processEvents,
    });
    expect(exit).toBe("back");
    const written = out.written();
    expect(written.startsWith(ENTER)).toBe(true);
    expect(written.endsWith(LEAVE)).toBe(true);
    expect(written).toContain("Overview");
    expect(written).toContain("Charts");
    expect(written.split(LEAVE)).toHaveLength(2);
    // Every listener is gone again.
    for (const event of ["SIGINT", "SIGTERM", "exit", "uncaughtException"]) {
      expect(processEvents.listenerCount(event), event).toBe(0);
    }
    expect(out.stream.listenerCount("resize")).toBe(0);
  });

  it("returns cancel only after the person confirms Ctrl+C", async () => {
    const out = fakeStdout();
    const exit = await runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys: scripted(ctrlC, press("n"), ctrlC, press("y")),
      processEvents: new EventEmitter(),
    });
    expect(exit).toBe("cancel");
    expect(out.written()).toContain("Cancel and exit? [y/N]");
    expect(out.written().endsWith(LEAVE)).toBe(true);
  });

  it("restores the cursor and the screen when reading a key fails", async () => {
    const out = fakeStdout();
    const processEvents = new EventEmitter();
    await expect(
      runPanelsScreen({
        result: panelsFixtureResult(),
        locale: "en",
        stdout: out.stream,
        env: EMPTY_ENV,
        keys: keysOf(async () => {
          throw new Error("terminal failed");
        }),
        processEvents,
      }),
    ).rejects.toThrow("terminal failed");
    expect(out.written().endsWith(LEAVE)).toBe(true);
    expect(processEvents.listenerCount("SIGINT")).toBe(0);
  });

  it("ends as cancel on SIGINT and as terminated on SIGTERM, restoring the terminal", async () => {
    for (const [signal, expected] of [
      ["SIGINT", "cancel"],
      ["SIGTERM", "terminated"],
    ] as const) {
      const out = fakeStdout();
      const processEvents = new EventEmitter();
      const never = keysOf(() => new Promise<Key>(() => undefined));
      const running = runPanelsScreen({
        result: panelsFixtureResult(),
        locale: "en",
        stdout: out.stream,
        env: EMPTY_ENV,
        keys: never,
        processEvents,
      });
      // The first draw happens synchronously; the signal arrives while a key is awaited.
      expect(out.written().startsWith(ENTER)).toBe(true);
      processEvents.emit(signal);
      expect(await running, signal).toBe(expected);
      expect(out.written().endsWith(LEAVE), signal).toBe(true);
      expect(processEvents.listenerCount(signal)).toBe(0);
    }
  });

  it("only observes an uncaught exception: it restores and does not rethrow or hide it", async () => {
    const out = fakeStdout();
    const processEvents = new EventEmitter();
    void runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys: keysOf(() => new Promise<Key>(() => undefined)),
      processEvents,
    });
    // No "uncaughtException" listener: Node keeps its own message and exit code.
    expect(processEvents.listenerCount("uncaughtException")).toBe(0);
    expect(() => processEvents.emit("uncaughtExceptionMonitor", new Error("boom"))).not.toThrow();
    expect(out.written().endsWith(LEAVE)).toBe(true);
    const length = out.written().length;
    processEvents.emit("exit");
    expect(out.written().length).toBe(length);
  });

  it("restores the terminal on process exit alone", async () => {
    const out = fakeStdout();
    const processEvents = new EventEmitter();
    void runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys: keysOf(() => new Promise<Key>(() => undefined)),
      processEvents,
    });
    processEvents.emit("exit");
    expect(out.written().endsWith(LEAVE)).toBe(true);
  });

  it("redraws at the new size when the terminal is resized", async () => {
    const out = fakeStdout(80, 24);
    let release: (key: Key) => void = () => undefined;
    const waiting = new Promise<Key>((resolve) => {
      release = resolve;
    });
    let calls = 0;
    const keys = keysOf(() => (calls++ === 0 ? waiting : Promise.resolve(press("escape"))));
    const running = runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys,
      processEvents: new EventEmitter(),
    });
    const before = out.written().length;
    out.stream.columns = 30;
    out.stream.rows = 8;
    out.stream.emit("resize");
    const after = out.written().slice(before);
    expect(after).toContain("Terminal too small (30x8)");
    out.stream.columns = 60;
    out.stream.rows = 20;
    out.stream.emit("resize");
    expect(out.written()).toContain("Overview");
    release(press("tab"));
    expect(await running).toBe("back");
  });

  it("draws colour only when the terminal allows it", async () => {
    for (const [env, hasColour] of [
      [{}, true],
      [{ NO_COLOR: "1" }, false],
      [{ TERM: "dumb" }, false],
    ] as const) {
      const out = fakeStdout();
      await runPanelsScreen({
        result: panelsFixtureResult(),
        locale: "en",
        stdout: out.stream,
        env,
        keys: scripted(press("escape")),
        processEvents: new EventEmitter(),
      });
      const body = out.written().replace(ENTER, "").replace(LEAVE, "");
      // eslint-disable-next-line no-control-regex
      const sgr = /\u001b\[[0-9;]*m/;
      expect(sgr.test(body), JSON.stringify(env)).toBe(hasColour);
    }
  });
});

describe("renderPanelsOnce", () => {
  it("prints one plain frame without screen-control codes, sized by COLUMNS and LINES", () => {
    const out = fakeStdout();
    out.stream.isTTY = false;
    renderPanelsOnce({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: out.stream,
      env: { COLUMNS: "60", LINES: "14" },
    });
    const lines = out.written().split("\n");
    expect(lines.at(-1)).toBe("");
    expect(lines).toHaveLength(15);
    expect(out.written()).not.toContain("\u001b");
    expect(out.written()).toContain("PGARD panels");
  });
});

describe("runPanelsScreen, interrupts and end of input", () => {
  const never = (): KeyReader => keysOf(() => new Promise<Key>(() => undefined));

  it("restores the terminal at the first SIGINT, before anything else runs, and survives more", async () => {
    const out = fakeStdout();
    const processEvents = new EventEmitter();
    const running = runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys: never(),
      processEvents,
    });
    // A double interrupt right after the screen was entered, before any key was read.
    processEvents.emit("SIGINT");
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(out.written().endsWith(LEAVE)).toBe(true);
    processEvents.emit("SIGINT");
    await new Promise((resolve) => setTimeout(resolve, 300));
    processEvents.emit("SIGINT");
    expect(await running).toBe("cancel");
    expect(out.written().split(LEAVE)).toHaveLength(2);
    expect(processEvents.listenerCount("SIGINT")).toBe(0);
  });

  it("restores the terminal at SIGTERM too", async () => {
    const out = fakeStdout();
    const processEvents = new EventEmitter();
    const running = runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys: never(),
      processEvents,
    });
    processEvents.emit("SIGTERM");
    expect(out.written().endsWith(LEAVE)).toBe(true);
    expect(await running).toBe("terminated");
  });

  it("leaves like Esc when input ends (a closed terminal)", async () => {
    const out = fakeStdout();
    const exit = await runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys: keysOf(async () => {
        throw new UserCancelledError();
      }),
      processEvents: new EventEmitter(),
    });
    expect(exit).toBe("back");
    expect(out.written().endsWith(LEAVE)).toBe(true);
  });

  it("leaves on Ctrl+D", async () => {
    const out = fakeStdout();
    const exit = await runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys: scripted({ name: "d", sequence: "\u0004", ctrl: true }),
      processEvents: new EventEmitter(),
    });
    expect(exit).toBe("back");
    expect(out.written().endsWith(LEAVE)).toBe(true);
  });
});

describe("runPanelsScreen, details and the signal restore", () => {
  it("passes the rule catalog to the view (standards links in the opened finding)", async () => {
    const out = fakeStdout();
    const exit = await runPanelsScreen({
      result: testResult({ findings: [testFinding({ ruleId: "PG-SQL-001" })] }),
      locale: "en",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys: scripted(press("left"), press("return"), press("escape"), press("escape")),
      ruleTexts: getRuleTextCatalog(),
      processEvents: new EventEmitter(),
    });
    expect(exit).toBe("back");
    await new Promise((resolve) => setImmediate(resolve));
    expect(out.written()).toContain("https://cwe.mitre.org/data/definitions/89.html");
  });

  it("gives the screen back synchronously at SIGINT, before the key wait unwinds", () => {
    const writes: string[] = [];
    const stdout = {
      isTTY: true,
      columns: 80,
      rows: 24,
      write: (chunk: string) => {
        writes.push(chunk);
        return true;
      },
      on: () => stdout,
      off: () => stdout,
    };
    const processEvents = new EventEmitter();
    void runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: stdout as never,
      env: EMPTY_ENV,
      keys: keysOf(() => new Promise<Key>(() => undefined)),
      processEvents,
    });
    processEvents.emit("SIGINT");
    // No await: the terminal is already restored when the signal handler returns.
    expect(writes.at(-1)).toBe(LEAVE);
  });
});

describe("runPanelsScreen: the e key", () => {
  const BACK_TEXT = "Press any key to return to the panel view.";

  function run(
    keys: KeyReader,
    exportReport?: () => Promise<"saved" | "failed" | "cancelled">,
    processEvents: EventEmitter = new EventEmitter(),
  ) {
    const out = fakeStdout();
    const done = runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys,
      processEvents,
      ...(exportReport === undefined ? {} : { exportReport }),
    });
    return { out, done, processEvents };
  }

  it("leaves the screen, runs the export, then comes back to the same panel", async () => {
    const seen: string[] = [];
    const out = fakeStdout();
    const keys = scripted(
      press("tab"),
      press("tab"),
      press("tab"),
      press("tab"),
      press("/"),
      press("s"),
      press("q"),
      press("return"),
      press("e"),
      press("x"), // any key after the export
      press("q"),
    );
    // "q" typed into the search must not leave: it is text while the search line is open.
    const exit = await runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys,
      processEvents: new EventEmitter(),
      exportReport: async () => {
        seen.push(out.written().endsWith(LEAVE) ? "screen left" : "screen still open");
        return "saved";
      },
    });
    expect(exit).toBe("back");
    expect(seen).toEqual(["screen left"]);
    const written = out.written();
    const parts = written.split(ENTER);
    // Entered twice: before and after the export.
    expect(parts).toHaveLength(3);
    expect(parts[2]).toContain("[Findings (0 of 12)]");
    expect(parts[2]).toContain('search: "sq"');
    expect(parts[1]).toContain(BACK_TEXT);
    expect(written.endsWith(LEAVE)).toBe(true);
  });

  it("also restores the scroll position of the panel", async () => {
    const out = fakeStdout(80, 12);
    const exit = await runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys: scripted(
        press("down"),
        press("down"),
        press("down"),
        press("e"),
        press("x"),
        press("q"),
      ),
      processEvents: new EventEmitter(),
      exportReport: async () => "failed",
    });
    expect(exit).toBe("back");
    const parts = out.written().split(ENTER);
    const lastBefore = parts[1]?.split("\u001b[H").at(-1) ?? "";
    const firstAfter = parts[2]?.split("\u001b[H")[1] ?? "";
    expect(firstAfter).toBe(lastBefore.split("\u001b[?25h")[0]);
  });

  it("returns to the panel at once when the export is cancelled (no key wait)", async () => {
    // No key is scripted for a pause: waiting for one would throw "no more keys".
    const { done, out } = (() => {
      const r = run(scripted(press("e"), press("escape")), async () => "cancelled");
      return { done: r.done, out: r.out };
    })();
    expect(await done).toBe("back");
    expect(out.written().split(ENTER)).toHaveLength(3);
    expect(out.written()).not.toContain(BACK_TEXT);
  });

  it("waits for a key after a failed write and then resumes; the view's exit is unchanged", async () => {
    const { done, out } = run(
      scripted(press("e"), press("n"), press("escape")),
      async () => "failed",
    );
    expect(await done).toBe("back");
    expect(out.written()).toContain(BACK_TEXT);
  });

  it("shows the return line in Korean", async () => {
    const out = fakeStdout();
    await runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "ko",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys: scripted(press("e"), press("n"), press("escape")),
      processEvents: new EventEmitter(),
      exportReport: async () => "saved",
    });
    expect(out.written()).toContain("아무 키나 누르면 패널 화면으로 돌아갑니다.");
  });

  it("asks the usual cancel question when Ctrl+C is pressed at the pause; y then cancels", async () => {
    const { done, out } = run(scripted(press("e"), ctrlC, press("y")), async () => "saved");
    expect(await done).toBe("cancel");
    expect(out.written()).toContain("Cancel and exit? [y/N]");
    expect(out.written().endsWith(LEAVE)).toBe(true);
    const back = run(scripted(press("e"), ctrlC, press("n"), press("escape")), async () => "saved");
    expect(await back.done).toBe("back");
  });

  it("ends as cancel when a prompt inside the export confirmed Ctrl+C", async () => {
    const { done, out, processEvents } = run(scripted(press("e")), async () => {
      throw new UserCancelledError();
    });
    expect(await done).toBe("cancel");
    expect(out.written().endsWith(LEAVE)).toBe(true);
    expect(processEvents.listenerCount("SIGTERM")).toBe(0);
  });

  it("rethrows an unexpected error from the export with the terminal restored", async () => {
    const { done, out } = run(scripted(press("e")), async () => {
      throw new Error("export broke");
    });
    await expect(done).rejects.toThrow("export broke");
    expect(out.written().endsWith(LEAVE)).toBe(true);
  });

  it("ends as terminated on SIGTERM and as cancel on SIGINT during the export prompts", async () => {
    for (const [signal, expected] of [
      ["SIGTERM", "terminated"],
      ["SIGINT", "cancel"],
    ] as const) {
      const processEvents = new EventEmitter();
      const { done, out } = run(
        scripted(press("e")),
        () => new Promise<"saved">(() => undefined),
        processEvents,
      );
      await new Promise((resolve) => setImmediate(resolve));
      expect(out.written().endsWith(LEAVE), signal).toBe(true);
      processEvents.emit(signal);
      expect(await done, signal).toBe(expected);
      expect(out.written().endsWith(LEAVE), signal).toBe(true);
      expect(processEvents.listenerCount("SIGTERM"), signal).toBe(0);
    }
  });

  it("ignores e when no export is given, and keeps the screen open", async () => {
    const { done, out } = run(scripted(press("e"), press("escape")));
    expect(await done).toBe("back");
    expect(out.written().split(ENTER)).toHaveLength(2);
    expect(out.written()).not.toContain("e: export");
  });
});
