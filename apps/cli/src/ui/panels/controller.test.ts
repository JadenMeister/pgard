import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import type { Key, KeyReader } from "../../adapters/terminal.js";
import { panelsFixtureResult } from "../../test-support.js";
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
          throw new UserCancelledError();
        }),
        processEvents,
      }),
    ).rejects.toBeInstanceOf(UserCancelledError);
    expect(out.written().endsWith(LEAVE)).toBe(true);
    expect(processEvents.listenerCount("SIGINT")).toBe(0);
  });

  it("restores the terminal and ends as cancel on SIGINT and on SIGTERM", async () => {
    for (const signal of ["SIGINT", "SIGTERM"]) {
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
      expect(await running, signal).toBe("cancel");
      expect(out.written().endsWith(LEAVE), signal).toBe(true);
      expect(processEvents.listenerCount(signal)).toBe(0);
    }
  });

  it("restores the terminal when the process exits or throws unexpectedly", async () => {
    const out = fakeStdout();
    const processEvents = new EventEmitter();
    const never = keysOf(() => new Promise<Key>(() => undefined));
    void runPanelsScreen({
      result: panelsFixtureResult(),
      locale: "en",
      stdout: out.stream,
      env: EMPTY_ENV,
      keys: never,
      processEvents,
    });
    const boom = new Error("boom");
    expect(() => processEvents.emit("uncaughtException", boom)).toThrow(boom);
    expect(out.written().endsWith(LEAVE)).toBe(true);
    // Restoring twice writes nothing more.
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
