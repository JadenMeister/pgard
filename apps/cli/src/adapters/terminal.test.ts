import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { UserCancelledError } from "../ui/components/prompts.js";
import { createKeyReader, waitForEnter, type InputStream } from "./terminal.js";

function fakeTty(): InputStream & PassThrough & { rawModes: boolean[] } {
  const stream = new PassThrough() as PassThrough & InputStream & { rawModes: boolean[] };
  stream.isTTY = true;
  stream.rawModes = [];
  stream.setRawMode = (mode: boolean) => {
    stream.rawModes.push(mode);
    return stream;
  };
  return stream;
}

describe("createKeyReader", () => {
  it("reads keys in raw mode and fully detaches on suspend", async () => {
    const stdin = fakeTty();
    const keys = createKeyReader(stdin);
    const pending = keys.readKey();
    stdin.write("y");
    expect((await pending).name).toBe("y");
    expect(stdin.rawModes).toEqual([true]);
    expect(stdin.listenerCount("keypress")).toBeGreaterThan(0);

    keys.suspend();
    expect(stdin.rawModes).toEqual([true, false]);
    // Only readline's internal listener may remain; ours is gone.
    const listenersAfterSuspend = stdin.listenerCount("keypress");

    // Ctrl+C typed while suspended is not queued for the next prompt.
    stdin.emit("keypress", "\u0003", { name: "c", ctrl: true, sequence: "\u0003" });
    const next = keys.readKey();
    expect(stdin.rawModes).toEqual([true, false, true]);
    expect(stdin.listenerCount("keypress")).toBe(listenersAfterSuspend + 1);
    await new Promise((resolve) => setTimeout(resolve, 60));
    stdin.write("n");
    expect((await next).name).toBe("n");
    keys.close();
  });

  it("discards input typed ahead while work was running", async () => {
    const stdin = fakeTty();
    let clock = 0;
    const keys = createKeyReader(stdin, () => clock);
    const first = keys.readKey();
    clock = 100;
    stdin.write("a");
    expect((await first).name).toBe("a");
    keys.suspend();
    // Typed while suspended (stdin paused): buffered and flushed right after re-activation.
    stdin.write("y");
    clock = 1000;
    const next = keys.readKey();
    await new Promise((resolve) => setTimeout(resolve, 10));
    clock = 1100;
    stdin.write("n");
    expect((await next).name).toBe("n");
    keys.close();
  });

  it("discards type-ahead even when suspend() ran before the first prompt", async () => {
    const stdin = fakeTty();
    let clock = 0;
    const keys = createKeyReader(stdin, () => clock);
    keys.suspend(); // long-running work starts before any prompt was shown
    clock = 500;
    const pending = keys.readKey();
    stdin.write("y"); // typed during the work, delivered on activation
    await new Promise((resolve) => setTimeout(resolve, 10));
    clock = 600;
    stdin.write("n");
    expect((await pending).name).toBe("n");
    keys.close();
  });
});

describe("end of input", () => {
  const ended = (stream: PassThrough) =>
    new Promise<void>((resolve) => {
      stream.once("end", () => resolve());
      stream.resume();
      stream.end();
    });

  it("rejects readKey with the cancel error once stdin has ended", async () => {
    const stdin = fakeTty();
    const keys = createKeyReader(stdin);
    await ended(stdin);
    await expect(keys.readKey()).rejects.toBeInstanceOf(UserCancelledError);
  });

  it("rejects a readKey that is already waiting when stdin ends", async () => {
    const stdin = fakeTty();
    const keys = createKeyReader(stdin);
    const pending = keys.readKey();
    stdin.end();
    stdin.resume();
    await expect(pending).rejects.toBeInstanceOf(UserCancelledError);
  });

  it("rejects readKey on a stream that had ended before the reader was made", async () => {
    const stdin = fakeTty();
    await ended(stdin);
    await expect(createKeyReader(stdin).readKey()).rejects.toBeInstanceOf(UserCancelledError);
  });

  it("waitForEnter stops quietly on end and never calls onEnter", async () => {
    const stdin = fakeTty();
    let entered = 0;
    waitForEnter(
      stdin,
      () => (entered += 1),
      () => 1000,
    );
    await ended(stdin);
    expect(entered).toBe(0);
    expect(stdin.listenerCount("data")).toBe(0);
  });

  it("opens only once: a second Enter does nothing", () => {
    const stdin = fakeTty();
    let entered = 0;
    let clock = 0;
    waitForEnter(
      stdin,
      () => (entered += 1),
      () => (clock += 100),
    );
    stdin.write("\n");
    stdin.write("\n");
    expect(entered).toBe(1);
  });
});
