import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { createKeyReader, type InputStream } from "./terminal.js";

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
    stdin.write("n");
    expect((await next).name).toBe("n");
    keys.close();
  });
});
