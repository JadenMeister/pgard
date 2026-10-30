import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readTextFile } from "./walk.js";

describe("readTextFile never follows a link or waits on a FIFO (#427)", () => {
  const dirs: string[] = [];
  const temp = () => {
    const dir = mkdtempSync(path.join(tmpdir(), "pgard-readtext-"));
    dirs.push(dir);
    return dir;
  };
  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  it("reads a regular text file, and refuses NUL bytes and a file over the limit", async () => {
    const dir = temp();
    writeFileSync(path.join(dir, "a.js"), "const a = 1;\n");
    writeFileSync(path.join(dir, "bin.js"), Buffer.from([0x61, 0, 0x62]));
    expect(await readTextFile(path.join(dir, "a.js"))).toBe("const a = 1;\n");
    expect(await readTextFile(path.join(dir, "bin.js"))).toBeNull();
    expect(await readTextFile(path.join(dir, "a.js"), 4)).toBeNull();
    expect(await readTextFile(path.join(dir, "missing.js"))).toBeNull();
  });

  it.skipIf(process.platform === "win32")("does not follow a symbolic link", async () => {
    const dir = temp();
    writeFileSync(path.join(dir, "real.js"), "const secret = 1;\n");
    symlinkSync(path.join(dir, "real.js"), path.join(dir, "link.js"));
    expect(await readTextFile(path.join(dir, "link.js"))).toBeNull();
  });

  it.skipIf(process.platform === "win32")("does not block on a FIFO", async () => {
    const dir = temp();
    const fifo = path.join(dir, "pipe.js");
    execFileSync("mkfifo", [fifo]);
    const started = Date.now();
    expect(await readTextFile(fifo)).toBeNull();
    expect(Date.now() - started).toBeLessThan(2000);
  });
});
