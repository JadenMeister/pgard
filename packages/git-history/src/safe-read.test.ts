import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readSmallRegularFile } from "./safe-read.js";

describe("readSmallRegularFile", () => {
  const dirs: string[] = [];
  const temp = () => {
    const dir = mkdtempSync(path.join(tmpdir(), "pgard-saferead-"));
    dirs.push(dir);
    return dir;
  };
  afterEach(() => {
    for (const dir of dirs.splice(0)) {
      try {
        chmodSync(path.join(dir, "locked"), 0o755);
      } catch {
        // not created in this test
      }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reads a small regular file and reports a missing one as absent", async () => {
    const dir = temp();
    writeFileSync(path.join(dir, "f"), "hello\n");
    expect(await readSmallRegularFile(path.join(dir, "f"), 100)).toEqual({
      state: "ok",
      text: "hello\n",
    });
    expect(await readSmallRegularFile(path.join(dir, "missing"), 100)).toEqual({
      state: "absent",
    });
  });

  it("treats a file used as a parent directory (ENOTDIR) as unsafe, not absent", async () => {
    const dir = temp();
    writeFileSync(path.join(dir, "parent"), "x");
    expect(await readSmallRegularFile(path.join(dir, "parent", "child"), 100)).toEqual({
      state: "unsafe",
    });
  });

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "treats an inaccessible parent directory (EACCES) as unsafe, not absent",
    async () => {
      const dir = temp();
      mkdirSync(path.join(dir, "locked"));
      writeFileSync(path.join(dir, "locked", "f"), "x");
      chmodSync(path.join(dir, "locked"), 0o000);
      expect(await readSmallRegularFile(path.join(dir, "locked", "f"), 100)).toEqual({
        state: "unsafe",
      });
    },
  );

  it("treats a file over the cap as unsafe", async () => {
    const dir = temp();
    writeFileSync(path.join(dir, "f"), "x".repeat(101));
    expect(await readSmallRegularFile(path.join(dir, "f"), 100)).toEqual({ state: "unsafe" });
  });
});
