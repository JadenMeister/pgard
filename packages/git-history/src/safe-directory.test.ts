import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { lstat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { isGitDirectoryName, openDirectoryNoFollow } from "./safe-read.js";

describe("openDirectoryNoFollow (#427)", () => {
  const dirs: string[] = [];
  const temp = () => {
    const dir = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-safedir-")));
    dirs.push(dir);
    return dir;
  };
  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  async function entries(directory: string): Promise<string[]> {
    const opened = await openDirectoryNoFollow(directory);
    if (opened.state !== "ok") throw new Error(`not opened: ${JSON.stringify(opened)}`);
    const names: string[] = [];
    try {
      for await (const entry of opened.dir) names.push(entry.name);
    } finally {
      // Iterating to the end closes the handle already.
      await opened.dir.close().catch(() => undefined);
    }
    return names.sort();
  }

  it("opens a real folder and lists its entries", async () => {
    const dir = temp();
    writeFileSync(path.join(dir, "a.txt"), "x");
    mkdirSync(path.join(dir, "sub"));
    expect(await entries(dir)).toEqual(["a.txt", "sub"]);
  });

  it("reports a missing folder as absent", async () => {
    expect(await openDirectoryNoFollow(path.join(temp(), "missing"))).toEqual({
      state: "absent",
    });
  });

  it("refuses a folder that is a symbolic link, and a file", async () => {
    const dir = temp();
    mkdirSync(path.join(dir, "real"));
    writeFileSync(path.join(dir, "real", "secret.txt"), "x");
    writeFileSync(path.join(dir, "file"), "x");
    try {
      symlinkSync(path.join(dir, "real"), path.join(dir, "link"), "junction");
    } catch {
      return; // no permission to link here
    }
    expect(await openDirectoryNoFollow(path.join(dir, "link"))).toEqual({
      state: "unsafe",
      found: "symlink",
    });
    expect(await openDirectoryNoFollow(path.join(dir, "file"))).toEqual({
      state: "unsafe",
      found: "special",
    });
  });

  it("follows a link only when the caller says the walk's root may be one", async () => {
    const dir = temp();
    mkdirSync(path.join(dir, "real"));
    writeFileSync(path.join(dir, "real", "a.txt"), "x");
    try {
      symlinkSync(path.join(dir, "real"), path.join(dir, "link"), "junction");
    } catch {
      return;
    }
    const opened = await openDirectoryNoFollow(path.join(dir, "link"), { allowSymlink: true });
    expect(opened.state).toBe("ok");
    if (opened.state === "ok") await opened.dir.close();
  });

  it("does not enter a folder on another device (a mount point)", async () => {
    const dir = temp();
    const device = (await lstat(dir, { bigint: true })).dev;
    expect((await openDirectoryNoFollow(dir, { expectedDev: device })).state).toBe("ok");
    const other = await openDirectoryNoFollow(dir, { expectedDev: device + 1n });
    expect(other).toEqual({ state: "unsafe", found: "mount" });
  });

  it("recognises .git in any case only where the file system ignores case", () => {
    expect(isGitDirectoryName(".git", "linux")).toBe(true);
    expect(isGitDirectoryName(".GIT", "linux")).toBe(false);
    expect(isGitDirectoryName(".Git", "darwin")).toBe(true);
    expect(isGitDirectoryName(".GIT", "win32")).toBe(true);
    expect(isGitDirectoryName(".gitignore", "darwin")).toBe(false);
  });
});
