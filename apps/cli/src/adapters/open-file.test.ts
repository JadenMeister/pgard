import { describe, expect, it } from "vitest";
import { openLocalFile, openerCommandForFile } from "./open-file.js";

describe("openerCommandForFile", () => {
  it("uses a fixed argument vector per platform", () => {
    expect(openerCommandForFile("darwin", "/tmp/r.html")).toEqual({
      command: "/usr/bin/open",
      args: ["/tmp/r.html"],
    });
    expect(openerCommandForFile("linux", "/tmp/r.pdf")).toEqual({
      command: "xdg-open",
      args: ["/tmp/r.pdf"],
    });
    expect(openerCommandForFile("win32", "C:\\Temp\\r.html", { SystemRoot: "D:\\Win" })).toEqual({
      command: "D:\\Win\\explorer.exe",
      args: ["C:\\Temp\\r.html"],
    });
  });

  it("opens only absolute .html and .pdf paths", () => {
    expect(openerCommandForFile("linux", "r.html")).toBeNull();
    expect(openerCommandForFile("linux", "/tmp/r.exe")).toBeNull();
    expect(openerCommandForFile("linux", "/tmp/r.html\n")).toBeNull();
    expect(openerCommandForFile("linux", "-x.html")).toBeNull();
    expect(openerCommandForFile("win32", "\\rooted.html")).toBeNull();
    expect(openerCommandForFile("win32", "C:rel.html")).toBeNull();
    expect(openerCommandForFile("win32", "\\\\host\\share\\r.html")).not.toBeNull();
  });
});

describe("openLocalFile", () => {
  it("passes the command to the spawner and reports failure as false", async () => {
    const calls: Array<[string, readonly string[]]> = [];
    const spawn = async (command: string, args: readonly string[]) => {
      calls.push([command, args]);
      return true;
    };
    expect(await openLocalFile("/tmp/r.html", { platform: "darwin", spawn })).toBe(true);
    expect(calls).toEqual([["/usr/bin/open", ["/tmp/r.html"]]]);
    expect(await openLocalFile("relative.html", { platform: "darwin", spawn })).toBe(false);
    expect(
      await openLocalFile("/tmp/r.html", {
        platform: "linux",
        spawn: async () => {
          throw new Error("boom");
        },
      }),
    ).toBe(false);
  });
});
