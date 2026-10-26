import { describe, expect, it } from "vitest";
import { resolveStoreDirectory } from "./paths.js";

describe("resolveStoreDirectory", () => {
  it("uses Application Support on macOS", () => {
    expect(resolveStoreDirectory({ platform: "darwin", env: {}, homeDir: "/Users/ann" })).toBe(
      "/Users/ann/Library/Application Support/pgard",
    );
  });

  it("follows XDG_DATA_HOME on Linux, only when absolute", () => {
    expect(
      resolveStoreDirectory({ platform: "linux", env: { XDG_DATA_HOME: "/data" }, homeDir: "/h" }),
    ).toBe("/data/pgard");
    expect(
      resolveStoreDirectory({ platform: "linux", env: { XDG_DATA_HOME: "rel" }, homeDir: "/h" }),
    ).toBe("/h/.local/share/pgard");
    expect(resolveStoreDirectory({ platform: "linux", env: {}, homeDir: "/h" })).toBe(
      "/h/.local/share/pgard",
    );
  });

  it("uses LOCALAPPDATA on Windows, with a home fallback", () => {
    expect(
      resolveStoreDirectory({
        platform: "win32",
        env: { LOCALAPPDATA: "C:\\Users\\ann\\AppData\\Local" },
        homeDir: "C:\\Users\\ann",
      }),
    ).toBe("C:\\Users\\ann\\AppData\\Local\\pgard");
    expect(resolveStoreDirectory({ platform: "win32", env: {}, homeDir: "C:\\Users\\ann" })).toBe(
      "C:\\Users\\ann\\AppData\\Local\\pgard",
    );
    expect(
      resolveStoreDirectory({ platform: "win32", env: { LOCALAPPDATA: "relative" }, homeDir: "" }),
    ).toBeNull();
  });

  it("returns null without a usable home directory", () => {
    expect(resolveStoreDirectory({ platform: "darwin", env: {}, homeDir: "" })).toBeNull();
    expect(resolveStoreDirectory({ platform: "linux", env: {}, homeDir: "rel" })).toBeNull();
  });
});
