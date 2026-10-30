import path from "node:path";
import { describe, expect, it } from "vitest";
import { tooBroadToScan } from "./folder-breadth.js";

const posix = { pathApi: path.posix };

describe("tooBroadToScan (shared by pgard scan code and the web folder chooser)", () => {
  it("refuses the root and every top-level folder", () => {
    expect(tooBroadToScan("/", "/Users/u", posix)).toBe("root");
    for (const folder of ["/Users", "/home", "/Volumes", "/etc", "/opt", "/tmp", "/private"]) {
      expect(tooBroadToScan(folder, "/Users/u", posix)).toBe("top_level");
    }
  });

  it("treats folders directly in /private as top-level (macOS real paths of /etc, /tmp, /var)", () => {
    for (const folder of ["/private/etc", "/private/tmp", "/private/var"]) {
      expect(tooBroadToScan(folder, "/Users/u", posix)).toBe("top_level");
    }
    expect(tooBroadToScan("/Private/Tmp", "/Users/u", { ...posix, ignoreCase: true })).toBe(
      "top_level",
    );
    expect(tooBroadToScan("/private/var/folders", "/Users/u", posix)).toBeNull();
    expect(tooBroadToScan("/srv/etc", "/Users/u", posix)).toBeNull();
  });

  it("refuses the home folder and folders above it, but not folders inside it", () => {
    expect(tooBroadToScan("/Users/u", "/Users/u", posix)).toBe("home");
    expect(tooBroadToScan("/Users/u/", "/Users/u", posix)).toBe("home");
    expect(tooBroadToScan("/srv/homes", "/srv/homes/u", posix)).toBe("above_home");
    expect(tooBroadToScan("/Users/u/code/app", "/Users/u", posix)).toBeNull();
    // A sibling whose name starts like the home folder is not above it.
    expect(tooBroadToScan("/srv/home", "/srv/homes/u", posix)).toBeNull();
  });

  it("ignores case only when asked (macOS and Windows)", () => {
    expect(tooBroadToScan("/users/U", "/Users/u", posix)).toBeNull();
    expect(tooBroadToScan("/users/U", "/Users/u", { ...posix, ignoreCase: true })).toBe("home");
  });

  it("works with Windows paths", () => {
    const win32 = { pathApi: path.win32, ignoreCase: true };
    expect(tooBroadToScan("C:\\", "C:\\Users\\u", win32)).toBe("root");
    expect(tooBroadToScan("C:\\Users", "C:\\Users\\u", win32)).toBe("top_level");
    expect(tooBroadToScan("c:\\users\\U", "C:\\Users\\u", win32)).toBe("home");
    expect(tooBroadToScan("C:\\Users\\u\\code\\app", "C:\\Users\\u", win32)).toBeNull();
  });

  it("checks only the root and top-level rule when the home folder is unknown", () => {
    expect(tooBroadToScan("/Users/u", null, posix)).toBeNull();
    expect(tooBroadToScan("/Users", null, posix)).toBe("top_level");
  });
});
