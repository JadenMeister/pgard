import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  folderBreadthRefusal,
  repositoryRootOf,
  tooBroadToScan,
  type EntryKind,
  type FileIdentity,
} from "./folder-breadth.js";

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

describe("alias spellings that realpath keeps (#427)", () => {
  const mac = { ...posix, ignoreCase: true };

  it("reads macOS firmlinks (/System/Volumes/Data/...) as the short path", () => {
    const home = "/Users/me";
    expect(tooBroadToScan("/System/Volumes/Data/Users/me", home, mac)).toBe("home");
    expect(tooBroadToScan("/System/Volumes/Data/Users", home, mac)).toBe("top_level");
    expect(tooBroadToScan("/System/Volumes/Data", home, mac)).toBe("root");
    expect(tooBroadToScan("/system/volumes/data/users/ME", home, mac)).toBe("home");
    expect(tooBroadToScan("/System/Volumes/Data/Users/me/code/app", home, mac)).toBeNull();
    // Home itself spelled through the firmlink.
    expect(tooBroadToScan("/Users/me", "/System/Volumes/Data/Users/me", mac)).toBe("home");
    expect(tooBroadToScan("/Users", "/System/Volumes/Data/Users/me", mac)).toBe("top_level");
  });

  it("treats /System/Volumes/<x> as top-level", () => {
    for (const volume of ["Data", "Preboot", "VM", "Update"]) {
      expect(tooBroadToScan(`/System/Volumes/${volume}`, "/Users/me", mac)).not.toBeNull();
    }
    expect(tooBroadToScan("/System/Volumes/Preboot", "/Users/me", mac)).toBe("top_level");
    expect(tooBroadToScan("/System/Volumes/Preboot/x", "/Users/me", mac)).toBeNull();
  });

  it("refuses /proc, /sys and /dev at any depth", () => {
    for (const folder of ["/proc", "/proc/1234", "/proc/1234/cwd/x", "/sys/kernel", "/dev/shm/a"]) {
      expect(tooBroadToScan(folder, "/home/u", posix)).toBe("virtual");
    }
    expect(tooBroadToScan("/home/u/proc/1", "/home/u", posix)).toBeNull();
    expect(tooBroadToScan("/srv/sys", "/home/u", posix)).toBeNull();
  });

  it("reads Windows prefixes and administrative shares", () => {
    const win = { pathApi: path.win32, ignoreCase: true };
    const home = "C:\\Users\\me";
    expect(tooBroadToScan("\\\\?\\C:\\Users\\me", home, win)).toBe("home");
    expect(tooBroadToScan("\\\\.\\C:\\Users\\me", home, win)).toBe("home");
    expect(tooBroadToScan("\\\\?\\C:\\Users", home, win)).toBe("top_level");
    expect(tooBroadToScan("\\\\?\\C:\\", home, win)).toBe("root");
    expect(tooBroadToScan("\\\\?\\UNC\\localhost\\C$\\Users\\me", home, win)).toBe("home");
    expect(tooBroadToScan("\\\\localhost\\C$\\Users\\me", home, win)).toBe("home");
    expect(tooBroadToScan("\\\\127.0.0.1\\c$\\Users", home, win)).toBe("top_level");
    expect(tooBroadToScan("\\\\host\\C$", home, win)).toBe("root");
    expect(tooBroadToScan("\\\\localhost\\C$\\Users\\me\\code\\app", home, win)).toBeNull();
    // Home itself given with a prefix.
    expect(tooBroadToScan("C:\\Users\\me", "\\\\?\\C:\\Users\\me", win)).toBe("home");
    // A normal share that is not an administrative one stays a share root.
    expect(tooBroadToScan("\\\\fileserver\\projects\\app", home, win)).toBe("top_level");
    expect(tooBroadToScan("\\\\fileserver\\projects\\app\\src", home, win)).toBeNull();
    expect(tooBroadToScan("\\\\fileserver\\projects", home, win)).toBe("root");
  });
});

describe("folderBreadthRefusal: identity check (#427)", () => {
  const ids = new Map<string, FileIdentity>([
    ["/", { dev: 1, ino: 2 }],
    ["/Users", { dev: 1, ino: 20 }],
    ["/Users/me", { dev: 1, ino: 200 }],
    ["/Users/me/code", { dev: 1, ino: 300 }],
    // Aliases the string rules do not know.
    ["/mnt/alias-of-home", { dev: 1, ino: 200 }],
    ["/mnt/alias-of-users", { dev: 1, ino: 20 }],
    ["/mnt/alias-of-root", { dev: 1, ino: 2 }],
    ["/mnt/other-device", { dev: 9, ino: 200 }],
  ]);
  const identityOf = async (target: string): Promise<FileIdentity> => ids.get(target) ?? null;
  const options = { ...posix, identityOf };

  it("refuses a folder that is the same object as home, a parent of home or the root", async () => {
    expect(await folderBreadthRefusal("/mnt/alias-of-home/x/..", "/Users/me", options)).toBe(
      "home",
    );
    expect(await folderBreadthRefusal("/mnt/alias-of-users", "/Users/me", options)).toBe(
      "above_home",
    );
    expect(await folderBreadthRefusal("/mnt/alias-of-root/y/..", "/Users/me", options)).toBe(
      "root",
    );
  });

  it("allows a different folder, a same inode on another device and an unreadable path", async () => {
    expect(await folderBreadthRefusal("/Users/me/code", "/Users/me", options)).toBeNull();
    expect(await folderBreadthRefusal("/mnt/other-device", "/Users/me", options)).toBeNull();
    expect(await folderBreadthRefusal("/mnt/missing", "/Users/me", options)).toBeNull();
  });

  it("still applies the string rules first, and ignores a zero inode (Windows)", async () => {
    expect(await folderBreadthRefusal("/System/Volumes/Data/Users/me", "/Users/me", options)).toBe(
      "home",
    );
    const zero = async (): Promise<FileIdentity> => ({ dev: 1, ino: 0 });
    expect(
      await folderBreadthRefusal("/srv/app", "/Users/me", { ...posix, identityOf: zero }),
    ).toBeNull();
  });
});

describe("repositoryRootOf: the .git walk without Git (#427)", () => {
  const entries = new Map<string, EntryKind>([
    ["/home/u/.git", "directory"],
    ["/home/u/work/app/.git", "directory"],
    ["/srv/sub/.git", "file"],
  ]);
  const kindOf = async (entry: string): Promise<EntryKind> => entries.get(entry) ?? null;

  it("finds the nearest folder with a .git entry, the folder itself first", async () => {
    expect(await repositoryRootOf("/home/u/work/app", "/home/u", kindOf, posix)).toBe(
      "/home/u/work/app",
    );
    expect(await repositoryRootOf("/home/u/work/app/src/deep", "/home/u", kindOf, posix)).toBe(
      "/home/u/work/app",
    );
    expect(await repositoryRootOf("/srv/sub/x", null, kindOf, posix)).toBe("/srv/sub");
  });

  it("stops at home: a dotfiles repository at home never encloses a project folder", async () => {
    expect(await repositoryRootOf("/home/u/proj", "/home/u", kindOf, posix)).toBeNull();
    // But the home folder itself reports its own repository, so the caller can refuse it.
    expect(await repositoryRootOf("/home/u", "/home/u", kindOf, posix)).toBe("/home/u");
  });
});
