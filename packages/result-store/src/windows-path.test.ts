import { describe, expect, it } from "vitest";
import {
  isWindowsDrivePath,
  loadSearchScope,
  normalizeWindowsPath,
  pathDepth,
  pathRulesFor,
  safetyProblemOf,
  validateSearchRoot,
  windowsPathProblem,
  windowsSystemFolders,
  type ScopeFs,
  type ScopeStat,
} from "./index.js";

/** The Windows path rules run on every OS: the platform is passed in (#477). */

describe("windowsPathProblem", () => {
  it.each([
    ["C:\\Users\\me\\code", null],
    ["c:/Users/me/code", null],
    ["D:\\", null],
    ["C:\\Users\\김철수\\프로젝트 폴더", null],
    ["C:\\code\\my.app", null],
    ["\\\\server\\share\\code", "unc"],
    ["//server/share/code", "unc"],
    ["\\\\?\\C:\\Users\\me", "device"],
    ["\\\\.\\C:\\Users\\me", "device"],
    ["//?/C:/Users/me", "device"],
    ["//./pipe/x", "device"],
    ["\\??\\C:\\Users\\me", "device"],
    ["\\\\?\\UNC\\server\\share", "device"],
    ["C:code", "drive_relative"],
    ["C:", "drive_relative"],
    ["\\code", "drive_relative"],
    ["/code", "drive_relative"],
    ["code\\app", "not_absolute"],
    ["~\\code", "not_absolute"],
    ["C:\\Users\\me\\file.txt:stream", "stream"],
    ["C:\\Users\\me\\file.txt::$DATA", "stream"],
    ["C:\\Users\\me\\code.", "trailing"],
    ["C:\\Users\\me\\code ", "trailing"],
    ["C:\\Users\\me\\code. .", "trailing"],
    ["C:\\Users\\me\\NUL", "reserved"],
    ["C:\\Users\\me\\com1.txt", "reserved"],
    ["C:\\Users\\me\\a<b", "invalid_char"],
    ["C:\\Users\\me\\a*b", "invalid_char"],
    ["C:\\Users\\me\\a\u0001b", "invalid_char"],
  ] as const)("%j -> %s", (value, expected) => {
    expect(windowsPathProblem(value)).toBe(expected);
  });

  it("recognizes the drive spelling", () => {
    expect(isWindowsDrivePath("C:\\x")).toBe(true);
    expect(isWindowsDrivePath("c:/x")).toBe(true);
    expect(isWindowsDrivePath("/x")).toBe(false);
    expect(isWindowsDrivePath("C:x")).toBe(false);
  });
});

describe("normalizeWindowsPath", () => {
  it("normalizes separators, dots and the trailing separator", () => {
    expect(normalizeWindowsPath("C:/Users/me/code/")).toBe("C:\\Users\\me\\code");
    expect(normalizeWindowsPath("C:\\Users\\me\\.\\code\\..\\code")).toBe("C:\\Users\\me\\code");
    expect(normalizeWindowsPath("C:\\Users\\\\me")).toBe("C:\\Users\\me");
    expect(normalizeWindowsPath("c:\\")).toBe("c:\\");
  });

  it("refuses what is not a plain local path, also after `..` is collapsed", () => {
    expect(normalizeWindowsPath("\\\\server\\share")).toBeNull();
    expect(normalizeWindowsPath("C:foo")).toBeNull();
    expect(normalizeWindowsPath("C:\\a\\..\\..\\..\\Windows")).toBe("C:\\Windows");
    expect(normalizeWindowsPath("C:\\a\\b:s")).toBeNull();
  });
});

describe("pathRulesFor", () => {
  it("compares Windows paths without case and POSIX paths with case", () => {
    const windows = pathRulesFor("win32");
    expect(windows.isBelow("c:\\users\\ME\\code", "C:\\Users\\me")).toBe(true);
    expect(windows.isBelow("C:\\Users\\meX", "C:\\Users\\me")).toBe(false);
    expect(windows.isBelow("C:\\x", "C:\\")).toBe(true);
    expect(windows.lastName("C:\\Users\\me\\code")).toBe("code");
    const posix = pathRulesFor("linux");
    expect(posix.isBelow("/Home/u/code", "/home/u")).toBe(false);
    expect(posix.isBelow("/home/u/code", "/home/u")).toBe(true);
    expect(posix.lastName("/home/u/a\\b")).toBe("a\\b");
  });

  it("counts Windows depth below the drive root", () => {
    expect(pathDepth("C:\\", "win32")).toBe(0);
    expect(pathDepth("C:\\Users", "win32")).toBe(1);
    expect(pathDepth("C:\\Users\\me", "win32")).toBe(2);
  });
});

describe("windowsSystemFolders", () => {
  it("takes the environment's folders when they are plain drive paths, plus the defaults", () => {
    const folders = windowsSystemFolders({
      SystemRoot: "D:\\WINNT",
      ProgramFiles: "D:\\Programs",
      ProgramData: "\\\\evil\\share",
    });
    expect(folders).toContain("D:\\WINNT");
    expect(folders).toContain("D:\\Programs");
    expect(folders).not.toContain("\\\\evil\\share");
    expect(folders).toContain("C:\\Windows");
  });
});

const dirStat = (): ScopeStat => ({
  isDirectory: true,
  isFile: false,
  isSymbolicLink: false,
  uid: 0,
  mode: 0o40777,
  dev: 7,
  ino: 9,
});

/** A Windows-like file system: `links` maps a path to what `realpath` returns for it. */
function windowsFs(options: {
  existing: string[];
  links?: Record<string, string>;
  symlinks?: string[];
}): ScopeFs {
  const known = new Set(options.existing.map((entry) => entry.toLowerCase()));
  const links = new Map(
    Object.entries(options.links ?? {}).map(([from, to]) => [from.toLowerCase(), to]),
  );
  const symlinks = new Set((options.symlinks ?? []).map((entry) => entry.toLowerCase()));
  const missing = (): Error => Object.assign(new Error("missing"), { code: "ENOENT" });
  return {
    async lstat(target) {
      if (!known.has(target.toLowerCase())) throw missing();
      return { ...dirStat(), isSymbolicLink: symlinks.has(target.toLowerCase()) };
    },
    async realpath(target) {
      const linked = links.get(target.toLowerCase());
      if (linked !== undefined) return linked;
      const match = options.existing.find((entry) => entry.toLowerCase() === target.toLowerCase());
      if (match === undefined) throw missing();
      return match;
    },
    async readdir() {
      return [];
    },
  };
}

describe("validateSearchRoot on Windows (injected platform)", () => {
  const fs = windowsFs({
    existing: [
      "C:\\Users\\me",
      "C:\\Users\\me\\code",
      "C:\\Users\\me\\김철수 프로젝트",
      "C:\\Windows\\System32",
      "D:\\work\\app",
      "C:\\Users",
      "C:\\",
      "D:\\",
    ],
    links: {
      "C:\\Users\\me\\share-link": "\\\\server\\share\\code",
      "C:\\Users\\me\\to-code": "C:\\Users\\me\\code",
      "C:\\Users\\me\\to-system": "C:\\Windows\\System32",
    },
  });
  const check = (value: string, requireCanonical = false) =>
    validateSearchRoot(value, fs, undefined, "win32", requireCanonical, ["C:\\Windows"]);

  it("accepts a local folder (any case, either separator) and stores the real spelling", async () => {
    expect(await check("C:\\Users\\me\\code")).toMatchObject({
      ok: true,
      path: "C:\\Users\\me\\code",
    });
    expect(await check("c:/users/ME/CODE/")).toMatchObject({
      ok: true,
      path: "C:\\Users\\me\\code",
    });
    expect(await check("D:\\work\\app")).toMatchObject({ ok: true, path: "D:\\work\\app" });
    expect(await check("C:\\Users\\me\\김철수 프로젝트")).toMatchObject({ ok: true });
  });

  it("refuses network, device, drive-relative, stream and trailing-dot spellings", async () => {
    const reason = async (value: string) => {
      const checked = await check(value);
      return checked.ok ? "ok" : checked.reason;
    };
    expect(await reason("\\\\server\\share\\code")).toBe("unsafe_path");
    expect(await reason("\\\\?\\C:\\Users\\me\\code")).toBe("unsafe_path");
    expect(await reason("\\\\.\\C:\\Users\\me\\code")).toBe("unsafe_path");
    expect(await reason("//?/C:/Users/me/code")).toBe("unsafe_path");
    expect(await reason("C:\\Users\\me\\code:stream")).toBe("unsafe_path");
    expect(await reason("C:\\Users\\me\\code.")).toBe("unsafe_path");
    expect(await reason("C:\\Users\\me\\code ")).toBe("unsafe_path");
    expect(await reason("C:code")).toBe("not_absolute");
    expect(await reason("\\code")).toBe("not_absolute");
    expect(await reason("code")).toBe("not_absolute");
  });

  it("refuses drive roots and top-level folders, and system folders", async () => {
    expect(await check("D:\\")).toEqual({ ok: false, reason: "too_shallow" });
    expect(await check("C:\\Users")).toEqual({ ok: false, reason: "too_shallow" });
    expect(await check("C:\\")).toEqual({ ok: false, reason: "too_shallow" });
    expect(await check("c:\\windows\\system32")).toEqual({ ok: false, reason: "unsafe_path" });
  });

  it("resolves links before the checks: a link to a share or a system folder is refused", async () => {
    expect(await check("C:\\Users\\me\\share-link")).toEqual({ ok: false, reason: "unsafe_path" });
    expect(await check("C:\\Users\\me\\to-system")).toEqual({ ok: false, reason: "unsafe_path" });
    expect(await check("C:\\Users\\me\\to-code")).toMatchObject({
      ok: true,
      path: "C:\\Users\\me\\code",
    });
    // A stored root must already be its own real path.
    expect(await check("C:\\Users\\me\\to-code", true)).toEqual({ ok: false, reason: "symlink" });
    expect(await check("c:\\users\\me\\code", true)).toMatchObject({ ok: true });
  });

  it("refuses a root that is itself a symbolic link or junction", async () => {
    const linked = windowsFs({
      existing: ["C:\\Users\\me\\code"],
      symlinks: ["C:\\Users\\me\\code"],
    });
    expect(
      await validateSearchRoot("C:\\Users\\me\\code", linked, undefined, "win32", false, []),
    ).toEqual({
      ok: false,
      reason: "symlink",
    });
  });

  it("has no owner or mode rule (Windows reports none)", () => {
    expect(safetyProblemOf({ ...dirStat(), uid: 5, mode: 0o40777 }, undefined, "win32")).toBeNull();
    expect(safetyProblemOf({ ...dirStat(), uid: 5, mode: 0o40777 }, undefined)).toBe(
      "not_owned_by_you",
    );
  });

  it("loadSearchScope offers default folders under the profile and drops duplicates by case", async () => {
    const scopeFs = windowsFs({
      existing: ["C:\\Users\\me", "C:\\Users\\me\\code", "C:\\Users\\me\\Developer"],
    });
    const loaded = await loadSearchScope({
      storage: null,
      fs: scopeFs,
      uid: undefined,
      homeDir: "C:\\Users\\me",
      platform: "win32",
    });
    expect(loaded.roots.map((root) => root.path)).toEqual([
      "C:\\Users\\me\\code",
      "C:\\Users\\me\\Developer",
    ]);
    const none = await loadSearchScope({
      storage: null,
      fs: scopeFs,
      uid: undefined,
      homeDir: "/c/Users/me",
      platform: "win32",
    });
    expect(none.roots).toEqual([]);
  });
});
