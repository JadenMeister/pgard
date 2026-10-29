import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createWebStorage,
  DEFAULT_SCOPE_FOLDERS,
  loadSearchScope,
  nodeScopeFs,
  pathDepth,
  safetyProblemOf,
  validateSearchRoot,
  type ScopeFs,
  type ScopeStat,
  type WebStorage,
} from "./index.js";

let base: string;
let home: string;
const uid = process.getuid?.();
beforeEach(() => {
  base = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-scope-")));
  home = path.join(base, "home", "alice");
  mkdirSync(home, { recursive: true, mode: 0o755 });
});
afterEach(() => rmSync(base, { recursive: true, force: true }));

const dir = (...segments: string[]): string => {
  const target = path.join(home, ...segments);
  mkdirSync(target, { recursive: true, mode: 0o755 });
  return target;
};

describe.skipIf(process.platform === "win32")("search roots (T4, T13)", () => {
  it("counts path depth below /", () => {
    expect(pathDepth("/")).toBe(0);
    expect(pathDepth("/Users")).toBe(1);
    expect(pathDepth("/Users/alice")).toBe(2);
  });

  it("accepts a safe directory and stores its realpath with dev and ino", async () => {
    const code = dir("code");
    const link = path.join(base, "link-to-code");
    symlinkSync(code, link);
    const checked = await validateSearchRoot(link, nodeScopeFs, uid);
    expect(checked).toMatchObject({ ok: true, path: code });
    expect(checked.ok && checked.ino).toBeGreaterThan(0);
  });

  it("rejects relative paths, missing paths, files, / and /Users-like roots", async () => {
    writeFileSync(path.join(home, "file"), "x");
    expect(await validateSearchRoot("code", nodeScopeFs, uid)).toEqual({
      ok: false,
      reason: "not_absolute",
    });
    expect(await validateSearchRoot(path.join(home, "missing"), nodeScopeFs, uid)).toEqual({
      ok: false,
      reason: "missing",
    });
    expect(await validateSearchRoot(path.join(home, "file"), nodeScopeFs, uid)).toEqual({
      ok: false,
      reason: "not_a_directory",
    });
    expect(await validateSearchRoot("/", nodeScopeFs, uid)).toEqual({
      ok: false,
      reason: "too_shallow",
    });
    const usersFs: ScopeFs = { ...nodeScopeFs, realpath: async () => "/Users" };
    expect(await validateSearchRoot("/Users", usersFs, uid)).toEqual({
      ok: false,
      reason: "too_shallow",
    });
  });

  it("rejects a root owned by another user or writable by group or others", async () => {
    const code = dir("code");
    const fakeFs = (override: Partial<ScopeStat>): ScopeFs => ({
      ...nodeScopeFs,
      lstat: async (target) => ({
        ...(await nodeScopeFs.lstat(target)),
        ...(target === code ? override : {}),
      }),
    });
    expect(await validateSearchRoot(code, fakeFs({ uid: (uid ?? 0) + 1 }), uid)).toEqual({
      ok: false,
      reason: "not_owned_by_you",
    });
    expect(await validateSearchRoot(code, fakeFs({ mode: 0o40775 }), uid)).toEqual({
      ok: false,
      reason: "group_or_world_writable",
    });
    expect(await validateSearchRoot(code, fakeFs({ mode: 0o40757 }), uid)).toEqual({
      ok: false,
      reason: "group_or_world_writable",
    });
    chmodSync(code, 0o775);
    expect(await validateSearchRoot(code, nodeScopeFs, uid)).toEqual({
      ok: false,
      reason: "group_or_world_writable",
    });
  });

  it("is not available on Windows", async () => {
    expect(await validateSearchRoot(home, nodeScopeFs, uid, "win32")).toEqual({
      ok: false,
      reason: "unsupported_platform",
    });
  });

  it("applies the strict rule to ownership: no uid means no trust", () => {
    const stat = {
      isDirectory: true,
      isFile: false,
      isSymbolicLink: false,
      uid: 5,
      mode: 0o40755,
      dev: 1,
      ino: 2,
    };
    expect(safetyProblemOf(stat, 5)).toBeNull();
    expect(safetyProblemOf(stat, undefined)).toBe("not_owned_by_you");
    expect(safetyProblemOf({ ...stat, mode: 0o40720 }, 5)).toBe("group_or_world_writable");
    expect(safetyProblemOf({ ...stat, mode: 0o40702 }, 5)).toBe("group_or_world_writable");
  });
});

describe.skipIf(process.platform === "win32")("loading the scope", () => {
  let storage: WebStorage;
  beforeEach(() => {
    storage = createWebStorage({ dir: path.join(base, "data", "pgard") });
  });

  it("uses only the default development folders that exist, and does not report the missing ones", async () => {
    dir("code");
    dir("Developer");
    const scope = await loadSearchScope({ storage, uid, homeDir: home });
    expect(scope.source).toBe("default");
    expect(scope.roots.map((root) => path.basename(root.path)).sort()).toEqual([
      "Developer",
      "code",
    ]);
    expect(scope.dropped).toEqual([]);
    expect(DEFAULT_SCOPE_FOLDERS).toEqual([
      "code",
      "projects",
      "dev",
      "src",
      "workspace",
      "git",
      "Developer",
    ]);
  });

  it("never includes the whole home folder by default", async () => {
    const scope = await loadSearchScope({ storage, uid, homeDir: home });
    expect(scope.roots).toEqual([]);
  });

  it("uses the saved roots, revalidates them and drops an invalid one with a reason", async () => {
    const code = dir("code");
    const unsafe = dir("shared");
    chmodSync(unsafe, 0o777);
    await storage.writeSettings([code, unsafe, path.join(home, "gone")]);
    const scope = await loadSearchScope({ storage, uid, homeDir: home });
    expect(scope.source).toBe("stored");
    expect(scope.roots.map((root) => root.path)).toEqual([code]);
    expect(scope.dropped).toEqual([
      { path: unsafe, reason: "group_or_world_writable" },
      { path: path.join(home, "gone"), reason: "missing" },
    ]);
  });

  it("falls back to the defaults with a notice when the settings file is ignored", async () => {
    dir("code");
    await storage.writeSettings([dir("projects")]);
    writeFileSync(
      path.join(storage.dir, "settings.json"),
      JSON.stringify({ schemaVersion: "9.0" }),
    );
    const scope = await loadSearchScope({ storage, uid, homeDir: home });
    expect(scope.settingsIgnored).toBe(true);
    expect(scope.source).toBe("default");
  });

  it("uses no storage with an empty home", async () => {
    expect(await loadSearchScope({ storage: null, uid, homeDir: "" })).toMatchObject({
      roots: [],
      source: "default",
    });
  });
});
