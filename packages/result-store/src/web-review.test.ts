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
  loadSearchScope,
  MAX_SEARCH_ROOTS,
  nodeScopeFs,
  RECENT_FILE,
  SETTINGS_FILE,
} from "./index.js";

let base: string;
beforeEach(() => {
  base = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-web-review-")));
});
afterEach(() => rmSync(base, { recursive: true, force: true }));
const uid = process.getuid?.();

describe("settings are never written in a form this build would ignore", () => {
  it("refuses more than the cap of roots and leaves the file as it was", async () => {
    const storage = createWebStorage({ dir: path.join(base, "pgard") });
    const roots = Array.from({ length: MAX_SEARCH_ROOTS }, (_, index) => `/home/u/r${index}`);
    expect((await storage.writeSettings(roots)).ok).toBe(true);
    expect((await storage.writeSettings([...roots, "/home/u/one-more"])).ok).toBe(false);
    const read = await storage.readSettings();
    expect(read.status === "ok" && read.value.roots).toHaveLength(MAX_SEARCH_ROOTS);
  });
});

describe.skipIf(process.platform === "win32")("owner-only reads (T9)", () => {
  it("ignores a file with group or other read access, not only write access", async () => {
    const storage = createWebStorage({ dir: path.join(base, "pgard") });
    await storage.writeSettings(["/home/u/code"]);
    await storage.writeRecent([]);
    for (const name of [SETTINGS_FILE, RECENT_FILE]) {
      const file = path.join(storage.dir, name);
      chmodSync(file, 0o644);
      const read =
        name === SETTINGS_FILE ? await storage.readSettings() : await storage.readRecent();
      expect(read, name).toEqual({ status: "ignored", reason: "unsafe" });
      chmodSync(file, 0o600);
    }
    expect((await storage.readSettings()).status).toBe("ok");
  });

  it("ignores a file owned by another uid (injected)", async () => {
    const storage = createWebStorage({
      dir: path.join(base, "pgard"),
      environment: { isPosix: true, getuid: () => (uid ?? 0) + 1 },
    });
    // The folder check already refuses another owner; both reads end ignored.
    mkdirSync(storage.dir, { recursive: true, mode: 0o700 });
    writeFileSync(path.join(storage.dir, SETTINGS_FILE), "{}", { mode: 0o600 });
    expect((await storage.readSettings()).status).toBe("ignored");
  });
});

describe.skipIf(process.platform === "win32")("a stored root that became a symlink", () => {
  it("is dropped, not re-pointed to its target", async () => {
    const real = path.join(base, "home", "real");
    mkdirSync(real, { recursive: true, mode: 0o755 });
    const link = path.join(base, "home", "link");
    symlinkSync(real, link);
    const storage = createWebStorage({ dir: path.join(base, "pgard") });
    await storage.writeSettings([real, link]);
    const scope = await loadSearchScope({ storage, fs: nodeScopeFs, uid, homeDir: base });
    expect(scope.roots.map((root) => root.path)).toEqual([real]);
    expect(scope.dropped).toEqual([{ path: link, reason: "symlink" }]);
  });
});
