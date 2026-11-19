import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createRedirectFile, redirectRoot, RedirectFileError } from "./redirect-file.js";

/** #419 review: where the redirect folder goes (Snap browsers on Ubuntu cannot read /tmp). */
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function scratch(): string {
  const root = mkdtempSync(path.join(os.tmpdir(), "pgard-root-test-"));
  roots.push(root);
  return root;
}
const uid = process.getuid?.();

describe("redirectRoot", () => {
  it("macOS and Windows: the OS temp folder", async () => {
    for (const platform of ["darwin", "win32"] as const) {
      expect(
        await redirectRoot({
          platform,
          env: { XDG_RUNTIME_DIR: "/run/user/1" },
          homeDir: "/h",
          uid,
        }),
      ).toBe(os.tmpdir());
    }
  });
});

describe("redirectRoot on Windows (#430)", () => {
  it("refuses a UNC or device temp folder, accepts a local one", async () => {
    const root = (tmpDir: string) =>
      redirectRoot({ platform: "win32", env: {}, homeDir: "C:\\Users\\u", uid: undefined, tmpDir });
    await expect(root("\\\\server\\share\\tmp")).rejects.toThrow("network or device");
    await expect(root("\\\\?\\C:\\Temp")).rejects.toThrow("network or device");
    expect(await root("C:\\Users\\김철수\\AppData\\Local\\Temp")).toBe(
      "C:\\Users\\김철수\\AppData\\Local\\Temp",
    );
  });
});

describe.skipIf(process.platform === "win32")("redirectRoot on Linux", () => {
  it("uses XDG_RUNTIME_DIR when it is ours and private (0700)", async () => {
    const runtime = path.join(scratch(), "run");
    mkdirSync(runtime, { mode: 0o700 });
    chmodSync(runtime, 0o700);
    expect(
      await redirectRoot({
        platform: "linux",
        env: { XDG_RUNTIME_DIR: runtime },
        homeDir: "/nonexistent",
        uid,
      }),
    ).toBe(runtime);
  });

  it("falls back to ~/.cache/pgard/open (created 0700) when XDG_RUNTIME_DIR is unset or unsafe", async () => {
    const home = scratch();
    const open = path.join(home, ".cache", "pgard", "open");
    const shared = path.join(home, "shared");
    mkdirSync(shared, { mode: 0o777 });
    chmodSync(shared, 0o777);
    const link = path.join(home, "link");
    symlinkSync(shared, link);
    for (const env of [
      {},
      { XDG_RUNTIME_DIR: "relative/dir" },
      { XDG_RUNTIME_DIR: shared },
      { XDG_RUNTIME_DIR: link },
    ]) {
      expect(await redirectRoot({ platform: "linux", env, homeDir: home, uid })).toBe(open);
    }
    expect(statSync(open).mode & 0o777).toBe(0o700);
    // The redirect folder and file then live there.
    const redirect = await createRedirectFile("http://127.0.0.1:1/#token=abcdef", {
      tmpRoot: open,
    });
    expect(path.dirname(redirect.dir)).toBe(open);
    await redirect.remove();
  });

  it("refuses a cache folder that others can enter, or a link in its place", async () => {
    const home = scratch();
    const parent = path.join(home, ".cache", "pgard");
    mkdirSync(parent, { recursive: true });
    const open = path.join(parent, "open");
    mkdirSync(open, { mode: 0o755 });
    chmodSync(open, 0o755);
    await expect(
      redirectRoot({ platform: "linux", env: {}, homeDir: home, uid }),
    ).rejects.toBeInstanceOf(RedirectFileError);
    rmSync(open, { recursive: true });
    const elsewhere = path.join(home, "elsewhere");
    mkdirSync(elsewhere, { mode: 0o700 });
    symlinkSync(elsewhere, open);
    await expect(
      redirectRoot({ platform: "linux", env: {}, homeDir: home, uid }),
    ).rejects.toBeInstanceOf(RedirectFileError);
    await expect(
      redirectRoot({ platform: "linux", env: {}, homeDir: "", uid }),
    ).rejects.toBeInstanceOf(RedirectFileError);
  });

  describe("parents (#430)", () => {
    const rootFor = (home: string) =>
      redirectRoot({ platform: "linux", env: {}, homeDir: home, uid });

    it("refuses a ~/.cache or ~/.cache/pgard link into a world-writable folder", async () => {
      for (const linked of [".cache", path.join(".cache", "pgard")]) {
        const home = scratch();
        const shared = path.join(home, "shared");
        mkdirSync(shared, { mode: 0o777 });
        chmodSync(shared, 0o777);
        mkdirSync(path.join(shared, "pgard", "open"), { recursive: true, mode: 0o700 });
        if (linked === ".cache") symlinkSync(shared, path.join(home, ".cache"));
        else {
          mkdirSync(path.join(home, ".cache"));
          symlinkSync(path.join(shared, "pgard"), path.join(home, ".cache", "pgard"));
        }
        await expect(rootFor(home)).rejects.toBeInstanceOf(RedirectFileError);
      }
    });

    it("checks each parent before creating anything inside it", async () => {
      const home = scratch();
      const shared = path.join(home, "shared");
      mkdirSync(shared, { mode: 0o777 });
      chmodSync(shared, 0o777);
      symlinkSync(shared, path.join(home, ".cache"));
      await expect(rootFor(home)).rejects.toBeInstanceOf(RedirectFileError);
      expect(readdirSync(shared)).toEqual([]); // no pgard/open was created in the shared folder
    });

    it("accepts a group-writable ~/.cache of our own group, refuses a foreign group or o+w", async () => {
      const home = scratch();
      mkdirSync(path.join(home, ".cache"));
      chmodSync(path.join(home, ".cache"), 0o775);
      const gid = process.getgid?.();
      expect(await rootFor(home)).toBe(path.join(home, ".cache", "pgard", "open"));
      const foreign = scratch();
      mkdirSync(path.join(foreign, ".cache"));
      chmodSync(path.join(foreign, ".cache"), 0o775);
      await expect(
        redirectRoot({
          platform: "linux",
          env: {},
          homeDir: foreign,
          uid,
          gid: gid === undefined ? undefined : gid + 12345,
        }),
      ).rejects.toBeInstanceOf(RedirectFileError);
      const open = scratch();
      mkdirSync(path.join(open, ".cache"));
      chmodSync(path.join(open, ".cache"), 0o757);
      await expect(rootFor(open)).rejects.toBeInstanceOf(RedirectFileError);
    });

    it("accepts a link to a private folder of ours", async () => {
      const real = path.join(scratch(), "real-cache");
      mkdirSync(real, { mode: 0o755 });
      const home2 = scratch();
      symlinkSync(real, path.join(home2, ".cache"));
      expect(await rootFor(home2)).toBe(path.join(home2, ".cache", "pgard", "open"));
    });
  });
});
