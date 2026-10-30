import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync, symlinkSync } from "node:fs";
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
});
