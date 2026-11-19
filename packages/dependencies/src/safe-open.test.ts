import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { rename } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { openRegularFileNoFollow } from "./safe-open.js";

/** #395: a file swapped for a link after the inspection is never read. */
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function scratch(): string {
  const root = mkdtempSync(path.join(os.tmpdir(), "pgard-safe-open-"));
  roots.push(root);
  return root;
}

async function text(handle: Awaited<ReturnType<typeof openRegularFileNoFollow>>): Promise<string> {
  try {
    return (await handle?.readFile("utf8")) ?? "<refused>";
  } finally {
    await handle?.close();
  }
}

describe("openRegularFileNoFollow", () => {
  it("opens a plain regular file, also on a system without O_NOFOLLOW", async () => {
    const file = path.join(scratch(), "a.lock");
    writeFileSync(file, "plain");
    expect(await text(await openRegularFileNoFollow(file))).toBe("plain");
    expect(await text(await openRegularFileNoFollow(file, { pretendNoNoFollow: true }))).toBe(
      "plain",
    );
  });

  it("refuses a missing file, a directory and a link, never following it", async () => {
    const dir = scratch();
    writeFileSync(path.join(dir, "target"), "secret-elsewhere");
    mkdirSync(path.join(dir, "folder"));
    expect(await openRegularFileNoFollow(path.join(dir, "missing"))).toBeNull();
    expect(await openRegularFileNoFollow(path.join(dir, "folder"))).toBeNull();
    if (process.platform !== "win32") {
      symlinkSync(path.join(dir, "target"), path.join(dir, "link"));
      expect(await openRegularFileNoFollow(path.join(dir, "link"))).toBeNull();
      expect(
        await openRegularFileNoFollow(path.join(dir, "link"), { pretendNoNoFollow: true }),
      ).toBeNull();
    }
  });

  it.skipIf(process.platform === "win32")(
    "without O_NOFOLLOW, a link swapped in after the inspection is refused (dev/ino)",
    async () => {
      const dir = scratch();
      const file = path.join(dir, "package-lock.json");
      writeFileSync(file, "inspected");
      writeFileSync(path.join(dir, "other"), "followed-by-mistake");
      const swapped = await openRegularFileNoFollow(file, {
        pretendNoNoFollow: true,
        afterInspect: async () => {
          await rename(file, path.join(dir, "moved"));
          symlinkSync(path.join(dir, "other"), file);
        },
      });
      expect(swapped).toBeNull();
    },
  );

  it.skipIf(process.platform === "win32")(
    "a different regular file swapped in is refused even with O_NOFOLLOW",
    async () => {
      const dir = scratch();
      const file = path.join(dir, "go.sum");
      writeFileSync(file, "inspected");
      const swapped = await openRegularFileNoFollow(file, {
        afterInspect: async () => {
          await rename(file, path.join(dir, "moved"));
          writeFileSync(file, "replacement");
        },
      });
      expect(swapped).toBeNull();
    },
  );

  it.skipIf(process.platform === "win32")(
    "a different regular file swapped in is refused where O_NOFOLLOW is missing",
    async () => {
      const dir = scratch();
      const file = path.join(dir, "yarn.lock");
      writeFileSync(file, "inspected");
      const swapped = await openRegularFileNoFollow(file, {
        pretendNoNoFollow: true,
        afterInspect: async () => {
          await rename(file, path.join(dir, "moved"));
          writeFileSync(file, "replacement");
        },
      });
      expect(swapped).toBeNull();
    },
  );
});
