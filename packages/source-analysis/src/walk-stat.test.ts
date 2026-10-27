import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync, type Stats } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

// `lstat` is replaced for chosen names, so failures and race swaps are deterministic on every OS.
const behaviour = vi.hoisted(() => ({ fail: new Set<string>(), special: new Set<string>() }));
vi.mock("node:fs/promises", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...original,
    lstat: async (target: string) => {
      const name = String(target).split(/[\\/]/).pop() ?? "";
      if (behaviour.fail.has(name)) throw Object.assign(new Error("EACCES"), { code: "EACCES" });
      const stats: Stats = await original.lstat(target);
      if (behaviour.special.has(name)) {
        return Object.assign(Object.create(Object.getPrototypeOf(stats)), stats, {
          isFile: () => false,
        }) as Stats;
      }
      return stats;
    },
  };
});

import { walkSourceTree } from "./walk.js";

const roots: string[] = [];
afterEach(() => {
  behaviour.fail.clear();
  behaviour.special.clear();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function project(files: string[]): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-stat-")));
  roots.push(root);
  for (const relative of files) {
    mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
    writeFileSync(path.join(root, relative), "x\n");
  }
  return root;
}

describe("walk stat handling", () => {
  it("records every kind of file whose lstat fails, and keeps going", async () => {
    const root = project(["a.ts", "b.py", "c.xml", "d.jsp", "ok.ts"]);
    for (const name of ["a.ts", "b.py", "c.xml", "d.jsp"]) behaviour.fail.add(name);
    const result = await walkSourceTree(root);
    expect([...result.unreadableEntries].sort()).toEqual(["a.ts", "b.py", "c.xml", "d.jsp"]);
    expect(result.files.map((file) => file.relativePath)).toEqual(["ok.ts"]);
    expect(result.skippedSpecialFiles).toEqual([]);
  });

  it("counts a file that is no longer regular when stat-ed as special, not unreadable", async () => {
    const root = project(["a.ts", "b.py", "c.xml", "d.jsp", "ok.ts"]);
    for (const name of ["a.ts", "b.py", "c.xml", "d.jsp"]) behaviour.special.add(name);
    const result = await walkSourceTree(root);
    expect([...result.skippedSpecialFiles].sort()).toEqual(["a.ts", "b.py", "c.xml", "d.jsp"]);
    expect(result.unreadableEntries).toEqual([]);
    expect(result.files.map((file) => file.relativePath)).toEqual(["ok.ts"]);
    expect(result.trackFiles.python).toEqual([]);
    expect(result.xmlFiles).toEqual([]);
    expect(result.templateFiles).toEqual([]);
  });
});
