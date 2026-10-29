import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createWebStorage, MAX_SEARCH_ROOTS } from "@pgard/result-store";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createTestContext, createTestDeps, createTestIo, scriptedKeys } from "../test-support.js";
import { runWebScope } from "./web-scope.js";

let base: string;
let home: string;
let dataDir: string;
beforeEach(() => {
  base = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-cli-review-")));
  home = path.join(base, "home");
  mkdirSync(home, { mode: 0o755 });
  dataDir = path.join(base, "data", "pgard");
});
afterEach(() => rmSync(base, { recursive: true, force: true }));

function setup(keys: string[], env: Record<string, string> = {}) {
  const captured = createTestIo({ isTTY: true, env: { HOME: home, ...env }, cwd: home });
  const deps = createTestDeps({
    openWebStorage: () => createWebStorage({ dir: dataDir }),
    platform: "linux",
  });
  return { captured, context: createTestContext(captured, deps, scriptedKeys(keys)) };
}

describe.skipIf(process.platform === "win32")("pgard web scope limits and no-store", () => {
  it("refuses the 51st folder with a clear message and keeps the saved list readable", async () => {
    const storage = createWebStorage({ dir: dataDir });
    const roots = Array.from({ length: MAX_SEARCH_ROOTS }, (_, index) => `/home/u/r${index}`);
    await storage.writeSettings(roots);
    const extra = path.join(home, "extra");
    mkdirSync(extra, { mode: 0o755 });
    const { captured, context } = setup(["y"]);
    expect(await runWebScope(context, "add", extra)).toBe(2);
    expect(captured.stderr()).toContain(`At most ${MAX_SEARCH_ROOTS} search folders`);
    const read = await storage.readSettings();
    expect(read.status === "ok" && read.value.roots).toHaveLength(MAX_SEARCH_ROOTS);
  });

  it("add and remove refuse under PGARD_NO_STORE=1 and write nothing; list shows the defaults only", async () => {
    const code = path.join(home, "code");
    mkdirSync(code, { mode: 0o755 });
    const storage = createWebStorage({ dir: dataDir });
    await storage.writeSettings([path.join(home, "saved")]);
    for (const action of ["add", "remove"] as const) {
      const { captured, context } = setup(["y"], { PGARD_NO_STORE: "1" });
      expect(await runWebScope(context, action, code)).toBe(2);
      expect(captured.stderr()).toContain("PGARD_NO_STORE=1");
    }
    const read = await storage.readSettings();
    expect(read.status === "ok" && read.value.roots).toEqual([path.join(home, "saved")]);
    const { captured, context } = setup([], { PGARD_NO_STORE: "1" });
    expect(await runWebScope(context, "list", null)).toBe(0);
    expect(captured.stdout()).toContain(code);
    expect(captured.stdout()).not.toContain("saved in settings.json");
  });
});
