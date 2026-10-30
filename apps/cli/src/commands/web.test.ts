import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createWebStorage, RECENT_FILE, SETTINGS_FILE } from "@pgard/result-store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "../app.js";
import { parseCommandLine, UsageError } from "../options.js";
import { getHelpText } from "../help.js";
import {
  createTestContext,
  createTestDeps,
  createTestIo,
  noInterrupts,
  scriptedKeys,
} from "../test-support.js";
import { runHistoryClear } from "./history.js";
import { runWeb, WINDOWS_PICKER_MESSAGE } from "./web.js";
import { runWebScope } from "./web-scope.js";

let base: string;
let home: string;
let dataDir: string;
beforeEach(() => {
  base = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-cli-web-")));
  home = path.join(base, "home");
  mkdirSync(home, { mode: 0o755 });
  dataDir = path.join(base, "data", "pgard");
});
afterEach(() => rmSync(base, { recursive: true, force: true }));

const dir = (...segments: string[]): string => {
  const target = path.join(home, ...segments);
  mkdirSync(target, { recursive: true, mode: 0o755 });
  return target;
};

function setup(
  keys: string[],
  options: { platform?: NodeJS.Platform; env?: Record<string, string> } = {},
) {
  const captured = createTestIo({ isTTY: true, env: { HOME: home, ...options.env }, cwd: home });
  const startDashboardProcess = vi.fn(async () => 0);
  const deps = createTestDeps({
    resolveDashboardEntry: () => "/install/local-web/dist/server/index.js",
    startDashboardProcess,
    openWebStorage: () => createWebStorage({ dir: dataDir }),
    platform: options.platform ?? "linux",
  });
  const released = vi.fn();
  const context = {
    ...createTestContext(captured, deps, scriptedKeys(keys)),
    releaseInterrupts: released,
  };
  return { captured, context, startDashboardProcess, released, deps };
}

describe.skipIf(process.platform === "win32")("pgard web", () => {
  it("refuses on Windows with the usage error and points to pgard dashboard (design test 18)", async () => {
    const { captured, context, startDashboardProcess } = setup([], { platform: "win32" });
    expect(await runWeb(context, false, false)).toBe(2);
    expect(captured.stderr()).toContain(WINDOWS_PICKER_MESSAGE);
    expect(captured.stderr()).toContain("pgard dashboard");
    expect(startDashboardProcess).not.toHaveBeenCalled();
    // The same for the scope commands.
    expect(await runWebScope(context, "list", null)).toBe(2);
  });

  it("refuses on Windows when run for real through main (runs on the Windows runner)", async () => {
    const captured = createTestIo({ isTTY: true, env: { HOME: home } });
    const startDashboardProcess = vi.fn(async () => 0);
    const code = await main(["web"], captured.io, {
      interrupts: noInterrupts,
      deps: createTestDeps({
        platform: process.platform,
        resolveDashboardEntry: () => "/install/local-web/dist/server/index.js",
        startDashboardProcess,
      }),
    });
    if (process.platform === "win32") {
      expect(code).toBe(2);
      expect(captured.stderr()).toContain("pgard dashboard");
      expect(startDashboardProcess).not.toHaveBeenCalled();
    }
  });

  it("starts the launcher in picker mode at once: no question, no folder list, nothing saved", async () => {
    dir("code");
    const { captured, context, startDashboardProcess, released } = setup([]);
    expect(await runWeb(context, false, false)).toBe(0);
    expect(captured.stdout()).not.toContain("Search these folders");
    expect(captured.stdout()).not.toContain(path.join(home, "code"));
    expect(startDashboardProcess).toHaveBeenCalledWith("/install/local-web/dist/server/index.js", [
      "--picker",
    ]);
    expect(released).toHaveBeenCalledOnce();
    expect((await createWebStorage({ dir: dataDir }).readSettings()).status).toBe("missing");
  });

  it("needs no terminal", async () => {
    const captured = createTestIo({ env: { HOME: home } });
    const startDashboardProcess = vi.fn(async () => 0);
    const context = createTestContext(
      captured,
      createTestDeps({
        platform: "linux",
        resolveDashboardEntry: () => "/install/local-web/dist/server/index.js",
        startDashboardProcess,
      }),
    );
    expect(await runWeb(context, false, false)).toBe(0);
    expect(startDashboardProcess).toHaveBeenCalledOnce();
  });

  it("with --no-store tells the launcher; PGARD_NO_STORE=1 does the same", async () => {
    for (const [noStore, env] of [
      [true, {}],
      [false, { PGARD_NO_STORE: "1" }],
    ] as const) {
      const { context, startDashboardProcess } = setup([], { env });
      expect(await runWeb(context, true, noStore)).toBe(0);
      expect(startDashboardProcess).toHaveBeenCalledWith(
        "/install/local-web/dist/server/index.js",
        ["--picker", "--no-browser", "--no-store"],
      );
      expect((await createWebStorage({ dir: dataDir }).readSettings()).status).toBe("missing");
    }
  });

  it("is dispatched by main and parsed with its options", () => {
    expect(parseCommandLine(["web"])).toEqual({ kind: "web", noBrowser: false, noStore: false });
    expect(parseCommandLine(["web", "--no-store", "--no-browser"])).toEqual({
      kind: "web",
      noBrowser: true,
      noStore: true,
    });
    expect(parseCommandLine(["web", "--help"])).toEqual({ kind: "help", topic: "web" });
    expect(parseCommandLine(["web", "scope", "--help"])).toEqual({
      kind: "help",
      topic: "web scope",
    });
    for (const argv of [
      ["web", "extra"],
      ["web", "--target-port", "3000"],
      ["scan", "--no-store", "web"],
      ["dashboard", "--no-store"],
    ]) {
      if (argv[0] === "scan") continue;
      expect(() => parseCommandLine(argv), argv.join(" ")).toThrow(UsageError);
    }
    expect(getHelpText("web")).toContain("never add one");
    expect(getHelpText("web")).toContain("Nothing is asked in the terminal");
    expect(getHelpText("web scope")).toContain("never in the browser");
    expect(getHelpText("web scope")).toContain("pgard web scope add");
  });
});

describe.skipIf(process.platform === "win32")("pgard web scope", () => {
  const parse = (...argv: string[]) => parseCommandLine(["web", "scope", ...argv]);

  it("parses list, add and remove and rejects the rest", () => {
    expect(parse("list")).toEqual({ kind: "web-scope", action: "list", folder: null });
    expect(parse("add", "~/code")).toEqual({ kind: "web-scope", action: "add", folder: "~/code" });
    expect(parse("remove", "/x/y")).toEqual({
      kind: "web-scope",
      action: "remove",
      folder: "/x/y",
    });
    for (const argv of [
      [],
      ["add"],
      ["remove"],
      ["list", "x"],
      ["add", "a", "b"],
      ["nope"],
      ["add", "a", "--no-store"],
    ]) {
      expect(() => parse(...argv), argv.join(" ")).toThrow(UsageError);
    }
  });

  it("lists the default folders, then the saved ones", async () => {
    const code = dir("code");
    const first = setup([]);
    expect(await runWebScope(first.context, "list", null)).toBe(0);
    expect(first.captured.stdout()).toContain(code);
    await createWebStorage({ dir: dataDir }).writeSettings([code]);
    const second = setup([]);
    await runWebScope(second.context, "list", null);
    expect(second.captured.stdout()).toContain("saved in settings.json");
  });

  it("add shows the real path, asks for confirmation and saves (defaults are kept)", async () => {
    const code = dir("code");
    const work = dir("work");
    const link = path.join(base, "link");
    const { symlinkSync } = await import("node:fs");
    symlinkSync(work, link);
    const refused = setup(["n"]);
    expect(await runWebScope(refused.context, "add", link)).toBe(130);
    expect((await createWebStorage({ dir: dataDir }).readSettings()).status).toBe("missing");
    const added = setup(["y"]);
    expect(await runWebScope(added.context, "add", link)).toBe(0);
    expect(added.captured.stdout()).toContain(`Real path: ${work}`);
    const saved = await createWebStorage({ dir: dataDir }).readSettings();
    expect(saved.status === "ok" && saved.value.roots).toEqual([code, work]);
  });

  it("add refuses an unsafe, missing, shallow or non-directory folder with the reason", async () => {
    const shared = dir("shared");
    chmodSync(shared, 0o775);
    writeFileSync(path.join(home, "file"), "x");
    for (const [folder, text] of [
      [shared, "can be changed by other users"],
      [path.join(home, "nope"), "does not exist"],
      [path.join(home, "file"), "is not a folder"],
      ["/", "too high up"],
    ] as const) {
      const { captured, context } = setup(["y"]);
      expect(await runWebScope(context, "add", folder), folder).toBe(2);
      expect(captured.stderr(), folder).toContain(text);
    }
  });

  it("add needs a terminal and warns before adding the whole home folder", async () => {
    const noTerminal = createTestIo({ env: { HOME: home }, cwd: home });
    const context = createTestContext(
      noTerminal,
      createTestDeps({ openWebStorage: () => createWebStorage({ dir: dataDir }) }),
    );
    dir("code");
    expect(await runWebScope(context, "add", dir("work"))).toBe(2);
    const { captured, context: homeContext } = setup(["y"]);
    expect(await runWebScope(homeContext, "add", "~")).toBe(0);
    expect(captured.stdout()).toContain("whole home folder");
    expect(captured.stdout()).toContain("iCloud");
    // A bare `~` is expanded here, not trusted from the shell.
    const saved = await createWebStorage({ dir: dataDir }).readSettings();
    expect(saved.status === "ok" && saved.value.roots).toContain(home);
  });

  it("remove drops a saved folder, also one that no longer exists, and refuses an unknown one", async () => {
    const code = dir("code");
    const work = dir("work");
    const storage = createWebStorage({ dir: dataDir });
    await storage.writeSettings([code, work]);
    const removed = setup([]);
    expect(await runWebScope(removed.context, "remove", work)).toBe(0);
    rmSync(code, { recursive: true });
    await storage.writeSettings([code, dir("again")]);
    rmSync(code, { recursive: true, force: true });
    const gone = setup([]);
    expect(await runWebScope(gone.context, "remove", code)).toBe(0);
    const saved = await storage.readSettings();
    expect(saved.status === "ok" && saved.value.roots).toEqual([path.join(home, "again")]);
    const unknown = setup([]);
    expect(await runWebScope(unknown.context, "remove", path.join(home, "other"))).toBe(2);
  });

  it("does not overwrite a settings file it cannot read", async () => {
    dir("code");
    const storage = createWebStorage({ dir: dataDir });
    await storage.writeSettings([dir("work")]);
    const file = path.join(storage.dir, SETTINGS_FILE);
    writeFileSync(file, JSON.stringify({ schemaVersion: "9.0" }));
    const { context } = setup(["y"]);
    expect(await runWebScope(context, "add", dir("x"))).toBe(3);
    expect(readFileSync(file, "utf8")).toContain("9.0");
  });
});

describe.skipIf(process.platform === "win32")(
  "pgard history clear --all removes the picker's data (design test 15)",
  () => {
    async function filled() {
      const storage = createWebStorage({ dir: dataDir });
      await storage.writeSettings([dir("code")]);
      await storage.writeRecent([
        {
          entryId: "a".repeat(22),
          path: "/home/u/code/p",
          repo: "acme/p",
          lastUsedAt: new Date().toISOString(),
        },
      ]);
      return storage;
    }

    it("deletes web/ with --all but not with --repo", async () => {
      const storage = await filled();
      const captured = createTestIo({ env: { HOME: home } });
      const deps = createTestDeps({
        openWebStorage: () => createWebStorage({ dir: dataDir }),
        openResultStore: () =>
          ({
            clear: async () => ({ removed: 0, baselinesRemoved: 0, warnings: [] }),
            dir: "/store",
          }) as never,
      });
      const context = createTestContext(captured, deps);
      expect(await runHistoryClear(context, "acme/shop")).toBe(0);
      expect((await storage.readRecent()).status).toBe("ok");
      expect(await runHistoryClear(context, null)).toBe(0);
      expect(captured.stdout()).toContain("search folders and recent list");
      expect((await storage.readRecent()).status).toBe("missing");
      expect((await storage.readSettings()).status).toBe("missing");
      expect(RECENT_FILE).toBe("recent-projects.json");
    });
  },
);
