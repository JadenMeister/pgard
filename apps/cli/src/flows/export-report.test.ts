import { mkdirSync, mkdtempSync, realpathSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createTestContext,
  createTestDeps,
  createTestIo,
  panelsFixtureResult,
  scriptedKeys,
} from "../test-support.js";
import { checkOutputDir, runReportExport } from "./export-report.js";
import { defaultReportDir, expandHome, shownDir } from "./report-dir.js";

function fakeFiles(dirs: string[], files: Record<string, string> = {}) {
  return {
    isDirectory: async (target: string) => dirs.includes(target),
    readText: async (target: string) => files[target] ?? null,
  };
}

describe("defaultReportDir", () => {
  it("prefers Downloads, then Documents, then home, on macOS", async () => {
    const home = "/Users/u";
    const base = { platform: "darwin" as const, env: {}, home };
    expect(
      await defaultReportDir({
        ...base,
        ...fakeFiles([home + "/Downloads", home + "/Documents"]),
      }),
    ).toBe("/Users/u/Downloads");
    expect(await defaultReportDir({ ...base, ...fakeFiles([home + "/Documents"]) })).toBe(
      "/Users/u/Documents",
    );
    expect(await defaultReportDir({ ...base, ...fakeFiles([]) })).toBe(home);
  });

  it("uses USERPROFILE on Windows", async () => {
    const base = { platform: "win32" as const, env: { USERPROFILE: "C:\\Users\\u" } };
    const home = "C:\\Users\\other";
    expect(
      await defaultReportDir({ ...base, home, ...fakeFiles(["C:\\Users\\u\\Downloads"]) }),
    ).toBe("C:\\Users\\u\\Downloads");
    expect(
      await defaultReportDir({ ...base, home, ...fakeFiles(["C:\\Users\\u\\Documents"]) }),
    ).toBe("C:\\Users\\u\\Documents");
    expect(await defaultReportDir({ ...base, home, ...fakeFiles([]) })).toBe(home);
  });

  it("reads XDG_DOWNLOAD_DIR on Linux and falls back to ~/Downloads", async () => {
    const home = "/home/u";
    const base = { platform: "linux" as const, env: {}, home };
    const dirsFile =
      '# comment\nXDG_DOWNLOAD_DIR="$HOME/Herunterladen"\nXDG_DOCUMENTS_DIR="$HOME/Dokumente"\n';
    const files = { "/home/u/.config/user-dirs.dirs": dirsFile };
    expect(
      await defaultReportDir({
        ...base,
        ...fakeFiles(["/home/u/Herunterladen", "/home/u/Downloads"], files),
      }),
    ).toBe("/home/u/Herunterladen");
    expect(await defaultReportDir({ ...base, ...fakeFiles(["/home/u/Dokumente"], files) })).toBe(
      "/home/u/Dokumente",
    );
    expect(await defaultReportDir({ ...base, ...fakeFiles(["/home/u/Downloads"]) })).toBe(
      "/home/u/Downloads",
    );
    expect(await defaultReportDir({ ...base, ...fakeFiles([]) })).toBe(home);
  });

  it("is null when home is unknown", async () => {
    expect(
      await defaultReportDir({ platform: "linux", env: {}, home: null, ...fakeFiles([]) }),
    ).toBeNull();
  });
});

describe("expandHome and shownDir", () => {
  it("expands ~, ~/x and (Windows) ~\\x only", () => {
    expect(expandHome("~", "/h", "linux")).toBe("/h");
    expect(expandHome("~/x", "/h", "linux")).toBe("/h/x");
    expect(expandHome("~\\x", "C:\\h", "win32")).toBe("C:\\h\\x");
    expect(expandHome("~\\x", "/h", "linux")).toBe("~\\x");
    expect(expandHome("~other/x", "/h", "linux")).toBe("~other/x");
    expect(expandHome("/a/~/b", "/h", "linux")).toBe("/a/~/b");
    expect(expandHome("~/x", null, "linux")).toBe("~/x");
  });

  it("shows places under home with a leading ~", () => {
    expect(shownDir("/h/Downloads", "/h", "linux")).toBe("~/Downloads");
    expect(shownDir("/h", "/h", "linux")).toBe("~");
    expect(shownDir("/x/y", "/h", "linux")).toBe("/x/y");
    expect(shownDir("C:\\h\\Downloads", "C:\\h", "win32")).toBe("~\\Downloads");
  });
});

describe("report folder prompt", () => {
  let home: string;
  let repo: string;
  const isPosix = process.platform !== "win32";

  beforeEach(() => {
    home = realpathSync(mkdtempSync(path.join(os.tmpdir(), "pgard-home-")));
    repo = path.join(home, "repo");
    mkdirSync(repo);
  });
  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  const chars = (text: string) => [...text];
  const FORMAT = ["down", "return"]; // HTML
  const ENTER = ["return"];

  function setup(
    keys: string[],
    options: { isTTY?: boolean; inside?: (p: string) => boolean; home?: string } = {},
  ) {
    const captured = createTestIo({
      isTTY: options.isTTY ?? true,
      env: { HOME: options.home ?? home },
      cwd: repo,
    });
    const writeReports = vi.fn(async () => [{ format: "html" as const, filePath: "/out/r.html" }]);
    const isPathInsideDirectory = vi.fn(async (candidate: string) =>
      options.inside === undefined ? false : options.inside(candidate),
    );
    const deps = createTestDeps({
      writeReports,
      isPathInsideDirectory: isPathInsideDirectory as never,
      platform: process.platform,
    });
    const context = createTestContext(captured, deps, scriptedKeys(keys));
    return { captured, context, writeReports, isPathInsideDirectory };
  }
  const run = (s: ReturnType<typeof setup>) =>
    runReportExport(s.context, panelsFixtureResult(), repo);

  it("offers Downloads, and Enter accepts it", async () => {
    mkdirSync(path.join(home, "Downloads"));
    const s = setup([...FORMAT, ...ENTER]);
    expect(await run(s)).toBe("saved");
    expect(s.captured.stdout()).toContain(`Save to folder [~${path.sep}Downloads]:`);
    expect(s.writeReports).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ outputDir: path.join(home, "Downloads") }),
    );
  });

  it("offers Documents, then home, when Downloads is missing", async () => {
    mkdirSync(path.join(home, "Documents"));
    const s = setup([...FORMAT, ...ENTER]);
    expect(await run(s)).toBe("saved");
    expect(s.captured.stdout()).toContain(`[~${path.sep}Documents]`);
    rmSync(path.join(home, "Documents"), { recursive: true });
    const t = setup([...FORMAT, ...ENTER]);
    expect(await run(t)).toBe("saved");
    expect(t.captured.stdout()).toContain("Save to folder [~]:");
  });

  it("expands ~/x", async () => {
    mkdirSync(path.join(home, "x"));
    const s = setup([...FORMAT, ...chars("~/x"), ...ENTER]);
    expect(await run(s)).toBe("saved");
    expect(s.writeReports).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ outputDir: path.join(home, "x") }),
    );
  });

  it("creates a missing folder on y (mode 0700) and re-prompts on N", async () => {
    const target = path.join(home, "a", "b");
    const typed = chars(target);
    const s = setup([...FORMAT, ...typed, ...ENTER, "n", "escape"]);
    expect(await run(s)).toBe("cancelled");
    expect(s.captured.stdout()).toContain("The folder doesn't exist. Create it? [y/N]");
    expect(s.writeReports).not.toHaveBeenCalled();
    expect(() => statSync(target)).toThrow();

    const t = setup([...FORMAT, ...typed, ...ENTER, "y"]);
    expect(await run(t)).toBe("saved");
    expect(statSync(target).isDirectory()).toBe(true);
    if (isPosix) {
      expect(statSync(target).mode & 0o777).toBe(0o700);
      expect(statSync(path.join(home, "a")).mode & 0o777).toBe(0o700);
    }
  });

  it("will not create a folder outside home", async () => {
    const outside = realpathSync(mkdtempSync(path.join(os.tmpdir(), "pgard-outside-")));
    try {
      const target = path.join(outside, "new");
      const s = setup([...FORMAT, ...chars(target), ...ENTER, "y", "escape"], { home: repo });
      expect(await run(s)).toBe("cancelled");
      expect(() => statSync(target)).toThrow();
      expect(s.captured.stdout()).toContain("could not be created");
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("still asks before creating inside the repository", async () => {
    const target = path.join(repo, "reports");
    const inside = (p: string) => p.startsWith(repo);
    const no = setup([...FORMAT, ...chars(target), ...ENTER, "y", "n", "escape"], { inside });
    expect(await run(no)).toBe("cancelled");
    expect(() => statSync(target)).toThrow();
    expect(no.captured.stderr()).toContain("inside the Git repository");

    const yes = setup([...FORMAT, ...chars(target), ...ENTER, "y", "y"], { inside });
    expect(await run(yes)).toBe("saved");
    expect(statSync(target).isDirectory()).toBe(true);
  });

  it("writes nothing and asks nothing without a terminal", async () => {
    const s = setup([], { isTTY: false });
    const noKeys = createTestContext(s.captured, s.context.deps, null);
    expect(await runReportExport(noKeys, panelsFixtureResult(), repo)).toBe("cancelled");
    expect(s.captured.stdout()).toBe("");
    expect(s.writeReports).not.toHaveBeenCalled();
  });

  it("--output-dir: a missing folder is an error, ~ is expanded", async () => {
    const s = setup([]);
    const missing = await checkOutputDir(s.context, path.join(home, "nope"), repo);
    expect(missing.kind).toBe("invalid");
    expect(missing).not.toHaveProperty("missing");
    const missingTilde = await checkOutputDir(s.context, "~/nope", repo);
    expect(missingTilde.kind).toBe("invalid");
    expect(() => statSync(path.join(home, "nope"))).toThrow();
    mkdirSync(path.join(home, "x"));
    const ok = await checkOutputDir(s.context, "~/x", repo);
    expect(ok).toMatchObject({ kind: "ok", outputDir: path.join(home, "x") });
  });
});
