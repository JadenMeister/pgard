import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
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
import { checkOutputDir, createReportDir, runReportExport } from "./export-report.js";
import { defaultReportDir, expandHome, reportHome, shownDir } from "./report-dir.js";

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

  it("uses the one Windows home (USERPROFILE first, then HOME)", async () => {
    const home = "C:\\Users\\u";
    const base = { platform: "win32" as const, env: {}, home };
    expect(await defaultReportDir({ ...base, ...fakeFiles(["C:\\Users\\u\\Downloads"]) })).toBe(
      "C:\\Users\\u\\Downloads",
    );
    expect(await defaultReportDir({ ...base, ...fakeFiles(["C:\\Users\\u\\Documents"]) })).toBe(
      "C:\\Users\\u\\Documents",
    );
    expect(await defaultReportDir({ ...base, ...fakeFiles([]) })).toBe(home);
    expect(reportHome({ USERPROFILE: "C:\\P", HOME: "C:\\H" }, "win32")).toBe("C:\\P");
    expect(reportHome({ HOME: "C:\\H" }, "win32")).toBe("C:\\H");
    expect(reportHome({ USERPROFILE: "/p", HOME: "/h" }, "linux")).toBe("/h");
  });

  it("expands ~\\x against a UNC home", () => {
    expect(expandHome("~\\x", "\\\\srv\\share\\u", "win32")).toBe("\\\\srv\\share\\u\\x");
    expect(shownDir("\\\\srv\\share\\u\\Downloads", "\\\\srv\\share\\u", "win32")).toBe(
      "~\\Downloads",
    );
  });

  it("ignores unsafe or odd XDG values: $HOMEevil, /tmp, $HOME/../.., control characters", async () => {
    const home = "/home/u";
    const base = { platform: "linux" as const, env: {}, home };
    for (const value of [
      "$HOMEevil/Downloads",
      "/tmp",
      "$HOME/../..",
      "$HOME/../other",
      "$HOME/D\u001b[31mx",
      "$HOME/D\u0007x",
    ]) {
      const files = { "/home/u/.config/user-dirs.dirs": `XDG_DOWNLOAD_DIR="${value}"\n` };
      const dirs = ["/tmp", "/", "/home", "/home/u/Downloads"];
      expect(await defaultReportDir({ ...base, ...fakeFiles(dirs, files) })).toBe(
        "/home/u/Downloads",
      );
    }
  });

  it("lets the last XDG definition win and normalizes it", async () => {
    const files = {
      "/home/u/.config/user-dirs.dirs":
        'XDG_DOWNLOAD_DIR="$HOME/A"\nXDG_DOWNLOAD_DIR="$HOME/x/../B"\n',
    };
    const base = { platform: "linux" as const, env: {}, home: "/home/u" };
    expect(
      await defaultReportDir({ ...base, ...fakeFiles(["/home/u/A", "/home/u/B"], files) }),
    ).toBe("/home/u/B");
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
    options: {
      isTTY?: boolean;
      inside?: (p: string) => boolean;
      home?: string;
      uid?: number;
      gid?: number;
    } = {},
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
      currentUid: () => options.uid ?? process.getuid?.(),
      currentGid: () => options.gid ?? process.getgid?.(),
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
    expect(s.captured.stdout()).toContain(
      `"~${path.sep}a${path.sep}b" doesn't exist. Create it? [y/N]`,
    );
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
      expect(s.captured.stdout()).toContain("Only folders inside your home folder");
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("shows the resolved path for a relative name", async () => {
    const s = setup([...FORMAT, ...chars("rel"), ...ENTER, "n", "escape"]);
    expect(await run(s)).toBe("cancelled");
    expect(s.captured.stdout()).toContain(
      `"~${path.sep}repo${path.sep}rel" doesn't exist. Create it? [y/N]`,
    );
  });

  it("refuses ~user and says to use ~/", async () => {
    const s = setup([...FORMAT, ...chars("~bob/x"), ...ENTER, "escape"]);
    expect(await run(s)).toBe("cancelled");
    expect(s.captured.stdout()).toContain("Use ~/ (e.g. ~/Downloads).");
  });

  it("refuses --output-dir ~user with the same hint and does not resolve it from the cwd", async () => {
    const s = setup([]);
    for (const source of ["option", "prompt"] as const) {
      const check = await checkOutputDir(s.context, "~bob/x", repo, source);
      expect(check).toEqual({
        kind: "invalid",
        message: "Use ~/ (e.g. ~/Downloads). (For a folder named ~…, type ./~…)",
      });
    }
    mkdirSync(path.join(repo, "~bob"));
    expect((await checkOutputDir(s.context, "~bob", repo)).kind).toBe("invalid");
    // `~` and `~/x` still work.
    expect((await checkOutputDir(s.context, "~", repo)).kind).toBe("ok");
  });

  it("says the Korean ~user hint", async () => {
    const s = setup([]);
    const ko = { ...s.context, ruleLocale: "ko" as const };
    expect(await checkOutputDir(ko, "~bob", repo)).toEqual({
      kind: "invalid",
      message:
        "~ 바로 뒤에 /를 붙이세요(예: ~/Downloads). (이름이 ~로 시작하는 폴더는 ./~… 로 입력하세요)",
    });
  });

  describe.skipIf(!isPosix)("createReportDir hardening", () => {
    const uid = process.getuid?.() ?? 0;
    const gid = process.getgid?.() ?? 0;
    const create = (target: string, ids = { uid: uid as number | undefined, gid }) =>
      createReportDir(target, home, "linux", ids);
    const mk = (name: string, mode: number) => {
      const dir = path.join(home, name);
      mkdirSync(dir);
      chmodSync(dir, mode);
      return dir;
    };

    it("N2: refuses when the process uid differs from the home owner, creating nothing", async () => {
      const target = path.join(home, "fresh");
      expect((await create(target, { uid: uid + 1, gid })).outcome).toBe("home-owner");
      expect(() => statSync(target)).toThrow();
      expect((await create(target)).outcome).toBe("created");
    });

    it("m1: an unknown uid on POSIX is a refusal, not a skip", async () => {
      const target = path.join(home, "fresh");
      expect((await create(target, { uid: undefined, gid })).outcome).toBe("home-owner");
      expect(() => statSync(target)).toThrow();
    });

    it("N2/m2: the prompt names the home folder and says to run as yourself (EN and KO)", async () => {
      for (const [locale, expected] of [
        [
          "en",
          `Your home folder (${home}) belongs to another user. Run pgard as yourself (not with sudo).`,
        ],
        ["ko", `홈 폴더(${home})가 다른 사용자 소유입니다. sudo 없이 본인 계정으로 실행하세요.`],
      ] as const) {
        const s = setup([...FORMAT, ...chars(path.join(home, "new")), ...ENTER, "y", "escape"], {
          uid: uid + 1,
        });
        const context = { ...s.context, ruleLocale: locale };
        expect(await runReportExport(context, panelsFixtureResult(), repo)).toBe("cancelled");
        expect(s.captured.stdout()).toContain(expected);
        expect(() => statSync(path.join(home, "new"))).toThrow();
      }
    });

    it("N1: refuses a parent writable by others, unless sticky and owned by the user", async () => {
      for (const mode of [0o757, 0o777, 0o772]) {
        const parent = mk(`w${mode.toString(8)}`, mode);
        expect((await create(path.join(parent, "x"))).outcome).toBe("writable");
        expect(() => statSync(path.join(parent, "x"))).toThrow();
      }
      const sticky = mk("sticky", 0o1777);
      expect((await create(path.join(sticky, "x"))).outcome).toBe("created");
      const own = mk("own", 0o755);
      expect((await create(path.join(own, "x", "y"))).outcome).toBe("created");
    });

    it("M1: group-write is fine for a folder of the user's own group", async () => {
      const dir = mk("g775", 0o775);
      expect((await create(path.join(dir, "x"))).outcome).toBe("created");
    });

    it("M1: group-write with another group is still refused", async () => {
      const dir = mk("g775other", 0o775);
      const result = await create(path.join(dir, "x"), { uid, gid: gid + 1 });
      expect(result).toEqual({ outcome: "writable", folder: dir });
      expect(() => statSync(path.join(dir, "x"))).toThrow();
    });

    it("M1: an unknown gid cannot make group-write safe", async () => {
      const dir = mk("g775nogid", 0o775);
      const result = await createReportDir(path.join(dir, "x"), home, "linux", {
        uid,
        gid: undefined,
      });
      expect(result.outcome).toBe("writable");
    });

    it("M1: a 0775 home owned by the user is fine, even with another group", async () => {
      chmodSync(home, 0o775);
      expect((await create(path.join(home, "a"))).outcome).toBe("created");
      expect((await create(path.join(home, "b"), { uid, gid: gid + 1 })).outcome).toBe("created");
      chmodSync(home, 0o777);
      expect((await create(path.join(home, "c"))).outcome).toBe("writable");
      chmodSync(home, 0o700);
    });

    it("N1: the closest existing parent is the one checked, not an earlier one", async () => {
      const parent = mk("open", 0o777);
      expect((await create(path.join(parent, "a", "b"))).outcome).toBe("writable");
      expect(() => statSync(path.join(parent, "a"))).toThrow();
    });

    it("n1: the writable refusal names the folder and the fix (EN and KO)", async () => {
      const dir = mk("open2", 0o777);
      for (const [locale, expected] of [
        [
          "en",
          `"${dir}" can be changed by other users, so the folder was not created. Run chmod go-w "${dir}", or create the folder yourself.`,
        ],
        [
          "ko",
          `"${dir}"를 다른 사용자가 바꿀 수 있어 폴더를 만들지 않았습니다. chmod go-w "${dir}"를 실행하거나 폴더를 직접 만드세요.`,
        ],
      ] as const) {
        const s = setup([...FORMAT, ...chars(path.join(dir, "new")), ...ENTER, "y", "escape"]);
        const context = { ...s.context, ruleLocale: locale };
        expect(await runReportExport(context, panelsFixtureResult(), repo)).toBe("cancelled");
        expect(s.captured.stdout()).toContain(expected);
      }
    });

    it("N3: a link gives its own outcome, and a link out of home is a home refusal", async () => {
      const outside = realpathSync(mkdtempSync(path.join(os.tmpdir(), "pgard-outside-")));
      try {
        symlinkSync(outside, path.join(home, "dangling-ok"));
        expect((await create(path.join(home, "dangling-ok"))).outcome).toBe("link");
        expect((await create(path.join(home, "dangling-ok", "x"))).outcome).toBe("policy");
      } finally {
        rmSync(outside, { recursive: true, force: true });
      }
    });

    it("N3: the texts differ per refusal, in EN and KO", async () => {
      const { cliText } = await import("../ui/i18n/cli-text.js");
      for (const locale of ["en", "ko"] as const) {
        const t = cliText(locale).commands.report;
        const all = [
          t.homeOnly,
          t.linkRefused,
          t.otherUserRefused,
          t.homeOwnedByOther("/h"),
          t.parentWritable("/p"),
        ];
        expect(new Set(all).size).toBe(all.length);
      }
    });

    it("N3: the prompt shows the link text for a link as the final name", async () => {
      const outside = realpathSync(mkdtempSync(path.join(os.tmpdir(), "pgard-outside-")));
      try {
        symlinkSync(path.join(outside, "gone"), path.join(home, "dangling"));
        const s = setup([
          ...FORMAT,
          ...chars(path.join(home, "dangling")),
          ...ENTER,
          "y",
          "escape",
        ]);
        expect(await run(s)).toBe("cancelled");
        expect(s.captured.stdout()).toContain("A link is on that path");
        expect(s.captured.stdout()).not.toContain("Only folders inside your home folder");
        expect(() => statSync(path.join(outside, "gone"))).toThrow();
      } finally {
        rmSync(outside, { recursive: true, force: true });
      }
    });
  });

  it("N5/n3: Windows has no uid checks; an unknown home is still refused", async () => {
    expect(
      (await createReportDir(path.join(home, "w"), null, "win32", { uid: 1, gid: 1 })).outcome,
    ).toBe("policy");
    // A uid that matches nothing, and a folder others can write to: both checks are skipped.
    if (process.platform !== "win32") chmodSync(home, 0o777);
    const result = await createReportDir(path.join(home, "w"), home, "win32", {
      uid: 424242,
      gid: 424242,
    });
    expect(result.outcome).toBe("created");
  });

  it.skipIf(!isPosix)("refuses a symlinked parent and a symlink as the final name", async () => {
    const outside = realpathSync(mkdtempSync(path.join(os.tmpdir(), "pgard-outside-")));
    try {
      symlinkSync(outside, path.join(home, "link"));
      const viaParent = setup([
        ...FORMAT,
        ...chars(path.join(home, "link", "new")),
        ...ENTER,
        "y",
        "escape",
      ]);
      expect(await run(viaParent)).toBe("cancelled");
      expect(() => statSync(path.join(outside, "new"))).toThrow();
      expect(viaParent.captured.stdout()).toContain("Only folders inside your home folder");

      symlinkSync(path.join(outside, "gone"), path.join(home, "dangling"));
      const finalLink = setup([
        ...FORMAT,
        ...chars(path.join(home, "dangling")),
        ...ENTER,
        "y",
        "escape",
      ]);
      expect(await run(finalLink)).toBe("cancelled");
      expect(() => statSync(path.join(outside, "gone"))).toThrow();
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
