import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { isPathInside, resolveHookIndexFile, resolveHooksLocation } from "./hook-paths.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";

const isWindows = process.platform === "win32";

describe("isPathInside", () => {
  it("follows POSIX rules", () => {
    expect(isPathInside("/repo", "/repo")).toBe(true);
    expect(isPathInside("/repo", "/repo/.git/hooks")).toBe(true);
    expect(isPathInside("/repo/.git", "/repo/.git/../x", path.posix)).toBe(false);
    expect(isPathInside("/repo", "/repository", path.posix)).toBe(false);
    expect(isPathInside("/repo", "/other/repo", path.posix)).toBe(false);
    // Case matters on POSIX.
    expect(isPathInside("/Repo", "/repo/x", path.posix)).toBe(false);
  });

  it("follows Windows rules: drive letters, case, separators, UNC shares", () => {
    const win = path.win32;
    expect(isPathInside("C:\\Repo\\.git", "c:\\repo\\.git\\hooks", win)).toBe(true);
    expect(isPathInside("C:\\Repo\\.git", "C:/Repo/.git/hooks/pre-commit", win)).toBe(true);
    expect(isPathInside("C:\\Repo\\.git", "D:\\Repo\\.git\\hooks", win)).toBe(false);
    expect(isPathInside("C:\\Repo\\.git", "C:\\Repo\\.git\\..\\evil", win)).toBe(false);
    expect(isPathInside("C:\\Repo", "C:\\RepoEvil", win)).toBe(false);
    expect(isPathInside("C:\\Repo", "\\\\server\\share\\Repo", win)).toBe(false);
    expect(isPathInside("\\\\server\\share\\Repo", "\\\\server\\share\\Repo\\x", win)).toBe(true);
    expect(isPathInside("\\\\server\\share\\Repo", "\\\\other\\share\\Repo\\x", win)).toBe(false);
  });
});

describe("resolveHooksLocation", () => {
  const fixtures: GitFixture[] = [];
  const temps: string[] = [];
  afterEach(() => {
    for (const fixture of fixtures.splice(0)) fixture.cleanup();
    for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
  });
  const repo = () => {
    const fixture = createGitFixture();
    fixtures.push(fixture);
    fixture.commit({});
    return fixture;
  };
  const outside = () => {
    const dir = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-outside-")));
    temps.push(dir);
    return dir;
  };

  it("finds the repository's own .git/hooks", async () => {
    const fixture = repo();
    const location = await resolveHooksLocation(fixture.root);
    expect(location.kind).toBe("ready");
    if (location.kind !== "ready") return;
    expect(realpathSync.native(location.hooksDir)).toBe(
      realpathSync.native(path.join(fixture.root, ".git", "hooks")),
    );
  });

  it("reports core.hooksPath outside the repository as such", async () => {
    const fixture = repo();
    const elsewhere = outside();
    fixture.git("config", "core.hooksPath", elsewhere);
    const location = await resolveHooksLocation(fixture.root);
    expect(location).toMatchObject({ kind: "custom", isInsideRepository: false });
  });

  it("reports a core.hooksPath inside the repository, relative or absolute, as custom too", async () => {
    const fixture = repo();
    mkdirSync(path.join(fixture.root, ".githooks"));
    fixture.git("config", "core.hooksPath", ".githooks");
    expect(await resolveHooksLocation(fixture.root)).toMatchObject({
      kind: "custom",
      hooksPath: ".githooks",
      isInsideRepository: true,
    });
    fixture.git("config", "core.hooksPath", "../escape");
    expect(await resolveHooksLocation(fixture.root)).toMatchObject({
      kind: "custom",
      isInsideRepository: false,
    });
  });

  it("is not fooled by an empty value or the null device", async () => {
    const fixture = repo();
    fixture.git("config", "core.hooksPath", "/dev/null");
    expect((await resolveHooksLocation(fixture.root)).kind).toBe("custom");
  });

  it.skipIf(isWindows)(
    "refuses a hooks directory that is a symbolic link out of .git",
    async () => {
      const fixture = repo();
      const elsewhere = outside();
      rmSync(path.join(fixture.root, ".git", "hooks"), { recursive: true, force: true });
      symlinkSync(elsewhere, path.join(fixture.root, ".git", "hooks"));
      const location = await resolveHooksLocation(fixture.root);
      expect(location.kind).toBe("unsafe");
    },
  );

  it.skipIf(isWindows)("accepts a hooks symlink that stays inside .git", async () => {
    const fixture = repo();
    const hooks = path.join(fixture.root, ".git", "hooks");
    rmSync(hooks, { recursive: true, force: true });
    mkdirSync(path.join(fixture.root, ".git", "real-hooks"));
    symlinkSync(path.join(fixture.root, ".git", "real-hooks"), hooks);
    expect((await resolveHooksLocation(fixture.root)).kind).toBe("ready");
  });

  it("reports the shared hooks directory of a linked worktree", async () => {
    const fixture = repo();
    const parent = outside();
    const linked = path.join(parent, "linked");
    fixture.git("worktree", "add", "-q", "-b", "other", linked);
    const location = await resolveHooksLocation(linked);
    expect(location.kind).toBe("ready");
    if (location.kind !== "ready") return;
    expect(realpathSync.native(location.hooksDir)).toBe(
      realpathSync.native(path.join(fixture.root, ".git", "hooks")),
    );
  });

  it.skipIf(isWindows)("refuses a repository whose layout is unsafe (alternates)", async () => {
    const fixture = repo();
    writeFileSync(path.join(fixture.root, ".git", "objects", "info", "alternates"), "/tmp/other\n");
    expect((await resolveHooksLocation(fixture.root)).kind).toBe("unsafe");
  });
});

describe("resolveHookIndexFile", () => {
  const fixtures: GitFixture[] = [];
  const temps: string[] = [];
  afterEach(() => {
    for (const fixture of fixtures.splice(0)) fixture.cleanup();
    for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
  });
  const repo = () => {
    const fixture = createGitFixture();
    fixtures.push(fixture);
    fixture.commit({});
    return fixture;
  };

  it("uses the default index when GIT_INDEX_FILE is unset, empty or the repository's own", async () => {
    const fixture = repo();
    expect(await resolveHookIndexFile(fixture.root, fixture.root, undefined)).toEqual({
      state: "default",
    });
    expect(await resolveHookIndexFile(fixture.root, fixture.root, "")).toEqual({
      state: "default",
    });
    expect(await resolveHookIndexFile(fixture.root, fixture.root, ".git/index")).toEqual({
      state: "default",
    });
  });

  it("accepts Git's temporary index inside .git", async () => {
    const fixture = repo();
    const lock = path.join(fixture.root, ".git", "index.lock");
    writeFileSync(lock, "x");
    const result = await resolveHookIndexFile(fixture.root, fixture.root, lock);
    expect(result).toEqual({ state: "custom", indexFile: realpathSync.native(lock) });
  });

  it("refuses an index outside .git, a missing file and a directory", async () => {
    const fixture = repo();
    const dir = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-idx-")));
    temps.push(dir);
    writeFileSync(path.join(dir, "index"), "x");
    expect(
      (await resolveHookIndexFile(fixture.root, fixture.root, path.join(dir, "index"))).state,
    ).toBe("unsafe");
    expect(
      (
        await resolveHookIndexFile(
          fixture.root,
          fixture.root,
          path.join(fixture.root, ".git", "nope"),
        )
      ).state,
    ).toBe("unsafe");
    expect(
      (await resolveHookIndexFile(fixture.root, fixture.root, path.join(fixture.root, ".git")))
        .state,
    ).toBe("unsafe");
    expect(
      (await resolveHookIndexFile(fixture.root, fixture.root, path.join(fixture.root, "../x\0y")))
        .state,
    ).toBe("unsafe");
  });

  it.skipIf(isWindows)("refuses a symbolic link even when it points inside .git", async () => {
    const fixture = repo();
    const real = path.join(fixture.root, ".git", "real-index");
    writeFileSync(real, "x");
    const link = path.join(fixture.root, ".git", "index.lock");
    symlinkSync(real, link);
    expect((await resolveHookIndexFile(fixture.root, fixture.root, link)).state).toBe("unsafe");
  });
});
