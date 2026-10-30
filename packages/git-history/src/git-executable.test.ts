import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resolveGitExecutable, trustedPathEntries } from "./git-executable.js";
import { findGitRoot } from "./git-root.js";
import { buildGitEnv, runGit } from "./run-git.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";

describe("trustedPathEntries", () => {
  it("keeps absolute drive entries and normalizes them", () => {
    expect(trustedPathEntries("C:\\Windows;D:/tools/bin")).toEqual([
      "C:\\Windows",
      "D:\\tools\\bin",
    ]);
  });

  it("strips quotes", () => {
    expect(trustedPathEntries('"C:\\Program Files\\Git\\cmd";C:\\a')).toEqual([
      "C:\\Program Files\\Git\\cmd",
      "C:\\a",
    ]);
  });

  it("drops empty, relative, rooted-without-drive, UNC and malformed entries", () => {
    expect(
      trustedPathEntries(
        ';;  ;.;..;bin;.\\bin;\\Windows;C:rel;\\\\host\\share;C:\\a|b;C:\\a<b;"C:\\unterminated',
      ),
    ).toEqual([]);
  });
});

describe("resolveGitExecutable", () => {
  const env = { Path: "C:\\work\\repo\\bin;;.;C:\\cwd;\\rooted;C:\\Git\\cmd;D:\\other" };
  const present = new Set([
    "C:\\work\\repo\\bin\\git.exe",
    "C:\\cwd\\git.exe",
    "C:\\Git\\cmd\\git.exe",
  ]);
  const isFile = (file: string) => present.has(file);

  it("returns plain git outside Windows, where the working directory is not searched", () => {
    expect(resolveGitExecutable({ platform: "linux", env })).toBe("git");
    expect(resolveGitExecutable({ platform: "darwin", env })).toBe("git");
  });

  it("skips entries inside the repository and the current directory", () => {
    expect(
      resolveGitExecutable({
        platform: "win32",
        env,
        isFile,
        cwd: "C:\\work\\repo",
        processCwd: "C:\\cwd",
      }),
    ).toBe("C:\\Git\\cmd\\git.exe");
  });

  it("compares case-insensitively and ignores sibling directories with a shared prefix", () => {
    const options = { platform: "win32", isFile, processCwd: "C:\\elsewhere" } as const;
    expect(resolveGitExecutable({ ...options, env, cwd: "c:\\WORK\\REPO" })).toBe(
      "C:\\cwd\\git.exe",
    );
    expect(
      resolveGitExecutable({
        ...options,
        env: { Path: "C:\\work\\repo2\\git.exe;C:\\work\\repo2" },
        cwd: "C:\\work\\repo",
      }),
    ).toBeNull();
  });

  it("accepts only git.exe, never git.com, git.cmd or git.bat", () => {
    const only = new Set(["C:\\a\\git.com", "C:\\a\\git.cmd", "C:\\a\\git.bat"]);
    expect(
      resolveGitExecutable({
        platform: "win32",
        env: { Path: "C:\\a" },
        isFile: (file) => only.has(file),
        processCwd: "C:\\z",
      }),
    ).toBeNull();
  });

  it("returns null when PATH has no usable git", () => {
    expect(resolveGitExecutable({ platform: "win32", env: {}, isFile })).toBeNull();
    expect(resolveGitExecutable({ platform: "win32", env: { Path: "git;." }, isFile })).toBeNull();
  });
});

describe("hostile global git config is ignored (all platforms)", () => {
  let fixture: GitFixture | null = null;
  let home: string | null = null;
  const saved = { ...process.env };
  afterEach(() => {
    fixture?.cleanup();
    fixture = null;
    if (home) rmSync(home, { recursive: true, force: true });
    home = null;
    process.env = { ...saved };
  });

  it("does not read ~/.gitconfig, XDG config or GIT_CONFIG_GLOBAL", async () => {
    home = mkdtempSync(path.join(tmpdir(), "pgard-home-"));
    const hostile = [
      "[core]",
      "\tabbrev = 4",
      "\tpager = exit 1",
      "[alias]",
      "\tls-tree = !exit 1",
      "",
    ].join("\n");
    const globalFile = path.join(home, "hostile-gitconfig");
    writeFileSync(globalFile, hostile);
    writeFileSync(path.join(home, ".gitconfig"), hostile);
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    process.env.XDG_CONFIG_HOME = home;
    process.env.GIT_CONFIG_GLOBAL = globalFile;
    expect(buildGitEnv().GIT_CONFIG_GLOBAL).not.toBe(globalFile);

    fixture = createGitFixture();
    fixture.commit({});
    const output = await runGit(
      { subcommand: "for-each-ref", flags: ["--format=%(objectname:short)"] },
      { cwd: fixture.root },
    );
    // With the hostile `core.abbrev = 4` applied this would be 4 characters long.
    expect(output.trim().length).toBeGreaterThanOrEqual(7);
  });
});

describe.skipIf(process.platform !== "win32")(
  "a git.exe planted in the repository (Windows)",
  () => {
    let fixture: GitFixture | null = null;
    afterEach(() => {
      fixture?.cleanup();
      fixture = null;
    });

    function plant(): GitFixture {
      fixture = createGitFixture();
      fixture.commit({});
      // node.exe cannot act as git: if it ran in place of git, every call would fail.
      copyFileSync(process.execPath, path.join(fixture.root, "git.exe"));
      copyFileSync(process.execPath, path.join(fixture.root, "git.com"));
      return fixture;
    }

    it("is the thing a bare spawn would run (the test is not vacuous)", () => {
      const repo = plant();
      const env = { ...process.env };
      delete env.NoDefaultCurrentDirectoryInExePath;
      const result = spawnSync("git", ["--version"], {
        cwd: repo.root,
        env,
        encoding: "utf8",
        timeout: 60_000,
        killSignal: "SIGKILL",
      });
      expect(result.stdout.startsWith("git version")).toBe(false);
    });

    it("never runs for findGitRoot or runGit", async () => {
      const repo = plant();
      expect(await findGitRoot(repo.root)).toBe(repo.root);
      const head = await runGit(
        { subcommand: "rev-parse", flags: ["--verify"], operands: ["HEAD"] },
        { cwd: repo.root },
      );
      expect(head.trim()).toMatch(/^[0-9a-f]{40}$/);
    });

    it("never runs for the doctor version check", () => {
      const repo = plant();
      const depsUrl = new URL("../../../apps/cli/dist/deps.js", import.meta.url).href;
      const script = `import { readGitVersionDefault } from ${JSON.stringify(depsUrl)}; process.stdout.write(String(await readGitVersionDefault()));`;
      const result = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
        cwd: repo.root,
        encoding: "utf8",
        timeout: 60_000,
        killSignal: "SIGKILL",
      });
      expect(result.stdout).toMatch(/^git version /);
    });
  },
);
