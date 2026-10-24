import { chmodSync, existsSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { findGitRoot } from "./git-root.js";
import { buildGitArgs, buildGitEnv, GitCommandError, runGit } from "./run-git.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";

describe("buildGitArgs", () => {
  it("prepends hardening config and separates operands and paths", () => {
    const args = buildGitArgs({
      subcommand: "diff-tree",
      flags: ["-p", "-r"],
      operands: ["HEAD"],
      paths: ["src"],
    });
    expect(args.slice(0, 2)).toEqual(["-c", "core.fsmonitor=false"]);
    expect(args).toContain("protocol.allow=never");
    expect(args).toContain("log.showSignature=false");
    expect(args).toContain("gpg.program=");
    const index = args.indexOf("diff-tree");
    expect(args.slice(index)).toEqual([
      "diff-tree",
      "--no-ext-diff",
      "--no-textconv",
      "-p",
      "-r",
      "--end-of-options",
      "HEAD",
      "--",
      "src",
    ]);
  });

  it.each([
    "--output=/tmp/x",
    "-O/tmp/order",
    "--ext-diff",
    "--textconv",
    "--exec=sh",
    "-c",
    "--show-signature",
    "--use-mailmap",
    "--format=%H %G?",
    "--pretty=format:%GS",
    "--format=%(signature)",
    "--textc",
    "--filt",
    "--ext-d",
    "--max-count=1 --output=x",
  ])("refuses forbidden flag %s", (flag) => {
    expect(() => buildGitArgs({ subcommand: "rev-list", flags: [flag] })).toThrow(GitCommandError);
  });

  it.each([
    ["cat-file", "--textc"],
    ["cat-file", "--filt"],
    ["cat-file", "--textconv"],
    ["cat-file", "--filters"],
    ["diff-tree", "--ext-d"],
    ["diff-tree", "--textconv"],
    ["ls-files", "--with-tree=HEAD"],
    ["rev-parse", "--git-path"],
  ] as const)("refuses %s %s (exact allowlist, no abbreviations)", (subcommand, flag) => {
    expect(() => buildGitArgs({ subcommand, flags: [flag] })).toThrow(GitCommandError);
  });

  it("refuses operands that look like options", () => {
    expect(() => buildGitArgs({ subcommand: "rev-list", operands: ["--output=/tmp/pwn"] })).toThrow(
      GitCommandError,
    );
    expect(() => buildGitArgs({ subcommand: "cat-file", operands: [""] })).toThrow(GitCommandError);
  });

  it("refuses flags that do not start with a dash", () => {
    expect(() => buildGitArgs({ subcommand: "rev-list", flags: ["HEAD"] })).toThrow(
      GitCommandError,
    );
  });

  it.each(["log", "show", "checkout", "config", "status"])(
    "refuses subcommand %s outside the allowlist",
    (subcommand) => {
      expect(() =>
        buildGitArgs({ subcommand: subcommand as unknown as "rev-list", flags: [] }),
      ).toThrow(GitCommandError);
    },
  );
});

describe("buildGitEnv", () => {
  it("does not pass GIT_* variables or secrets through and ignores global config", () => {
    const env = buildGitEnv({
      PATH: "/usr/bin",
      GIT_DIR: "/elsewhere/.git",
      GIT_CONFIG_PARAMETERS: "'core.pager=evil'",
      GITHUB_TOKEN: "not-for-git",
    });
    expect(env.PATH).toBe("/usr/bin");
    expect(env.GIT_DIR).toBeUndefined();
    expect(env.GIT_CONFIG_PARAMETERS).toBeUndefined();
    expect(env.GITHUB_TOKEN).toBeUndefined();
    expect(env.GIT_TERMINAL_PROMPT).toBe("0");
    expect(env.GIT_PAGER).toBe("cat");
    expect(env.GIT_CONFIG_NOSYSTEM).toBe("1");
    expect(env.GIT_CONFIG_GLOBAL).toBeTruthy();
    expect(env.GIT_NO_REPLACE_OBJECTS).toBe("1");
  });
});

describe("runGit against a malicious repository", () => {
  let fixture: GitFixture | null = null;
  let markerDir: string | null = null;
  afterEach(() => {
    fixture?.cleanup();
    fixture = null;
    if (markerDir) {
      rmSync(markerDir, { recursive: true, force: true });
    }
    markerDir = null;
  });

  const MARKERS = ["clean", "smudge", "textconv", "command", "fsmonitor", "pager", "gpg"];

  function createMaliciousRepo() {
    markerDir = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-marker-")));
    const marker = (name: string) => path.join(markerDir as string, name);
    fixture = createGitFixture();
    fixture.commit({
      files: { "a.txt": "one\n", ".gitattributes": "*.txt filter=pwn diff=pwn\n" },
    });
    fixture.commit({ files: { "a.txt": "two\n" } });

    // Rewrite HEAD with a (bogus) gpgsig header so signature display would invoke gpg.program.
    const raw = fixture.git("cat-file", "commit", "HEAD");
    const signed = raw.replace(
      /^(committer .*\n)/m,
      "$1gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEEfakefakefake\n -----END PGP SIGNATURE-----\n",
    );
    const signedSha = fixture
      .gitWithInput(signed, "hash-object", "-t", "commit", "-w", "--stdin")
      .trim();
    fixture.git("update-ref", "HEAD", signedSha);

    const gpgScript = path.join(markerDir, "fake-gpg.sh");
    writeFileSync(gpgScript, `#!/bin/sh\ntouch ${marker("gpg")}\nexit 1\n`);
    chmodSync(gpgScript, 0o755);

    fixture.git("config", "filter.pwn.clean", `touch ${marker("clean")}; cat`);
    fixture.git("config", "filter.pwn.smudge", `touch ${marker("smudge")}; cat`);
    fixture.git("config", "diff.pwn.textconv", `touch ${marker("textconv")}; cat`);
    fixture.git("config", "diff.pwn.command", `touch ${marker("command")}`);
    fixture.git("config", "core.fsmonitor", `touch ${marker("fsmonitor")}`);
    fixture.git("config", "core.pager", `touch ${marker("pager")}; cat`);
    fixture.git("config", "log.showSignature", "true");
    fixture.git("config", "gpg.program", gpgScript);
    return { root: fixture.root, marker };
  }

  it("the fixture really is malicious for plain git", () => {
    const { marker } = createMaliciousRepo();
    fixture?.git("log", "-p", "-2");
    expect(existsSync(marker("textconv"))).toBe(true);
    expect(existsSync(marker("gpg"))).toBe(true);
  });

  it("runs no repository-defined program for any allowlisted subcommand", async () => {
    const { root, marker } = createMaliciousRepo();
    const patch = await runGit(
      { subcommand: "diff-tree", flags: ["-p", "-r", "--root"], operands: ["HEAD"] },
      { cwd: root },
    );
    expect(patch).toContain("+two");
    await runGit(
      { subcommand: "rev-list", flags: ["--all", "--format=%H%x1f%an%x1f%ae"] },
      { cwd: root },
    );
    await runGit({ subcommand: "cat-file", flags: ["-p"], operands: ["HEAD"] }, { cwd: root });
    await runGit(
      { subcommand: "cat-file", flags: ["-p"], operands: ["HEAD:a.txt"] },
      { cwd: root },
    );
    const batch = await runGit(
      { subcommand: "cat-file", flags: ["--batch"] },
      { cwd: root, input: "HEAD:a.txt\n" },
    );
    expect(batch).toContain("two");
    await runGit({ subcommand: "ls-files", flags: ["-s"] }, { cwd: root });
    await runGit({ subcommand: "ls-tree", flags: ["-r"], operands: ["HEAD"] }, { cwd: root });
    await runGit({ subcommand: "for-each-ref" }, { cwd: root });
    await runGit(
      { subcommand: "rev-parse", flags: ["--verify"], operands: ["HEAD"] },
      { cwd: root },
    );
    for (const name of MARKERS) {
      expect(existsSync(marker(name)), name).toBe(false);
    }
  });

  it("cannot be steered into writing files through operands", async () => {
    const { root } = createMaliciousRepo();
    const target = path.join(markerDir as string, "written");
    await expect(
      runGit({ subcommand: "rev-list", operands: [`--output=${target}`] }, { cwd: root }),
    ).rejects.toBeInstanceOf(GitCommandError);
    expect(existsSync(target)).toBe(false);
  });
});

describe("findGitRoot", () => {
  it("returns null outside a Git repository", async () => {
    const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-nogit-")));
    try {
      expect(await findGitRoot(dir)).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("returns the repository root", async () => {
    const fixture = createGitFixture();
    try {
      fixture.commit({});
      expect(await findGitRoot(fixture.root)).toBe(fixture.root);
    } finally {
      fixture.cleanup();
    }
  });
});
