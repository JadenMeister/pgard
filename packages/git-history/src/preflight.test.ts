import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { preflightIsolation } from "./isolation.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";

const posixOnly = process.platform === "win32";

describe("preflightIsolation", () => {
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
  const gitfileFor = (fixture: GitFixture) => {
    const work = mkdtempSync(path.join(tmpdir(), "pgard-gitfile-"));
    temps.push(work);
    writeFileSync(path.join(work, ".git"), `gitdir: ${path.join(fixture.root, ".git")}\n`);
    return work;
  };
  const fifo = (file: string) => {
    mkdirSync(path.dirname(file), { recursive: true });
    execFileSync("mkfifo", [file]);
  };
  const zero = (file: string) => {
    mkdirSync(path.dirname(file), { recursive: true });
    symlinkSync("/dev/zero", file);
  };

  it("passes a healthy repository, a gitfile and a repository with an include", async () => {
    const fixture = repo();
    expect(await preflightIsolation(fixture.root)).toBeNull();
    expect(await preflightIsolation(gitfileFor(fixture))).toBeNull();
    fixture.writeFile(".git/extra.cfg", "[user]\n\tname = x\n");
    fixture.git("config", "include.path", "extra.cfg");
    expect(await preflightIsolation(fixture.root)).toBeNull();
  });

  it("passes a directory without a repository and a linked worktree", async () => {
    expect(await preflightIsolation(tmpdir())).toBeNull();
    const fixture = repo();
    const linked = path.join(fixture.root, "..", `${path.basename(fixture.root)}-wt`);
    temps.push(linked);
    fixture.git("worktree", "add", "-q", "-b", "wt", linked);
    expect(await preflightIsolation(linked)).toBeNull();
  });

  it.skipIf(posixOnly)("blocks a symlinked .git", async () => {
    const fixture = repo();
    const work = mkdtempSync(path.join(tmpdir(), "pgard-dotgit-link-"));
    temps.push(work);
    symlinkSync(path.join(fixture.root, ".git"), path.join(work, ".git"));
    const result = await preflightIsolation(work);
    expect(result?.isIsolated).toBe(false);
    expect(result && !result.isIsolated && result.reason).toMatch(/\.git entry/);
  });

  const faults: [string, (g: string) => void, RegExp][] = [
    ["commondir symlinked to /dev/zero", (g) => zero(path.join(g, "commondir")), /commondir/],
    ["commondir FIFO", (g) => fifo(path.join(g, "commondir")), /commondir/],
    ["HEAD FIFO", (g) => rmAndFifo(path.join(g, "HEAD")), /HEAD/],
    ["config FIFO", (g) => rmAndFifo(path.join(g, "config")), /config/],
    ["packed-refs FIFO", (g) => fifo(path.join(g, "packed-refs")), /packed-refs/],
    ["loose ref FIFO", (g) => rmAndFifo(path.join(g, "refs", "heads", "main")), /refs/],
    [
      "loose ref symlinked to /dev/zero",
      (g) => rmAndZero(path.join(g, "refs", "heads", "main")),
      /refs/,
    ],
    ["alternates FIFO", (g) => fifo(path.join(g, "objects", "info", "alternates")), /alternates/],
    ["shallow FIFO", (g) => fifo(path.join(g, "shallow")), /shallow/],
  ];
  function rmAndFifo(file: string) {
    rmSync(file);
    fifo(file);
  }
  function rmAndZero(file: string) {
    rmSync(file);
    zero(file);
  }

  describe.skipIf(posixOnly).each(["plain", "gitfile"])("%s layout", (layout) => {
    it.each(faults)("blocks %s before any Git process", async (_name, inject, reason) => {
      const fixture = repo();
      inject(path.join(fixture.root, ".git"));
      const root = layout === "plain" ? fixture.root : gitfileFor(fixture);
      const started = Date.now();
      const result = await preflightIsolation(root);
      expect(Date.now() - started).toBeLessThan(3000);
      expect(result?.isIsolated).toBe(false);
      expect(result && !result.isIsolated && result.reason).toMatch(reason);
    });

    it("blocks an include of a FIFO", async () => {
      const fixture = repo();
      const target = path.join(fixture.root, "inc.cfg");
      fifo(target);
      fixture.writeFile(".git/config.d", "");
      fixture.git("config", "include.path", target);
      const root = layout === "plain" ? fixture.root : gitfileFor(fixture);
      const result = await preflightIsolation(root);
      expect(result && !result.isIsolated && result.reason).toMatch(/included config file/);
    });

    it("probes the directory named by commondir", async () => {
      const other = repo();
      fifo(path.join(other.root, ".git", "objects", "info", "alternates"));
      const fixture = repo();
      writeFileSync(path.join(fixture.root, ".git", "commondir"), path.join(other.root, ".git"));
      const root = layout === "plain" ? fixture.root : gitfileFor(fixture);
      const result = await preflightIsolation(root);
      expect(result && !result.isIsolated && result.reason).toMatch(/alternates/);
    });
  });
});
