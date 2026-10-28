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

  const reasonOf = (result: Awaited<ReturnType<typeof preflightIsolation>>) =>
    result && !result.isIsolated ? result.reason : "";
  const workWith = () => {
    const work = mkdtempSync(path.join(tmpdir(), "pgard-link-"));
    temps.push(work);
    return work;
  };

  describe.skipIf(posixOnly)("symlinked layouts pass, links to FIFOs and devices block", () => {
    it("follows a symlinked .git directory (repo-tool layout) but not one aimed at a FIFO or /dev/zero", async () => {
      const fixture = repo();
      const work = workWith();
      symlinkSync(path.join(fixture.root, ".git"), path.join(work, ".git"));
      expect(await preflightIsolation(work)).toBeNull();
      const toZero = workWith();
      symlinkSync("/dev/zero", path.join(toZero, ".git"));
      expect(reasonOf(await preflightIsolation(toZero))).toMatch(/\.git entry/);
      const toFifo = workWith();
      fifo(path.join(toFifo, "pipe"));
      symlinkSync(path.join(toFifo, "pipe"), path.join(toFifo, ".git"));
      expect(reasonOf(await preflightIsolation(toFifo))).toMatch(/\.git entry/);
    });

    it("follows a symlinked HEAD (core.preferSymlinkRefs) but not one aimed at a FIFO or /dev/zero", async () => {
      const fixture = repo();
      const head = path.join(fixture.root, ".git", "HEAD");
      writeFileSync(path.join(fixture.root, ".git", "HEAD.real"), "ref: refs/heads/main\n");
      rmSync(head);
      symlinkSync("HEAD.real", head);
      expect(await preflightIsolation(fixture.root)).toBeNull();
      for (const makeTarget of [zero, fifo]) {
        rmSync(head);
        const target = path.join(fixture.root, ".git", "HEAD.bad");
        rmSync(target, { force: true });
        makeTarget(target);
        symlinkSync("HEAD.bad", head);
        const reason = reasonOf(await preflightIsolation(fixture.root));
        expect(reason).toMatch(/HEAD/);
        expect(reason).toMatch(/preferSymlinkRefs/);
      }
    });

    it("follows symlinked config, packed-refs, refs and objects (shared-object layouts)", async () => {
      const fixture = repo();
      const git = path.join(fixture.root, ".git");
      const shared = workWith();
      for (const name of ["config", "refs", "objects"]) {
        rmSync(path.join(shared, name), { recursive: true, force: true });
        execFileSync("cp", ["-R", path.join(git, name), path.join(shared, name)]);
        rmSync(path.join(git, name), { recursive: true, force: true });
        symlinkSync(path.join(shared, name), path.join(git, name));
      }
      writeFileSync(path.join(shared, "packed-refs"), "# pack-refs\n");
      symlinkSync(path.join(shared, "packed-refs"), path.join(git, "packed-refs"));
      expect(await preflightIsolation(fixture.root)).toBeNull();
    });

    it.each(["config", "packed-refs"])(
      "blocks a symlinked %s aimed at a FIFO or /dev/zero, without deletion advice",
      async (name) => {
        for (const makeTarget of [zero, fifo]) {
          const fixture = repo();
          const git = path.join(fixture.root, ".git");
          const target = path.join(workWith(), "target");
          makeTarget(target);
          rmSync(path.join(git, name), { force: true });
          symlinkSync(target, path.join(git, name));
          const reason = reasonOf(await preflightIsolation(fixture.root));
          expect(reason).toContain(name);
          expect(reason).not.toMatch(/remove|delete|replace/i);
          expect(reason).toMatch(/git clone/);
        }
      },
    );

    it("blocks a ref symlinked to a FIFO and never advises deleting refs", async () => {
      const fixture = repo();
      const ref = path.join(fixture.root, ".git", "refs", "heads", "main");
      const target = path.join(workWith(), "target");
      fifo(target);
      rmSync(ref);
      symlinkSync(target, ref);
      const reason = reasonOf(await preflightIsolation(fixture.root));
      expect(reason).toMatch(/refs/);
      expect(reason).not.toMatch(/remove|delete|replace/i);
    });

    it("blocks a refs subdirectory linked outside refs, but allows a linked top-level refs", async () => {
      const fixture = repo();
      const git = path.join(fixture.root, ".git");
      const outside = workWith();
      mkdirSync(path.join(outside, "dir"));
      rmSync(path.join(git, "refs", "tags"), { recursive: true, force: true });
      symlinkSync(path.join(outside, "dir"), path.join(git, "refs", "tags"));
      const reason = reasonOf(await preflightIsolation(fixture.root));
      expect(reason).toMatch(/refs directory contains a symbolic link to a directory outside it/);
      expect(reason).not.toMatch(/remove|delete|replace/i);
    });

    it("gives no git repack advice for an unsafe alternates file, but does for a real one", async () => {
      const fixture = repo();
      const alternates = path.join(fixture.root, ".git", "objects", "info", "alternates");
      fifo(alternates);
      const unsafeReason = reasonOf(await preflightIsolation(fixture.root));
      expect(unsafeReason).toMatch(/alternates/);
      expect(unsafeReason).not.toMatch(/repack/);
      rmSync(alternates);
      writeFileSync(alternates, "/elsewhere/objects\n");
      expect(reasonOf(await preflightIsolation(fixture.root))).toMatch(/git repack -a -d/);
    });

    it.each([
      ["objects/info/commit-graph", /commit-graph/],
      ["objects/info/commit-graphs/commit-graph-chain", /commit-graphs/],
      ["config.worktree", /config\.worktree/],
    ])("blocks a FIFO %s", async (relative, pattern) => {
      const fixture = repo();
      fifo(path.join(fixture.root, ".git", ...relative.split("/")));
      expect(reasonOf(await preflightIsolation(fixture.root))).toMatch(pattern);
    });
  });

  describe("includes Git reads differently from PGARD are refused", () => {
    const withInclude = async (configText: string) => {
      const fixture = repo();
      writeFileSync(path.join(fixture.root, ".git", "config"), configText);
      return reasonOf(await preflightIsolation(fixture.root));
    };
    it.each([
      ["a line continuation", "[include]\n\tpath = fi\\\nfo\n"],
      ["partial quoting", '[include]\n\tpath = fi"fo"\n'],
      ["an unbalanced quote", '[include]\n\tpath = "fifo\n'],
      ["a ~user path", "[include]\n\tpath = ~root/x.cfg\n"],
      ["a continuation in another key", "[include]\n\tx = y\\\n[core]\n\tpath = fifo\n"],
    ])("blocks %s", async (_name, text) => {
      expect(await withInclude(text)).toMatch(/include PGARD can't interpret/);
    });

    it("accepts plain, quoted and ~/ includes", async () => {
      expect(
        await withInclude('[include]\n\tpath = a.cfg\n\tpath = "b.cfg" # note\n\tpath = ~/c.cfg\n'),
      ).toBe("");
    });

    it("blocks a chain of more than 50 included files", async () => {
      const fixture = repo();
      const git = path.join(fixture.root, ".git");
      for (let index = 0; index < 55; index += 1) {
        writeFileSync(
          path.join(git, `c${index}.cfg`),
          index < 54 ? `[include]\n\tpath = c${index + 1}.cfg\n` : "",
        );
      }
      writeFileSync(path.join(git, "config"), "[include]\n\tpath = c0.cfg\n");
      expect(reasonOf(await preflightIsolation(fixture.root))).toMatch(/more than 50 files/);
    });

    it("terminates on an include loop", async () => {
      const fixture = repo();
      const git = path.join(fixture.root, ".git");
      writeFileSync(path.join(git, "a.cfg"), "[include]\n\tpath = b.cfg\n");
      writeFileSync(path.join(git, "b.cfg"), "[include]\n\tpath = a.cfg\n");
      writeFileSync(path.join(git, "config"), "[include]\n\tpath = a.cfg\n");
      expect(await preflightIsolation(fixture.root)).toBeNull();
    });
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
