import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readRepositoryIsolation } from "./isolation.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";

describe("readRepositoryIsolation", () => {
  const fixtures: GitFixture[] = [];
  const create = () => {
    const fixture = createGitFixture();
    fixtures.push(fixture);
    return fixture;
  };
  afterEach(() => {
    for (const fixture of fixtures.splice(0)) {
      fixture.cleanup();
    }
  });

  it("accepts a self-contained repository", async () => {
    const repo = create();
    repo.commit({});
    expect(await readRepositoryIsolation(repo.root)).toEqual({ isIsolated: true });
  });

  it("rejects object alternates pointing at another repository", async () => {
    const sibling = create();
    sibling.commit({ files: { "secret.txt": "from sibling\n" } });
    const repo = create();
    repo.commit({});
    writeFileSync(
      path.join(repo.root, ".git", "objects", "info", "alternates"),
      `${path.join(sibling.root, ".git", "objects")}\n`,
    );
    const result = await readRepositoryIsolation(repo.root);
    expect(result.isIsolated).toBe(false);
    expect(!result.isIsolated && result.reason).toMatch(/alternates/);
  });

  it("rejects grafts", async () => {
    const repo = create();
    const first = repo.commit({});
    const second = repo.commit({});
    writeFileSync(path.join(repo.root, ".git", "info", "grafts"), `${second} ${first}\n`);
    expect((await readRepositoryIsolation(repo.root)).isIsolated).toBe(false);
  });

  it("rejects replace refs", async () => {
    const repo = create();
    const first = repo.commit({});
    const second = repo.commit({});
    repo.git("replace", first, second);
    const result = await readRepositoryIsolation(repo.root);
    expect(result.isIsolated).toBe(false);
    expect(!result.isIsolated && result.reason).toMatch(/replace/);
  });

  describe("unsafe metadata files fail closed", () => {
    const alternates = (repo: GitFixture) =>
      path.join(repo.root, ".git", "objects", "info", "alternates");
    const expectBlocked = async (repo: GitFixture) => {
      const result = await readRepositoryIsolation(repo.root);
      expect(result.isIsolated).toBe(false);
      expect(!result.isIsolated && result.reason).toMatch(/could not be read safely/);
      expect(!result.isIsolated && result.reason).toMatch(/alternates/);
    };

    it("blocks a symlink to a large file without reading it", async () => {
      const repo = create();
      repo.commit({});
      const big = path.join(repo.root, "big.bin");
      writeFileSync(big, Buffer.alloc(8 * 1024 * 1024, 0x61));
      symlinkSync(big, alternates(repo));
      await expectBlocked(repo);
    });

    it("blocks a symlink to a missing target", async () => {
      const repo = create();
      repo.commit({});
      symlinkSync(path.join(repo.root, "does-not-exist"), alternates(repo));
      await expectBlocked(repo);
    });

    it.skipIf(process.platform === "win32")("blocks a FIFO without blocking", async () => {
      const repo = create();
      repo.commit({});
      execFileSync("mkfifo", [alternates(repo)]);
      await expectBlocked(repo);
    });

    it("blocks a directory in the file's place", async () => {
      const repo = create();
      repo.commit({});
      mkdirSync(alternates(repo));
      await expectBlocked(repo);
    });

    it("blocks an oversized file", async () => {
      const repo = create();
      repo.commit({});
      writeFileSync(alternates(repo), Buffer.alloc(1024 * 1024, 0x20));
      await expectBlocked(repo);
    });

    it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
      "blocks an unreadable file",
      async () => {
        const repo = create();
        repo.commit({});
        writeFileSync(alternates(repo), "/nowhere\n", { mode: 0o000 });
        await expectBlocked(repo);
      },
    );

    it("blocks an unsafe grafts file", async () => {
      const repo = create();
      repo.commit({});
      symlinkSync(tmpdir(), path.join(repo.root, ".git", "info", "grafts"));
      const result = await readRepositoryIsolation(repo.root);
      expect(result.isIsolated).toBe(false);
      expect(!result.isIsolated && result.reason).toMatch(/grafts/);
    });

    it("blocks a symlinked shallow file but allows a regular one", async () => {
      const repo = create();
      repo.commit({});
      const shallow = path.join(repo.root, ".git", "shallow");
      writeFileSync(shallow, `${repo.shas[0]}\n`);
      expect((await readRepositoryIsolation(repo.root)).isIsolated).toBe(true);
      rmSync(shallow);
      symlinkSync(path.join(repo.root, "README.md"), shallow);
      const result = await readRepositoryIsolation(repo.root);
      expect(result.isIsolated).toBe(false);
      expect(!result.isIsolated && result.reason).toMatch(
        /shallow file .*could not be read safely/,
      );
    });

    it.skipIf(process.platform === "win32")("blocks a FIFO shallow file quickly", async () => {
      const repo = create();
      repo.commit({});
      execFileSync("mkfifo", [path.join(repo.root, ".git", "shallow")]);
      const result = await readRepositoryIsolation(repo.root);
      expect(result.isIsolated).toBe(false);
      expect(!result.isIsolated && result.reason).toMatch(
        /shallow file .*could not be read safely/,
      );
    });

    it.skipIf(process.platform === "win32")(
      "blocks a FIFO alternates file behind a gitfile",
      async () => {
        const repo = create();
        repo.commit({});
        execFileSync("mkfifo", [alternates(repo)]);
        const work = mkdtempSync(path.join(tmpdir(), "pgard-gitfile-"));
        try {
          writeFileSync(path.join(work, ".git"), `gitdir: ${path.join(repo.root, ".git")}\n`);
          const started = Date.now();
          const result = await readRepositoryIsolation(work);
          expect(Date.now() - started).toBeLessThan(4000);
          expect(result.isIsolated).toBe(false);
          expect(!result.isIsolated && result.reason).toMatch(/alternates/);
        } finally {
          rmSync(work, { recursive: true, force: true });
        }
      },
    );
  });
});
