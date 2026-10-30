import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { inspectGitRoot } from "./git-root.js";
import type { GitRunner } from "./run-git.js";

let base: string | null = null;
function scratch(): string {
  base = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-gitroot-")));
  return base;
}
afterEach(() => {
  if (base !== null) rmSync(base, { recursive: true, force: true });
  base = null;
});

/** A runner that answers `rev-parse --show-toplevel` the way Git does for a given work tree. */
const toplevel =
  (answer: string): GitRunner =>
  async () =>
    `${answer}\n`;

describe("inspectGitRoot (core.worktree redirect, #427)", () => {
  it("accepts a root that is the folder holding the .git entry, from a subfolder too", async () => {
    const root = scratch();
    mkdirSync(path.join(root, "repo", ".git"), { recursive: true });
    mkdirSync(path.join(root, "repo", "src", "deep"), { recursive: true });
    const repo = path.join(root, "repo");
    expect(await inspectGitRoot(path.join(repo, "src", "deep"), toplevel(repo))).toEqual({
      kind: "root",
      root: repo,
    });
  });

  it("accepts a linked work tree or submodule whose .git is a file", async () => {
    const root = scratch();
    mkdirSync(path.join(root, "linked"), { recursive: true });
    writeFileSync(path.join(root, "linked", ".git"), "gitdir: /elsewhere/.git/worktrees/linked\n");
    const linked = path.join(root, "linked");
    expect((await inspectGitRoot(linked, toplevel(linked))).kind).toBe("root");
  });

  it.skipIf(process.platform === "win32")(
    "accepts a .git that is a symbolic link to a Git directory or to a gitdir file",
    async () => {
      const root = scratch();
      mkdirSync(path.join(root, "sl-gitdir"));
      mkdirSync(path.join(root, "sl"));
      symlinkSync("../sl-gitdir", path.join(root, "sl", ".git"));
      const sl = path.join(root, "sl");
      expect((await inspectGitRoot(sl, toplevel(sl))).kind).toBe("root");
      writeFileSync(path.join(root, "gitfile"), "gitdir: /elsewhere\n");
      mkdirSync(path.join(root, "sl2"));
      symlinkSync("../gitfile", path.join(root, "sl2", ".git"));
      const sl2 = path.join(root, "sl2");
      expect((await inspectGitRoot(sl2, toplevel(sl2))).kind).toBe("root");
      renameSync(path.join(root, "sl2"), path.join(root, "sl3"));
    },
  );

  it("refuses a work tree that Git put elsewhere (core.worktree)", async () => {
    const root = scratch();
    const trap = path.join(root, "trap");
    const victim = path.join(root, "victim");
    mkdirSync(path.join(trap, ".git"), { recursive: true });
    mkdirSync(victim);
    const found = await inspectGitRoot(trap, toplevel(victim));
    expect(found).toEqual({ kind: "redirected", root: victim, repository: trap });
  });

  it("refuses a redirect to another repository's folder or to .git itself", async () => {
    const root = scratch();
    const trap = path.join(root, "trap");
    const other = path.join(root, "other");
    mkdirSync(path.join(trap, ".git"), { recursive: true });
    mkdirSync(path.join(other, ".git"), { recursive: true });
    expect((await inspectGitRoot(trap, toplevel(other))).kind).toBe("redirected");
    expect((await inspectGitRoot(trap, toplevel(path.join(other, ".git")))).kind).toBe(
      "redirected",
    );
  });

  it("refuses when no .git entry exists at all although Git found a root", async () => {
    const root = scratch();
    mkdirSync(path.join(root, "plain"));
    expect((await inspectGitRoot(path.join(root, "plain"), toplevel(root))).kind).toBe(
      "redirected",
    );
  });

  it("is none outside a repository", async () => {
    const root = scratch();
    const failing: GitRunner = async () => {
      throw new Error("not a repository");
    };
    expect(await inspectGitRoot(root, failing)).toEqual({ kind: "none" });
  });
});
