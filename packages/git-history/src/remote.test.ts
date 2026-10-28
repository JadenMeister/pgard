import { mkdirSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { listCommitCandidates, readHeadRevision } from "./commits.js";
import { findGitRoot } from "./git-root.js";
import { parseGitHubRemoteUrl, readGitHubRemote } from "./remote.js";
import { GitCommandError, runGit, type GitRunner } from "./run-git.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";

const REWRITE_CONFIG = '[url "git@evil.example.com:"]\n\tinsteadOf = https://github.com/\n';
const REMOTE_CONFIG = '[remote "mirror"]\n\turl = https://gitlab.com/x/y.git\n';

describe("parseGitHubRemoteUrl", () => {
  it.each([
    ["https://github.com/octo/app.git", { owner: "octo", name: "app" }],
    ["https://github.com/octo/app", { owner: "octo", name: "app" }],
    ["https://github.com/octo/app/", { owner: "octo", name: "app" }],
    ["https://GitHub.com/Octo/My.App.git", { owner: "Octo", name: "My.App" }],
    ["git@github.com:octo/app.git", { owner: "octo", name: "app" }],
    ["ssh://git@github.com/octo/app.git", { owner: "octo", name: "app" }],
    ["ssh://git@ssh.github.com:443/octo/app.git", { owner: "octo", name: "app" }],
  ])("accepts %s", (url, expected) => {
    expect(parseGitHubRemoteUrl(url)).toEqual(expected);
  });

  it.each([
    "https://gitlab.com/octo/app.git",
    "https://github.com.evil.example/octo/app.git",
    "https://evil.example/github.com/octo/app.git",
    "git@gitlab.com:octo/app.git",
    "https://github.com/octo/app/extra",
    "https://github.com/octo",
    "https://github.com/octo/app.git?x=1",
    "https://github.com/me/app%E0",
    "https://github.com/me/%61pp",
    "http://github.com/octo/app.git",
    "file:///tmp/repo",
    "/tmp/local/repo",
    "../sibling",
    "https://github.com/-bad/app",
    "https://github.com/octo/..",
    "ssh://root@github.com/octo/app.git",
    "",
  ])("rejects %s", (url) => {
    expect(parseGitHubRemoteUrl(url)).toBeNull();
  });
});

describe("readGitHubRemote", () => {
  let fixture: GitFixture | null = null;
  afterEach(() => {
    fixture?.cleanup();
    fixture = null;
  });

  it("resolves a single origin remote", async () => {
    fixture = createGitFixture({ remotes: { origin: "git@github.com:octo/app.git" } });
    expect(await readGitHubRemote(fixture.root)).toEqual({
      isResolved: true,
      repo: { owner: "octo", name: "app" },
      remoteName: "origin",
    });
  });

  it("accepts several remotes naming the same repository", async () => {
    fixture = createGitFixture({
      remotes: { origin: "https://github.com/octo/app.git", backup: "git@github.com:OCTO/app.git" },
    });
    const result = await readGitHubRemote(fixture.root);
    expect(result.isResolved).toBe(true);
  });

  it("rejects remotes pointing to different GitHub repositories", async () => {
    fixture = createGitFixture({
      remotes: { origin: "https://github.com/octo/app.git", fork: "https://github.com/me/app.git" },
    });
    const result = await readGitHubRemote(fixture.root);
    expect(result).toMatchObject({ isResolved: false });
    expect(!result.isResolved && result.reason).toMatch(/ambiguous/);
  });

  it("rejects a non-GitHub remote even next to a GitHub one", async () => {
    fixture = createGitFixture({
      remotes: { origin: "https://github.com/octo/app.git", mirror: "https://gitlab.com/x/y.git" },
    });
    expect((await readGitHubRemote(fixture.root)).isResolved).toBe(false);
  });

  it("rejects a GitHub fetch URL with a different push URL", async () => {
    fixture = createGitFixture({ remotes: { origin: "https://github.com/octo/app.git" } });
    fixture.git("remote", "set-url", "--push", "origin", "https://github.com/other/app.git");
    expect((await readGitHubRemote(fixture.root)).isResolved).toBe(false);
  });

  it("does not echo credential-bearing URLs in reasons", async () => {
    fixture = createGitFixture({
      remotes: { origin: "https://user:hunter2@gitlab.example/x/y.git" },
    });
    const result = await readGitHubRemote(fixture.root);
    expect(result.isResolved).toBe(false);
    expect(JSON.stringify(result)).not.toContain("hunter2");
  });

  it("blocks url.*.insteadOf rewrites that would change the remote host", async () => {
    fixture = createGitFixture({ remotes: { origin: "git@evil.example.com:victim/repo.git" } });
    fixture.git("config", "url.git@evil.example.com:.insteadOf", "https://github.com/");
    fixture.git("config", "remote.origin.url", "https://github.com/victim/repo.git");
    const result = await readGitHubRemote(fixture.root);
    expect(result.isResolved).toBe(false);
    expect(!result.isResolved && result.reason).toMatch(/insteadOf/);
  });

  it("blocks url.*.insteadOf even when the raw URL is not the rewritten target", async () => {
    fixture = createGitFixture({ remotes: { origin: "gh:victim/repo.git" } });
    fixture.git("config", "url.https://github.com/.insteadOf", "gh:");
    const result = await readGitHubRemote(fixture.root);
    expect(result.isResolved).toBe(false);
    expect(!result.isResolved && result.reason).toMatch(/insteadOf/);
  });

  it("blocks url.*.pushInsteadOf rewrites", async () => {
    fixture = createGitFixture({ remotes: { origin: "https://github.com/octo/app.git" } });
    fixture.git("config", "url.git@evil.example.com:.pushInsteadOf", "https://github.com/");
    const result = await readGitHubRemote(fixture.root);
    expect(result.isResolved).toBe(false);
    expect(!result.isResolved && result.reason).toMatch(/insteadOf/i);
  });

  it("blocks a rewrite defined in an included config file", async () => {
    fixture = createGitFixture({ remotes: { origin: "https://github.com/octo/app.git" } });
    fixture.writeFile(".git/extra.cfg", REWRITE_CONFIG);
    fixture.git("config", "include.path", "extra.cfg");
    const result = await readGitHubRemote(fixture.root);
    expect(result.isResolved).toBe(false);
    expect(!result.isResolved && result.reason).toMatch(/insteadOf/);
  });

  it("blocks a rewrite in a conditional include", async () => {
    fixture = createGitFixture({ remotes: { origin: "https://github.com/octo/app.git" } });
    fixture.writeFile(".git/extra.cfg", REWRITE_CONFIG);
    fixture.git("config", "includeIf.gitdir:**.path", "extra.cfg");
    const result = await readGitHubRemote(fixture.root);
    expect(result.isResolved).toBe(false);
    expect(!result.isResolved && result.reason).toMatch(/insteadOf/);
  });

  it("reads remote URLs defined in an included config file", async () => {
    fixture = createGitFixture({ remotes: { origin: "https://github.com/octo/app.git" } });
    fixture.writeFile(".git/extra.cfg", REMOTE_CONFIG);
    fixture.git("config", "include.path", "extra.cfg");
    expect((await readGitHubRemote(fixture.root)).isResolved).toBe(false);
  });

  it("follows includes: a remote defined only in an included file is resolved", async () => {
    fixture = createGitFixture();
    fixture.writeFile(
      ".git/extra.cfg",
      '[remote "origin"]\n\turl = https://github.com/octo/app.git\n',
    );
    fixture.git("config", "include.path", "extra.cfg");
    expect(await readGitHubRemote(fixture.root)).toEqual({
      isResolved: true,
      repo: { owner: "octo", name: "app" },
      remoteName: "origin",
    });
  });

  it.each([
    ["timeout", new GitCommandError("git command timed out", null, "timeout")],
    ["output limit", new GitCommandError("too big", null, "output_limit")],
    ["failure", new GitCommandError("git command failed", 128)],
    ["unknown error", new Error("boom")],
  ])("blocks with a fix hint when the config read fails (%s)", async (_name, error) => {
    fixture = createGitFixture({ remotes: { origin: "https://github.com/octo/app.git" } });
    const runner: GitRunner = (invocation, options) => {
      if (invocation.subcommand === "config") return Promise.reject(error);
      return runGit(invocation, options);
    };
    const result = await readGitHubRemote(fixture.root, runner);
    expect(result.isResolved).toBe(false);
    expect(!result.isResolved && result.reason).toMatch(/readable regular files, then check again/);
  });

  it("is unaffected by an unrelated url.* setting", async () => {
    fixture = createGitFixture({ remotes: { origin: "https://github.com/octo/app.git" } });
    fixture.git("config", "url.https://github.com/.foo", "bar");
    expect((await readGitHubRemote(fixture.root)).isResolved).toBe(true);
  });

  it("rejects repositories without remotes", async () => {
    fixture = createGitFixture();
    expect((await readGitHubRemote(fixture.root)).isResolved).toBe(false);
  });
});

describe("history helpers", () => {
  let fixture: GitFixture | null = null;
  afterEach(() => {
    fixture?.cleanup();
    fixture = null;
  });

  it("reads HEAD and lists commit candidates newest first", async () => {
    fixture = createGitFixture();
    const first = fixture.commit({ authorName: "A", authorEmail: "a@example.com" });
    const second = fixture.commit({ authorName: "B", authorEmail: "b@example.com" });
    expect(await readHeadRevision(fixture.root)).toBe(second);
    const candidates = await listCommitCandidates(fixture.root);
    expect(candidates.map((candidate) => candidate.sha)).toEqual([second, first]);
    expect(candidates[0]).toMatchObject({ authorName: "B", authorEmail: "b@example.com" });
  });

  it("lists only HEAD's ancestry, not other branches or an orphan history", async () => {
    fixture = createGitFixture();
    const onMain = fixture.commit({ authorName: "A", authorEmail: "a@example.com" });
    fixture.git("checkout", "-q", "--orphan", "unrelated");
    const orphan = fixture.commit({ authorName: "B", authorEmail: "b@example.com" });
    const candidates = await listCommitCandidates(fixture.root);
    expect(candidates.map((candidate) => candidate.sha)).toEqual([orphan]);
    expect(candidates.map((candidate) => candidate.sha)).not.toContain(onMain);
  });

  it("returns null HEAD for an empty repository", async () => {
    fixture = createGitFixture();
    expect(await readHeadRevision(fixture.root)).toBeNull();
  });

  it("finds the Git root from a subdirectory", async () => {
    fixture = createGitFixture();
    fixture.commit({});
    const nested = path.join(fixture.root, "a", "b");
    mkdirSync(nested, { recursive: true });
    expect(await findGitRoot(nested)).toBe(fixture.root);
  });
});
