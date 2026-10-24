import { execFileSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { GitCommandError, runGit, type GitRunner } from "./run-git.js";
import { decodeGitPath, scanGitHistory } from "./scan-history.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";

const join = (...parts: string[]) => parts.join("");
const TOKEN_A = join("ghp", "_", "AaBbCcDdEeFfGgHhIiJj", "KkLlMmNnOoPpQqRr");
const pem = (body: string) =>
  join("-----BEGIN ", "RSA PRIVATE KEY-----\n", body, "\n-----END ", "RSA PRIVATE KEY-----\n");
const KEY_ONE = pem(join("MIIEowIBAAKCAQEA", "oneoneone1111", "QQQQ"));
const KEY_TWO = pem(join("MIIEowIBAAKCAQEA", "twotwotwo2222", "WWWW"));
const KEY_FIXTURE = pem(join("MIIEowIBAAKCAQEA", "fixturefix333", "EEEE"));

const cleanups: (() => void)[] = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup();
});
function fixture(): GitFixture {
  const created = createGitFixture();
  cleanups.push(created.cleanup);
  return created;
}
function tempDir(): string {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-shallow-")));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}
const git = (cwd: string, args: string[], input?: Buffer) =>
  execFileSync("git", args, {
    cwd,
    ...(input ? { input } : {}),
    env: { PATH: process.env.PATH ?? "", HOME: cwd, GIT_CONFIG_NOSYSTEM: "1" },
  });

describe("shallow clones (#77)", () => {
  it("marks history partial and words boundary findings as 'present in'", async () => {
    const source = fixture();
    source.commit({ files: { "a.txt": "a" } });
    source.commit({ files: { "deploy.sh": `export GH="${TOKEN_A}"\n` } });
    source.commit({ remove: ["deploy.sh"], files: { "a.txt": "b" } });
    const target = path.join(tempDir(), "clone");
    git(source.root, ["clone", "-q", "--depth", "2", `file://${source.root}`, target]);

    const result = await scanGitHistory(target);
    const commits = result.coverage.find((entry) => entry.area === "history:commits");
    expect(commits?.status).toBe("partial");
    expect(commits?.note).toMatch(/shallow clone/);
    const removed = result.findings.find((finding) => finding.ruleId === "PG-SECRET-003");
    expect(removed?.evidence).toMatch(/present in commit/);
    expect(removed?.evidence).not.toMatch(/added in/);
  });
});

describe("private keys (#78)", () => {
  it("does not let a tracked key hide a different removed key", async () => {
    const repo = fixture();
    repo.commit({ files: { "prod.pem": KEY_ONE, "fixture.pem": KEY_FIXTURE } });
    repo.commit({ remove: ["prod.pem"] });
    const result = await scanGitHistory(repo.root);
    expect(
      result.findings.filter((f) => f.ruleId === "PG-SECRET-003").map((f) => f.location.path),
    ).toEqual(["prod.pem"]);
    expect(JSON.stringify(result)).not.toContain("oneoneone");
  });

  it("reports two distinct removed keys separately", async () => {
    const repo = fixture();
    repo.commit({ files: { "a.pem": KEY_ONE, "b.pem": KEY_TWO, "README.md": "x" } });
    repo.commit({ remove: ["a.pem", "b.pem"] });
    const result = await scanGitHistory(repo.root);
    expect(result.findings.filter((f) => f.ruleId === "PG-SECRET-003")).toHaveLength(2);
  });
});

describe("cost and cancellation (#79)", () => {
  it("lists all commits' changes with one diff-tree process per batch", async () => {
    const repo = fixture();
    for (let index = 0; index < 30; index += 1) repo.commit({ files: { "n.txt": `${index}` } });
    const calls: string[] = [];
    const counting: GitRunner = (invocation, options) => {
      calls.push(invocation.subcommand);
      return runGit(invocation, options);
    };
    await scanGitHistory(repo.root, { runner: counting });
    expect(calls.filter((name) => name === "diff-tree")).toHaveLength(1);
  });

  it("stops at the time budget and reports partial coverage", async () => {
    const repo = fixture();
    repo.commit({ files: { "n.txt": "1" } });
    let clock = 0;
    const result = await scanGitHistory(repo.root, {
      timeBudgetMs: 10,
      now: () => {
        clock += 100;
        return clock;
      },
    });
    const commits = result.coverage.find((entry) => entry.area === "history:commits");
    expect(commits?.status).toBe("partial");
    expect(commits?.note).toMatch(/time budget/);
  });

  it("rejects promptly when aborted", async () => {
    const repo = fixture();
    repo.commit({ files: { "n.txt": "1" } });
    const controller = new AbortController();
    controller.abort();
    await expect(scanGitHistory(repo.root, { signal: controller.signal })).rejects.toBeDefined();
  });
});

describe("oversized git output (#80)", () => {
  it("degrades to partial instead of failing the whole area", async () => {
    const repo = fixture();
    repo.commit({ files: { "a.txt": "x" } });
    const limited: GitRunner = (invocation, options) =>
      invocation.subcommand === "ls-tree" || invocation.subcommand === "diff-tree"
        ? Promise.reject(new GitCommandError("too big", null, "output_limit"))
        : runGit(invocation, options);
    const result = await scanGitHistory(repo.root, { runner: limited });
    const coverage = Object.fromEntries(result.coverage.map((entry) => [entry.area, entry]));
    expect(coverage["history:tracked-files"]?.status).toBe("partial");
    expect(coverage["history:tracked-files"]?.note).toMatch(/too large/);
    expect(coverage["history:commits"]?.status).toBe("partial");
    expect(coverage["history:commits"]?.note).toMatch(/too large/);
  });
});

describe("paths, revisions and edge cases (#81)", () => {
  it("decodes non-UTF-8 paths exactly", () => {
    expect(decodeGitPath(Buffer.from("lat\xe9.txt", "latin1").toString("latin1"))).toBe(
      "lat\\xe9.txt",
    );
    expect(decodeGitPath(Buffer.from("한글.txt", "utf8").toString("latin1"))).toBe("한글.txt");
  });

  it("reports a non-UTF-8 tracked path with escapes", async () => {
    const repo = fixture();
    repo.commit({ files: { "README.md": "x" } });
    const blob = git(repo.root, ["hash-object", "-w", "--stdin"], Buffer.from(`t = "${TOKEN_A}"\n`))
      .toString()
      .trim();
    const tree = git(
      repo.root,
      ["mktree"],
      Buffer.concat([
        Buffer.from(`100644 blob ${blob}\t`),
        Buffer.from("lat\xe9.env", "latin1"),
        Buffer.from("\n"),
      ]),
    )
      .toString()
      .trim();
    const commit = git(repo.root, [
      "-c",
      "user.name=a",
      "-c",
      "user.email=a@example.com",
      "commit-tree",
      tree,
      "-m",
      "x",
    ])
      .toString()
      .trim();
    git(repo.root, ["update-ref", "HEAD", commit]);
    const result = await scanGitHistory(repo.root);
    expect(result.findings.map((finding) => finding.location.path)).toContain("lat\\xe9.env");
  });

  it("scans the authorized revision, not a later HEAD", async () => {
    const repo = fixture();
    const authorized = repo.commit({ files: { "a.ts": "safe" } });
    repo.commit({ files: { "a.ts": `const t = "${TOKEN_A}";` } });
    const result = await scanGitHistory(repo.root, { revision: authorized });
    expect(result.findings).toEqual([]);
    expect(result.coverage[0]?.note).toContain(authorized.slice(0, 12));
  });

  it("returns not_tested for a repository without commits", async () => {
    const repo = fixture();
    const result = await scanGitHistory(repo.root);
    expect(result.findings).toEqual([]);
    expect(result.coverage.every((entry) => entry.status === "not_tested")).toBe(true);
  });

  it("counts skipped binary files in the notes", async () => {
    const repo = fixture();
    repo.commit({ files: { "img.bin": "\u0000\u0001\u0002", "a.txt": "x" } });
    const result = await scanGitHistory(repo.root);
    expect(result.coverage[0]?.note).toMatch(/1 binary file\(s\) not scanned/);
  });
});

describe("merged side branches (#101)", () => {
  it("finds a secret added and removed on a --no-ff merged branch", async () => {
    const repo = fixture();
    repo.commit({ files: { "a.txt": "base" } });
    repo.git("checkout", "-q", "-b", "side");
    const added = repo.commit({ files: { "deploy.sh": `export GH="${TOKEN_A}"\n` } });
    repo.commit({ remove: ["deploy.sh"], files: { "b.txt": "side" } });
    repo.git("checkout", "-q", "main");
    repo.commit({ files: { "a.txt": "main" } });
    repo.git(
      "-c",
      "user.name=a",
      "-c",
      "user.email=a@example.com",
      "merge",
      "-q",
      "--no-ff",
      "side",
      "-m",
      "merge",
    );
    const result = await scanGitHistory(repo.root);
    expect(result.findings).toEqual([
      expect.objectContaining({
        ruleId: "PG-SECRET-003",
        location: expect.objectContaining({ path: "deploy.sh", commit: added }),
      }),
    ]);
  });
});

describe("incomplete current file list (#102)", () => {
  it("does not report secrets still at the revision as removed", async () => {
    const repo = fixture();
    repo.commit({ files: { "current.ts": `const t = "${TOKEN_A}";\n`, "old.pem": KEY_ONE } });
    repo.commit({ remove: ["old.pem"], files: { "README.md": "x" } });
    const noTree: GitRunner = (invocation, options) =>
      invocation.subcommand === "ls-tree"
        ? Promise.reject(new GitCommandError("too big", null, "output_limit"))
        : runGit(invocation, options);
    const result = await scanGitHistory(repo.root, { runner: noTree });
    const byPath = Object.fromEntries(
      result.findings.map((finding) => [finding.location.path, finding.ruleId]),
    );
    expect(byPath).toEqual({ "current.ts": "PG-SECRET-002", "old.pem": "PG-SECRET-003" });
    expect(result.coverage.find((entry) => entry.area === "history:tracked-files")?.status).toBe(
      "partial",
    );
  });
});

describe("current-file lookups on the overflow path (#107)", () => {
  const noTree =
    (inner: GitRunner): GitRunner =>
    (invocation, options) =>
      invocation.subcommand === "ls-tree"
        ? Promise.reject(new GitCommandError("too big", null, "output_limit"))
        : inner(invocation, options);

  function repoWithManyFiles() {
    const repo = fixture();
    const files: Record<string, string> = {};
    for (let index = 0; index < 60; index += 1) files[`f${index}.txt`] = `${index}`;
    repo.commit({ files: { ...files, "deploy.sh": `export GH="${TOKEN_A}"\n` } });
    repo.commit({ remove: ["deploy.sh"] });
    return repo;
  }

  it("looks up only paths that produced history findings", async () => {
    const repo = repoWithManyFiles();
    const lookups: string[] = [];
    const spy: GitRunner = (invocation, options) => {
      if (invocation.subcommand === "cat-file" && options.input?.includes(":")) {
        lookups.push(...options.input.trim().split("\n"));
      }
      return runGit(invocation, options);
    };
    const result = await scanGitHistory(repo.root, { runner: noTree(spy) });
    expect(lookups.map((line) => line.split(":")[1])).toEqual(["deploy.sh"]);
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(["PG-SECRET-003"]);
  });

  it("degrades to neutral wording and partial coverage when the lookup fails", async () => {
    const repo = repoWithManyFiles();
    const failing: GitRunner = (invocation, options) =>
      invocation.subcommand === "cat-file" && options.input?.includes(":")
        ? Promise.reject(new GitCommandError("slow", null, "timeout"))
        : runGit(invocation, options);
    const result = await scanGitHistory(repo.root, { runner: noTree(failing) });
    expect(result.findings[0]?.evidence).toMatch(/could not be checked/);
    const commits = result.coverage.find((entry) => entry.area === "history:commits");
    expect(commits?.status).toBe("partial");
  });

  it("skips the lookup once the time budget is used", async () => {
    const repo = repoWithManyFiles();
    let lookedUp = false;
    const spy: GitRunner = (invocation, options) => {
      if (invocation.subcommand === "cat-file" && options.input?.includes(":")) lookedUp = true;
      return runGit(invocation, options);
    };
    let clock = 0;
    const result = await scanGitHistory(repo.root, {
      runner: noTree(spy),
      timeBudgetMs: 1_000_000,
      now: () => {
        clock += 600_000;
        return clock;
      },
    });
    expect(lookedUp).toBe(false);
    expect(result.coverage.find((entry) => entry.area === "history:commits")?.status).toBe(
      "partial",
    );
  });
});

describe("oversized commits and unknown revisions (#103)", () => {
  it("retries a too-large batch commit by commit and skips only the oversized one", async () => {
    const repo = fixture();
    const huge = repo.commit({ files: { "big.txt": "x" } });
    repo.commit({ files: { "deploy.sh": `export GH="${TOKEN_A}"\n` } });
    repo.commit({ remove: ["deploy.sh"] });
    const limited: GitRunner = (invocation, options) =>
      invocation.subcommand === "diff-tree" && options.input?.includes(huge)
        ? Promise.reject(new GitCommandError("too big", null, "output_limit"))
        : runGit(invocation, options);
    const result = await scanGitHistory(repo.root, { runner: limited });
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(["PG-SECRET-003"]);
    const commits = result.coverage.find((entry) => entry.area === "history:commits");
    expect(commits?.status).toBe("partial");
    expect(commits?.note).toMatch(/changes of 1 commit\(s\) were too large/);
  });

  it("explains an unknown revision", async () => {
    const repo = fixture();
    repo.commit({});
    const result = await scanGitHistory(repo.root, { revision: "f".repeat(40) });
    expect(result.coverage[0]).toMatchObject({ status: "not_tested" });
    expect(result.coverage[0]?.note).toMatch(/was not found/);
  });
});

describe("overflow-path classification (#108)", () => {
  const noTree =
    (inner: GitRunner): GitRunner =>
    (invocation, options) =>
      invocation.subcommand === "ls-tree"
        ? Promise.reject(new GitCommandError("too big", null, "output_limit"))
        : inner(invocation, options);
  const isLookup = (invocation: { subcommand: string }, input: string | undefined) =>
    invocation.subcommand === "cat-file" && (input?.includes(":") ?? false);

  it("does not call a .env removed when the lookup fails", async () => {
    const repo = fixture();
    repo.commit({ files: { ".env": "A=1\n", "a.txt": "x" } });
    const failing: GitRunner = (invocation, options) =>
      isLookup(invocation, options.input)
        ? Promise.reject(new GitCommandError("slow", null, "timeout"))
        : runGit(invocation, options);
    const result = await scanGitHistory(repo.root, { runner: noTree(failing) });
    const env = result.findings.find((finding) => finding.location.path === ".env");
    expect(env?.evidence).toMatch(/could not be checked/);
    expect(env?.evidence).not.toMatch(/later removed/);
    const commits = result.coverage.find((entry) => entry.area === "history:commits");
    expect(commits?.status).toBe("partial");
    expect(commits?.note).toMatch(/1 environment file\(s\) it could not be checked/);
  });

  it("does not call a .env removed when the time budget skips the lookup", async () => {
    const repo = fixture();
    repo.commit({ files: { ".env": "A=1\n", "a.txt": "x" } });
    let clock = 0;
    const result = await scanGitHistory(repo.root, {
      runner: noTree(runGit),
      timeBudgetMs: 1_000_000,
      now: () => {
        clock += 600_000;
        return clock;
      },
    });
    const env = result.findings.find((finding) => finding.location.path === ".env");
    expect(env?.evidence).not.toMatch(/later removed/);
    expect(result.coverage.find((entry) => entry.area === "history:commits")?.note).toMatch(
      /environment file\(s\) it could not be checked/,
    );
  });

  it("still calls a .env removed when the lookup answers missing", async () => {
    const repo = fixture();
    repo.commit({ files: { ".env": "A=1\n", "a.txt": "x" } });
    repo.commit({ remove: [".env"] });
    const result = await scanGitHistory(repo.root, { runner: noTree(runGit) });
    const env = result.findings.find((finding) => finding.location.path === ".env");
    expect(env?.evidence).toMatch(/later removed/);
    expect(result.coverage.find((entry) => entry.area === "history:commits")?.note).not.toMatch(
      /environment file\(s\) it could not be checked/,
    );
  });
});
