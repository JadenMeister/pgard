import { execFileSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { GitCommandError, runGit, type GitRunner } from "./run-git.js";
import {
  decodeGitPath,
  formatByteLimit,
  MIN_SEARCH_LENGTH,
  scanGitHistory,
  searchStringFor,
} from "./scan-history.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";
import { TIME_FACTOR } from "../../../tests/support/timing.js";

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

  it("reports a secret moved to another file as current, not removed", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({ remove: ["old.sh"], files: { "scripts/new.sh": `\nexport GH="${TOKEN_A}"\n` } });
    const result = await scanGitHistory(repo.root, { runner: noTree(runGit) });
    expect(result.findings).toEqual([
      expect.objectContaining({
        ruleId: "PG-SECRET-002",
        location: expect.objectContaining({ path: "scripts/new.sh", line: 2, commit: null }),
      }),
    ]);
  });

  it("does not claim removal when a looked-up current file could not be read", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({ remove: ["old.sh"], files: { "new.sh": `export GH="${TOKEN_A}"\n` } });
    repo.commit({ files: { "new.sh": `export GH="${TOKEN_A}"\n${"#".repeat(500)}\n` } });
    const result = await scanGitHistory(repo.root, { runner: noTree(runGit), maxBlobBytes: 200 });
    const secret = result.findings.find((finding) => finding.ruleId === "PG-SECRET-003");
    expect(secret?.evidence).toMatch(/could not be checked/);
    expect(secret?.evidence).not.toMatch(/no longer present/);
  });
});

describe("overflow-path unqueryable current paths (#108 review)", () => {
  const noTree =
    (inner: GitRunner): GitRunner =>
    (invocation, options) =>
      invocation.subcommand === "ls-tree"
        ? Promise.reject(new GitCommandError("too big", null, "output_limit"))
        : inner(invocation, options);
  const expectUnknown = (result: Awaited<ReturnType<typeof scanGitHistory>>) => {
    const secret = result.findings.find((finding) => finding.ruleId === "PG-SECRET-003");
    expect(secret?.evidence).toMatch(/could not be checked/);
    expect(secret?.evidence).not.toMatch(/no longer present/);
    const commits = result.coverage.find((entry) => entry.area === "history:commits");
    expect(commits?.status).toBe("partial");
    expect(commits?.note).toMatch(/could not be checked whether the value is still/);
  };

  // A newline cannot be part of a Windows file name.
  it.skipIf(process.platform === "win32")(
    "does not claim removal when the secret moved to a path with a newline",
    async () => {
      const repo = fixture();
      repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
      repo.commit({ remove: ["old.sh"], files: { "a\nb.sh": `export GH="${TOKEN_A}"\n` } });
      expectUnknown(await scanGitHistory(repo.root, { runner: noTree(runGit) }));
    },
  );

  it("does not claim removal when the secret moved to a non-UTF-8 path", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    git(repo.root, ["rm", "-q", "old.sh"]);
    const blob = git(repo.root, ["hash-object", "-w", "--stdin"], Buffer.from(`GH="${TOKEN_A}"\n`))
      .toString()
      .trim();
    git(
      repo.root,
      ["update-index", "--add", "-z", "--index-info"],
      Buffer.concat([
        Buffer.from(`100644 ${blob}\t`),
        Buffer.from("n\xff.sh", "latin1"),
        Buffer.from([0]),
      ]),
    );
    git(repo.root, ["-c", "user.name=a", "-c", "user.email=a@example.com", "commit", "-qm", "mv"]);
    expectUnknown(await scanGitHistory(repo.root, { runner: noTree(runGit) }));
  });

  it("does not claim removal when the current copy predates the commit window", async () => {
    const repo = fixture();
    repo.commit({ files: { "keep.sh": `export GH="${TOKEN_A}"\n` } });
    repo.commit({ files: { "a.txt": "x" } });
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n` } });
    repo.commit({ remove: ["old.sh"] });
    const result = await scanGitHistory(repo.root, { runner: noTree(runGit), maxCommits: 2 });
    const secret = result.findings.find((finding) => finding.ruleId === "PG-SECRET-003");
    expect(secret?.location.path).toBe("old.sh");
    expect(secret?.evidence).toMatch(/could not be checked/);
    expect(secret?.evidence).not.toMatch(/no longer present/);
  });

  it("still claims removal on the overflow path when history is complete", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({ remove: ["old.sh"] });
    const result = await scanGitHistory(repo.root, { runner: noTree(runGit) });
    const secret = result.findings.find((finding) => finding.ruleId === "PG-SECRET-003");
    expect(secret?.evidence).toMatch(/no longer present/);
  });
});

describe("unread current files (#132)", () => {
  it("does not claim removal when the secret moved into a file over maxBlobBytes", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({
      remove: ["old.sh"],
      files: { "big.sh": `export GH="${TOKEN_A}"\n${"#".repeat(500)}\n` },
    });
    const result = await scanGitHistory(repo.root, { maxBlobBytes: 200 });
    const secret = result.findings.find((finding) => finding.ruleId === "PG-SECRET-003");
    expect(secret?.location.path).toBe("old.sh");
    expect(secret?.evidence).toMatch(/could not be checked/);
    expect(secret?.evidence).not.toMatch(/no longer present/);
    const commits = result.coverage.find((entry) => entry.area === "history:commits");
    expect(commits?.status).toBe("partial");
    expect(commits?.note).toMatch(/could not be checked whether the value is still/);
    expect(JSON.stringify(result)).not.toContain(TOKEN_A);
  });

  it("still claims removal when no current file was skipped", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({ remove: ["old.sh"], files: { "small.sh": "echo ok\n" } });
    const result = await scanGitHistory(repo.root, { maxBlobBytes: 200 });
    const secret = result.findings.find((finding) => finding.ruleId === "PG-SECRET-003");
    expect(secret?.evidence).toMatch(/no longer present/);
    const commits = result.coverage.find((entry) => entry.area === "history:commits");
    expect(commits?.status).toBe("completed");
    expect(JSON.stringify(result)).not.toContain(TOKEN_A);
  });

  it("still reports a value found in a read current file as current", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({
      remove: ["old.sh"],
      files: { "new.sh": `export GH="${TOKEN_A}"\n`, "big.txt": `${"#".repeat(500)}\n` },
    });
    const result = await scanGitHistory(repo.root, { maxBlobBytes: 200 });
    expect(result.findings).toEqual([
      expect.objectContaining({
        ruleId: "PG-SECRET-002",
        location: expect.objectContaining({ path: "new.sh", commit: null }),
      }),
    ]);
    expect(JSON.stringify(result)).not.toContain(TOKEN_A);
  });
});

describe("binary and skipped current files (#136)", () => {
  const recording = () => {
    const calls: { invocation: Parameters<GitRunner>[0]; input: string }[] = [];
    const runner: GitRunner = (invocation, options) => {
      calls.push({ invocation, input: options.input ?? "" });
      return runGit(invocation, options);
    };
    return { calls, runner };
  };
  const removedSecret = (result: Awaited<ReturnType<typeof scanGitHistory>>) =>
    result.findings.find((finding) => finding.ruleId === "PG-SECRET-003");
  const commitsArea = (result: Awaited<ReturnType<typeof scanGitHistory>>) =>
    result.coverage.find((entry) => entry.area === "history:commits");

  it("does not claim removal when the secret moved into a binary current file", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({ remove: ["old.sh"], files: { "bin.dat": `\u0000${TOKEN_A}\u0000` } });
    const { calls, runner } = recording();
    const result = await scanGitHistory(repo.root, { runner });
    expect(removedSecret(result)?.evidence).toMatch(/could not be checked/);
    expect(removedSecret(result)?.evidence).not.toMatch(/no longer present/);
    expect(commitsArea(result)?.status).toBe("partial");
    expect(JSON.stringify(result)).not.toContain(TOKEN_A);
    // The value is searched for on stdin only, never in argv.
    const grep = calls.filter((call) => call.invocation.subcommand === "grep");
    expect(grep).toHaveLength(1);
    expect(grep[0]?.input).toContain(TOKEN_A);
    for (const { invocation } of calls) {
      expect(JSON.stringify(invocation)).not.toContain(TOKEN_A);
    }
  });

  it("does not claim removal when a key moved into a binary current file", async () => {
    const repo = fixture();
    repo.commit({ files: { "prod.pem": KEY_ONE, "a.txt": "x" } });
    repo.commit({ remove: ["prod.pem"], files: { "keys.bin": `\u0000${KEY_ONE}` } });
    const result = await scanGitHistory(repo.root);
    expect(removedSecret(result)?.evidence).toMatch(/could not be checked/);
    expect(JSON.stringify(result)).not.toContain("oneoneone");
  });

  it("still claims removal when the binary current files do not hold the value", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({ remove: ["old.sh"], files: { "img.bin": "\u0000\u0001\u0002" } });
    const result = await scanGitHistory(repo.root);
    expect(removedSecret(result)?.evidence).toMatch(/no longer present/);
    expect(commitsArea(result)?.status).toBe("completed");
  });

  it("claims removal when the skipped large current files do not hold the value", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({ remove: ["old.sh"], files: { "big.txt": `${"#".repeat(500)}\n` } });
    const result = await scanGitHistory(repo.root, { maxBlobBytes: 200 });
    expect(removedSecret(result)?.evidence).toMatch(/no longer present/);
    expect(commitsArea(result)?.status).toBe("completed");
    // The skipped file is still reported as not scanned, with a limit that is not "0 KiB".
    const tracked = result.coverage.find((entry) => entry.area === "history:tracked-files");
    expect(tracked?.status).toBe("partial");
    expect(tracked?.note).toContain("1 file(s) over 200 bytes skipped");
  });

  it("formats size limits without rounding small ones to 0 KiB", () => {
    expect(formatByteLimit(200)).toBe("200 bytes");
    expect(formatByteLimit(1023)).toBe("1023 bytes");
    expect(formatByteLimit(1024)).toBe("1 KiB");
    expect(formatByteLimit(1536)).toBe("1.5 KiB");
    expect(formatByteLimit(1024 * 1024)).toBe("1024 KiB");
  });

  it("claims removal when files skipped after the read budget do not hold the value", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({ remove: ["old.sh"], files: { "z.txt": `${"#".repeat(300)}\n` } });
    const result = await scanGitHistory(repo.root, { maxTotalBytes: 120 });
    expect(removedSecret(result)?.evidence).toMatch(/no longer present/);
  });

  it("does not search the current files when nothing looks removed", async () => {
    const repo = fixture();
    repo.commit({ files: { "img.bin": "\u0000\u0001\u0002", "a.txt": "x" } });
    const { calls, runner } = recording();
    await scanGitHistory(repo.root, { runner });
    expect(calls.some((call) => call.invocation.subcommand === "grep")).toBe(false);
  });

  it("leaves the state unknown when the search fails", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({ remove: ["old.sh"], files: { "img.bin": "\u0000\u0001\u0002" } });
    const failing: GitRunner = (invocation, options) =>
      invocation.subcommand === "grep"
        ? Promise.reject(new GitCommandError("git command failed", 128))
        : runGit(invocation, options);
    const result = await scanGitHistory(repo.root, { runner: failing });
    expect(removedSecret(result)?.evidence).toMatch(/could not be checked/);
    expect(commitsArea(result)?.status).toBe("partial");
  });

  // Review of #144.
  const writeRaw = (root: string, file: string, bytes: Buffer) =>
    writeFileSync(path.join(root, file), bytes);
  const expectUnknown = (result: Awaited<ReturnType<typeof scanGitHistory>>) => {
    expect(removedSecret(result)?.evidence).toMatch(/could not be checked/);
    expect(removedSecret(result)?.evidence).not.toMatch(/no longer present/);
    expect(commitsArea(result)?.status).toBe("partial");
  };

  it("does not claim removal for a value with invalid UTF-8 bytes moved into a large file", async () => {
    const repo = fixture();
    const line = Buffer.from("password=Xq7\xe9Zr9pLm2Kw\n", "latin1");
    writeRaw(repo.root, "old.cfg", line);
    repo.commit({ files: { "a.txt": "x" } });
    writeRaw(repo.root, "big.cfg", Buffer.concat([line, Buffer.from(`${"#".repeat(500)}\n`)]));
    repo.commit({ remove: ["old.cfg"], files: {} });
    expectUnknown(await scanGitHistory(repo.root, { maxBlobBytes: 200 }));
  });

  it("does not claim removal on the overflow path when the value moved into a binary file", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({ remove: ["old.sh"], files: { "bin.dat": `\u0000${TOKEN_A}\u0000` } });
    const noTree: GitRunner = (invocation, options) =>
      invocation.subcommand === "ls-tree"
        ? Promise.reject(new GitCommandError("too big", null, "output_limit"))
        : runGit(invocation, options);
    expectUnknown(await scanGitHistory(repo.root, { runner: noTree }));
  });

  const utf16le = (text: string) =>
    Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]);
  const utf16be = (text: string) =>
    Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(text, "utf16le").swap16()]);

  it.each([
    ["UTF-16LE", utf16le],
    ["UTF-16BE", utf16be],
  ])("does not claim removal when the value moved into a %s file", async (_label, encode) => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    writeRaw(repo.root, "notes.txt", encode(`GH=${TOKEN_A}\r\n`));
    repo.commit({ remove: ["old.sh"], files: {} });
    expectUnknown(await scanGitHistory(repo.root));
  });

  it("does not claim removal when a skipped large file is UTF-16", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    writeRaw(repo.root, "big.txt", utf16le(`GH=${TOKEN_A}\r\n${"#".repeat(300)}`));
    repo.commit({ remove: ["old.sh"], files: {} });
    expectUnknown(await scanGitHistory(repo.root, { maxBlobBytes: 200 }));
  });

  it("still claims removal when a UTF-16 current file does not hold the value", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    writeRaw(repo.root, "notes.txt", utf16le("hello\r\n"));
    repo.commit({ remove: ["old.sh"], files: {} });
    const result = await scanGitHistory(repo.root);
    expect(removedSecret(result)?.evidence).toMatch(/no longer present/);
  });

  it("does not crash on an odd-length UTF-16BE file anywhere in history", async () => {
    const repo = fixture();
    writeRaw(repo.root, "odd.bin", Buffer.from([0xfe, 0xff, 0x00]));
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n` } });
    writeRaw(repo.root, "odd2.bin", Buffer.from([0xfe, 0xff, 0x00, 0x41, 0x00]));
    repo.commit({ remove: ["old.sh", "odd.bin"], files: {} });
    const result = await scanGitHistory(repo.root);
    expect(result.coverage.map((entry) => entry.status)).toEqual(["completed", "completed"]);
    expect(removedSecret(result)?.evidence).toMatch(/no longer present/);
  });

  it("does not claim removal when a key moved into a UTF-16LE CRLF file", async () => {
    const repo = fixture();
    repo.commit({ files: { "prod.pem": KEY_ONE, "a.txt": "x" } });
    writeRaw(repo.root, "keys.txt", utf16le(KEY_ONE.replace(/\n/g, "\r\n")));
    repo.commit({ remove: ["prod.pem"], files: {} });
    expectUnknown(await scanGitHistory(repo.root));
  });

  it("does not check more than 100 skipped files for a UTF-16 mark", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    const big = Object.fromEntries(
      Array.from({ length: 101 }, (_, index) => [
        `big/${index}.txt`,
        `${index}${"#".repeat(300)}\n`,
      ]),
    );
    repo.commit({ remove: ["old.sh"], files: big });
    let prefixReads = 0;
    const runner: GitRunner = (invocation, options) => {
      if (options.truncate) prefixReads += 1;
      return runGit(invocation, options);
    };
    expectUnknown(await scanGitHistory(repo.root, { runner, maxBlobBytes: 200 }));
    expect(prefixReads).toBe(0);
  });

  it("stops checking skipped files for a UTF-16 mark when the time budget runs out", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({
      remove: ["old.sh"],
      files: { "a.big": `${"#".repeat(300)}\n`, "b.big": `${"=".repeat(300)}\n` },
    });
    let clock = 0;
    let prefixReads = 0;
    const runner: GitRunner = async (invocation, options) => {
      if (options.truncate) {
        prefixReads += 1;
        clock = 10_000; // the first prefix read uses up the budget
      }
      return runGit(invocation, options);
    };
    const result = await scanGitHistory(repo.root, {
      runner,
      maxBlobBytes: 200,
      now: () => clock,
      timeBudgetMs: 5_000,
    });
    expect(prefixReads).toBe(1);
    expectUnknown(result);
  });

  it("does not search once the time budget is used up", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({ remove: ["old.sh"], files: { "img.bin": "\u0000\u0001\u0002" } });
    let clock = 0;
    const calls: string[] = [];
    const runner: GitRunner = async (invocation, options) => {
      calls.push(invocation.subcommand);
      const output = await runGit(invocation, options);
      if (invocation.subcommand === "diff-tree") clock = 10_000; // history listed in time
      return output;
    };
    const result = await scanGitHistory(repo.root, {
      runner,
      now: () => clock,
      timeBudgetMs: 5_000,
    });
    expect(calls).not.toContain("grep");
    expectUnknown(result);
  });

  it("stops the search when the remaining time budget runs out", async () => {
    const repo = fixture();
    repo.commit({ files: { "old.sh": `export GH="${TOKEN_A}"\n`, "a.txt": "x" } });
    repo.commit({ remove: ["old.sh"], files: { "img.bin": "\u0000\u0001\u0002" } });
    let grepSignal: AbortSignal | undefined;
    const runner: GitRunner = (invocation, options) => {
      if (invocation.subcommand !== "grep") return runGit(invocation, options);
      grepSignal = options.signal;
      // A search that never finishes on its own.
      return new Promise((_resolve, reject) =>
        options.signal?.addEventListener("abort", () =>
          reject(new GitCommandError("git command was cancelled", null, "cancelled")),
        ),
      );
    };
    const started = Date.now();
    const result = await scanGitHistory(repo.root, { runner, now: () => 0, timeBudgetMs: 300 });
    expect(Date.now() - started).toBeLessThan(5_000 * TIME_FACTOR);
    expect(grepSignal?.aborted).toBe(true);
    expectUnknown(result);
  });
});

describe("searchStringFor (#144)", () => {
  it("searches the value, or the longest line of a multi-line value", () => {
    expect(searchStringFor("Xq9vR2mT7pLw4")).toBe("Xq9vR2mT7pLw4");
    expect(searchStringFor("-----BEGIN X-----\n  MIIEowIBAAKCAQEAlongerline \n-----END-----")).toBe(
      "MIIEowIBAAKCAQEAlongerline",
    );
  });

  it("refuses values that cannot be searched reliably", () => {
    expect(searchStringFor("a".repeat(MIN_SEARCH_LENGTH - 1))).toBeNull();
    expect(searchStringFor("a".repeat(MIN_SEARCH_LENGTH))).toBe("a".repeat(MIN_SEARCH_LENGTH));
    expect(searchStringFor("short\nlines\nonly")).toBeNull();
    expect(searchStringFor("Xq7�Zr9pLm2Kw")).toBeNull();
    expect(searchStringFor("Xq7\u0000Zr9pLm2Kw")).toBeNull();
  });
});
