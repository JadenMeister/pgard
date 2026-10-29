import { copyFileSync, symlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { GitCommandError, runGit, type GitRunner } from "./run-git.js";
import { readStagedChanges } from "./staged.js";
import { addedLineNumbers, scanStagedSecrets } from "./staged-secrets.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";

// Assembled at run time so this file holds no literal token.
const GITHUB_TOKEN = `ghp_${"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"}`;
const AWS_KEY = `AKIA${"IOSFODNN7EXAMPLQ"}`;

describe("readStagedChanges", () => {
  const fixtures: GitFixture[] = [];
  afterEach(() => {
    for (const fixture of fixtures.splice(0)) fixture.cleanup();
  });
  const repo = (files: Record<string, string> = { "README.md": "hello\n" }) => {
    const fixture = createGitFixture();
    fixtures.push(fixture);
    fixture.commit({ files });
    return fixture;
  };
  const stage = (fixture: GitFixture, ...paths: string[]) => fixture.git("add", "--", ...paths);

  it("reads the staged content, not the working tree", async () => {
    const fixture = repo({ "a.txt": "one\n" });
    fixture.writeFile("a.txt", `staged ${GITHUB_TOKEN}\n`);
    stage(fixture, "a.txt");
    // After staging, the working tree is changed again and must not matter.
    fixture.writeFile("a.txt", "clean working tree\n");
    const changes = await readStagedChanges(fixture.root);
    expect(changes.files.map((file) => file.path)).toEqual(["a.txt"]);
    expect(changes.files[0]?.content).toContain(GITHUB_TOKEN);
    expect(changes.files[0]?.previous).toBe("one\n");
    expect(changes.files[0]?.kind).toBe("modified");
  });

  it("ignores unstaged edits and untracked files", async () => {
    const fixture = repo({ "a.txt": "one\n" });
    fixture.writeFile("a.txt", `unstaged ${GITHUB_TOKEN}\n`);
    fixture.writeFile("new.txt", `untracked ${GITHUB_TOKEN}\n`);
    const changes = await readStagedChanges(fixture.root);
    expect(changes.files).toEqual([]);
    expect(changes.skipped).toEqual([]);
  });

  it("handles the first commit (no HEAD yet)", async () => {
    const fixture = createGitFixture();
    fixtures.push(fixture);
    fixture.writeFile("first.txt", "first\n");
    stage(fixture, "first.txt");
    const changes = await readStagedChanges(fixture.root);
    expect(changes.files.map((file) => [file.path, file.kind, file.previous])).toEqual([
      ["first.txt", "added", null],
    ]);
  });

  it("treats a rename as a new path with the old text, and a delete as nothing to scan", async () => {
    const fixture = repo({
      "old.txt": "same content\n",
      "gone.txt": "bye\n",
      "keep.txt": "keep\n",
    });
    fixture.git("mv", "old.txt", "new.txt");
    fixture.git("rm", "-q", "gone.txt");
    const changes = await readStagedChanges(fixture.root);
    expect(changes.files.map((file) => [file.path, file.kind, file.previous])).toEqual([
      ["new.txt", "renamed", "same content\n"],
    ]);
    expect(changes.deleted).toBe(2);
    expect(changes.unchanged).toBe(1);
  });

  it("skips binary files by design, and reads UTF-16 text", async () => {
    const fixture = repo();
    writeFileSync(path.join(fixture.root, "image.bin"), Buffer.from([0x89, 0x50, 0, 1, 2, 0, 3]));
    writeFileSync(
      path.join(fixture.root, "wide.txt"),
      Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`k = ${GITHUB_TOKEN}\n`, "utf16le")]),
    );
    stage(fixture, "image.bin", "wide.txt");
    const changes = await readStagedChanges(fixture.root);
    expect(changes.skipped).toEqual([{ path: "image.bin", reason: "binary" }]);
    expect(changes.files[0]?.content).toContain(GITHUB_TOKEN);
  });

  it("lists files over the size limit, the file limit and the byte budget as not scanned", async () => {
    const fixture = repo();
    fixture.writeFile("big.txt", "x".repeat(2000));
    fixture.writeFile("a.txt", "a\n");
    fixture.writeFile("b.txt", "b\n");
    fixture.writeFile("c.txt", "c\n");
    stage(fixture, "big.txt", "a.txt", "b.txt", "c.txt");
    const sized = await readStagedChanges(fixture.root, { maxFileBytes: 1000 });
    expect(sized.skipped).toEqual([{ path: "big.txt", reason: "too_large" }]);
    expect(sized.files.map((file) => file.path)).toEqual(["a.txt", "b.txt", "c.txt"]);
    const limited = await readStagedChanges(fixture.root, { maxFiles: 2 });
    expect(limited.files.map((file) => file.path)).toEqual(["a.txt", "b.txt"]);
    expect(limited.skipped.map((item) => item.path)).toEqual(["big.txt", "c.txt"]);
    expect(limited.skipped.map((item) => item.reason)).toEqual(["file_limit", "file_limit"]);
    const budget = await readStagedChanges(fixture.root, { maxTotalBytes: 100 });
    expect(budget.skipped).toEqual([{ path: "big.txt", reason: "byte_budget" }]);
  });

  it("stops reading when the time budget is gone and says which files were left", async () => {
    const fixture = repo();
    fixture.writeFile("a.txt", "a\n");
    stage(fixture, "a.txt");
    // The clock jumps past the deadline once the sizes are known, before any content is read.
    let clock = 0;
    const runner: GitRunner = async (invocation, options) => {
      const output = await runGit(invocation, options);
      if (invocation.flags?.includes("--batch-check") === true) clock = 5000;
      return output;
    };
    const changes = await readStagedChanges(fixture.root, {
      deadline: 1000,
      now: () => clock,
      runner,
    });
    expect(changes.files).toEqual([]);
    expect(changes.skipped).toEqual([{ path: "a.txt", reason: "time_budget" }]);
  });

  it("lists symbolic links and does not read their target", async () => {
    const fixture = repo();
    symlinkSync("/etc/passwd", path.join(fixture.root, "link"));
    stage(fixture, "link");
    const changes = await readStagedChanges(fixture.root);
    expect(changes.skipped).toEqual([{ path: "link", reason: "symlink" }]);
    expect(changes.files).toEqual([]);
  });

  it("reports unresolved merge entries as not scanned", async () => {
    const fixture = repo({ "f.txt": "base\n" });
    fixture.git("checkout", "-q", "-b", "side");
    fixture.writeFile("f.txt", "side\n");
    fixture.git("-c", "user.name=a", "-c", "user.email=a@b.c", "commit", "-qam", "side");
    fixture.git("checkout", "-q", "main");
    fixture.writeFile("f.txt", "main\n");
    fixture.git("-c", "user.name=a", "-c", "user.email=a@b.c", "commit", "-qam", "main");
    try {
      fixture.git("-c", "user.name=a", "-c", "user.email=a@b.c", "merge", "side");
    } catch {
      // The conflict is the point.
    }
    const changes = await readStagedChanges(fixture.root);
    expect(changes.skipped.some((item) => item.reason === "unmerged")).toBe(true);
  });

  it("reads another index when one is given (git commit -a and git commit <path>)", async () => {
    const fixture = repo({ "a.txt": "one\n" });
    fixture.writeFile("a.txt", "two\n");
    stage(fixture, "a.txt");
    // A copy of the index, then a different staged state in the real one.
    const copy = path.join(fixture.root, ".git", "next-index-1.lock");
    copyFileSync(path.join(fixture.root, ".git", "index"), copy);
    fixture.writeFile("a.txt", "three\n");
    stage(fixture, "a.txt");
    const real = await readStagedChanges(fixture.root);
    const other = await readStagedChanges(fixture.root, { indexFile: copy });
    expect(real.files[0]?.content).toBe("three\n");
    expect(other.files[0]?.content).toBe("two\n");
  });

  it("handles paths with spaces and non-ASCII names", async () => {
    const fixture = repo();
    fixture.writeFile("dir with space/파일.txt", "x\n");
    stage(fixture, "dir with space/파일.txt");
    const changes = await readStagedChanges(fixture.root);
    expect(changes.files.map((file) => file.path)).toEqual(["dir with space/파일.txt"]);
  });

  it("fails (rather than reporting nothing) when git cannot list the index", async () => {
    const missing = path.join(createGitFixture().root, "does-not-exist");
    await expect(readStagedChanges(missing)).rejects.toBeInstanceOf(GitCommandError);
  });
});

describe("runGit indexFile", () => {
  it("is accepted for ls-files only, as an absolute path", async () => {
    const fixture = createGitFixture();
    try {
      fixture.commit({});
      await expect(
        runGit(
          { subcommand: "rev-parse", flags: ["--show-toplevel"] },
          { cwd: fixture.root, indexFile: "/x" },
        ),
      ).rejects.toThrow("git index file is not allowed");
      await expect(
        runGit(
          { subcommand: "ls-files", flags: ["-s"] },
          { cwd: fixture.root, indexFile: "relative/index" },
        ),
      ).rejects.toThrow("git index file is not allowed");
      await expect(
        runGit(
          { subcommand: "ls-files", flags: ["-s"] },
          { cwd: fixture.root, indexFile: "/x\0y" },
        ),
      ).rejects.toThrow("git index file is not allowed");
    } finally {
      fixture.cleanup();
    }
  });

  it("does not let GIT_INDEX_FILE of the caller's environment through", async () => {
    const fixture = createGitFixture();
    const previous = process.env.GIT_INDEX_FILE;
    try {
      fixture.commit({ files: { "a.txt": "a\n" } });
      process.env.GIT_INDEX_FILE = path.join(fixture.root, "elsewhere-index");
      const listed = await runGit({ subcommand: "ls-files", flags: ["-s"] }, { cwd: fixture.root });
      expect(listed).toContain("a.txt");
    } finally {
      if (previous === undefined) delete process.env.GIT_INDEX_FILE;
      else process.env.GIT_INDEX_FILE = previous;
      fixture.cleanup();
    }
  });
});

describe("staged secrets", () => {
  it("counts a line as new only when the older text lacks it", () => {
    expect([...addedLineNumbers("a\nb\n", "a\nc\nb\n")]).toEqual([2]);
    expect([...addedLineNumbers("a\na\n", "a\na\na\n")]).toEqual([3]);
    expect([...addedLineNumbers(null, "x\ny")]).toEqual([1, 2]);
    expect([...addedLineNumbers("same  \n", "same\n")]).toEqual([]);
  });

  const file = (
    filePath: string,
    content: string,
    previous: string | null = null,
    kind: "added" | "modified" | "renamed" = "added",
  ) => ({ path: filePath, content, previous, kind });

  it("reports a secret on an added line, and not one the commit leaves alone", () => {
    const old = `const key = "${AWS_KEY}";\n`;
    const next = `${old}const other = 1;\nconst token = "${GITHUB_TOKEN}";\n`;
    const result = scanStagedSecrets([file("src/config.ts", next, old, "modified")]);
    expect(result.findings.map((item) => [item.ruleId, item.location.line])).toEqual([
      ["PG-SECRET-002", 3],
    ]);
    expect(result.preexisting).toBe(1);
    expect(JSON.stringify(result.findings)).not.toContain(GITHUB_TOKEN);
    expect(result.findings[0]?.sources).toEqual(["code"]);
  });

  it("flags a new .env file but not a modified or example one", () => {
    expect(scanStagedSecrets([file(".env", "A=1\n")]).findings.map((f) => f.ruleId)).toEqual([
      "PG-SECRET-001",
    ]);
    expect(
      scanStagedSecrets([file("config/prod.env", "A=1\n", "A=0\n", "modified")]).findings,
    ).toEqual([]);
    expect(scanStagedSecrets([file(".env.example", "A=\n")]).findings).toEqual([]);
  });

  it("does not repeat the secrets of a pure rename", () => {
    const text = `token = "${GITHUB_TOKEN}"\n`;
    expect(scanStagedSecrets([file("b.cfg", text, text, "renamed")]).findings).toEqual([]);
  });
});
