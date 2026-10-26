/**
 * Test-only helpers that build throwaway Git repositories in the OS temp directory.
 * Excluded from the package build.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

export interface FixtureCommit {
  files?: Record<string, string>;
  /** Paths to delete before committing. */
  remove?: string[];
  authorName?: string;
  authorEmail?: string;
  message?: string;
}

export interface GitFixture {
  root: string;
  shas: string[];
  git(...args: string[]): string;
  gitWithInput(input: string, ...args: string[]): string;
  commit(commit: FixtureCommit): string;
  writeFile(relativePath: string, content: string): void;
  cleanup(): void;
}

export function createGitFixture(options: { remotes?: Record<string, string> } = {}): GitFixture {
  // `.native` expands Windows 8.3 short names (RUNNER~1), matching what git reports.
  const root = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-fixture-")));
  const gitWithInput = (input: string | undefined, args: string[]) =>
    execFileSync("git", args, {
      cwd: root,
      encoding: "utf8",
      ...(input !== undefined ? { input } : {}),
      env: {
        PATH: process.env.PATH ?? "",
        HOME: root,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_TERMINAL_PROMPT: "0",
      },
    });
  const git = (...args: string[]) => gitWithInput(undefined, args);
  git("init", "-q", "-b", "main");
  git("config", "commit.gpgsign", "false");
  for (const [name, url] of Object.entries(options.remotes ?? {})) {
    git("remote", "add", name, url);
  }
  const shas: string[] = [];
  const writeFile = (relativePath: string, content: string) => {
    const target = path.join(root, relativePath);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  };
  const commit = (spec: FixtureCommit) => {
    for (const [file, content] of Object.entries(spec.files ?? { "README.md": `${shas.length}` })) {
      writeFile(file, content);
    }
    for (const file of spec.remove ?? []) {
      git("rm", "-q", "--", file);
    }
    git("add", "-A");
    const name = spec.authorName ?? "Fixture Author";
    const email = spec.authorEmail ?? "fixture@example.com";
    git(
      "-c",
      `user.name=${name}`,
      "-c",
      `user.email=${email}`,
      "commit",
      "-q",
      "--allow-empty",
      "-m",
      spec.message ?? `commit ${shas.length}`,
    );
    const sha = git("rev-parse", "HEAD").trim();
    shas.push(sha);
    return sha;
  };
  return {
    root,
    shas,
    git,
    gitWithInput: (input: string, ...args: string[]) => gitWithInput(input, args),
    commit,
    writeFile,
    // Retries: on Windows a just-exited git process can still hold the directory (EBUSY).
    cleanup: () => rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }),
  };
}
