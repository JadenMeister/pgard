/**
 * Test-only helpers for the picker: throwaway scope trees and Git repositories in the OS temp
 * directory, and inspector dependencies with an injectable file system. Never part of the build.
 */
import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { runGit } from "@pgard/git-history";
import { inspectRepository } from "@pgard/policy";
import { nodeScopeFs, type ScopeFs, type ScopeRoot, type ScopeStat } from "@pgard/result-store";
import type { InspectorDeps } from "../inspect.js";
import type { ChildMessage } from "../protocol.js";

export interface ScopeTree {
  /** Real path of the scope root (a fresh directory). */
  root: string;
  rootStat: ScopeRoot;
  cleanup: () => void;
}

/** A scope root with the safe mode the picker demands (0755, ours). */
export function createScopeTree(): ScopeTree {
  const base = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-picker-")));
  const root = path.join(base, "scope");
  mkdirSync(root, { mode: 0o755 });
  return {
    root,
    rootStat: rootOf(root),
    cleanup: () => rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }),
  };
}

export function rootOf(rootPath: string): ScopeRoot {
  const stat = lstatSync(rootPath);
  return { path: rootPath, dev: stat.dev, ino: stat.ino };
}

const GIT_ENV = {
  PATH: process.env.PATH ?? "",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_TERMINAL_PROMPT: "0",
};

export interface RepoOptions {
  remotes?: Record<string, string>;
  /** Make a first commit (default true). */
  isCommitted?: boolean;
  /** Author of the first commit (the contribution check matches the email). */
  author?: { name: string; email: string };
}

/** `git init` in `dir` (created, mode 0755), optional remotes and a first commit. */
export function createRepo(dir: string, options: RepoOptions = {}): string {
  mkdirSync(dir, { recursive: true, mode: 0o755 });
  const git = (...args: string[]): string =>
    execFileSync("git", args, {
      cwd: dir,
      encoding: "utf8",
      env: { ...GIT_ENV, HOME: dir },
      timeout: 60_000,
      killSignal: "SIGKILL",
    });
  git("init", "-q", "-b", "main");
  git("config", "commit.gpgsign", "false");
  for (const [name, url] of Object.entries(options.remotes ?? {})) git("remote", "add", name, url);
  if (options.isCommitted !== false) {
    writeFileSync(path.join(dir, "README.md"), "x\n");
    git("add", "-A");
    const author = options.author ?? { name: "T", email: "t@example.com" };
    git(
      "-c",
      `user.name=${author.name}`,
      "-c",
      `user.email=${author.email}`,
      "commit",
      "-q",
      "-m",
      "first",
    );
  }
  return dir;
}

export const GITHUB_REMOTES = { origin: "https://github.com/acme/shop.git" };

/** What a test overrides about one path of the real file system. */
export interface StatOverride {
  uid?: number;
  mode?: number;
  dev?: number;
}

/** The real file system with per-path overrides of owner, mode and device (an injected fs). */
export function overridingFs(overrides: Map<string, StatOverride>): ScopeFs {
  return {
    ...nodeScopeFs,
    async lstat(target) {
      const stat = await nodeScopeFs.lstat(target);
      const override = overrides.get(target);
      return override === undefined ? stat : ({ ...stat, ...override } satisfies ScopeStat);
    },
  };
}

export interface InspectorHarness {
  deps: InspectorDeps;
  messages: ChildMessage[];
}

export function createInspectorDeps(overrides: Partial<InspectorDeps> = {}): InspectorHarness {
  const messages: ChildMessage[] = [];
  const deps: InspectorDeps = {
    fs: nodeScopeFs,
    uid: process.getuid?.(),
    runGit,
    inspectRepository,
    now: () => performance.now(),
    platform: process.platform,
    emit: (message) => messages.push(message),
    ...overrides,
  };
  return { deps, messages };
}
