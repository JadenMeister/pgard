import { execFile } from "node:child_process";

export interface GitRunOptions {
  cwd: string;
  /** Maximum stdout bytes; larger output fails instead of being buffered without bound. */
  maxBuffer?: number;
}

/**
 * Runs `git` with an argument vector (never a shell string) and resolves with stdout.
 * Rejects with `GitCommandError` on non-zero exit.
 */
export type GitRunner = (args: readonly string[], options: GitRunOptions) => Promise<string>;

export class GitCommandError extends Error {
  readonly exitCode: number | null;

  constructor(message: string, exitCode: number | null) {
    super(message);
    this.name = "GitCommandError";
    this.exitCode = exitCode;
  }
}

const DEFAULT_MAX_BUFFER = 16 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 60_000;

/**
 * Config overrides that stop a scanned repository's own `.git/config` from making read-only
 * commands execute programs (fsmonitor hooks, pagers, external diff/textconv drivers).
 */
const HARDENING_ARGS: readonly string[] = [
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.pager=cat",
  "-c",
  "core.hooksPath=/dev/null",
  "-c",
  "diff.external=",
  "-c",
  "protocol.allow=never",
  "--no-pager",
];

function buildGitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of ["PATH", "HOME", "SystemRoot", "TMPDIR", "TEMP", "TMP", "LANG"]) {
    const value = process.env[key];
    if (value !== undefined) {
      env[key] = value;
    }
  }
  env.GIT_TERMINAL_PROMPT = "0";
  env.GIT_OPTIONAL_LOCKS = "0";
  env.GIT_PAGER = "cat";
  env.LC_ALL = "C";
  return env;
}

/** Default runner backed by `child_process.execFile("git", [...])`. */
export const runGit: GitRunner = (args, options) =>
  new Promise((resolve, reject) => {
    execFile(
      "git",
      [...HARDENING_ARGS, ...args],
      {
        cwd: options.cwd,
        env: buildGitEnv(),
        maxBuffer: options.maxBuffer ?? DEFAULT_MAX_BUFFER,
        timeout: DEFAULT_TIMEOUT_MS,
        windowsHide: true,
        encoding: "utf8",
      },
      (error, stdout) => {
        if (error) {
          const code = typeof error.code === "number" ? error.code : null;
          reject(new GitCommandError(`git ${args[0] ?? ""} failed`, code));
          return;
        }
        resolve(stdout);
      },
    );
  });
