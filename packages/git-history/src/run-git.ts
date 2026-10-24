import { execFile } from "node:child_process";

export interface GitRunOptions {
  cwd: string;
  /** Maximum stdout bytes; larger output fails instead of being buffered without bound. */
  maxBuffer?: number;
}

/** Read-only subcommands PGARD may run. Working-tree-mutating commands are not representable. */
export type GitSubcommand =
  | "rev-parse"
  | "remote"
  | "remote get-url"
  | "log"
  | "rev-list"
  | "show"
  | "cat-file"
  | "ls-tree"
  | "ls-files";

export interface GitInvocation {
  subcommand: GitSubcommand;
  /**
   * Fixed option flags written in PGARD source (never derived from repository or user data).
   * Each must start with `-`; flags that write files or run external programs are refused.
   */
  flags?: readonly string[];
  /** Refs, object ids or remote names. Passed after `--end-of-options`; must not start with `-`. */
  operands?: readonly string[];
  /** Pathspecs. Passed after `--`. */
  paths?: readonly string[];
}

/**
 * Runs one allowlisted, read-only git subcommand with an argument vector (never a shell string)
 * and resolves with stdout. Rejects with `GitCommandError` on refusal or non-zero exit.
 */
export type GitRunner = (invocation: GitInvocation, options: GitRunOptions) => Promise<string>;

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

const SUBCOMMAND_ARGS: Record<GitSubcommand, readonly string[]> = {
  "rev-parse": ["rev-parse"],
  remote: ["remote"],
  "remote get-url": ["remote", "get-url"],
  log: ["log"],
  "rev-list": ["rev-list"],
  show: ["show"],
  "cat-file": ["cat-file"],
  "ls-tree": ["ls-tree"],
  "ls-files": ["ls-files"],
};

/** Subcommands that never read file contents, so no filter/diff driver can be involved. */
const METADATA_ONLY: ReadonlySet<GitSubcommand> = new Set([
  "rev-parse",
  "remote",
  "remote get-url",
]);

/** Subcommands that can render diffs; external diff and textconv are always disabled. */
const DIFF_CAPABLE: ReadonlySet<GitSubcommand> = new Set(["log", "show"]);

/** Flags that write files, run programs or re-enable drivers. */
const FORBIDDEN_FLAG_PATTERN =
  /^(--output|--ext-diff|--textconv|--filters|--exec|--upload-pack|--receive-pack|--config|-c$|--git-dir|--work-tree|--namespace|--open-files-in-pager|-O)/;

/**
 * Config overrides that stop a scanned repository's own `.git/config` from making read-only
 * commands execute programs (fsmonitor hooks, pagers, external diff, network helpers).
 */
const BASE_HARDENING_ARGS: readonly string[] = [
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.pager=cat",
  "-c",
  "core.hooksPath=/dev/null",
  "-c",
  "core.untrackedCache=false",
  "-c",
  "diff.external=",
  "-c",
  "protocol.allow=never",
  "--no-pager",
];

const DRIVER_KEY_PATTERN = /^(filter|diff|merge)\.(.+)\.([A-Za-z]+)$/s;
/** Driver keys that name a program to execute. */
const DRIVER_PROGRAM_KEYS: Record<string, readonly string[]> = {
  filter: ["clean", "smudge", "process"],
  diff: ["textconv", "command"],
  merge: ["driver"],
};

/** Environment for git: allowlisted variables only, so GIT_DIR/GIT_CONFIG_* never leak in. */
export function buildGitEnv(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of ["PATH", "HOME", "SystemRoot", "TMPDIR", "TEMP", "TMP"]) {
    const value = source[key];
    if (value !== undefined) {
      env[key] = value;
    }
  }
  env.GIT_TERMINAL_PROMPT = "0";
  env.GIT_OPTIONAL_LOCKS = "0";
  env.GIT_PAGER = "cat";
  env.GIT_CONFIG_NOSYSTEM = "1";
  env.LC_ALL = "C";
  return env;
}

/** Builds the argument vector, refusing anything that could become an unintended option. */
export function buildGitArgs(
  invocation: GitInvocation,
  driverOverrides: readonly string[] = [],
): string[] {
  const base = SUBCOMMAND_ARGS[invocation.subcommand];
  if (!base) {
    throw new GitCommandError("git subcommand is not allowed", null);
  }
  const flags = invocation.flags ?? [];
  for (const flag of flags) {
    if (!flag.startsWith("-") || FORBIDDEN_FLAG_PATTERN.test(flag) || flag.includes("\0")) {
      throw new GitCommandError("git flag is not allowed", null);
    }
  }
  const operands = invocation.operands ?? [];
  for (const operand of operands) {
    if (operand.length === 0 || operand.startsWith("-") || operand.includes("\0")) {
      throw new GitCommandError("git operand is not allowed", null);
    }
  }
  const paths = invocation.paths ?? [];
  for (const pathspec of paths) {
    if (pathspec.length === 0 || pathspec.includes("\0")) {
      throw new GitCommandError("git path is not allowed", null);
    }
  }
  const args = [...BASE_HARDENING_ARGS, ...driverOverrides, ...base];
  if (DIFF_CAPABLE.has(invocation.subcommand)) {
    args.push("--no-ext-diff", "--no-textconv");
  }
  args.push(...flags);
  if (operands.length > 0) {
    args.push("--end-of-options", ...operands);
  }
  if (paths.length > 0) {
    args.push("--", ...paths);
  }
  return args;
}

function execGit(args: readonly string[], options: GitRunOptions): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      "git",
      [...args],
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
          reject(new GitCommandError("git command failed", code));
          return;
        }
        resolve(stdout);
      },
    );
  });
}

/**
 * Reads every filter/diff/merge driver configured for the repository (any config level) and
 * returns `-c` overrides that blank out their programs, so `.gitattributes` cannot route
 * content through a repository-defined command.
 */
export async function readDriverOverrides(cwd: string): Promise<string[]> {
  let output: string;
  try {
    output = await execGit(
      [
        ...BASE_HARDENING_ARGS,
        "config",
        "--null",
        "--name-only",
        "--get-regexp",
        "^(filter|diff|merge)\\.",
      ],
      { cwd },
    );
  } catch (error) {
    // Exit code 1 means no matching keys.
    if (error instanceof GitCommandError && error.exitCode === 1) {
      return [];
    }
    throw error;
  }
  const overrides = new Set<string>();
  for (const key of output.split("\0")) {
    const match = DRIVER_KEY_PATTERN.exec(key);
    if (!match) {
      continue;
    }
    const [, section, driverName] = match;
    if (!section || !driverName) {
      continue;
    }
    if (driverName.includes("=") || /[\r\n]/.test(driverName)) {
      throw new GitCommandError("repository defines an unsupported driver name", null);
    }
    for (const programKey of DRIVER_PROGRAM_KEYS[section] ?? []) {
      overrides.add(`${section}.${driverName}.${programKey}=`);
    }
  }
  return [...overrides].flatMap((override) => ["-c", override]);
}

/** Default runner backed by `child_process.execFile("git", [...])`. */
export const runGit: GitRunner = async (invocation, options) => {
  const overrides = METADATA_ONLY.has(invocation.subcommand)
    ? []
    : await readDriverOverrides(options.cwd);
  return execGit(buildGitArgs(invocation, overrides), options);
};
