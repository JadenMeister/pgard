import { spawn, type ChildProcess } from "node:child_process";
import path from "node:path";
import { resolveGitExecutable } from "./git-executable.js";

export interface GitRunOptions {
  cwd: string;
  /** Maximum stdout bytes; larger output fails instead of being buffered without bound. */
  maxBuffer?: number;
  /** Data written to stdin (e.g. object ids for `cat-file --batch`). */
  input?: string;
  /** `latin1` maps every byte to one character, so byte offsets (e.g. `cat-file --batch` sizes) stay exact. */
  encoding?: "utf8" | "latin1";
  /** Aborting kills the git process and rejects with kind `cancelled`. */
  signal?: AbortSignal;
  /**
   * Resolve with the first `maxBuffer` bytes and stop git, instead of failing with
   * `output_limit` (e.g. to read only the start of a large blob).
   */
  truncate?: boolean;
  /** Overrides the 60 s time limit (tests and the pre-commit time cap). */
  timeoutMs?: number;
  /**
   * Absolute path of the index file to read instead of the default one (`GIT_INDEX_FILE`).
   * Git points a pre-commit hook at a temporary index for `git commit -a` and `git commit
   * <path>`; the staged content is only correct when read from that file. Accepted for
   * `ls-files` alone (the one subcommand that reads the index); the caller must already have
   * checked that the file lies inside the repository's Git directory.
   */
  indexFile?: string;
}

/**
 * Subcommands PGARD may run. Only plumbing, two metadata-only remote lookups, a read-only
 * `config --null --get-regexp <one pattern>` lookup (any other `config` form can write and is
 * refused in `buildGitArgs`) and a fixed-string
 * `grep` of a tree (patterns on stdin, see the flag allowlist): porcelain commands such as
 * `log`/`show` are deliberately absent because they carry the most config-driven hooks (pager,
 * signature verification, textconv, mailmap). Commit metadata and diffs are parsed from plumbing
 * output instead. Nothing here can modify the repository.
 */
export type GitSubcommand =
  | "rev-parse"
  | "remote"
  | "remote get-url"
  | "config"
  | "rev-list"
  | "cat-file"
  | "ls-tree"
  | "ls-files"
  | "diff-tree"
  | "for-each-ref"
  | "grep";

export interface GitInvocation {
  subcommand: GitSubcommand;
  /**
   * Fixed option flags written in PGARD source (never derived from repository or user data).
   * Only exact spellings from the per-subcommand allowlist are accepted (no abbreviations);
   * formats that would verify signatures are refused.
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

export type GitCommandFailure = "failed" | "timeout" | "output_limit" | "cancelled";

export class GitCommandError extends Error {
  readonly exitCode: number | null;
  readonly kind: GitCommandFailure;

  constructor(message: string, exitCode: number | null, kind: GitCommandFailure = "failed") {
    super(message);
    this.name = "GitCommandError";
    this.exitCode = exitCode;
    this.kind = kind;
  }
}

const DEFAULT_MAX_BUFFER = 16 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 60_000;

const SUBCOMMAND_ARGS: Record<GitSubcommand, readonly string[]> = {
  "rev-parse": ["rev-parse"],
  remote: ["remote"],
  "remote get-url": ["remote", "get-url"],
  config: ["config"],
  "rev-list": ["rev-list"],
  "cat-file": ["cat-file"],
  "ls-tree": ["ls-tree"],
  "ls-files": ["ls-files"],
  "diff-tree": ["diff-tree"],
  "for-each-ref": ["for-each-ref"],
  grep: ["grep"],
};

/** Subcommands that never read file contents, so no filter/diff driver can be involved. */
const METADATA_ONLY: ReadonlySet<GitSubcommand> = new Set([
  "rev-parse",
  "remote",
  "remote get-url",
  "config",
  "for-each-ref",
]);

/** Subcommands that can render diffs; external diff and textconv are always disabled. */
const DIFF_CAPABLE: ReadonlySet<GitSubcommand> = new Set(["diff-tree"]);

type FlagRule = string | RegExp;

/** The only accepted `config` invocation: a read-only regexp lookup with one pattern operand. */
const CONFIG_LOOKUP_FLAGS: readonly string[] = ["--null", "--get-regexp"];

/**
 * The only accepted `grep` invocation, in this exact order: fixed strings read from stdin
 * (`-f-`, never a file) so searched values never appear in argv, exit status only (`-q`), no
 * textconv, color or pager.
 */
export const GREP_FLAGS: readonly string[] = ["-F", "-q", "--no-textconv", "--no-color", "-f-"];

/**
 * Exact per-subcommand flag allowlist. Git accepts unambiguous abbreviations of long options
 * (`--textc` for `--textconv`), so a denylist cannot be complete; only these exact spellings
 * are accepted. Regexes are anchored and only admit value-carrying flags PGARD needs.
 */
const ALLOWED_FLAGS: Record<GitSubcommand, readonly FlagRule[]> = {
  "rev-parse": [
    "--show-toplevel",
    "--verify",
    "--quiet",
    "--git-common-dir",
    "--absolute-git-dir",
    "--is-shallow-repository",
  ],
  remote: [],
  "remote get-url": ["--all", "--push"],
  // Read-only lookup of raw config values (`remote get-url` applies `url.*.insteadOf`).
  config: CONFIG_LOOKUP_FLAGS,
  "rev-list": [
    "--all",
    "--first-parent",
    "--reverse",
    "--no-merges",
    "--parents",
    "--topo-order",
    "--date-order",
    /^--max-count=\d{1,7}$/,
    /^--format=[^\n]*$/,
  ],
  "cat-file": ["-p", "-t", "-s", "-e", "--batch", "--batch-check", /^--batch(?:-check)?=[^\n]*$/],
  "ls-tree": ["-r", "-z", "-l", "-t", "--name-only", "--full-tree"],
  "ls-files": ["-s", "-z", "--cached", "--stage", "--full-name"],
  "diff-tree": [
    "-p",
    "-r",
    "-z",
    "-m",
    "--root",
    "--raw",
    "--stdin",
    "--numstat",
    "--no-renames",
    "--name-only",
    "--name-status",
    "--no-commit-id",
    "--first-parent",
    "--full-index",
    /^-U\d{1,3}$/,
    /^--diff-filter=[ACDMRTUXB]+$/i,
  ],
  "for-each-ref": [/^--count=\d{1,7}$/, /^--format=[^\n]*$/, /^--sort=-?[a-z:]+$/],
  // Fixed-string search of a tree object; the whole flag set is enforced in `buildGitArgs`.
  grep: GREP_FLAGS,
};

/** Format placeholders that trigger signature verification (`%G?`, `%GS`, `%(signature)`...). */
const FORBIDDEN_FORMAT_PATTERN = /%G|%\(signature/;

function isFlagAllowed(subcommand: GitSubcommand, flag: string): boolean {
  if (flag.includes("\0") || FORBIDDEN_FORMAT_PATTERN.test(flag)) {
    return false;
  }
  return (ALLOWED_FLAGS[subcommand] ?? []).some((rule) =>
    typeof rule === "string" ? rule === flag : rule.test(flag),
  );
}

/**
 * Git's null device. Not `os.devNull`: on Windows that is a `\\.\nul` device path, which git
 * rejects as a config path ("unable to access ... Invalid argument"), whereas `NUL` works.
 */
const GIT_NULL_DEVICE = process.platform === "win32" ? "NUL" : "/dev/null";

/**
 * Config overrides that stop a scanned repository's own config from making read-only commands
 * execute programs: fsmonitor hooks, pagers, external diff, signature verification programs,
 * and network helpers.
 */
const BASE_HARDENING_ARGS: readonly string[] = [
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.pager=cat",
  "-c",
  `core.hooksPath=${GIT_NULL_DEVICE}`,
  "-c",
  "core.untrackedCache=false",
  "-c",
  "diff.external=",
  "-c",
  "log.showSignature=false",
  "-c",
  "gpg.program=",
  "-c",
  "gpg.openpgp.program=",
  "-c",
  "gpg.ssh.program=",
  "-c",
  "gpg.x509.program=",
  "-c",
  "gpg.ssh.allowedSignersFile=",
  "-c",
  "protocol.allow=never",
  "-c",
  "core.alternateRefsCommand=",
  "-c",
  "credential.helper=",
  "-c",
  "core.sshCommand=",
  "--no-pager",
];

const DRIVER_KEY_PATTERN = /^(filter|diff|merge)\.(.+)\.([A-Za-z]+)$/s;
/** Driver keys that name a program to execute. */
const DRIVER_PROGRAM_KEYS: Record<string, readonly string[]> = {
  filter: ["clean", "smudge", "process"],
  diff: ["textconv", "command"],
  merge: ["driver"],
};

/**
 * Environment for git: allowlisted variables only, so GIT_DIR/GIT_CONFIG_* never leak in.
 * System and global config are ignored; only the scanned repository's config is read, and its
 * program-running keys are neutralized above.
 */
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
  env.GIT_CONFIG_GLOBAL = GIT_NULL_DEVICE;
  env.GIT_NO_REPLACE_OBJECTS = "1";
  env.GIT_NO_LAZY_FETCH = "1";
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
  if (
    invocation.subcommand === "grep" &&
    (flags.length !== GREP_FLAGS.length || flags.some((flag, index) => flag !== GREP_FLAGS[index]))
  ) {
    throw new GitCommandError("git grep must use the fixed flag set", null);
  }
  if (invocation.subcommand === "config") {
    // `git config` writes when given a name and a value, or no mode flag. Only the read-only
    // regexp lookup with exactly one pattern is accepted.
    const fixed = new Set(CONFIG_LOOKUP_FLAGS);
    if (
      flags.length !== CONFIG_LOOKUP_FLAGS.length ||
      !flags.every((flag) => fixed.has(flag)) ||
      new Set(flags).size !== flags.length ||
      (invocation.operands ?? []).length !== 1 ||
      (invocation.paths ?? []).length !== 0
    ) {
      throw new GitCommandError("git config must be a single read-only regexp lookup", null);
    }
  }
  for (const flag of flags) {
    if (!isFlagAllowed(invocation.subcommand, flag)) {
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

/** Git children that have started and not yet closed. */
const liveChildren = new Set<ChildProcess>();
let exitHooksInstalled = false;

/** Kills every live git child at once (used on process exit and termination signals). */
export function killAllGitChildren(): void {
  for (const child of liveChildren) {
    child.kill("SIGKILL");
  }
}

/** Process ids of live git children (test seam: lets tests check none is left alive). */
export function liveGitChildPids(): number[] {
  return [...liveChildren].flatMap((child) => (child.pid === undefined ? [] : [child.pid]));
}

function onTerminationSignal(signal: "SIGINT" | "SIGTERM"): void {
  // Another handler (the CLI's Ctrl+C handler) owns this signal and cancels through the abort
  // path, which kills the child right away; do not preempt it. If only this listener is left,
  // Node's default (terminate) was replaced by it, so kill the children and restore the default.
  if (process.listenerCount(signal) > 1) return;
  killAllGitChildren();
  // Re-raise on the next turn, so a handler that re-attaches during this signal (or another
  // `once` wrapper that already removed itself) is counted. Known limit: a `once` handler that
  // already ran has done its work synchronously; PGARD itself uses no `once` for these signals.
  setImmediate(() => {
    if (process.listenerCount(signal) > 1) return;
    process.removeListener(signal, signalListeners[signal]);
    process.kill(process.pid, signal);
  });
}

const signalListeners = {
  SIGINT: () => onTerminationSignal("SIGINT"),
  SIGTERM: () => onTerminationSignal("SIGTERM"),
};

function trackChild(child: ChildProcess): void {
  liveChildren.add(child);
  if (exitHooksInstalled) return;
  exitHooksInstalled = true;
  // A blocked git child would otherwise outlive PGARD. `exit` also fires on process.exit and on
  // uncaught exceptions; a hard kill (SIGKILL) of PGARD cannot be intercepted by any process.
  process.on("exit", killAllGitChildren);
  process.on("SIGINT", signalListeners.SIGINT);
  process.on("SIGTERM", signalListeners.SIGTERM);
}

function execGit(args: readonly string[], options: GitRunOptions): Promise<string> {
  const env = buildGitEnv();
  if (options.indexFile !== undefined) env.GIT_INDEX_FILE = options.indexFile;
  const maxBuffer = options.maxBuffer ?? DEFAULT_MAX_BUFFER;
  return new Promise((resolve, reject) => {
    // An absolute path on Windows, so a `git.exe` inside the scanned repository never runs.
    const gitProgram = resolveGitExecutable({ cwd: options.cwd });
    if (gitProgram === null) {
      reject(new GitCommandError("git could not be started", null));
      return;
    }
    const child = spawn(gitProgram, [...args], {
      cwd: options.cwd,
      env,
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "ignore"],
    });
    trackChild(child);
    const chunks: Buffer[] = [];
    let size = 0;
    let failure: GitCommandError | null = null;
    let truncated = false;
    const timer = setTimeout(() => {
      failure = new GitCommandError("git command timed out", null, "timeout");
      child.kill("SIGKILL");
    }, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    const onAbort = () => {
      failure ??= new GitCommandError("git command was cancelled", null, "cancelled");
      child.kill("SIGKILL");
    };
    if (options.signal?.aborted) onAbort();
    options.signal?.addEventListener("abort", onAbort, { once: true });
    child.stdout.on("data", (chunk: Buffer) => {
      if (truncated) return;
      size += chunk.length;
      if (size > maxBuffer && options.truncate) {
        chunks.push(chunk.subarray(0, chunk.length - (size - maxBuffer)));
        truncated = true;
        child.kill("SIGKILL");
        return;
      }
      if (size > maxBuffer) {
        failure ??= new GitCommandError("git output exceeded the size limit", null, "output_limit");
        child.kill("SIGKILL");
        return;
      }
      chunks.push(chunk);
    });
    child.on("error", () => {
      failure ??= new GitCommandError("git could not be started", null);
    });
    child.on("close", (code) => {
      liveChildren.delete(child);
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      if (failure) {
        reject(failure);
      } else if (truncated) {
        // Stopped on purpose after `maxBuffer` bytes (`truncate`), so the exit code is moot.
        resolve(Buffer.concat(chunks).toString(options.encoding ?? "utf8"));
      } else if (code !== 0) {
        reject(new GitCommandError("git command failed", code));
      } else {
        resolve(Buffer.concat(chunks).toString(options.encoding ?? "utf8"));
      }
    });
    child.stdin.on("error", () => {
      // The child may exit before reading all input; the exit code reports the failure.
    });
    child.stdin.end(options.input ?? "");
  });
}

/**
 * Reads every filter/diff/merge driver configured for the repository and returns `-c`
 * overrides that blank out their programs, so `.gitattributes` cannot route content through
 * a repository-defined command.
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

/** Default runner backed by `child_process.spawn("git", [...], { shell: false })`. */
export const runGit: GitRunner = async (invocation, options) => {
  if (
    options.indexFile !== undefined &&
    (invocation.subcommand !== "ls-files" ||
      !path.isAbsolute(options.indexFile) ||
      options.indexFile.includes("\0"))
  ) {
    throw new GitCommandError("git index file is not allowed", null);
  }
  const overrides = METADATA_ONLY.has(invocation.subcommand)
    ? []
    : await readDriverOverrides(options.cwd);
  return execGit(buildGitArgs(invocation, overrides), options);
};
