import { lstat, readdir, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { runGit as defaultRunGit, type GitRunner } from "./run-git.js";
import { readSmallRegularFile, type SafeReadResult, type UnsafeKind } from "./safe-read.js";

export type RepositoryIsolation = { isIsolated: true } | { isIsolated: false; reason: string };

/** Alternates and grafts hold a few short lines; anything bigger is not a normal repository. */
const MAX_METADATA_BYTES = 64 * 1024;
const MAX_SHALLOW_BYTES = 8 * 1024 * 1024;
const MAX_SMALL_FILE_BYTES = 4096;
const MAX_CONFIG_BYTES = 8 * 1024 * 1024;
const MAX_PACKED_REFS_BYTES = 512 * 1024 * 1024;
const MAX_COMMIT_GRAPH_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_LOOSE_REF_BYTES = 4096;
const MAX_REF_ENTRIES = 100_000;
const MAX_INCLUDE_FILES = 50;

type Block = { isIsolated: false; reason: string };

/** How a file that cannot be read safely was found, for reasons that say what is wrong. */
type Found = UnsafeKind | "loop";

const SAFE_WAY_FORWARD =
  "Scan a normal clone (`git clone`) or a `git worktree add` checkout instead.";

function describeFound(found: Found): string {
  switch (found) {
    case "symlink":
      return "it is a symbolic link";
    case "loop":
      return "it is a symbolic link that can't be resolved (a loop or too many levels)";
    case "special":
      return "it is not a regular file: a FIFO, device, socket or directory";
    case "too-large":
      return "it is larger than PGARD reads";
    case "unreadable":
      return "it can't be read: permissions, a broken path or an I/O error";
  }
}

/** Reason for a layout file PGARD cannot read safely. Never advises deleting repository files. */
function layoutBlock(name: string, found: Found): Block {
  const headHint =
    name === "HEAD"
      ? " If HEAD is a symbolic link, run `git config --unset core.preferSymlinkRefs` and `git symbolic-ref HEAD refs/heads/<branch>`."
      : "";
  return {
    isIsolated: false,
    reason: `The repository's ${name} could not be read safely (${describeFound(found)}), so PGARD can't safely read this repository layout.${headHint} ${SAFE_WAY_FORWARD}`,
  };
}

/** Alternates, grafts and shallow: removing the file is the usual fix, after copying objects in. */
function metadataBlock(relative: string, found: Found, label: string, advice: string): Block {
  return {
    isIsolated: false,
    reason: `The repository's ${relative} could not be read safely (${describeFound(found)}), so its ${label} can't be ruled out. ${advice}`,
  };
}

const ALTERNATES_ADVICE =
  "If the repository borrows objects from another one, run `git repack -a -d` first to copy them in; then remove that file, or scan a normal clone instead.";

type Probe = { kind: "empty" } | { kind: "content" } | { kind: "unsafe"; found: Found };

async function probeFile(filePath: string): Promise<Probe> {
  const result = await readSmallRegularFile(filePath, MAX_METADATA_BYTES);
  if (result.state === "absent") return { kind: "empty" };
  if (result.state === "unsafe") return { kind: "unsafe", found: result.found };
  return result.text.trim().length > 0 ? { kind: "content" } : { kind: "empty" };
}

const METADATA_FILES = [
  [path.join("objects", "info", "alternates"), "object alternates", ALTERNATES_ADVICE],
  [path.join("objects", "info", "http-alternates"), "object alternates", ALTERNATES_ADVICE],
  [
    path.join("info", "grafts"),
    "grafts",
    "Grafts rewrite history; remove the file if it is not needed, or scan a normal clone instead.",
  ],
] as const;

/** Returns a blocking result when an alternates or grafts file is present or unsafe to read. */
async function checkMetadataFiles(gitDir: string): Promise<RepositoryIsolation | null> {
  for (const [relative, label, advice] of METADATA_FILES) {
    const probe = await probeFile(path.join(gitDir, relative));
    if (probe.kind === "unsafe") {
      return metadataBlock(relative.split(path.sep).join("/"), probe.found, label, advice);
    }
    if (probe.kind === "content") {
      return {
        isIsolated: false,
        reason: `The repository uses ${label}, so its objects or history may come from elsewhere; this is not supported.`,
      };
    }
  }
  // A regular `shallow` file is allowed (shallow clones are supported); an unsafe one is not.
  const shallow = await readSmallRegularFile(path.join(gitDir, "shallow"), MAX_SHALLOW_BYTES);
  if (shallow.state === "unsafe") {
    return metadataBlock(
      "shallow file",
      shallow.found,
      "history boundary",
      "Scan a normal clone instead, or run `git fetch --unshallow` in a normal checkout.",
    );
  }
  return null;
}

type Inspect =
  | { state: "absent" }
  | { state: "file"; size: bigint }
  | { state: "directory" }
  | { state: "bad"; found: Found };

/** Stat only (never opens), following symlinks: a link to a FIFO or device is still refused. */
async function inspectFollowing(target: string): Promise<Inspect> {
  try {
    const stats = await stat(target, { bigint: true });
    if (stats.isFile()) return { state: "file", size: stats.size };
    if (stats.isDirectory()) return { state: "directory" };
    return { state: "bad", found: "special" };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { state: "absent" };
    return { state: "bad", found: code === "ELOOP" ? "loop" : "unreadable" };
  }
}

/** A regular file within `maxBytes` (following symlinks), or absent; anything else blocks. */
async function checkStatFile(
  target: string,
  name: string,
  maxBytes: number,
): Promise<Block | null> {
  const result = await inspectFollowing(target);
  if (result.state === "absent") return null;
  if (result.state === "bad") return layoutBlock(name, result.found);
  if (result.state === "directory") return layoutBlock(name, "special");
  return result.size > BigInt(maxBytes) ? layoutBlock(name, "too-large") : null;
}

/** `realpath` (bounded by the OS, ELOOP on loops), then the safe read of the resolved file. */
async function readFollowing(
  target: string,
  maxBytes: number,
): Promise<SafeReadResult | { state: "unsafe"; found: Found }> {
  let resolved: string;
  try {
    resolved = await realpath(target);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { state: "absent" };
    return { state: "unsafe", found: code === "ELOOP" ? "loop" : "unreadable" };
  }
  return readSmallRegularFile(resolved, maxBytes);
}

interface IncludeScan {
  paths: string[];
  /** The text uses syntax PGARD does not interpret the way Git does (continuation, partial quotes). */
  unsupported: boolean;
}

/** Include paths (`[include]` and `[includeIf ...]` `path = ...`) of one config file's text. */
function parseIncludePaths(text: string): IncludeScan {
  const scan: IncludeScan = { paths: [], unsupported: false };
  let inInclude = false;
  for (const rawLine of text.split(/\r?\n/)) {
    let line = rawLine.trim();
    const header = /^\[\s*([A-Za-z0-9.-]+)(?:\s+"(?:[^"\\]|\\.)*")?\s*\](.*)$/.exec(line);
    if (header) {
      const section = (header[1] ?? "").toLowerCase();
      inInclude = section === "include" || section === "includeif";
      line = (header[2] ?? "").trim();
    }
    if (!inInclude) continue;
    const match = /^path\s*=\s*(.*)$/i.exec(line);
    if (!match) continue;
    const raw = (match[1] ?? "").trim();
    if (raw.includes("\\")) {
      scan.unsupported = true;
      continue;
    }
    let value: string;
    if (raw.includes('"')) {
      const quoted = /^"([^"]*)"\s*(?:[#;].*)?$/.exec(raw);
      if (!quoted) {
        scan.unsupported = true;
        continue;
      }
      value = quoted[1] ?? "";
    } else {
      value = raw.replace(/[#;].*$/, "").trim();
    }
    if (/^~[^/]/.test(value) || value === "~") {
      scan.unsupported = true;
      continue;
    }
    if (value.length > 0) scan.paths.push(value);
  }
  return scan;
}

/**
 * Walks a config file and everything it includes, with a bounded read of every target (Git reads
 * included files without a size limit, and blocks on a FIFO). A missing include is ignored, as
 * Git does. Symlinked config files (shared `repo` checkouts) are resolved first.
 */
async function checkConfigFiles(
  configPath: string,
  name: string,
  seen: Set<string>,
): Promise<RepositoryIsolation | null> {
  if (seen.has(configPath)) return null;
  if (seen.size >= MAX_INCLUDE_FILES) {
    return {
      isIsolated: false,
      reason: `The repository config includes more than ${MAX_INCLUDE_FILES} files, which PGARD won't follow. ${SAFE_WAY_FORWARD}`,
    };
  }
  seen.add(configPath);
  const read = await readFollowing(configPath, MAX_CONFIG_BYTES);
  if (read.state === "absent") return null;
  if (read.state === "unsafe") return layoutBlock(name, read.found);
  const scan = parseIncludePaths(read.text);
  if (scan.unsupported) {
    return {
      isIsolated: false,
      reason: `The repository's ${name} has an include path PGARD can't interpret the way Git does (a line continuation, partial quoting or a ~user path), so what it includes can't be checked. Write each include as a plain \`path = <file>\` or \`path = ~/<file>\`, or ${SAFE_WAY_FORWARD.charAt(0).toLowerCase()}${SAFE_WAY_FORWARD.slice(1)}`,
    };
  }
  for (const included of scan.paths) {
    const home = process.env.HOME ?? "";
    const expanded = included.startsWith("~/") ? path.join(home, included.slice(2)) : included;
    const target = path.resolve(path.dirname(configPath), expanded);
    const result = await checkConfigFiles(target, "included config file", seen);
    if (result !== null) return result;
  }
  return null;
}

/** Loose refs: stat-only walk (following links); only small regular files and directories pass. */
async function checkLooseRefs(refsDir: string): Promise<RepositoryIsolation | null> {
  let count = 0;
  const visited = new Set<string>();
  const pending = [refsDir];
  while (pending.length > 0) {
    const dir = pending.pop() as string;
    const entries = await readdir(dir).catch((error: NodeJS.ErrnoException) =>
      error.code === "ENOENT" ? [] : null,
    );
    if (entries === null) return layoutBlock("refs directory", "unreadable");
    for (const entry of entries) {
      count += 1;
      if (count > MAX_REF_ENTRIES) {
        return {
          isIsolated: false,
          reason: `The repository has more than ${MAX_REF_ENTRIES} loose refs, which PGARD won't walk. Run \`git pack-refs --all\` and check again.`,
        };
      }
      const full = path.join(dir, entry);
      const result = await inspectFollowing(full);
      if (result.state === "absent") continue;
      if (result.state === "bad") return layoutBlock("refs", result.found);
      if (result.state === "directory") {
        const real = await realpath(full).catch(() => full);
        if (!visited.has(real)) {
          visited.add(real);
          pending.push(full);
        }
      } else if (result.size > BigInt(MAX_LOOSE_REF_BYTES)) {
        return layoutBlock("refs", "too-large");
      }
    }
  }
  return null;
}

/** `objects/info/commit-graph` and the `commit-graphs/` chain, which `rev-parse HEAD` reads. */
async function checkCommitGraphs(gitDir: string): Promise<RepositoryIsolation | null> {
  const info = path.join(gitDir, "objects", "info");
  const single = await checkStatFile(
    path.join(info, "commit-graph"),
    "commit-graph file",
    MAX_COMMIT_GRAPH_BYTES,
  );
  if (single !== null) return single;
  const chainDir = path.join(info, "commit-graphs");
  const entries = await readdir(chainDir).catch((error: NodeJS.ErrnoException) =>
    error.code === "ENOENT" ? [] : null,
  );
  if (entries === null) return layoutBlock("commit-graphs directory", "unreadable");
  for (const entry of entries.slice(0, MAX_REF_ENTRIES)) {
    const blocked = await checkStatFile(
      path.join(chainDir, entry),
      "commit-graphs file",
      MAX_COMMIT_GRAPH_BYTES,
    );
    if (blocked !== null) return blocked;
  }
  return null;
}

/**
 * Every file Git opens in a git directory while we run `rev-parse`, `config` and the HEAD
 * lookup, which it reads without a size limit and may block on. `commondir` is read here and its
 * target is returned so the caller checks that directory too.
 */
async function checkGitDirectory(
  gitDir: string,
  seenConfigs: Set<string>,
  commonDirs: string[],
): Promise<RepositoryIsolation | null> {
  const commonFile = await readFollowing(path.join(gitDir, "commondir"), MAX_SMALL_FILE_BYTES);
  if (commonFile.state === "unsafe") return layoutBlock("commondir file", commonFile.found);
  if (commonFile.state === "ok" && commonFile.text.trim().length > 0) {
    commonDirs.push(path.resolve(gitDir, commonFile.text.trim()));
  }
  for (const [name, limit] of [
    ["HEAD", MAX_SMALL_FILE_BYTES],
    ["packed-refs", MAX_PACKED_REFS_BYTES],
  ] as const) {
    const blocked = await checkStatFile(path.join(gitDir, name), name, limit);
    if (blocked !== null) return blocked;
  }
  for (const name of ["config", "config.worktree"]) {
    const config = await checkConfigFiles(path.join(gitDir, name), name, seenConfigs);
    if (config !== null) return config;
  }
  const refs = await checkLooseRefs(path.join(gitDir, "refs"));
  if (refs !== null) return refs;
  const graphs = await checkCommitGraphs(gitDir);
  if (graphs !== null) return graphs;
  return checkMetadataFiles(gitDir);
}

/**
 * Checks, before any Git process starts, every file Git would read without a size limit or block
 * on: for a plain `.git` directory, or a gitfile (`gitdir: <path>`) and the `commondir` it or the
 * directory names. Symbolic links are followed (shared-object layouts such as `repo`,
 * `git new-workdir` and `core.preferSymlinkRefs` use them), but only to a regular file or a
 * directory: nothing is opened until the target is known to be a small regular file, so a link to
 * a FIFO or `/dev/zero` is refused. Returns a blocking result, or `null` when nothing unsafe was
 * found; the full check after `rev-parse` still runs.
 */
export async function preflightIsolation(projectRoot: string): Promise<RepositoryIsolation | null> {
  const dotGit = path.join(projectRoot, ".git");
  const entry = await lstat(dotGit).catch(() => null);
  if (entry === null) return null;
  const resolved = await inspectFollowing(dotGit);
  if (resolved.state === "absent") return null; // a dangling link: Git finds no repository here
  if (resolved.state === "bad") return layoutBlock(".git entry", resolved.found);
  let gitDir = dotGit;
  if (resolved.state === "file") {
    const gitfile = await readFollowing(dotGit, MAX_SMALL_FILE_BYTES);
    if (gitfile.state === "unsafe") return layoutBlock(".git file", gitfile.found);
    if (gitfile.state !== "ok") return null;
    const match = /^gitdir:\s*(.+?)\s*$/m.exec(gitfile.text);
    if (!match?.[1]) return null;
    gitDir = path.resolve(projectRoot, match[1]);
  }
  const seenConfigs = new Set<string>();
  const checked = new Set<string>();
  const queue = [gitDir];
  while (queue.length > 0 && checked.size < 4) {
    const dir = queue.shift() as string;
    if (checked.has(dir)) continue;
    checked.add(dir);
    const commonDirs: string[] = [];
    const blocked = await checkGitDirectory(dir, seenConfigs, commonDirs);
    if (blocked !== null) return blocked;
    queue.push(...commonDirs);
  }
  return null;
}

/**
 * Verifies the repository only uses its own objects and real history. Alternates
 * (`objects/info/alternates`, `http-alternates`) would let git read objects from other
 * repositories on disk; grafts and replace refs rewrite history. Any of them makes the checkout
 * an unreliable basis for authorization and analysis, so it is rejected. A metadata file that
 * cannot be read safely (symlink, FIFO, directory, oversized, unreadable) also rejects: the check
 * never fails open.
 */
export async function readRepositoryIsolation(
  projectRoot: string,
  runner: GitRunner = defaultRunGit,
): Promise<RepositoryIsolation> {
  const early = await preflightIsolation(projectRoot);
  if (early !== null) return early;
  let commonDir: string;
  try {
    const output = (
      await runner({ subcommand: "rev-parse", flags: ["--git-common-dir"] }, { cwd: projectRoot })
    ).trim();
    if (output.length === 0) {
      return { isIsolated: false, reason: "Could not locate the Git directory." };
    }
    commonDir = path.resolve(projectRoot, output);
  } catch {
    return { isIsolated: false, reason: "Could not locate the Git directory." };
  }
  const blocked = await checkMetadataFiles(commonDir);
  if (blocked !== null) return blocked;
  try {
    const replaceRefs = (
      await runner(
        {
          subcommand: "for-each-ref",
          flags: ["--count=1", "--format=%(refname)"],
          operands: ["refs/replace/"],
        },
        { cwd: projectRoot },
      )
    ).trim();
    if (replaceRefs.length > 0) {
      return {
        isIsolated: false,
        reason: "The repository has replace refs that rewrite history; this is not supported.",
      };
    }
  } catch {
    return { isIsolated: false, reason: "Could not inspect repository refs." };
  }
  return { isIsolated: true };
}
