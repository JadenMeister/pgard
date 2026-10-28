import { lstat, readdir } from "node:fs/promises";
import path from "node:path";
import { runGit as defaultRunGit, type GitRunner } from "./run-git.js";
import { readSmallRegularFile } from "./safe-read.js";

export type RepositoryIsolation = { isIsolated: true } | { isIsolated: false; reason: string };

/** Alternates and grafts hold a few short lines; anything bigger is not a normal repository. */
const MAX_METADATA_BYTES = 64 * 1024;

const MAX_SHALLOW_BYTES = 8 * 1024 * 1024;

type Probe = "empty" | "content" | "unsafe";

async function probeFile(filePath: string): Promise<Probe> {
  const result = await readSmallRegularFile(filePath, MAX_METADATA_BYTES);
  if (result.state === "absent") return "empty";
  if (result.state === "unsafe") return "unsafe";
  return result.text.trim().length > 0 ? "content" : "empty";
}

const METADATA_FILES = [
  [path.join("objects", "info", "alternates"), "object alternates"],
  [path.join("objects", "info", "http-alternates"), "object alternates"],
  [path.join("info", "grafts"), "grafts"],
] as const;

/** Returns a blocking result when an alternates or grafts file is present or unsafe to read. */
async function checkMetadataFiles(gitDir: string): Promise<RepositoryIsolation | null> {
  for (const [relative, label] of METADATA_FILES) {
    const probe = await probeFile(path.join(gitDir, relative));
    if (probe === "unsafe") {
      return {
        isIsolated: false,
        reason: `The repository's ${relative.split(path.sep).join("/")} could not be read safely (it is a symbolic link, not a regular file, too large or unreadable), so its ${label} can't be ruled out. Remove it or replace it with a regular file, or use a normal clone, and check again.`,
      };
    }
    if (probe === "content") {
      return {
        isIsolated: false,
        reason: `The repository uses ${label}, so its objects or history may come from elsewhere; this is not supported.`,
      };
    }
  }
  // A regular `shallow` file is allowed (shallow clones are supported); an unsafe one is not.
  const shallow = await readSmallRegularFile(path.join(gitDir, "shallow"), MAX_SHALLOW_BYTES);
  if (shallow.state === "unsafe") {
    return {
      isIsolated: false,
      reason:
        "The repository's shallow file could not be read safely (it is a symbolic link, not a regular file, too large or unreadable), so its history boundary can't be trusted. Remove it or replace it with a regular file, or use a normal clone, and check again.",
    };
  }
  return null;
}

const MAX_SMALL_FILE_BYTES = 4096;
const MAX_CONFIG_BYTES = 8 * 1024 * 1024;
const MAX_PACKED_REFS_BYTES = 512 * 1024 * 1024;
const MAX_LOOSE_REF_BYTES = 4096;
const MAX_REF_ENTRIES = 100_000;
const MAX_INCLUDE_DEPTH = 10;
const MAX_INCLUDE_FILES = 50;

const unsafeFileReason = (name: string): string =>
  `The repository's ${name} could not be read safely (it is a symbolic link, not a regular file, too large or unreadable), so the repository can't be trusted. Remove it or replace it with a regular file, or use a normal clone, and check again.`;

const blockedBecause = (name: string): RepositoryIsolation => ({
  isIsolated: false,
  reason: unsafeFileReason(name),
});

/** Stat only (never opens): is the path absent, a plain file within `maxBytes`, or unsafe? */
async function statRegularFile(
  filePath: string,
  maxBytes: number,
): Promise<"absent" | "ok" | "unsafe"> {
  const stats = await lstat(filePath, { bigint: true }).catch(
    (error: NodeJS.ErrnoException) => error,
  );
  if (stats instanceof Error) {
    return (stats as NodeJS.ErrnoException).code === "ENOENT" ? "absent" : "unsafe";
  }
  return stats.isFile() && stats.size <= BigInt(maxBytes) ? "ok" : "unsafe";
}

/** Include paths (`[include]` and `[includeIf ...]` `path = ...`) of one config file's text. */
function parseIncludePaths(text: string): string[] {
  const paths: string[] = [];
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
    if (!match?.[1]) continue;
    let value = match[1].trim();
    const quoted = /^"((?:[^"\\]|\\.)*)"/.exec(value);
    value = quoted ? (quoted[1] ?? "") : value.replace(/\s+[#;].*$/, "");
    if (value.length > 0) paths.push(value);
  }
  return paths;
}

/**
 * Walks a config file and everything it includes, with stat-only checks on every target (Git
 * reads included files without a size limit, and blocks on a FIFO). A missing include is ignored,
 * as Git does.
 */
async function checkConfigFiles(
  configPath: string,
  state: { seen: Set<string>; depth: number },
): Promise<RepositoryIsolation | null> {
  if (state.seen.has(configPath)) return null;
  if (state.seen.size >= MAX_INCLUDE_FILES || state.depth > MAX_INCLUDE_DEPTH) {
    return blockedBecause("config (too many included files)");
  }
  state.seen.add(configPath);
  const read = await readSmallRegularFile(configPath, MAX_CONFIG_BYTES);
  if (read.state === "absent") return null;
  if (read.state === "unsafe") {
    return blockedBecause(state.depth === 0 ? "config" : "included config file");
  }
  for (const included of parseIncludePaths(read.text)) {
    const home = process.env.HOME ?? "";
    const expanded = included.startsWith("~/") ? path.join(home, included.slice(2)) : included;
    const target = path.resolve(path.dirname(configPath), expanded);
    const result = await checkConfigFiles(target, { seen: state.seen, depth: state.depth + 1 });
    if (result !== null) return result;
  }
  return null;
}

/** Loose refs: stat-only walk; anything but small regular files and directories is unsafe. */
async function checkLooseRefs(refsDir: string): Promise<RepositoryIsolation | null> {
  let count = 0;
  const pending = [refsDir];
  while (pending.length > 0) {
    const dir = pending.pop() as string;
    const entries = await readdir(dir, { withFileTypes: true }).catch(
      (error: NodeJS.ErrnoException) => (error.code === "ENOENT" ? [] : null),
    );
    if (entries === null) return blockedBecause("refs directory");
    for (const entry of entries) {
      count += 1;
      if (count > MAX_REF_ENTRIES) return blockedBecause("refs directory (too many entries)");
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        pending.push(full);
      } else if ((await statRegularFile(full, MAX_LOOSE_REF_BYTES)) !== "ok") {
        return blockedBecause("refs");
      }
    }
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
  const commonFile = await readSmallRegularFile(
    path.join(gitDir, "commondir"),
    MAX_SMALL_FILE_BYTES,
  );
  if (commonFile.state === "unsafe") return blockedBecause("commondir file");
  if (commonFile.state === "ok" && commonFile.text.trim().length > 0) {
    commonDirs.push(path.resolve(gitDir, commonFile.text.trim()));
  }
  for (const [name, limit] of [
    ["HEAD", MAX_SMALL_FILE_BYTES],
    ["packed-refs", MAX_PACKED_REFS_BYTES],
  ] as const) {
    if ((await statRegularFile(path.join(gitDir, name), limit)) === "unsafe") {
      return blockedBecause(name);
    }
  }
  const config = await checkConfigFiles(path.join(gitDir, "config"), {
    seen: seenConfigs,
    depth: 0,
  });
  if (config !== null) return config;
  const refs = await checkLooseRefs(path.join(gitDir, "refs"));
  if (refs !== null) return refs;
  return checkMetadataFiles(gitDir);
}

/**
 * Checks, before any Git process starts, every file Git would read without a size limit or block
 * on: for a plain `.git` directory, or a gitfile (`gitdir: <path>`) and the `commondir` it or the
 * directory names. A symbolic link as `.git` is refused (Git would follow it to a directory we
 * did not inspect as the project's own; a real `.git` directory or a gitfile covers every
 * normal layout). Returns a blocking result, or `null` when nothing unsafe was found; the full
 * check after `rev-parse` still runs.
 */
export async function preflightIsolation(projectRoot: string): Promise<RepositoryIsolation | null> {
  const dotGit = path.join(projectRoot, ".git");
  const stats = await lstat(dotGit).catch(() => null);
  if (stats === null) return null;
  if (stats.isSymbolicLink()) return blockedBecause(".git entry (a symbolic link)");
  let gitDir = dotGit;
  if (stats.isFile()) {
    const gitfile = await readSmallRegularFile(dotGit, MAX_SMALL_FILE_BYTES);
    if (gitfile.state !== "ok") return blockedBecause(".git file");
    const match = /^gitdir:\s*(.+?)\s*$/m.exec(gitfile.text);
    if (!match?.[1]) return null;
    gitDir = path.resolve(projectRoot, match[1]);
  } else if (!stats.isDirectory()) {
    return blockedBecause(".git entry");
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
