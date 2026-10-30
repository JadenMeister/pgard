import path from "node:path";
import type { GitRunner } from "@pgard/git-history";
import type { RepositoryInspection } from "@pgard/policy";
import {
  enclosingRepositoryRoot,
  isInsideGitDirectory,
  safetyProblemOf,
  tooBroadToScan,
  type EntryKind,
  type ScopeDirent,
  type ScopeFs,
  type ScopeRoot,
  type ScopeStat,
} from "@pgard/result-store";
import { matchRank, parseFolderName } from "./name.js";
import {
  PICKER_LIMITS,
  type PickerLimits,
  type ChainSegment,
  type ChildMessage,
  type GitIdentity,
  type InspectorJob,
  type PickerBlockCode,
  type RawCandidate,
  type RecentOutcome,
  type ResolveRefusal,
  type StoppedBy,
} from "./protocol.js";

/**
 * The inspector: directory walk, candidate inspection (including every Git call) and the
 * identity re-checks. It runs in a child process (`inspector-child.ts`) because it reads
 * untrusted directories and may block in the operating system. Everything it needs from the
 * outside is injected, so tests can fake owners, mode bits, `dev` and `ino`.
 *
 * Containment and identity are decided by walking down from the stored root: every directory
 * name comes from `readdir` and every `dev`/`ino` from `lstat`, and none may be a symlink. No
 * string comparison of paths ever counts as "inside".
 */

export interface InspectorDeps {
  fs: ScopeFs;
  uid: number | undefined;
  runGit: GitRunner;
  inspectRepository: (projectRoot: string, runner: GitRunner) => Promise<RepositoryInspection>;
  /** Milliseconds since an arbitrary start; injected so tests control the deadline. */
  now: () => number;
  platform: string;
  emit: (message: ChildMessage) => void;
  limits?: Partial<PickerLimits>;
}

function limitsOf(deps: InspectorDeps): PickerLimits {
  return { ...PICKER_LIMITS, ...deps.limits };
}

const SKIPPED_NAMES: ReadonlySet<string> = new Set([
  "node_modules",
  ".git",
  ".cache",
  ".npm",
  ".Trash",
]);

function isSkippedName(name: string, platform: string): boolean {
  return (
    name.startsWith(".") || SKIPPED_NAMES.has(name) || (platform === "darwin" && name === "Library")
  );
}

function isSafeSegmentName(name: string): boolean {
  return (
    name.length > 0 &&
    name.length <= 255 &&
    name !== "." &&
    name !== ".." &&
    !name.includes("/") &&
    !name.includes("\0")
  );
}

function errnoOf(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : undefined;
}

/** `ENOENT`, `ENOTDIR` and `ELOOP` mean "it is not what it was"; anything else is unreadable. */
function isGoneError(error: unknown): boolean {
  const code = errnoOf(error);
  return code === "ENOENT" || code === "ENOTDIR" || code === "ELOOP";
}

class ChainChanged extends Error {}
class ChainUnreadable extends Error {}

interface ChainWalk {
  /** Directory path and metadata, from the scope root down to the candidate. */
  directories: Array<{ path: string; stat: ScopeStat }>;
  segments: ChainSegment[];
  candidatePath: string;
}

async function lstatOrThrow(fs: ScopeFs, target: string): Promise<ScopeStat> {
  try {
    return await fs.lstat(target);
  } catch (error) {
    throw isGoneError(error) ? new ChainChanged() : new ChainUnreadable();
  }
}

/**
 * Walks down from the stored root: the root and each segment must be a non-symlink directory
 * on the root's file system. With `recorded` identities they must also match `dev`/`ino`.
 */
async function walkChain(
  deps: InspectorDeps,
  root: ScopeRoot,
  segments: ReadonlyArray<{ name: string; dev?: number; ino?: number }>,
): Promise<ChainWalk> {
  const rootStat = await lstatOrThrow(deps.fs, root.path);
  if (
    rootStat.isSymbolicLink ||
    !rootStat.isDirectory ||
    rootStat.dev !== root.dev ||
    rootStat.ino !== root.ino
  ) {
    throw new ChainChanged();
  }
  const directories = [{ path: root.path, stat: rootStat }];
  const walked: ChainSegment[] = [];
  let current = root.path;
  for (const segment of segments) {
    if (!isSafeSegmentName(segment.name)) throw new ChainChanged();
    current = path.posix.join(current, segment.name);
    const stat = await lstatOrThrow(deps.fs, current);
    if (stat.isSymbolicLink || !stat.isDirectory || stat.dev !== root.dev) throw new ChainChanged();
    if (
      (segment.dev !== undefined && segment.dev !== stat.dev) ||
      (segment.ino !== undefined && segment.ino !== stat.ino)
    ) {
      throw new ChainChanged();
    }
    directories.push({ path: current, stat });
    walked.push({ name: segment.name, dev: stat.dev, ino: stat.ino });
  }
  return { directories, segments: walked, candidatePath: current };
}

interface SafetyReport {
  notOwned: string[];
  writable: string[];
}

function collectSafety(
  deps: InspectorDeps,
  entries: ReadonlyArray<{ path: string; stat: ScopeStat }>,
): SafetyReport {
  const report: SafetyReport = { notOwned: [], writable: [] };
  for (const entry of entries) {
    const problem = safetyProblemOf(entry.stat, deps.uid);
    if (problem === "not_owned_by_you") report.notOwned.push(entry.path);
    else if (problem === "group_or_world_writable") report.writable.push(entry.path);
  }
  return report;
}

function blockFromSafety(report: SafetyReport): RawCandidate["block"] {
  if (report.notOwned.length > 0) return { code: "not_owned_by_you", paths: report.notOwned };
  if (report.writable.length > 0) {
    return { code: "group_or_world_writable", paths: report.writable };
  }
  return null;
}

function toRemote(inspection: RepositoryInspection): RawCandidate["remote"] {
  return inspection.status === "ok"
    ? { status: "github", owner: inspection.repo.owner, name: inspection.repo.name }
    : { status: "unreadable" };
}

const REMOTE_STATUS: Record<string, RawCandidate["remote"]> = {
  no_remote: { status: "none" },
  remote_not_github: { status: "not_github" },
  remote_ambiguous: { status: "ambiguous" },
  remote_unreadable: { status: "unreadable" },
};

function isTimeout(error: unknown): boolean {
  return (
    typeof error === "object" && error !== null && (error as { kind?: unknown }).kind === "timeout"
  );
}

/**
 * Inspects one directory whose chain is `segments` below `root`. The chain is walked and verified
 * first (`ChainChanged` when anything differs from `segments`' recorded identity); then `.git`
 * and `.git/config` are checked, and only for a safe candidate do the Git calls run.
 */
export async function inspectCandidate(
  deps: InspectorDeps,
  root: ScopeRoot,
  rootIndex: number,
  segments: ReadonlyArray<{ name: string; dev?: number; ino?: number }>,
  mode: "full" | "recheck" | "folder",
): Promise<RawCandidate> {
  const limits = limitsOf(deps);
  const chain = await walkChain(deps, root, segments);
  const base = { rootIndex, segments: chain.segments };
  if (mode === "folder") {
    // #414, code-only: the chain itself, its ownership and write bits; no Git.
    return {
      ...base,
      gitIdentity: null,
      remote: { status: "unreadable" },
      block: blockFromSafety(collectSafety(deps, chain.directories)),
    };
  }
  const blocked = (
    block: NonNullable<RawCandidate["block"]>,
    gitIdentity: GitIdentity | null = null,
    remote: RawCandidate["remote"] = { status: "unreadable" },
  ): RawCandidate => ({ ...base, gitIdentity, remote, block });

  const gitPath = path.posix.join(chain.candidatePath, ".git");
  let gitStat: ScopeStat;
  try {
    gitStat = await deps.fs.lstat(gitPath);
  } catch (error) {
    if (isGoneError(error)) return blocked({ code: "not_a_git_root", paths: [] });
    throw new ChainUnreadable();
  }
  if (gitStat.isSymbolicLink) return blocked({ code: "git_dir_unsupported", paths: [] });
  if (gitStat.isFile) return blocked({ code: "gitfile_unsupported", paths: [] });
  if (!gitStat.isDirectory) return blocked({ code: "git_dir_unsupported", paths: [] });
  const configPath = path.posix.join(gitPath, "config");
  let configStat: ScopeStat;
  try {
    configStat = await deps.fs.lstat(configPath);
  } catch (error) {
    if (isGoneError(error)) return blocked({ code: "not_a_git_root", paths: [] });
    throw new ChainUnreadable();
  }
  if (configStat.isSymbolicLink || !configStat.isFile) {
    return blocked({ code: "git_dir_unsupported", paths: [] });
  }
  const gitIdentity: GitIdentity = {
    gitDev: gitStat.dev,
    gitIno: gitStat.ino,
    configDev: configStat.dev,
    configIno: configStat.ino,
  };
  // Ownership and write bits along the whole chain, `.git` and `.git/config`: all failing paths
  // at once, so the user can fix them in one step.
  const safety = blockFromSafety(
    collectSafety(deps, [
      ...chain.directories,
      { path: gitPath, stat: gitStat },
      { path: configPath, stat: configStat },
    ]),
  );
  if (safety !== null) return blocked(safety, gitIdentity);
  if (mode === "recheck") {
    return { ...base, gitIdentity, remote: { status: "unreadable" }, block: null };
  }

  let hasTimedOut = false;
  const runner: GitRunner = async (invocation, options) => {
    try {
      return await deps.runGit(invocation, { ...options, timeoutMs: limits.gitTimeoutMs });
    } catch (error) {
      if (isTimeout(error)) hasTimedOut = true;
      throw error;
    }
  };
  // The Git directory must be the candidate's own `.git`, not one elsewhere.
  try {
    const output = (
      await runner(
        { subcommand: "rev-parse", flags: ["--git-common-dir"] },
        { cwd: chain.candidatePath },
      )
    ).trim();
    const [commonDir, ownDir] = await Promise.all([
      deps.fs.realpath(path.posix.resolve(chain.candidatePath, output)),
      deps.fs.realpath(gitPath),
    ]);
    if (output.length === 0 || commonDir !== ownDir) {
      return blocked({ code: "git_dir_unsupported", paths: [] }, gitIdentity);
    }
  } catch {
    return blocked({ code: hasTimedOut ? "unreadable" : "not_a_git_root", paths: [] }, gitIdentity);
  }
  const inspection = await deps.inspectRepository(chain.candidatePath, runner);
  if (hasTimedOut) return blocked({ code: "unreadable", paths: [] }, gitIdentity);
  if (inspection.status === "ok") {
    return { ...base, gitIdentity, remote: toRemote(inspection), block: null };
  }
  const code: PickerBlockCode = inspection.code;
  return blocked({ code, paths: [] }, gitIdentity, REMOTE_STATUS[code] ?? { status: "unreadable" });
}

/** Wraps `inspectCandidate`: a changed or unreadable chain is reported, never thrown. */
async function inspectOrBlock(
  deps: InspectorDeps,
  root: ScopeRoot,
  rootIndex: number,
  segments: ReadonlyArray<{ name: string; dev?: number; ino?: number }>,
  mode: "full" | "recheck" | "folder",
): Promise<RawCandidate | "changed"> {
  try {
    return await inspectCandidate(deps, root, rootIndex, segments, mode);
  } catch (error) {
    if (error instanceof ChainChanged) return "changed";
    return {
      rootIndex,
      segments: segments.map((s) => ({ name: s.name, dev: s.dev ?? 0, ino: s.ino ?? 0 })),
      gitIdentity: null,
      remote: { status: "unreadable" },
      block: { code: "unreadable", paths: [] },
    };
  }
}

interface QueueItem {
  path: string;
  name: string;
  segments: ChainSegment[];
}

interface Found {
  key: number;
  rootIndex: number;
  segments: ChainSegment[];
  rank: number;
}

/** The directory walk and inspection for one search. Always ends with a `done` message. */
async function runSearch(
  deps: InspectorDeps,
  job: Extract<InspectorJob, { kind: "search" }>,
): Promise<void> {
  const limits = limitsOf(deps);
  const started = deps.now();
  const elapsed = (): number => deps.now() - started;
  const query = parseFolderName(job.name, job.source);
  let stoppedBy: StoppedBy = null;
  let visited = 0;
  const skipped = new Map<string, number>();
  const skip = (reason: string): void => {
    skipped.set(reason, (skipped.get(reason) ?? 0) + 1);
  };
  const found: Found[] = [];
  if (!query.ok) {
    deps.emit({ t: "done", stoppedBy, elapsedMs: 0, visited: 0, skipped: [] });
    return;
  }
  const depthLimit = Math.min(limits.depth, limits.maxDepth);
  let reportedAt = 0;

  rootLoop: for (const [rootIndex, root] of job.roots.entries()) {
    let rootStat: ScopeStat;
    try {
      rootStat = await deps.fs.lstat(root.path);
    } catch {
      skip("root_unreadable");
      continue;
    }
    if (
      rootStat.isSymbolicLink ||
      !rootStat.isDirectory ||
      rootStat.dev !== root.dev ||
      rootStat.ino !== root.ino
    ) {
      skip("root_changed");
      continue;
    }
    const queue: QueueItem[] = [
      { path: root.path, name: path.posix.basename(root.path), segments: [] },
    ];
    while (queue.length > 0) {
      if (elapsed() >= limits.softBudgetMs) {
        stoppedBy = "time";
        break rootLoop;
      }
      const item = queue.shift() as QueueItem;
      let entries: ScopeDirent[];
      try {
        // One more than the cap: enough to know the folder is too large, never all of a huge one.
        entries = await deps.fs.readdir(item.path, limits.maxEntriesPerDirectory + 1);
      } catch {
        skip("unreadable_folder");
        continue;
      }
      if (entries.length > limits.maxEntriesPerDirectory) {
        skip("folder_too_large");
        continue;
      }
      visited += entries.length;
      if (visited > limits.maxEntriesVisited) {
        stoppedBy = "entries";
        break rootLoop;
      }
      if (visited - reportedAt >= 500) {
        reportedAt = visited;
        deps.emit({ t: "visited", n: visited });
      }
      const isRepository = entries.some((entry) => entry.name === ".git");
      if (isRepository) {
        // A repository is a leaf: no nested search inside it.
        const rank = matchRank(item.name, query, job.source);
        if (rank !== null) {
          const key = found.length;
          found.push({ key, rootIndex, segments: item.segments, rank });
          deps.emit({ t: "found", key, rootIndex, segments: item.segments });
          if (found.length >= limits.maxCandidates) {
            stoppedBy = "candidates";
            break rootLoop;
          }
        }
        continue;
      }
      if (item.segments.length >= depthLimit) continue;
      for (const entry of entries) {
        if (entry.isSymbolicLink) {
          skip("symlink");
          continue;
        }
        if (!entry.isDirectory) continue;
        if (!isSafeSegmentName(entry.name)) continue;
        if (isSkippedName(entry.name, job.platform)) {
          skip("skipped_folder");
          continue;
        }
        const childPath = path.posix.join(item.path, entry.name);
        let stat: ScopeStat;
        try {
          stat = await deps.fs.lstat(childPath);
        } catch {
          skip("unreadable_folder");
          continue;
        }
        if (stat.isSymbolicLink || !stat.isDirectory) continue;
        if (stat.dev !== root.dev) {
          // Like `find -xdev`: mounted volumes and network shares are never entered.
          skip("other_file_system");
          continue;
        }
        queue.push({
          path: childPath,
          name: entry.name,
          segments: [...item.segments, { name: entry.name, dev: stat.dev, ino: stat.ino }],
        });
      }
    }
  }

  // Exact matches first, then the rest in the order found.
  const order = [...found].sort((a, b) => a.rank - b.rank || a.key - b.key);
  for (const candidate of order) {
    if (elapsed() >= limits.hardBudgetMs - 1_000) {
      stoppedBy ??= "time";
      break;
    }
    const root = job.roots[candidate.rootIndex];
    if (root === undefined) continue;
    const inspected = await inspectOrBlock(
      deps,
      root,
      candidate.rootIndex,
      candidate.segments,
      "full",
    );
    deps.emit(
      inspected === "changed"
        ? {
            t: "inspected",
            key: candidate.key,
            candidate: {
              rootIndex: candidate.rootIndex,
              segments: candidate.segments,
              gitIdentity: null,
              remote: { status: "unreadable" },
              block: { code: "unreadable", paths: [] },
            },
          }
        : { t: "inspected", key: candidate.key, candidate: inspected },
    );
  }
  deps.emit({
    t: "done",
    stoppedBy,
    elapsedMs: elapsed(),
    visited,
    skipped: [...skipped].map(([reason, count]) => ({ reason, count })),
  });
}

async function hasGitEntry(deps: InspectorDeps, directory: string): Promise<boolean> {
  try {
    await deps.fs.lstat(path.posix.join(directory, ".git"));
    return true;
  } catch {
    return false;
  }
}

/** Resolves a stored recent path by walking down from the scope root that contains it. */
async function resolveRecent(
  deps: InspectorDeps,
  roots: readonly ScopeRoot[],
  target: string,
): Promise<RecentOutcome> {
  if (!path.posix.isAbsolute(target) || path.posix.normalize(target) !== target) {
    return { status: "outside_scope" };
  }
  // The string prefix only chooses which root to walk from; containment is the walk itself.
  const rootIndex = roots.findIndex((root) => target.startsWith(`${root.path}/`));
  const root = roots[rootIndex];
  if (root === undefined) return { status: "outside_scope" };
  const names = target.slice(root.path.length + 1).split("/");
  // The same rules as the walk: depth, no skipped or dot folder on the way, no repository above.
  if (names.length - 1 > limitsOf(deps).depth) return { status: "outside_scope" };
  if (names.some((name) => isSkippedName(name, deps.platform))) return { status: "outside_scope" };
  let ancestor = root.path;
  for (const name of names.slice(0, -1).map((n) => n)) {
    if (await hasGitEntry(deps, ancestor)) return { status: "outside_scope" };
    ancestor = path.posix.join(ancestor, name);
  }
  if (await hasGitEntry(deps, ancestor)) {
    // `ancestor` is the parent of the candidate: a repository there makes this one nested.
    return { status: "outside_scope" };
  }
  const result = await inspectOrBlock(
    deps,
    root,
    rootIndex,
    names.map((name) => ({ name })),
    "full",
  );
  if (result === "changed") return { status: "gone" };
  return { status: "candidate", candidate: result };
}

/** Most folder names from the anchor down to a chosen folder. */
export const MAX_RESOLVE_SEGMENTS = 24;

/**
 * #414: a folder the user chose in the OS dialog or pasted. The path is resolved
 * with realpath (a symbolic link anywhere in it is resolved, never trusted as a name), must be a
 * directory, and must not be `/`, a top-level folder, the home folder or one of its parents.
 *
 * The anchor the chain is checked from: the home folder when the folder is inside it; otherwise
 * the highest folder above it, still owned by this user. Every folder from the anchor down is
 * then walked by name with `lstat` exactly like a search candidate, so the ownership and
 * write-bit rules are the same; the folder just above the anchor must not let another user
 * replace the anchor (writable by others without the sticky bit refuses).
 */
async function resolveFolder(
  deps: InspectorDeps,
  job: Extract<InspectorJob, { kind: "resolve" }>,
): Promise<void> {
  const refuse = (reason: ResolveRefusal, paths: string[] = []): void =>
    deps.emit({ t: "refused", reason, paths });
  if (!path.posix.isAbsolute(job.path) || job.path.includes("\0")) return refuse("missing");
  let target: string;
  try {
    target = await deps.fs.realpath(job.path);
  } catch (error) {
    return refuse(isGoneError(error) ? "missing" : "unreadable");
  }
  let stat: ScopeStat;
  try {
    stat = await deps.fs.lstat(target);
  } catch {
    return refuse("unreadable");
  }
  if (stat.isSymbolicLink || !stat.isDirectory) return refuse("not_a_directory");
  let home: string | null = null;
  try {
    home = path.posix.isAbsolute(job.homeDir) ? await deps.fs.realpath(job.homeDir) : null;
  } catch {
    home = null;
  }
  // The same rule as `pgard scan code`: not the root, a top-level folder, home or above it.
  if (tooBroadToScan(target, home, { pathApi: path.posix }) !== null) return refuse("too_broad");
  const kindOf = async (entry: string): Promise<EntryKind> => {
    try {
      const entryStat = await deps.fs.lstat(entry);
      if (entryStat.isSymbolicLink) return "other";
      return entryStat.isFile ? "file" : entryStat.isDirectory ? "directory" : "other";
    } catch {
      return null;
    }
  };
  // A Git directory (`.git`, its objects, a bare repository) is never scanned as code, the same
  // rule as `pgard scan code`.
  if (await isInsideGitDirectory(target, kindOf, { pathApi: path.posix })) {
    return refuse("git_directory", [target]);
  }
  // A folder inside a repository is checked and scanned as that repository (its top folder).
  const repositoryRoot = await enclosingRepositoryRoot(target, home, kindOf, {
    pathApi: path.posix,
  });
  const insideRepository = repositoryRoot !== null;
  if (repositoryRoot !== null) {
    target = repositoryRoot;
    try {
      stat = await deps.fs.lstat(target);
    } catch {
      return refuse("unreadable");
    }
    if (stat.isSymbolicLink || !stat.isDirectory) return refuse("unreadable");
    if (tooBroadToScan(target, home, { pathApi: path.posix }) !== null) {
      return refuse("too_broad");
    }
  }
  let anchor: string;
  if (home !== null && target.startsWith(`${home}/`)) {
    anchor = home;
  } else {
    if (safetyProblemOf(stat, deps.uid) === "not_owned_by_you") {
      return refuse("not_owned_by_you", [target]);
    }
    anchor = target;
    for (;;) {
      const parent = path.posix.dirname(anchor);
      if (parent === "/" || parent === anchor) break;
      let parentStat: ScopeStat;
      try {
        parentStat = await deps.fs.lstat(parent);
      } catch {
        return refuse("unreadable");
      }
      if (deps.uid === undefined || parentStat.uid !== deps.uid) break;
      anchor = parent;
    }
  }
  const above = path.posix.dirname(anchor);
  if (above !== anchor) {
    let aboveStat: ScopeStat;
    try {
      aboveStat = await deps.fs.lstat(above);
    } catch {
      return refuse("unreadable");
    }
    const isWritableByOthers = (aboveStat.mode & 0o022) !== 0;
    const isSticky = (aboveStat.mode & 0o1000) !== 0;
    if (isWritableByOthers && !isSticky) return refuse("group_or_world_writable", [above]);
  }
  const names = target === anchor ? [] : target.slice(anchor.length + 1).split("/");
  if (names.length > MAX_RESOLVE_SEGMENTS) return refuse("too_deep");
  let anchorStat: ScopeStat;
  try {
    anchorStat = await deps.fs.lstat(anchor);
  } catch {
    return refuse("unreadable");
  }
  if (anchorStat.isSymbolicLink || !anchorStat.isDirectory) return refuse("unreadable");
  const root: ScopeRoot = { path: anchor, dev: anchorStat.dev, ino: anchorStat.ino };
  const chain = names.map((name) => ({ name }));
  const candidate = await inspectOrBlock(deps, root, 0, chain, "full");
  if (candidate === "changed") return refuse("unreadable");
  const folder = await inspectOrBlock(deps, root, 0, candidate.segments, "folder");
  if (folder === "changed") return refuse("unreadable");
  deps.emit({
    t: "resolved",
    root,
    candidate,
    folderBlock: folder.block,
    ...(insideRepository ? { insideRepository: true } : {}),
  });
}

/** Entry point of one inspector job. Always ends with a `done` message. */
export async function runInspectorJob(deps: InspectorDeps, job: InspectorJob): Promise<void> {
  const started = deps.now();
  const done = (): void =>
    deps.emit({
      t: "done",
      stoppedBy: null,
      elapsedMs: deps.now() - started,
      visited: 0,
      skipped: [],
    });
  if (job.kind === "search") return runSearch(deps, job);
  if (job.kind === "resolve") {
    try {
      await resolveFolder(deps, job);
    } catch {
      deps.emit({ t: "refused", reason: "unreadable", paths: [] });
    }
    return done();
  }
  if (job.kind === "inspect") {
    const result = await inspectOrBlock(deps, job.root, 0, job.segments, job.mode);
    deps.emit(
      result === "changed" ? { t: "changed" } : { t: "inspected", key: 0, candidate: result },
    );
    return done();
  }
  for (const entry of job.entries) {
    let outcome: RecentOutcome;
    try {
      outcome = await resolveRecent(deps, job.roots, entry.path);
    } catch {
      outcome = { status: "unreadable" };
    }
    deps.emit({ t: "recent", entryId: entry.entryId, outcome });
  }
  return done();
}
