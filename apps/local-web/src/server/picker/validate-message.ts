import {
  ID_PATTERN,
  PICKER_BLOCK_CODES,
  RESOLVE_REFUSALS,
  type ChainSegment,
  type ChildMessage,
  type GitIdentity,
  type InspectorJob,
  type PickerBlockCode,
  type RawCandidate,
  type RecentOutcome,
  type RemoteInfo,
  type ResolveRefusal,
  type StoppedBy,
} from "./protocol.js";

/**
 * The inspector child reads untrusted directories, so what it sends back is data, not code or
 * trust: every message is checked here against a strict schema (known keys, types, sizes). A
 * message that does not fit ends the job as failed.
 */

/** A search walks at most this deep. */
const MAX_SEARCH_SEGMENTS = 8;
// A chosen folder (`resolve`, prototype #414) can be deeper below its anchor than a search walks.
const MAX_SEGMENTS = 32;
const MAX_NAME = 255;
const MAX_PATH = 4096;
const MAX_BLOCK_PATHS = 64;

type Obj = Record<string, unknown>;

function obj(value: unknown, keys: readonly string[]): Obj | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Obj;
  return Object.keys(record).every((key) => keys.includes(key)) ? record : null;
}

function isInt(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isText(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length <= max && !value.includes("\0");
}

function parseSegments(value: unknown, max = MAX_SEGMENTS): ChainSegment[] | null {
  if (!Array.isArray(value) || value.length > max) return null;
  const segments: ChainSegment[] = [];
  for (const entry of value) {
    const segment = obj(entry, ["name", "dev", "ino"]);
    if (
      segment === null ||
      !isText(segment.name, MAX_NAME) ||
      segment.name.length === 0 ||
      segment.name === "." ||
      segment.name === ".." ||
      segment.name.includes("/") ||
      !isInt(segment.dev) ||
      !isInt(segment.ino)
    ) {
      return null;
    }
    segments.push({ name: segment.name, dev: segment.dev, ino: segment.ino });
  }
  return segments;
}

function parseGitIdentity(value: unknown): GitIdentity | null | undefined {
  if (value === null) return null;
  const identity = obj(value, ["gitDev", "gitIno", "configDev", "configIno"]);
  if (
    identity === null ||
    !isInt(identity.gitDev) ||
    !isInt(identity.gitIno) ||
    !isInt(identity.configDev) ||
    !isInt(identity.configIno)
  ) {
    return undefined;
  }
  return {
    gitDev: identity.gitDev,
    gitIno: identity.gitIno,
    configDev: identity.configDev,
    configIno: identity.configIno,
  };
}

const OWNER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_NAME_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;

function parseRemote(value: unknown): RemoteInfo | null {
  const record = obj(value, ["status", "owner", "name"]);
  if (record === null) return null;
  if (record.status === "github") {
    return typeof record.owner === "string" &&
      typeof record.name === "string" &&
      OWNER_PATTERN.test(record.owner) &&
      REPO_NAME_PATTERN.test(record.name)
      ? { status: "github", owner: record.owner, name: record.name }
      : null;
  }
  if (
    (record.status === "none" ||
      record.status === "not_github" ||
      record.status === "ambiguous" ||
      record.status === "unreadable") &&
    record.owner === undefined &&
    record.name === undefined
  ) {
    return { status: record.status };
  }
  return null;
}

function parseCandidate(
  value: unknown,
  rootCount: number,
  needsRemote = true,
  allowNoGit = false,
): RawCandidate | null {
  const record = obj(value, ["rootIndex", "segments", "gitIdentity", "remote", "block"]);
  if (record === null || !isInt(record.rootIndex) || record.rootIndex >= rootCount) return null;
  const segments = parseSegments(record.segments);
  const gitIdentity = parseGitIdentity(record.gitIdentity);
  const remote = parseRemote(record.remote);
  if (segments === null || gitIdentity === undefined || remote === null) return null;
  let block: RawCandidate["block"] = null;
  if (record.block !== null) {
    const raw = obj(record.block, ["code", "paths"]);
    if (
      raw === null ||
      typeof raw.code !== "string" ||
      !(PICKER_BLOCK_CODES as readonly string[]).includes(raw.code) ||
      !Array.isArray(raw.paths) ||
      raw.paths.length > MAX_BLOCK_PATHS ||
      !raw.paths.every((entry) => isText(entry, MAX_PATH))
    ) {
      return null;
    }
    block = { code: raw.code as PickerBlockCode, paths: raw.paths as string[] };
  }
  // A selectable candidate needs a github remote, a clean block and a known `.git` identity.
  // A `folder` re-check (code-only, prototype #414) has no Git identity and no remote.
  if (
    block === null &&
    ((needsRemote && remote.status !== "github") || (gitIdentity === null && !allowNoGit))
  ) {
    return null;
  }
  return { rootIndex: record.rootIndex, segments, gitIdentity, remote, block };
}

function parseRecentOutcome(value: unknown, rootCount: number): RecentOutcome | null {
  const record = obj(value, ["status", "candidate"]);
  if (record === null) return null;
  if (record.status === "candidate") {
    const candidate = parseCandidate(record.candidate, rootCount);
    return candidate === null ? null : { status: "candidate", candidate };
  }
  if (
    (record.status === "outside_scope" ||
      record.status === "unreadable" ||
      record.status === "gone") &&
    record.candidate === undefined
  ) {
    return { status: record.status };
  }
  return null;
}

const STOPPED: ReadonlyArray<StoppedBy> = ["time", "entries", "candidates", null];

/** The only blocks a `folder` check can report. */
const FOLDER_BLOCKS: readonly PickerBlockCode[] = ["not_owned_by_you", "group_or_world_writable"];

/** Returns the validated message, or `null` when it does not fit the schema for this job. */
export function validateChildMessage(raw: unknown, job: InspectorJob): ChildMessage | null {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
  const rootCount = job.kind === "inspect" || job.kind === "resolve" ? 1 : job.roots.length;
  switch ((raw as Obj).t) {
    case "visited": {
      const message = obj(raw, ["t", "n"]);
      return message !== null && isInt(message.n) ? { t: "visited", n: message.n } : null;
    }
    case "found": {
      const message = obj(raw, ["t", "key", "rootIndex", "segments"]);
      const segments =
        message === null ? null : parseSegments(message.segments, MAX_SEARCH_SEGMENTS);
      return message !== null &&
        job.kind === "search" &&
        isInt(message.key) &&
        isInt(message.rootIndex) &&
        message.rootIndex < rootCount &&
        segments !== null
        ? { t: "found", key: message.key, rootIndex: message.rootIndex, segments }
        : null;
    }
    case "inspected": {
      const message = obj(raw, ["t", "key", "candidate"]);
      const needsRemote = !(job.kind === "inspect" && job.mode !== "full");
      const allowNoGit = job.kind === "inspect" && job.mode === "folder";
      const candidate =
        message === null
          ? null
          : parseCandidate(message.candidate, rootCount, needsRemote, allowNoGit);
      return message !== null &&
        (job.kind === "search" || job.kind === "inspect") &&
        isInt(message.key) &&
        candidate !== null &&
        (job.kind !== "search" || candidate.segments.length <= MAX_SEARCH_SEGMENTS)
        ? { t: "inspected", key: message.key, candidate }
        : null;
    }
    case "resolved": {
      if (job.kind !== "resolve") return null;
      const message = obj(raw, ["t", "root", "candidate", "folderBlock"]);
      if (message === null) return null;
      const root = obj(message.root, ["path", "dev", "ino"]);
      if (
        root === null ||
        !isText(root.path, MAX_PATH) ||
        !root.path.startsWith("/") ||
        !isInt(root.dev) ||
        !isInt(root.ino)
      ) {
        return null;
      }
      const candidate = parseCandidate(message.candidate, 1);
      // The folder result carries only the ownership and write-bit block of the chain.
      const folder = parseCandidate(
        {
          rootIndex: 0,
          segments: candidate?.segments ?? [],
          gitIdentity: null,
          remote: { status: "unreadable" },
          block: message.folderBlock,
        },
        1,
        false,
        true,
      );
      if (candidate === null || folder === null) return null;
      if (folder.block !== null && !FOLDER_BLOCKS.includes(folder.block.code)) return null;
      return {
        t: "resolved",
        root: { path: root.path, dev: root.dev, ino: root.ino },
        candidate,
        folderBlock: folder.block,
      };
    }
    case "refused": {
      if (job.kind !== "resolve") return null;
      const message = obj(raw, ["t", "reason", "paths"]);
      if (
        message === null ||
        typeof message.reason !== "string" ||
        !(RESOLVE_REFUSALS as readonly string[]).includes(message.reason) ||
        !Array.isArray(message.paths) ||
        message.paths.length > MAX_BLOCK_PATHS ||
        !message.paths.every((entry) => isText(entry, MAX_PATH))
      ) {
        return null;
      }
      return {
        t: "refused",
        reason: message.reason as ResolveRefusal,
        paths: message.paths as string[],
      };
    }
    case "changed":
      return obj(raw, ["t"]) !== null && job.kind === "inspect" ? { t: "changed" } : null;
    case "recent": {
      const message = obj(raw, ["t", "entryId", "outcome"]);
      const outcome = message === null ? null : parseRecentOutcome(message.outcome, rootCount);
      return message !== null &&
        job.kind === "recent" &&
        typeof message.entryId === "string" &&
        ID_PATTERN.test(message.entryId) &&
        outcome !== null
        ? { t: "recent", entryId: message.entryId, outcome }
        : null;
    }
    case "done": {
      const message = obj(raw, ["t", "stoppedBy", "elapsedMs", "visited", "skipped"]);
      if (
        message === null ||
        !STOPPED.includes(message.stoppedBy as StoppedBy) ||
        typeof message.elapsedMs !== "number" ||
        !Number.isFinite(message.elapsedMs) ||
        message.elapsedMs < 0 ||
        !isInt(message.visited) ||
        !Array.isArray(message.skipped) ||
        message.skipped.length > 16
      ) {
        return null;
      }
      const skipped: Array<{ reason: string; count: number }> = [];
      for (const entry of message.skipped) {
        const item = obj(entry, ["reason", "count"]);
        if (item === null || !isText(item.reason, 40) || !isInt(item.count)) return null;
        skipped.push({ reason: item.reason, count: item.count });
      }
      return {
        t: "done",
        stoppedBy: message.stoppedBy as StoppedBy,
        elapsedMs: message.elapsedMs,
        visited: message.visited,
        skipped,
      };
    }
    default:
      return null;
  }
}
