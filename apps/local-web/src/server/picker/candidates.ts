import { createHash, randomBytes } from "node:crypto";
import { sanitizeDisplayText } from "@pgard/http-local";
import type { ScopeRoot } from "@pgard/result-store";
import { foldName, hasUnsafeNameCharacter } from "../../shared/folder-name.js";
import type { PickerCandidate, PickerRemote } from "../../shared/picker-types.js";
import {
  PICKER_LIMITS,
  type ChainSegment,
  type GitIdentity,
  type PickerBlockCode,
  type RawCandidate,
} from "./protocol.js";

/**
 * Turns what the inspector found into what the browser may see and into the server-held record
 * the later confirm and scan checks compare against. The browser never receives a remote URL or
 * a remote name, only `owner/name` for a github.com remote.
 */

export function newId(): string {
  return randomBytes(16).toString("base64url");
}

/** Fixed English reason and fix per block code (the page maps the code to English or Korean). */
export const BLOCK_TEXT: Record<PickerBlockCode, { reason: string; fix: string }> = {
  not_a_git_root: {
    reason: "This folder is not a Git repository, or it is not the repository's top folder.",
    fix: "Pick the repository's top folder.",
  },
  no_commit_history: {
    reason: "The repository has no commits.",
    fix: "Make a first commit, then search again.",
  },
  isolation_failed: {
    reason:
      "The repository uses alternates, grafts or replace refs, so its history is not self-contained.",
    fix: "Use a normal clone.",
  },
  no_remote: {
    reason: "No remote points to github.com.",
    fix: "Run `git remote -v`, set one github.com remote, then search again.",
  },
  remote_not_github: {
    reason: "A remote of this repository does not point to github.com.",
    fix: "PGARD scans only github.com repositories you are authorized for.",
  },
  remote_ambiguous: {
    reason: "The remotes point to different repositories, or rewrite their URLs.",
    fix: "Run `git remote -v`, keep one github.com repository, then search again.",
  },
  remote_unreadable: {
    reason: "The remotes of this repository could not be read.",
    fix: "Run `git remote -v` in the folder, fix what it reports, then search again.",
  },
  not_owned_by_you: {
    reason: "This folder, or a folder above it, belongs to another user.",
    fix: "Clone it into your own folder.",
  },
  group_or_world_writable: {
    reason: "This folder, a folder above it, or its .git can be changed by other users.",
    fix: "Remove group and other write access with the command shown.",
  },
  gitfile_unsupported: {
    reason:
      "This project uses a linked worktree, a submodule or a .git pointer file. These are not supported yet.",
    fix: "Open the main clone of the repository instead.",
  },
  git_dir_unsupported: {
    reason: "This repository keeps its Git data outside the project folder.",
    fix: "Use a normal clone.",
  },
  outside_scope: {
    reason: "This recent project is outside the current search folders.",
    fix: "Add its folder in the terminal with `pgard web scope add`, or remove the entry.",
  },
  unsafe_display: {
    reason: "The path contains characters that cannot be shown safely.",
    fix: "Rename the folder, or pick another one.",
  },
  not_inspected: {
    reason: "The search ran out of time before this folder was checked.",
    fix: "Type more of the name, or narrow the search folders in the terminal.",
  },
  unreadable: {
    reason: "This folder could not be read in time.",
    fix: "Check that the folder is readable and not on a slow or disconnected drive, then search again.",
  },
};

export function shortenHome(absolutePath: string, homeDir: string): string {
  if (homeDir.length > 1 && absolutePath === homeDir) return "~";
  if (homeDir.length > 1 && absolutePath.startsWith(`${homeDir}/`)) {
    return `~${absolutePath.slice(homeDir.length)}`;
  }
  return absolutePath;
}

/** Visible escape of every non-printable character; a very long path is cut in the middle. */
export function escapeForDisplay(text: string): string {
  const escaped = [...text]
    .map((char) => {
      const code = char.codePointAt(0) ?? 0;
      const isUnsafe = hasUnsafeNameCharacter(char) || (code >= 0xd800 && code <= 0xdfff);
      return isUnsafe ? `\\u{${code.toString(16)}}` : char;
    })
    .join("");
  if (escaped.length <= PICKER_LIMITS.maxDisplayPathLength) return escaped;
  const head = escaped.slice(0, 180);
  const tail = escaped.slice(-180);
  return `${head} … (${text.length} characters) … ${tail}`;
}

/** Sanitized text, or `null` when sanitizing would change it (then it is not safe to show). */
export function sanitizedOrNull(text: string, maxLength: number): string | null {
  if (text.length > maxLength) return null;
  // Stricter than the sanitizer: invisible and look-alike characters are never shown as safe.
  if (hasUnsafeNameCharacter(text)) return null;
  const cleaned = sanitizeDisplayText(text, maxLength + 1);
  return cleaned === text ? cleaned : null;
}

/** Quotes one value for the shell (single quotes when needed). */
export function shellQuote(value: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * Quotes a `~`-shortened path for the `chmod` command: the leading `~` must stay unquoted or the
 * shell would not expand it (`~/'my dir'`, not `'~/my dir'`).
 */
export function shellQuoteHomePath(value: string): string {
  if (value === "~") return "~";
  if (value.startsWith("~/")) return `~/${shellQuote(value.slice(2))}`;
  return shellQuote(value);
}

function hash(parts: ReadonlyArray<string | number>): string {
  return createHash("sha256").update(JSON.stringify(parts)).digest("hex").slice(0, 32);
}

/** Identity of the chain from the scope root down to `.git/config`; no repository name. */
export function identityFingerprint(
  root: ScopeRoot,
  segments: readonly ChainSegment[],
  git: GitIdentity | null,
): string {
  return hash([
    root.dev,
    root.ino,
    ...segments.flatMap((segment) => [segment.name, segment.dev, segment.ino]),
    ...(git === null ? ["no-git"] : [git.gitDev, git.gitIno, git.configDev, git.configIno]),
  ]);
}

/** What the UI shows and echoes back: identity plus `owner/name`. */
export function shownFingerprint(fingerprint: string, repo: string | null): string {
  return hash([fingerprint, repo ?? ""]);
}

export function absolutePathOf(root: ScopeRoot, segments: readonly ChainSegment[]): string {
  return [root.path, ...segments.map((segment) => segment.name)].join("/");
}

/** The server-held record of a candidate; the browser only sees `dto`. */
export interface CandidateRecord {
  id: string;
  createdAt: number;
  source: "scope" | "recent";
  /** Set when this candidate came from a recent entry. */
  entryId: string | null;
  root: ScopeRoot;
  segments: ChainSegment[];
  /** The real path (never sent to the browser as is). */
  path: string;
  repo: { owner: string; name: string } | null;
  gitIdentity: GitIdentity | null;
  fingerprint: string;
  shown: string;
  isSelectable: boolean;
  /** PROTOTYPE (#414): selectable for a code-only scan only (see `PickerCandidate.codeOnly`). */
  isFolderOnly?: boolean;
  /**
   * PROTOTYPE (#414): chosen in the OS folder dialog or pasted. Never written to the recent list:
   * the recent list holds only folders found by the search the user set up.
   */
  isChosenFolder?: boolean;
  dto: PickerCandidate;
}

function remoteDto(raw: RawCandidate["remote"]): PickerRemote {
  return raw.status === "github"
    ? { status: "github", repo: sanitizeDisplayText(`${raw.owner}/${raw.name}`, 140) }
    : { status: raw.status };
}

export interface BuildInput {
  raw: RawCandidate;
  root: ScopeRoot;
  source: "scope" | "recent";
  entryId: string | null;
  homeDir: string;
  now: number;
}

/** Builds the record and the browser view of one inspected candidate. */
export function buildCandidate(input: BuildInput): CandidateRecord {
  const { raw, root, homeDir } = input;
  const path = absolutePathOf(root, raw.segments);
  const repo =
    raw.remote.status === "github" ? { owner: raw.remote.owner, name: raw.remote.name } : null;
  const fingerprint = identityFingerprint(root, raw.segments, raw.gitIdentity);
  const shown = shownFingerprint(fingerprint, repo === null ? null : `${repo.owner}/${repo.name}`);

  const shortPath = shortenHome(path, homeDir);
  const lastName = raw.segments.at(-1)?.name ?? root.path.split("/").at(-1) ?? "";
  const safePath = sanitizedOrNull(shortPath, PICKER_LIMITS.maxDisplayPathLength);
  const safeName = sanitizedOrNull(lastName, PICKER_LIMITS.maxDisplayNameLength);
  const blockedPaths = (raw.block?.paths ?? []).map((failing) =>
    sanitizedOrNull(shortenHome(failing, homeDir), PICKER_LIMITS.maxDisplayPathLength),
  );
  const isUnsafe = safePath === null || safeName === null || blockedPaths.includes(null);

  let blocked: PickerCandidate["blocked"] = null;
  if (isUnsafe) {
    blocked = { code: "unsafe_display", paths: [], ...BLOCK_TEXT.unsafe_display };
  } else if (raw.block !== null) {
    const text = BLOCK_TEXT[raw.block.code];
    const paths = blockedPaths as string[];
    blocked = {
      code: raw.block.code,
      paths,
      reason: text.reason,
      fix:
        raw.block.code === "group_or_world_writable" && paths.length > 0
          ? `chmod go-w ${paths.map(shellQuoteHomePath).join(" ")}`
          : text.fix,
    };
  }
  const isSelectable = blocked === null && repo !== null;
  const dto: PickerCandidate = {
    candidateId: newId(),
    name: safeName ?? sanitizeDisplayText(lastName, PICKER_LIMITS.maxDisplayNameLength),
    displayPath: safePath ?? sanitizeDisplayText(shortPath, PICKER_LIMITS.maxDisplayPathLength),
    displayPathEscaped: isUnsafe ? escapeForDisplay(shortPath) : null,
    collision: null,
    shown,
    remote: remoteDto(raw.remote),
    selectable: isSelectable,
    blocked,
    source: input.source,
  };
  return {
    id: dto.candidateId,
    createdAt: input.now,
    source: input.source,
    entryId: input.entryId,
    root,
    segments: raw.segments,
    path,
    repo,
    gitIdentity: raw.gitIdentity,
    fingerprint,
    shown,
    isSelectable,
    dto,
  };
}

/** A card for a folder that was found but not inspected in time. Never selectable. */
export function buildUninspected(input: {
  root: ScopeRoot;
  segments: ChainSegment[];
  homeDir: string;
  now: number;
}): CandidateRecord {
  return buildCandidate({
    raw: {
      rootIndex: 0,
      segments: input.segments,
      gitIdentity: null,
      remote: { status: "unreadable" },
      block: { code: "not_inspected", paths: [] },
    },
    root: input.root,
    source: "scope",
    entryId: null,
    homeDir: input.homeDir,
    now: input.now,
  });
}

/** A card for a recent entry outside the current scope: shown from stored text, never selectable. */
export function buildOutsideScope(input: {
  storedPath: string;
  homeDir: string;
  entryId: string;
  now: number;
  outcome: "outside_scope" | "unreadable" | "gone";
}): CandidateRecord {
  const shortPath = shortenHome(input.storedPath, input.homeDir);
  const safePath = sanitizedOrNull(shortPath, PICKER_LIMITS.maxDisplayPathLength);
  const lastName = input.storedPath.split("/").at(-1) ?? "";
  const safeName = sanitizedOrNull(lastName, PICKER_LIMITS.maxDisplayNameLength);
  const isUnsafe = safePath === null || safeName === null;
  const code: PickerBlockCode = isUnsafe
    ? "unsafe_display"
    : input.outcome === "gone"
      ? "not_a_git_root"
      : input.outcome;
  const text = BLOCK_TEXT[code];
  const dto: PickerCandidate = {
    candidateId: newId(),
    name: safeName ?? sanitizeDisplayText(lastName, PICKER_LIMITS.maxDisplayNameLength),
    displayPath: safePath ?? sanitizeDisplayText(shortPath, PICKER_LIMITS.maxDisplayPathLength),
    displayPathEscaped: isUnsafe ? escapeForDisplay(shortPath) : null,
    collision: null,
    shown: "",
    remote: { status: "unreadable" },
    selectable: false,
    blocked: { code, paths: [], ...text },
    source: "recent",
  };
  return {
    id: dto.candidateId,
    createdAt: input.now,
    source: "recent",
    entryId: input.entryId,
    root: { path: "", dev: 0, ino: 0 },
    segments: [],
    path: input.storedPath,
    repo: null,
    gitIdentity: null,
    fingerprint: "",
    shown: "",
    isSelectable: false,
    dto,
  };
}

/** Display paths compare NFC-normalized and case-folded, so look-alike forms collide too. */
function collisionKey(record: CandidateRecord): string {
  return foldName(record.dto.displayPath);
}

/** Marks every candidate whose display path another one shares, with a short tag. */
export function markCollisions(records: readonly CandidateRecord[]): void {
  const counts = new Map<string, number>();
  for (const record of records) {
    const key = collisionKey(record);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  for (const record of records) {
    if ((counts.get(collisionKey(record)) ?? 0) > 1) {
      const basis = record.shown === "" ? hash([record.path]) : record.shown;
      record.dto.collision = { tag: basis.slice(0, 6) };
    }
  }
}
