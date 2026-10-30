import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, mkdir, open, readdir, rmdir, unlink } from "node:fs/promises";
import path from "node:path";
import {
  AUTHORIZATION_CHECK_IDS,
  readIncrementalState,
  readScanResult,
  SCHEMA_VERSION,
  stringifyJsonSafely,
  type IncrementalState,
  type ScanResult,
} from "@pgard/findings";
import {
  ensureOwnerOnlyDirectory,
  errnoOf,
  readFileCapped,
  SAFE_FILE_MODE,
  SafeFileError,
  writeFileAtomically,
  type SafeFileEnvironment,
} from "./safe-file.js";

/**
 * Local store of already-redacted scan results. Layout (all below one app-data directory):
 *
 *   <dir>/repos/<GitHub repository id>/<savedAtMs>-<hash of scanId>.json
 *   <dir>/.notice-shown            (marker: the first-run notice was printed)
 *
 * Keys are GitHub's numeric repository id, never a local path. Nothing here caches an
 * authorization: the gate runs on every scan, and `save` only accepts results the gate allowed.
 */

/** Scans kept per repository. Older ones are pruned after each save. */
export const RETENTION_MAX_SCANS_PER_REPO = 20;
/** Scans older than this many days are pruned after each save. */
export const RETENTION_MAX_AGE_DAYS = 90;
/** Largest result file read or written. Checked before `JSON.parse`; real results are far smaller. */
export const MAX_RESULT_FILE_BYTES = 8 * 1024 * 1024;

const MS_PER_DAY = 86_400_000;
const REPOS_DIRECTORY = "repos";
const NOTICE_MARKER = ".notice-shown";
const TEMP_PREFIX = ".tmp-";
/** Leftover temp files (a crashed write) older than this are removed by prune. */
const STALE_TEMP_MS = 3_600_000;
/** The repository's baseline (`pgard baseline set`); not a result, so retention never prunes it. */
const BASELINE_FILE = "baseline.json";
const BASELINE_KIND = "pgard-baseline";
const BASELINE_VERSION = 1;
const RESULT_FILE_PATTERN = /^(\d{13})-([0-9a-f]{16})\.json$/;
const FILE_MODE = SAFE_FILE_MODE;

export type StoreErrorCode =
  | "unavailable"
  | "invalid_input"
  | "not_allowed"
  | "contains_local_path"
  | "too_large"
  | "symlink"
  | "not_directory"
  | "wrong_owner"
  | "permissions"
  | "would_overwrite"
  | "io";

export interface StoreError {
  code: StoreErrorCode;
  message: string;
}

class StoreFailure extends Error {
  constructor(
    readonly code: StoreErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "StoreFailure";
  }
}

export interface SaveOptions {
  /** GitHub's numeric repository id from the authorization of this very scan. */
  repositoryId: number;
  /**
   * Strings that must not appear anywhere in the stored text (for example the absolute project
   * root). A defence in depth behind redaction: the save is refused instead.
   */
  forbidSubstrings?: readonly string[];
  /**
   * What a later incremental scan needs (per-file hashes and findings). Stored in the same file
   * as the result, so it can never belong to another scan. It is left out, and the result is
   * still saved, when it holds a forbidden string or would make the file too large.
   */
  incrementalState?: IncrementalState | null;
}

export type SaveOutcome =
  { ok: true; file: string; pruned: number } | { ok: false; error: StoreError };

export interface StoredScan {
  file: string;
  /** When PGARD stored it. */
  savedAt: Date;
  result: ScanResult;
  /** The `schemaVersion` the file carried (may be a newer minor). */
  sourceVersion: string;
  /** The incremental state stored with the result; null when there is none or it is unreadable. */
  incrementalState: IncrementalState | null;
  /** Why the state was left out when it was offered (too large, or it failed the checks). */
  incrementalStateOmitted: "too_large" | "rejected" | null;
}

/** The reference scan of a repository. */
export interface StoredBaseline {
  /** When the user set it. */
  setAt: Date;
  /** The repository id (from the gate) it was set for; checked against the id it is read for. */
  repositoryId: number;
  /** The redacted result the baseline was made from. */
  result: ScanResult;
  /** The `schemaVersion` the scan inside the file carried. */
  sourceVersion: string;
}

export type SetBaselineOutcome = { ok: true } | { ok: false; error: StoreError };
export type ClearBaselineOutcome =
  { ok: true; removed: boolean } | { ok: false; error: StoreError };
export type GetBaselineOutcome =
  { ok: true; baseline: StoredBaseline | null } | { ok: false; error: StoreError };

export interface ListOutcome {
  /** Newest first. */
  scans: StoredScan[];
  /** One line per file that was skipped (corrupt, oversized, unsupported version, unsafe). */
  warnings: string[];
  /** Readable scans that `isUsable` turned down (counted, not returned). Only with `ListOptions`. */
  rejected: number;
  /** Result files not opened because `limit` was reached. Only with `ListOptions`. */
  unread: number;
}

export interface ListOptions {
  /** Stop after this many usable scans; the files after that are counted in `unread`. */
  limit?: number;
  /** Scans for which this returns false are counted in `rejected` and do not use up `limit`. */
  isUsable?: (scan: StoredScan) => boolean;
}

export interface FindNewestOutcome {
  /** The newest stored scan that was readable and accepted; null when there is none. */
  scan: StoredScan | null;
  /** One line per file skipped on the way (unreadable, or rejected by `accept`). */
  warnings: string[];
}

export type LoadOutcome = { ok: true; scan: StoredScan } | { ok: false; error: StoreError };

export interface ClearOptions {
  /** Only this repository id. */
  repositoryId?: number;
  /** Only repositories whose stored results name this `owner/name` (case-insensitive). */
  repoName?: string;
}

export interface ClearOutcome {
  /** Result files deleted. */
  removed: number;
  /** Baselines deleted with them (a clear removes the baseline of every repository it touches). */
  baselinesRemoved: number;
  /** Files that could not be matched or deleted (named by `warnings`). */
  warnings: string[];
}

export interface ResultStoreOptions {
  dir: string;
  now?: () => number;
  maxScansPerRepo?: number;
  maxAgeDays?: number;
  /** For tests; defaults to the platform. */
  platform?: NodeJS.Platform;
  /** For tests; defaults to `process.getuid`. Directories owned by another uid are refused. */
  getuid?: () => number | undefined;
}

export interface ResultStore {
  readonly dir: string;
  save(result: ScanResult, options: SaveOptions): Promise<SaveOutcome>;
  list(repositoryId: number, options?: ListOptions): Promise<ListOutcome>;
  load(repositoryId: number, file: string): Promise<LoadOutcome>;
  /**
   * Reads stored scans newest first and stops at the first one that is readable and that
   * `accept` approves (it returns null to approve, or a reason to skip the file with a warning).
   * Unlike `list`, older files are not read once one is accepted.
   */
  findNewest(
    repositoryId: number,
    accept: (scan: StoredScan) => string | null,
  ): Promise<FindNewestOutcome>;
  prune(repositoryId: number): Promise<number>;
  /**
   * Stores `result` as the repository's baseline (replacing an earlier one). Same rules as
   * `save`: only a result the gate allowed, redacted text only, owner-only permissions, no
   * symbolic links.
   */
  setBaseline(result: ScanResult, options: SaveOptions): Promise<SetBaselineOutcome>;
  /** The baseline, or `baseline: null` when there is none. A corrupt file is an error, not "none". */
  getBaseline(repositoryId: number): Promise<GetBaselineOutcome>;
  /** Deletes the baseline: `removed` is false when there was none; a failure is an error. */
  clearBaseline(repositoryId: number): Promise<ClearBaselineOutcome>;
  clear(options?: ClearOptions): Promise<ClearOutcome>;
  /** True exactly once per store directory (the caller prints the first-run notice then). */
  claimFirstRunNotice(): Promise<boolean>;
}

const NO_FOLLOW = fsConstants.O_NOFOLLOW ?? 0;

const SYMLINK_HINT = "Remove the link by hand, then try again.";

function toStoreError(error: unknown): StoreError {
  if (error instanceof StoreFailure) {
    return {
      code: error.code,
      message: error.code === "symlink" ? `${error.message} ${SYMLINK_HINT}` : error.message,
    };
  }
  const code = errnoOf(error);
  if (code === "ELOOP") {
    return {
      code: "symlink",
      message: `Refusing to follow a symbolic link in the result store. ${SYMLINK_HINT}`,
    };
  }
  return { code: "io", message: `The result store could not be accessed (${code ?? "error"}).` };
}

/** Maps the shared helpers' errors to this store's own failure type; others pass through. */
function asStoreFailure(error: unknown): unknown {
  return error instanceof SafeFileError ? new StoreFailure(error.code, error.message) : error;
}

function isRepositoryId(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isNewerVersion(sourceVersion: string): boolean {
  const [major = 0, minor = 0] = sourceVersion.split(".").map(Number);
  const [currentMajor = 0, currentMinor = 0] = SCHEMA_VERSION.split(".").map(Number);
  return major > currentMajor || (major === currentMajor && minor > currentMinor);
}

/** The gate allowed this scan: exactly the five known checks, all passed. */
export function isAllowedByGate(result: ScanResult): boolean {
  const { decision, checks } = result.authorization;
  // 1.7: a code-only result is never stored, whatever its checks say (defence in depth).
  if (result.scanBasis !== undefined && result.scanBasis.authorization !== "verified") return false;
  return (
    decision === "allowed" &&
    checks.length === AUTHORIZATION_CHECK_IDS.length &&
    AUTHORIZATION_CHECK_IDS.every(
      (id, index) => checks[index]?.id === id && checks[index]?.status === "passed",
    )
  );
}

export function createResultStore(options: ResultStoreOptions): ResultStore {
  const root = options.dir;
  const now = options.now ?? Date.now;
  const maxScans = options.maxScansPerRepo ?? RETENTION_MAX_SCANS_PER_REPO;
  const maxAgeMs = (options.maxAgeDays ?? RETENTION_MAX_AGE_DAYS) * MS_PER_DAY;
  const isPosix = (options.platform ?? process.platform) !== "win32";
  const getuid = options.getuid ?? (() => process.getuid?.());
  const reposDir = path.join(root, REPOS_DIRECTORY);

  const environment: SafeFileEnvironment = { isPosix, getuid };

  /** Creates (owner-only) or validates a directory: no symlink, ours, 0700. */
  async function ensureDirectory(dir: string, create = true): Promise<void> {
    try {
      await ensureOwnerOnlyDirectory(dir, environment, create);
    } catch (error) {
      throw asStoreFailure(error);
    }
  }

  async function ensureRoot(): Promise<void> {
    await mkdir(path.dirname(root), { recursive: true });
    await ensureDirectory(root);
  }

  async function ensureRepoDirectory(repositoryId: number): Promise<string> {
    await ensureRoot();
    await ensureDirectory(reposDir);
    const dir = path.join(reposDir, String(repositoryId));
    await ensureDirectory(dir);
    return dir;
  }

  /** Reads a regular file without following a symlink, capped before parsing. */
  async function readCapped(file: string, refuseWritableByOthers = false): Promise<string> {
    try {
      return await readFileCapped(file, MAX_RESULT_FILE_BYTES, environment, refuseWritableByOthers);
    } catch (error) {
      throw asStoreFailure(error);
    }
  }

  function parseStored(file: string, text: string): StoredScan {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new StoreFailure("invalid_input", "The file is not valid JSON.");
    }
    const outcome = readScanResult(parsed);
    if (!outcome.ok) {
      throw new StoreFailure("invalid_input", `${outcome.error.code}: ${outcome.error.message}`);
    }
    const match = RESULT_FILE_PATTERN.exec(file);
    const stateDescriptor =
      typeof parsed === "object" && parsed !== null
        ? Object.getOwnPropertyDescriptor(parsed, "incrementalState")
        : undefined;
    const omittedDescriptor =
      typeof parsed === "object" && parsed !== null
        ? Object.getOwnPropertyDescriptor(parsed, "incrementalStateOmitted")
        : undefined;
    const omittedValue =
      omittedDescriptor !== undefined && "value" in omittedDescriptor
        ? omittedDescriptor.value
        : null;
    return {
      file,
      savedAt: new Date(Number(match?.[1] ?? 0)),
      incrementalStateOmitted:
        omittedValue === "too_large" || omittedValue === "rejected" ? omittedValue : null,
      result: outcome.result,
      sourceVersion: outcome.sourceVersion,
      incrementalState:
        stateDescriptor !== undefined && "value" in stateDescriptor
          ? readIncrementalState(stateDescriptor.value)
          : null,
    };
  }

  function fileNameFor(result: ScanResult, savedAtMs: number): string {
    const digest = createHash("sha256").update(result.scanId).digest("hex").slice(0, 16);
    return `${String(savedAtMs).padStart(13, "0")}-${digest}.json`;
  }

  /** Temp file in the same directory, owner-only, fsynced, then renamed over the target. */
  async function writeAtomically(
    dir: string,
    finalName: string,
    text: string,
    /** Version of an existing file; throws when it is unreadable. */
    existingVersion: (name: string, text: string) => string = (name, body) =>
      parseStored(name, body).sourceVersion,
    /** A baseline that cannot be read may be replaced: the user asked for a new one. */
    replaceUnreadable = false,
  ): Promise<void> {
    try {
      await writeFileAtomically(dir, finalName, text, environment, {
        tempPrefix: TEMP_PREFIX,
        // Never replace a file written by a newer PGARD, or one we cannot read.
        checkExisting: async (finalPath) => {
          let blocked: string | null = null;
          try {
            const version = existingVersion(finalName, await readCapped(finalPath));
            if (isNewerVersion(version)) {
              blocked = "A stored file with a newer schema version already has this name.";
            }
          } catch {
            if (!replaceUnreadable) blocked = "An unreadable stored file already has this name.";
          }
          if (blocked !== null) throw new StoreFailure("would_overwrite", blocked);
        },
      });
    } catch (error) {
      throw asStoreFailure(error);
    }
  }

  function parseBaseline(text: string): StoredBaseline {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new StoreFailure("invalid_input", "The baseline file is not valid JSON.");
    }
    const record = parsed as Record<string, unknown> | null;
    if (
      typeof record !== "object" ||
      record === null ||
      record.kind !== BASELINE_KIND ||
      record.version !== BASELINE_VERSION ||
      typeof record.setAt !== "string" ||
      !isRepositoryId(record.repositoryId)
    ) {
      throw new StoreFailure("invalid_input", "The baseline file is not a PGARD baseline.");
    }
    const setAt = new Date(record.setAt);
    if (Number.isNaN(setAt.getTime())) {
      throw new StoreFailure("invalid_input", "The baseline file has no valid date.");
    }
    const outcome = readScanResult(record.result);
    if (!outcome.ok) {
      throw new StoreFailure("invalid_input", `${outcome.error.code}: ${outcome.error.message}`);
    }
    return {
      setAt,
      repositoryId: record.repositoryId,
      result: outcome.result,
      sourceVersion: outcome.sourceVersion,
    };
  }

  async function listFiles(dir: string): Promise<string[]> {
    try {
      return await readdir(dir);
    } catch (error) {
      if (errnoOf(error) === "ENOENT") return [];
      throw error;
    }
  }

  async function pruneDirectory(dir: string, keep: string | null = null): Promise<number> {
    const names = await listFiles(dir);
    const timestamp = now();
    const results = names
      .map((name) => ({ name, match: RESULT_FILE_PATTERN.exec(name) }))
      .filter((entry): entry is { name: string; match: RegExpExecArray } => entry.match !== null)
      .map((entry) => ({
        name: entry.name,
        savedAt: Number(entry.match[1]),
        // Dated in the future (clock skew or tampering): cannot be a real scan yet.
        isFuture: Number(entry.match[1]) > timestamp,
      }))
      // The file just written comes first, so it is never the one pruned. Future-dated files
      // come last, so real scans are never crowded out by them; among the rest, newest first.
      .sort(
        (a, b) =>
          Number(b.name === keep) - Number(a.name === keep) ||
          Number(a.isFuture) - Number(b.isFuture) ||
          b.savedAt - a.savedAt ||
          (a.name < b.name ? 1 : -1),
      );
    const doomed = results
      .filter(
        (entry, index) =>
          entry.name !== keep &&
          (index >= maxScans || (!entry.isFuture && timestamp - entry.savedAt > maxAgeMs)),
      )
      .map((entry) => entry.name);
    for (const name of names) {
      if (!name.startsWith(TEMP_PREFIX)) continue;
      try {
        const stat = await lstat(path.join(dir, name));
        if (timestamp - stat.mtimeMs > STALE_TEMP_MS) doomed.push(name);
      } catch {
        // Gone already.
      }
    }
    let removed = 0;
    for (const name of doomed) {
      try {
        // unlink removes a symlink itself and never follows it.
        await unlink(path.join(dir, name));
        removed += 1;
      } catch {
        // Another process pruned it first, or it is not ours to delete.
      }
    }
    return removed;
  }

  return {
    dir: root,

    async save(result, saveOptions) {
      try {
        if (!isRepositoryId(saveOptions.repositoryId)) {
          throw new StoreFailure("invalid_input", "A GitHub repository id is required.");
        }
        if (
          !isAllowedByGate(result) ||
          result.overallStatus === "blocked" ||
          result.overallStatus === "failed"
        ) {
          throw new StoreFailure("not_allowed", "Only results of an allowed scan are stored.");
        }
        const checked = readScanResult(JSON.parse(JSON.stringify(result)) as unknown);
        if (!checked.ok) {
          throw new StoreFailure(
            "invalid_input",
            `The result is not valid: ${checked.error.code}.`,
          );
        }
        let text = `${stringifyJsonSafely(checked.result)}\n`;
        const containsForbidden = (body: string): boolean =>
          (saveOptions.forbidSubstrings ?? []).some((forbidden) => {
            // The file holds JSON text, where a backslash is written twice (Windows paths):
            // check the raw form and the escaped form.
            const escaped = stringifyJsonSafely(forbidden).slice(1, -1);
            return forbidden !== "" && (body.includes(forbidden) || body.includes(escaped));
          });
        if (containsForbidden(text)) {
          throw new StoreFailure("contains_local_path", "The result contains a local path.");
        }
        if (Buffer.byteLength(text, "utf8") > MAX_RESULT_FILE_BYTES) {
          throw new StoreFailure("too_large", "The result is too large to store.");
        }
        // The state is an optimization: when it does not fit or does not pass the same checks,
        // the result is stored without it and the next scan is a full one.
        const state = saveOptions.incrementalState
          ? readIncrementalState(JSON.parse(JSON.stringify(saveOptions.incrementalState)))
          : null;
        // The reason is stored too, so the next scan can say why it has no reusable data.
        let omitted: "too_large" | "rejected" | null =
          saveOptions.incrementalState && state === null ? "rejected" : null;
        if (state !== null) {
          const withState = `${stringifyJsonSafely({ ...checked.result, incrementalState: state })}\n`;
          if (Buffer.byteLength(withState, "utf8") > MAX_RESULT_FILE_BYTES) omitted = "too_large";
          else if (containsForbidden(withState)) omitted = "rejected";
          else text = withState;
        }
        if (omitted !== null) {
          text = `${stringifyJsonSafely({ ...checked.result, incrementalStateOmitted: omitted })}\n`;
        }
        const dir = await ensureRepoDirectory(saveOptions.repositoryId);
        const file = fileNameFor(checked.result, now());
        await writeAtomically(dir, file, text);
        const pruned = await pruneDirectory(dir, file).catch(() => 0);
        return { ok: true, file, pruned };
      } catch (error) {
        return { ok: false, error: toStoreError(error) };
      }
    },

    async setBaseline(result, saveOptions) {
      try {
        if (!isRepositoryId(saveOptions.repositoryId)) {
          throw new StoreFailure("invalid_input", "A GitHub repository id is required.");
        }
        if (
          !isAllowedByGate(result) ||
          result.overallStatus === "blocked" ||
          result.overallStatus === "failed"
        ) {
          throw new StoreFailure(
            "not_allowed",
            "Only results of an allowed scan can be a baseline.",
          );
        }
        const checked = readScanResult(JSON.parse(JSON.stringify(result)) as unknown);
        if (!checked.ok) {
          throw new StoreFailure(
            "invalid_input",
            `The result is not valid: ${checked.error.code}.`,
          );
        }
        const text = `${stringifyJsonSafely({
          kind: BASELINE_KIND,
          version: BASELINE_VERSION,
          setAt: new Date(now()).toISOString(),
          repositoryId: saveOptions.repositoryId,
          result: checked.result,
        })}\n`;
        for (const forbidden of saveOptions.forbidSubstrings ?? []) {
          const escaped = stringifyJsonSafely(forbidden).slice(1, -1);
          if (forbidden !== "" && (text.includes(forbidden) || text.includes(escaped))) {
            throw new StoreFailure("contains_local_path", "The result contains a local path.");
          }
        }
        if (Buffer.byteLength(text, "utf8") > MAX_RESULT_FILE_BYTES) {
          throw new StoreFailure("too_large", "The result is too large to store.");
        }
        const dir = await ensureRepoDirectory(saveOptions.repositoryId);
        await writeAtomically(
          dir,
          BASELINE_FILE,
          text,
          (_name, body) => parseBaseline(body).sourceVersion,
          true,
        );
        return { ok: true };
      } catch (error) {
        return { ok: false, error: toStoreError(error) };
      }
    },

    async getBaseline(repositoryId) {
      if (!isRepositoryId(repositoryId)) return { ok: true, baseline: null };
      try {
        const dir = path.join(reposDir, String(repositoryId));
        try {
          await ensureDirectory(root, false);
          await ensureDirectory(reposDir, false);
          await ensureDirectory(dir, false);
        } catch (error) {
          if (errnoOf(error) === "ENOENT") return { ok: true, baseline: null };
          throw error;
        }
        try {
          const text = await readCapped(path.join(dir, BASELINE_FILE), true);
          const baseline = parseBaseline(text);
          if (baseline.repositoryId !== repositoryId) {
            throw new StoreFailure(
              "invalid_input",
              "The baseline was set for another repository and is not used.",
            );
          }
          return { ok: true, baseline };
        } catch (error) {
          if (errnoOf(error) === "ENOENT") return { ok: true, baseline: null };
          throw error;
        }
      } catch (error) {
        return { ok: false, error: toStoreError(error) };
      }
    },

    async clearBaseline(repositoryId) {
      if (!isRepositoryId(repositoryId)) return { ok: true, removed: false };
      try {
        const dir = path.join(reposDir, String(repositoryId));
        try {
          await ensureDirectory(root, false);
          await ensureDirectory(reposDir, false);
          await ensureDirectory(dir, false);
          // unlink removes a symlink itself and never follows it.
          await unlink(path.join(dir, BASELINE_FILE));
        } catch (error) {
          if (errnoOf(error) === "ENOENT") return { ok: true, removed: false };
          throw error;
        }
        return { ok: true, removed: true };
      } catch (error) {
        return { ok: false, error: toStoreError(error) };
      }
    },

    async list(repositoryId, listOptions = {}) {
      const outcome: ListOutcome = { scans: [], warnings: [], rejected: 0, unread: 0 };
      const limit = listOptions.limit ?? Number.POSITIVE_INFINITY;
      // Files opened at most: a directory of unusable files must not be read to the end either.
      const maxOpened = limit * 5;
      if (!isRepositoryId(repositoryId)) return outcome;
      const dir = path.join(reposDir, String(repositoryId));
      let names: string[];
      try {
        await ensureDirectory(root, false);
        await ensureDirectory(reposDir, false);
        await ensureDirectory(dir, false);
        names = await listFiles(dir);
      } catch (error) {
        if (errnoOf(error) !== "ENOENT") outcome.warnings.push(toStoreError(error).message);
        return outcome;
      }
      const files = names
        .filter((n) => RESULT_FILE_PATTERN.test(n))
        .sort()
        .reverse();
      let opened = 0;
      for (const [index, name] of files.entries()) {
        if (outcome.scans.length >= limit || opened >= maxOpened) {
          outcome.unread = files.length - index;
          break;
        }
        opened += 1;
        try {
          const scan = parseStored(name, await readCapped(path.join(dir, name)));
          if (listOptions.isUsable === undefined || listOptions.isUsable(scan)) {
            outcome.scans.push(scan);
          } else {
            outcome.rejected += 1;
          }
        } catch (error) {
          outcome.warnings.push(`Skipped stored result ${name}: ${toStoreError(error).message}`);
        }
      }
      return outcome;
    },

    async findNewest(repositoryId, accept) {
      const outcome: FindNewestOutcome = { scan: null, warnings: [] };
      if (!isRepositoryId(repositoryId)) return outcome;
      const dir = path.join(reposDir, String(repositoryId));
      let names: string[];
      try {
        await ensureDirectory(root, false);
        await ensureDirectory(reposDir, false);
        await ensureDirectory(dir, false);
        names = await listFiles(dir);
      } catch (error) {
        if (errnoOf(error) !== "ENOENT") outcome.warnings.push(toStoreError(error).message);
        return outcome;
      }
      for (const name of names
        .filter((n) => RESULT_FILE_PATTERN.test(n))
        .sort()
        .reverse()) {
        try {
          const scan = parseStored(name, await readCapped(path.join(dir, name)));
          const reason = accept(scan);
          if (reason === null) {
            outcome.scan = scan;
            return outcome;
          }
          outcome.warnings.push(`Skipped stored result ${name}: ${reason}`);
        } catch (error) {
          outcome.warnings.push(`Skipped stored result ${name}: ${toStoreError(error).message}`);
        }
      }
      return outcome;
    },

    async load(repositoryId, file) {
      try {
        if (!isRepositoryId(repositoryId) || !RESULT_FILE_PATTERN.test(file)) {
          throw new StoreFailure("invalid_input", "Not a stored result.");
        }
        const dir = path.join(reposDir, String(repositoryId));
        return { ok: true, scan: parseStored(file, await readCapped(path.join(dir, file))) };
      } catch (error) {
        return { ok: false, error: toStoreError(error) };
      }
    },

    async prune(repositoryId) {
      if (!isRepositoryId(repositoryId)) return 0;
      try {
        const dir = path.join(reposDir, String(repositoryId));
        await ensureDirectory(root, false);
        await ensureDirectory(reposDir, false);
        await ensureDirectory(dir, false);
        return await pruneDirectory(dir);
      } catch {
        return 0;
      }
    },

    async clear(clearOptions = {}) {
      const outcome: ClearOutcome = { removed: 0, baselinesRemoved: 0, warnings: [] };
      try {
        // Same checks as every other operation: no symlink, ours, 0700. Nothing is created.
        try {
          await ensureDirectory(root, false);
          await ensureDirectory(reposDir, false);
        } catch (error) {
          if (errnoOf(error) === "ENOENT") return outcome;
          throw error;
        }
        const wantedName = clearOptions.repoName?.toLowerCase();
        if (clearOptions.repositoryId !== undefined && !isRepositoryId(clearOptions.repositoryId)) {
          throw new StoreFailure("invalid_input", "Not a valid repository id.");
        }
        for (const id of await listFiles(reposDir)) {
          if (!/^[1-9][0-9]{0,15}$/.test(id)) continue;
          if (clearOptions.repositoryId !== undefined && id !== String(clearOptions.repositoryId)) {
            continue;
          }
          const dir = path.join(reposDir, id);
          try {
            await ensureDirectory(dir, false);
          } catch (error) {
            if (errnoOf(error) !== "ENOENT") {
              outcome.warnings.push(
                `Skipped ${path.join(REPOS_DIRECTORY, id)}: ${toStoreError(error).message}`,
              );
            }
            continue;
          }
          for (const name of await listFiles(dir)) {
            const file = path.join(dir, name);
            const isResult = RESULT_FILE_PATTERN.test(name);
            const isBaseline = name === BASELINE_FILE;
            // A name-scoped clear only ever deletes result files and baselines it has matched.
            if (wantedName !== undefined && !isResult && !isBaseline) continue;
            if ((isResult || isBaseline) && wantedName !== undefined) {
              try {
                const text = await readCapped(file);
                const scan = isBaseline ? parseBaseline(text) : parseStored(name, text);
                if (scan.result.target.repo?.toLowerCase() !== wantedName) continue;
              } catch {
                outcome.warnings.push(
                  `Could not match stored ${isBaseline ? "baseline" : `result ${name}`}; left in place.`,
                );
                continue;
              }
            }
            try {
              await unlink(file);
              if (isResult) outcome.removed += 1;
              if (isBaseline) outcome.baselinesRemoved += 1;
            } catch (error) {
              if (errnoOf(error) !== "ENOENT") {
                outcome.warnings.push(`Could not delete ${name}.`);
              }
            }
          }
          // Only an empty directory goes away; rmdir never follows links.
          await rmdir(dir).catch(() => undefined);
        }
        await rmdir(reposDir).catch(() => undefined);
      } catch (error) {
        outcome.warnings.push(toStoreError(error).message);
      }
      return outcome;
    },

    async claimFirstRunNotice() {
      try {
        await ensureRoot();
        const handle = await open(
          path.join(root, NOTICE_MARKER),
          fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | NO_FOLLOW,
          FILE_MODE,
        );
        await handle.close();
        return true;
      } catch {
        // Already there (or the store is unusable): do not repeat the notice.
        return false;
      }
    },
  };
}
