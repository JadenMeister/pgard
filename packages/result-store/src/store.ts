import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants, type Stats } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  rmdir,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import path from "node:path";
import {
  AUTHORIZATION_CHECK_IDS,
  readScanResult,
  SCHEMA_VERSION,
  type ScanResult,
} from "@pgard/findings";

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
const RESULT_FILE_PATTERN = /^(\d{13})-([0-9a-f]{16})\.json$/;
const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;

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
}

export interface ListOutcome {
  /** Newest first. */
  scans: StoredScan[];
  /** One line per file that was skipped (corrupt, oversized, unsupported version, unsafe). */
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
  list(repositoryId: number): Promise<ListOutcome>;
  load(repositoryId: number, file: string): Promise<LoadOutcome>;
  prune(repositoryId: number): Promise<number>;
  clear(options?: ClearOptions): Promise<ClearOutcome>;
  /** True exactly once per store directory (the caller prints the first-run notice then). */
  claimFirstRunNotice(): Promise<boolean>;
}

const NO_FOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const DIRECTORY_FLAG = fsConstants.O_DIRECTORY ?? 0;

function errnoOf(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : undefined;
}

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

function isRepositoryId(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isNewerVersion(sourceVersion: string): boolean {
  const [major = 0, minor = 0] = sourceVersion.split(".").map(Number);
  const [currentMajor = 0, currentMinor = 0] = SCHEMA_VERSION.split(".").map(Number);
  return major > currentMajor || (major === currentMajor && minor > currentMinor);
}

/** The gate allowed this scan: exactly the five known checks, all passed. */
function isAllowedByGate(result: ScanResult): boolean {
  const { decision, checks } = result.authorization;
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

  /** Creates (owner-only) or validates a directory: no symlink, ours, 0700. */
  async function ensureDirectory(dir: string, create = true): Promise<void> {
    if (create) {
      try {
        await mkdir(dir, { mode: DIRECTORY_MODE });
      } catch (error) {
        if (errnoOf(error) !== "EEXIST") throw error;
      }
    }
    const before = await lstat(dir);
    if (before.isSymbolicLink()) {
      throw new StoreFailure("symlink", "Refusing to use a symbolic link as a result directory.");
    }
    if (!before.isDirectory()) {
      throw new StoreFailure("not_directory", "A result directory path is not a directory.");
    }
    // Open without following a link planted since the lstat, then check the same inode.
    let handle: FileHandle;
    try {
      handle = await open(dir, fsConstants.O_RDONLY | DIRECTORY_FLAG | NO_FOLLOW);
    } catch (error) {
      if (errnoOf(error) === "ELOOP" || errnoOf(error) === "ENOTDIR") {
        throw new StoreFailure("symlink", "Refusing to use a symbolic link as a result directory.");
      }
      throw error;
    }
    try {
      const stat = await handle.stat();
      if (!stat.isDirectory() || stat.ino !== before.ino || stat.dev !== before.dev) {
        throw new StoreFailure("symlink", "A result directory changed while it was opened.");
      }
      if (isPosix) {
        const uid = getuid();
        if (uid !== undefined && stat.uid !== uid) {
          throw new StoreFailure("wrong_owner", "A result directory is owned by another user.");
        }
        if ((stat.mode & 0o777) !== DIRECTORY_MODE) await handle.chmod(DIRECTORY_MODE);
        const verified = await handle.stat();
        if ((verified.mode & 0o777) !== DIRECTORY_MODE) {
          throw new StoreFailure("permissions", "Could not restrict a result directory to 0700.");
        }
      }
    } finally {
      await handle.close();
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
  async function readCapped(file: string): Promise<string> {
    const before = await lstat(file);
    if (before.isSymbolicLink() || !before.isFile()) {
      throw new StoreFailure("symlink", "Not a regular file (symbolic links are never followed).");
    }
    const handle = await open(file, fsConstants.O_RDONLY | NO_FOLLOW);
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.ino !== before.ino || stat.dev !== before.dev) {
        throw new StoreFailure("symlink", "The file changed while it was opened.");
      }
      if (stat.size > MAX_RESULT_FILE_BYTES) {
        throw new StoreFailure(
          "too_large",
          `The file is larger than ${MAX_RESULT_FILE_BYTES} bytes.`,
        );
      }
      const buffer = Buffer.alloc(Math.min(stat.size, MAX_RESULT_FILE_BYTES));
      let offset = 0;
      while (offset < buffer.length) {
        const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
        if (bytesRead === 0) break;
        offset += bytesRead;
      }
      return buffer.subarray(0, offset).toString("utf8");
    } finally {
      await handle.close();
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
    return {
      file,
      savedAt: new Date(Number(match?.[1] ?? 0)),
      result: outcome.result,
      sourceVersion: outcome.sourceVersion,
    };
  }

  function fileNameFor(result: ScanResult, savedAtMs: number): string {
    const digest = createHash("sha256").update(result.scanId).digest("hex").slice(0, 16);
    return `${String(savedAtMs).padStart(13, "0")}-${digest}.json`;
  }

  /** Temp file in the same directory, owner-only, fsynced, then renamed over the target. */
  async function writeAtomically(dir: string, finalName: string, text: string): Promise<void> {
    const finalPath = path.join(dir, finalName);
    const tempPath = path.join(
      dir,
      `${TEMP_PREFIX}${process.pid}-${randomBytes(8).toString("hex")}`,
    );
    // O_EXCL fails on any existing entry, including a planted symlink; O_NOFOLLOW adds a second guard.
    const handle = await open(
      tempPath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | NO_FOLLOW,
      FILE_MODE,
    );
    try {
      try {
        await handle.writeFile(text, "utf8");
        if (isPosix) {
          await handle.chmod(FILE_MODE);
          if (((await handle.stat()).mode & 0o777) !== FILE_MODE) {
            throw new StoreFailure("permissions", "Could not restrict a result file to 0600.");
          }
        }
        await handle.sync();
      } finally {
        await handle.close();
      }
      // Never replace a file written by a newer PGARD, or one we cannot read.
      let existing: Stats | null = null;
      try {
        existing = await lstat(finalPath);
      } catch (error) {
        if (errnoOf(error) !== "ENOENT") throw error;
      }
      if (existing !== null) {
        if (existing.isSymbolicLink() || !existing.isFile()) {
          throw new StoreFailure("symlink", "The target is not a regular file; not replacing it.");
        }
        let blocked: string | null = null;
        try {
          const previous = parseStored(finalName, await readCapped(finalPath));
          if (isNewerVersion(previous.sourceVersion)) {
            blocked = "A stored result with a newer schema version already has this name.";
          }
        } catch {
          blocked = "An unreadable stored result already has this name.";
        }
        if (blocked !== null) throw new StoreFailure("would_overwrite", blocked);
      }
      await rename(tempPath, finalPath);
    } catch (error) {
      await unlink(tempPath).catch(() => undefined);
      throw error;
    }
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
        const text = `${JSON.stringify(checked.result)}\n`;
        for (const forbidden of saveOptions.forbidSubstrings ?? []) {
          // The file holds JSON text, where a backslash is written twice (Windows paths): check
          // the raw form and the escaped form.
          const escaped = JSON.stringify(forbidden).slice(1, -1);
          if (forbidden !== "" && (text.includes(forbidden) || text.includes(escaped))) {
            throw new StoreFailure("contains_local_path", "The result contains a local path.");
          }
        }
        if (Buffer.byteLength(text, "utf8") > MAX_RESULT_FILE_BYTES) {
          throw new StoreFailure("too_large", "The result is too large to store.");
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

    async list(repositoryId) {
      const outcome: ListOutcome = { scans: [], warnings: [] };
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
          outcome.scans.push(parseStored(name, await readCapped(path.join(dir, name))));
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
      const outcome: ClearOutcome = { removed: 0, warnings: [] };
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
            // A name-scoped clear only ever deletes result files it has matched.
            if (wantedName !== undefined && !isResult) continue;
            if (isResult && wantedName !== undefined) {
              try {
                const scan = parseStored(name, await readCapped(file));
                if (scan.result.target.repo?.toLowerCase() !== wantedName) continue;
              } catch {
                outcome.warnings.push(`Could not match stored result ${name}; left in place.`);
                continue;
              }
            }
            try {
              await unlink(file);
              if (isResult) outcome.removed += 1;
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
