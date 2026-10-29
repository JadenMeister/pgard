import { lstat, mkdir, readdir, rmdir, unlink } from "node:fs/promises";
import path from "node:path";
import {
  DEFAULT_SAFE_FILE_ENVIRONMENT,
  ensureOwnerOnlyDirectory,
  errnoOf,
  readFileCapped,
  SafeFileError,
  writeFileAtomically,
  type SafeFileEnvironment,
} from "./safe-file.js";

/**
 * The two files of the `pgard web` project picker, kept next to the result store but in their
 * own `web/` folder so deleting `repos/` stays safe and unrelated:
 *
 *   <dir>/web/settings.json         the search roots (changed only in the terminal)
 *   <dir>/web/recent-projects.json  recent projects (absolute paths: the one place paths are kept)
 *
 * Both are `0600` in a `0700` folder, never followed through a symlink, size-capped before
 * parsing and written by temp file plus rename. An unsupported or newer `schemaVersion` is
 * ignored and never overwritten. Everything read here is a hint: the picker revalidates it.
 */

export const WEB_DIRECTORY = "web";
export const SETTINGS_FILE = "settings.json";
export const RECENT_FILE = "recent-projects.json";
export const WEB_SCHEMA_VERSION = "1.0";
export const MAX_WEB_FILE_BYTES = 64 * 1024;
export const MAX_RECENT_ENTRIES = 20;
export const RECENT_MAX_AGE_DAYS = 90;
export const MAX_SEARCH_ROOTS = 50;
const MAX_PATH_LENGTH = 4096;
const MS_PER_DAY = 86_400_000;
const TEMP_PREFIX = ".tmp-";

export const ENTRY_ID_PATTERN = /^[A-Za-z0-9_-]{22}$/;
const REPO_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/;

export interface StoredRecentEntry {
  entryId: string;
  /** Absolute path as it was when the project was confirmed. A hint, never authority. */
  path: string;
  /** Display hint only. */
  repo: string;
  lastUsedAt: string;
}

/**
 * - `missing`: no file.
 * - `ignored`: damaged, unsafe, too large, wrong shape or from a newer PGARD; never overwritten.
 */
export type WebFileRead<T> =
  | { status: "missing" }
  | { status: "ok"; value: T }
  | { status: "ignored"; reason: "unreadable" | "newer" | "invalid" | "unsafe" };

export type WebWriteOutcome =
  { ok: true } | { ok: false; reason: "ignored_file" | "io" | "unsafe" };

export interface WebStorageOptions {
  /** The result store's data directory (`resolveStoreDirectory`). */
  dir: string;
  now?: () => number;
  /** For tests. */
  environment?: SafeFileEnvironment;
}

export interface WebStorage {
  readonly dir: string;
  readSettings(): Promise<WebFileRead<{ roots: string[] }>>;
  writeSettings(roots: readonly string[]): Promise<WebWriteOutcome>;
  readRecent(): Promise<WebFileRead<StoredRecentEntry[]>>;
  writeRecent(entries: readonly StoredRecentEntry[]): Promise<WebWriteOutcome>;
  /** Deletes `web/` (both files). Used by `pgard history clear --all`. */
  clear(): Promise<{ removed: number; warnings: string[] }>;
}

function parseVersion(version: unknown): { major: number; minor: number } | null {
  if (typeof version !== "string" || !/^[0-9]{1,4}\.[0-9]{1,4}$/.test(version)) return null;
  const [major = 0, minor = 0] = version.split(".").map(Number);
  return { major, minor };
}

/** Same major as ours and not a newer minor: the only versions this build reads. */
function classifyVersion(version: unknown): "ok" | "newer" | "invalid" {
  const parsed = parseVersion(version);
  const current = parseVersion(WEB_SCHEMA_VERSION) as { major: number; minor: number };
  if (parsed === null) return "invalid";
  if (parsed.major > current.major) return "newer";
  if (parsed.major < current.major) return "invalid";
  return parsed.minor > current.minor ? "newer" : "ok";
}

function isAbsolutePathText(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_PATH_LENGTH &&
    !value.includes("\0") &&
    path.posix.isAbsolute(value)
  );
}

function hasOnlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

function asObject(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

type ParseResult<T> = { ok: true; value: T } | { ok: false; reason: "invalid" | "newer" };

export function parseSettings(text: string): ParseResult<{ roots: string[] }> {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return { ok: false, reason: "invalid" };
  }
  const root = asObject(json);
  if (root === null) return { ok: false, reason: "invalid" };
  const version = classifyVersion(root.schemaVersion);
  if (version !== "ok") return { ok: false, reason: version };
  if (!hasOnlyKeys(root, ["schemaVersion", "searchRoots"]) || !Array.isArray(root.searchRoots)) {
    return { ok: false, reason: "invalid" };
  }
  if (root.searchRoots.length > MAX_SEARCH_ROOTS) return { ok: false, reason: "invalid" };
  const roots: string[] = [];
  for (const entry of root.searchRoots) {
    const object = asObject(entry);
    if (object === null || !hasOnlyKeys(object, ["path"]) || !isAbsolutePathText(object.path)) {
      return { ok: false, reason: "invalid" };
    }
    if (!roots.includes(object.path)) roots.push(object.path);
  }
  return { ok: true, value: { roots } };
}

function isIsoTime(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= 40 &&
    /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

export function parseRecent(text: string): ParseResult<StoredRecentEntry[]> {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return { ok: false, reason: "invalid" };
  }
  const root = asObject(json);
  if (root === null) return { ok: false, reason: "invalid" };
  const version = classifyVersion(root.schemaVersion);
  if (version !== "ok") return { ok: false, reason: version };
  if (!hasOnlyKeys(root, ["schemaVersion", "entries"]) || !Array.isArray(root.entries)) {
    return { ok: false, reason: "invalid" };
  }
  // Truncated, not rejected: a file with too many entries keeps the newest ones.
  const entries: StoredRecentEntry[] = [];
  for (const entry of root.entries.slice(0, MAX_RECENT_ENTRIES)) {
    const object = asObject(entry);
    if (
      object === null ||
      !hasOnlyKeys(object, ["entryId", "path", "repo", "lastUsedAt"]) ||
      typeof object.entryId !== "string" ||
      !ENTRY_ID_PATTERN.test(object.entryId) ||
      !isAbsolutePathText(object.path) ||
      typeof object.repo !== "string" ||
      !REPO_PATTERN.test(object.repo) ||
      !isIsoTime(object.lastUsedAt)
    ) {
      return { ok: false, reason: "invalid" };
    }
    entries.push({
      entryId: object.entryId,
      path: object.path,
      repo: object.repo,
      lastUsedAt: object.lastUsedAt,
    });
  }
  return { ok: true, value: entries };
}

/** Newest first, one per path, none older than 90 days (and none dated in the future). */
export function normalizeRecent(
  entries: readonly StoredRecentEntry[],
  nowMs: number,
): StoredRecentEntry[] {
  const maxAgeMs = RECENT_MAX_AGE_DAYS * MS_PER_DAY;
  const seen = new Set<string>();
  const kept: StoredRecentEntry[] = [];
  const sorted = [...entries].sort((a, b) => Date.parse(b.lastUsedAt) - Date.parse(a.lastUsedAt));
  for (const entry of sorted) {
    const age = nowMs - Date.parse(entry.lastUsedAt);
    if (age > maxAgeMs || seen.has(entry.path)) continue;
    seen.add(entry.path);
    kept.push(entry);
    if (kept.length >= MAX_RECENT_ENTRIES) break;
  }
  return kept;
}

export function createWebStorage(options: WebStorageOptions): WebStorage {
  const environment = options.environment ?? DEFAULT_SAFE_FILE_ENVIRONMENT;
  const now = options.now ?? Date.now;
  const webDir = path.join(options.dir, WEB_DIRECTORY);

  async function ensureWebDirectory(create: boolean): Promise<void> {
    // The data directory may sit below folders that do not exist yet.
    if (create) await mkdir(path.dirname(options.dir), { recursive: true });
    await ensureOwnerOnlyDirectory(options.dir, environment, create);
    await ensureOwnerOnlyDirectory(webDir, environment, create);
  }

  async function readParsed<T>(
    name: string,
    parse: (text: string) => ParseResult<T>,
  ): Promise<WebFileRead<T>> {
    try {
      await ensureWebDirectory(false);
    } catch (error) {
      if (errnoOf(error) === "ENOENT") return { status: "missing" };
      return {
        status: "ignored",
        reason: error instanceof SafeFileError ? "unsafe" : "unreadable",
      };
    }
    let text: string;
    try {
      text = await readFileCapped(
        path.join(webDir, name),
        MAX_WEB_FILE_BYTES,
        environment,
        true,
        true,
      );
    } catch (error) {
      if (errnoOf(error) === "ENOENT") return { status: "missing" };
      if (error instanceof SafeFileError) {
        return { status: "ignored", reason: error.code === "too_large" ? "invalid" : "unsafe" };
      }
      return { status: "ignored", reason: "unreadable" };
    }
    const parsed = parse(text);
    return parsed.ok
      ? { status: "ok", value: parsed.value }
      : { status: "ignored", reason: parsed.reason };
  }

  async function writeChecked(
    name: string,
    text: string,
    parse: (text: string) => ParseResult<unknown>,
  ): Promise<WebWriteOutcome> {
    // What is written must be readable back: never write a file this build would then ignore
    // (more roots than the cap, an oversized or malformed text).
    if (Buffer.byteLength(text, "utf8") > MAX_WEB_FILE_BYTES || !parse(text).ok) {
      return { ok: false, reason: "io" };
    }
    try {
      await ensureWebDirectory(true);
      await writeFileAtomically(webDir, name, text, environment, {
        tempPrefix: TEMP_PREFIX,
        // A damaged or newer file is never replaced: the user decides (delete it by hand).
        checkExisting: async (finalPath) => {
          let existing: string;
          try {
            existing = await readFileCapped(finalPath, MAX_WEB_FILE_BYTES, environment, true, true);
          } catch {
            throw new SafeFileError("would_overwrite", "An unreadable file already has this name.");
          }
          if (!parse(existing).ok) {
            throw new SafeFileError(
              "would_overwrite",
              "An unsupported file already has this name.",
            );
          }
        },
      });
      return { ok: true };
    } catch (error) {
      if (error instanceof SafeFileError) {
        return { ok: false, reason: error.code === "would_overwrite" ? "ignored_file" : "unsafe" };
      }
      return { ok: false, reason: "io" };
    }
  }

  return {
    dir: webDir,
    readSettings: () => readParsed(SETTINGS_FILE, parseSettings),
    writeSettings: (roots) =>
      writeChecked(
        SETTINGS_FILE,
        `${JSON.stringify(
          { schemaVersion: WEB_SCHEMA_VERSION, searchRoots: roots.map((root) => ({ path: root })) },
          null,
          2,
        )}\n`,
        parseSettings,
      ),
    readRecent: async () => {
      const read = await readParsed(RECENT_FILE, parseRecent);
      return read.status === "ok"
        ? { status: "ok", value: normalizeRecent(read.value, now()) }
        : read;
    },
    writeRecent: (entries) =>
      writeChecked(
        RECENT_FILE,
        `${JSON.stringify(
          { schemaVersion: WEB_SCHEMA_VERSION, entries: normalizeRecent(entries, now()) },
          null,
          2,
        )}\n`,
        parseRecent,
      ),
    clear: async () => {
      const outcome = { removed: 0, warnings: [] as string[] };
      try {
        await ensureWebDirectory(false);
      } catch (error) {
        if (errnoOf(error) !== "ENOENT") {
          outcome.warnings.push("The web folder could not be used safely; left in place.");
        }
        return outcome;
      }
      let names: string[];
      try {
        names = await readdir(webDir);
      } catch {
        outcome.warnings.push("The web folder could not be listed.");
        return outcome;
      }
      for (const name of names) {
        try {
          // Only entries that are not directories; unlink never follows a link.
          const stat = await lstat(path.join(webDir, name));
          if (stat.isDirectory()) {
            outcome.warnings.push(`Skipped web/${name}: it is a folder.`);
            continue;
          }
          await unlink(path.join(webDir, name));
          if (name === SETTINGS_FILE || name === RECENT_FILE) outcome.removed += 1;
        } catch (error) {
          if (errnoOf(error) !== "ENOENT") outcome.warnings.push(`Could not delete web/${name}.`);
        }
      }
      await rmdir(webDir).catch(() => undefined);
      return outcome;
    },
  };
}
