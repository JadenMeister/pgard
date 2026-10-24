import { open, readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { compareVersions, isComparableVersion } from "./version.js";

export const ADVISORY_DB_ENV = "PGARD_ADVISORY_DB";
export const MAX_ADVISORY_AGE_DAYS = 30;
const MAX_DB_BYTES = 512 * 1024 * 1024;
const MAX_DB_FILES = 500_000;

export interface AdvisoryDbLimits {
  maxFiles: number;
  maxBytes: number;
}
const DEFAULT_LIMITS: AdvisoryDbLimits = { maxFiles: MAX_DB_FILES, maxBytes: MAX_DB_BYTES };

export type Ecosystem = "npm" | "Go";

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface Advisory {
  id: string;
  /** Set when the advisory was withdrawn; withdrawn advisories are never matched. */
  withdrawn: string | null;
  aliases: string[];
  summary: string | null;
  /** Normalized severity from `database_specific.severity` (GHSA style), if any. */
  severity: "critical" | "high" | "medium" | "low" | null;
  modified: string | null;
  affected: {
    ecosystem: string;
    name: string;
    ranges: { type: string; events: OsvEvent[] }[];
    versions: string[];
  }[];
}

export type AdvisoryDbState = "ok" | "missing" | "invalid" | "stale";

export interface AdvisoryDbStatus {
  status: AdvisoryDbState;
  version: string | null;
  updatedAt: string | null;
  advisoryCount: number;
  /** English explanation safe to display (never includes the DB path). */
  note: string;
  /**
   * `false` when the database was only checked cheaply (see `peekAdvisoryDb`): the sample check
   * passed, but the full contents, version and freshness were not verified. Absent (or `true`)
   * when the status comes from a full load.
   */
  validated?: boolean;
}

export interface LoadedAdvisoryDb {
  status: AdvisoryDbStatus;
  /** `${ecosystem}\0${name}` -> advisories; empty unless status is ok or stale. */
  index: Map<string, Advisory[]>;
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function normalizeSeverity(value: unknown): Advisory["severity"] {
  const text = asString(value)?.toLowerCase();
  if (text === "critical" || text === "high" || text === "low") return text;
  if (text === "moderate" || text === "medium") return "medium";
  return null;
}

/** Validates one OSV record; returns null when it lacks required fields. */
export function parseOsvRecord(raw: unknown): Advisory | null {
  if (typeof raw !== "object" || raw === null) return null;
  const record = raw as Record<string, unknown>;
  const id = asString(record.id);
  if (!id || !Array.isArray(record.affected)) return null;
  const affected: Advisory["affected"] = [];
  for (const entry of record.affected) {
    if (typeof entry !== "object" || entry === null) return null;
    const item = entry as Record<string, unknown>;
    const pkg = item.package as Record<string, unknown> | undefined;
    const ecosystem = asString(pkg?.ecosystem);
    const name = asString(pkg?.name);
    // OSV allows affected entries without a package (e.g. GIT-only ranges); they cannot match a
    // lockfile entry, so they are skipped rather than invalidating the database.
    if (!ecosystem || !name) continue;
    const ranges = Array.isArray(item.ranges)
      ? item.ranges.flatMap((range) => {
          if (typeof range !== "object" || range === null) return [];
          const value = range as Record<string, unknown>;
          const events = Array.isArray(value.events)
            ? value.events.filter(
                (event): event is OsvEvent => typeof event === "object" && event !== null,
              )
            : [];
          return [{ type: asString(value.type) ?? "", events }];
        })
      : [];
    const versions = Array.isArray(item.versions)
      ? item.versions.filter((v): v is string => typeof v === "string")
      : [];
    affected.push({ ecosystem, name, ranges, versions });
  }
  const databaseSpecific = record.database_specific as Record<string, unknown> | undefined;
  return {
    id,
    withdrawn: asString(record.withdrawn),
    aliases: Array.isArray(record.aliases)
      ? record.aliases.filter((a): a is string => typeof a === "string")
      : [],
    summary: asString(record.summary),
    severity: normalizeSeverity(databaseSpecific?.severity),
    modified: asString(record.modified),
    affected,
  };
}

/**
 * True when `version` falls in an affected range. Events are sorted by version and evaluated in
 * order (OSV semantics): introduced opens, fixed closes at that version, last_affected closes
 * after it. Callers must check `isComparableVersion(version)` first: a package version that is
 * not SemVer-like (git refs, aliases) returns false here and has to be counted as "not compared"
 * in coverage, never as safe.
 */
export function isVersionAffected(
  version: string,
  affected: Advisory["affected"][number],
): boolean {
  if (
    affected.versions.includes(version) ||
    affected.versions.includes(version.replace(/^v/, ""))
  ) {
    return true;
  }
  if (!isComparableVersion(version)) return false;
  for (const range of affected.ranges) {
    if (range.type !== "SEMVER" && range.type !== "ECOSYSTEM") continue;
    const events = range.events
      .map((event) => {
        const [kind, value] = (Object.entries(event).find(([, v]) => typeof v === "string") ??
          []) as [string, string];
        return kind && value !== undefined ? { kind, value } : null;
      })
      .filter((event): event is { kind: string; value: string } => event !== null)
      .sort((a, b) =>
        a.value === "0" ? -1 : b.value === "0" ? 1 : compareVersions(a.value, b.value),
      );
    let isAffected = false;
    for (const event of events) {
      if (event.kind === "introduced") {
        if (event.value === "0" || compareVersions(version, event.value) >= 0) isAffected = true;
      } else if (event.kind === "fixed" || event.kind === "limit") {
        if (compareVersions(version, event.value) >= 0) isAffected = false;
      } else if (event.kind === "last_affected") {
        if (compareVersions(version, event.value) > 0) isAffected = false;
      }
    }
    if (isAffected) return true;
  }
  return false;
}

export function firstFixedVersion(
  affected: Advisory["affected"][number],
  version: string,
): string | null {
  const fixes = affected.ranges
    .flatMap((range) => range.events.map((event) => event.fixed))
    .filter(
      (value): value is string => typeof value === "string" && compareVersions(value, version) > 0,
    )
    .sort(compareVersions);
  return fixes[0] ?? null;
}

class AdvisoryDbLimitError extends Error {}

/** Lists OSV files; throws when the file-count or total-size limit is exceeded (never truncates). */
async function collectJsonFiles(
  directory: string,
  files: string[],
  totals: { bytes: number },
  limits: AdvisoryDbLimits,
): Promise<void> {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      await collectJsonFiles(full, files, totals, limits);
    } else if (entry.isFile() && entry.name.endsWith(".json")) {
      if (files.length >= limits.maxFiles) throw new AdvisoryDbLimitError("file count");
      totals.bytes += (await stat(full)).size;
      if (totals.bytes > limits.maxBytes) throw new AdvisoryDbLimitError("total size");
      files.push(full);
    }
  }
}

function emptyDb(status: AdvisoryDbState, note: string): LoadedAdvisoryDb {
  return {
    status: { status, version: null, updatedAt: null, advisoryCount: 0, note },
    index: new Map(),
  };
}

const MISSING_NOTE = `No advisory database is configured. Set ${ADVISORY_DB_ENV} to a local OSV-format export; this version of PGARD has no network update command.`;

/**
 * Loads a local OSV database: a JSON file holding an array of OSV records or
 * `{ "version", "updatedAt", "vulnerabilities": [...] }`, or a directory of OSV `.json` files.
 * Missing, unreadable or invalid data never yields an empty-but-ok database.
 */
export async function loadAdvisoryDb(
  env: Readonly<Record<string, string | undefined>>,
  now: () => Date = () => new Date(),
  signal?: AbortSignal,
  limits: AdvisoryDbLimits = DEFAULT_LIMITS,
): Promise<LoadedAdvisoryDb> {
  const location = env[ADVISORY_DB_ENV]?.trim();
  if (!location) return emptyDb("missing", MISSING_NOTE);
  let info;
  try {
    info = await stat(location);
  } catch {
    return emptyDb(
      "missing",
      `The advisory database configured in ${ADVISORY_DB_ENV} was not found.`,
    );
  }

  let rawRecords: unknown[] = [];
  let declaredVersion: string | null = null;
  let declaredUpdatedAt: string | null = null;
  try {
    if (info.isDirectory()) {
      const files: string[] = [];
      await collectJsonFiles(location, files, { bytes: 0 }, limits);
      for (const file of files) {
        if (signal?.aborted)
          throw signal.reason instanceof Error ? signal.reason : new Error("aborted");
        rawRecords.push(JSON.parse(await readFile(file, "utf8")));
      }
    } else {
      if (info.size > limits.maxBytes) {
        return emptyDb("invalid", "The advisory database file is too large to load.");
      }
      const parsed: unknown = JSON.parse(await readFile(location, "utf8"));
      if (Array.isArray(parsed)) {
        rawRecords = parsed;
      } else if (
        typeof parsed === "object" &&
        parsed !== null &&
        Array.isArray((parsed as Record<string, unknown>).vulnerabilities)
      ) {
        const object = parsed as Record<string, unknown>;
        rawRecords = object.vulnerabilities as unknown[];
        declaredVersion = asString(object.version);
        declaredUpdatedAt = asString(object.updatedAt);
      } else {
        return emptyDb(
          "invalid",
          "The advisory database is not an OSV array or { vulnerabilities: [...] } object.",
        );
      }
    }
  } catch (error) {
    if (signal?.aborted) throw error;
    if (error instanceof AdvisoryDbLimitError) {
      return emptyDb(
        "invalid",
        `The advisory database directory exceeds PGARD's ${error.message} limit, so it was not loaded (a partial database could hide advisories).`,
      );
    }
    return emptyDb("invalid", "The advisory database could not be read or is not valid JSON.");
  }

  const index = new Map<string, Advisory[]>();
  let count = 0;
  let withdrawnCount = 0;
  let latestModified: string | null = null;
  for (const raw of rawRecords) {
    const advisory = parseOsvRecord(raw);
    if (!advisory) {
      return emptyDb(
        "invalid",
        "The advisory database contains records that are not valid OSV entries.",
      );
    }
    if (advisory.withdrawn) {
      withdrawnCount += 1;
      continue;
    }
    count += 1;
    if (advisory.modified && (!latestModified || advisory.modified > latestModified))
      latestModified = advisory.modified;
    for (const affected of advisory.affected) {
      const key = `${affected.ecosystem}\0${affected.name}`;
      const list = index.get(key) ?? [];
      if (!list.includes(advisory)) list.push(advisory);
      index.set(key, list);
    }
  }
  if (count === 0) return emptyDb("invalid", "The advisory database contains no advisories.");

  const updatedAt = declaredUpdatedAt ?? latestModified;
  const updatedTime = updatedAt ? Date.parse(updatedAt) : Number.NaN;
  if (Number.isNaN(updatedTime)) {
    return emptyDb(
      "invalid",
      "The advisory database has no valid update time (updatedAt or record modified dates).",
    );
  }
  if (updatedTime > now().getTime() + 86_400_000) {
    return emptyDb(
      "invalid",
      "The advisory database update time is in the future, so its freshness cannot be trusted.",
    );
  }
  const version =
    declaredVersion ?? `osv-${count}-${new Date(updatedTime).toISOString().slice(0, 10)}`;
  const ageDays = (now().getTime() - updatedTime) / 86_400_000;
  const isStale = ageDays > MAX_ADVISORY_AGE_DAYS;
  const updatedIso = new Date(updatedTime).toISOString();
  return {
    status: {
      status: isStale ? "stale" : "ok",
      version,
      updatedAt: updatedIso,
      advisoryCount: count,
      note: isStale
        ? `Advisory data is stale: last updated ${updatedIso.slice(0, 10)} (more than ${MAX_ADVISORY_AGE_DAYS} days ago). Newer advisories are not checked.`
        : `${count} advisories, updated ${updatedIso.slice(0, 10)}.${withdrawnCount > 0 ? ` ${withdrawnCount} withdrawn advisories ignored.` : ""}`,
    },
    index,
  };
}

const PEEK_MAX_BYTES = 8 * 1024 * 1024;

/** Depth-first search for the first `.json` file in a directory tree (sorted, stops early). */
async function findFirstJsonFile(directory: string, depth = 0): Promise<string | null> {
  if (depth > 16) return null;
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    if (entry.isFile() && entry.name.endsWith(".json")) return path.join(directory, entry.name);
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const found = await findFirstJsonFile(path.join(directory, entry.name), depth + 1);
    if (found) return found;
  }
  return null;
}

/** Cheap check of a large database file: its first non-blank byte opens a JSON array/object. */
async function startsLikeJson(file: string): Promise<boolean> {
  let handle;
  try {
    handle = await open(file, "r");
    const buffer = Buffer.alloc(4096);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    const first = buffer.subarray(0, bytesRead).toString("utf8").trimStart()[0];
    return first === "[" || first === "{";
  } catch {
    return false;
  } finally {
    await handle?.close();
  }
}

/**
 * Cheap check of a database directory: at least one `.json` file (≤ 8 MiB) must parse as an OSV
 * record. Returns a note explaining the failure, or null when the sample is valid.
 */
async function checkDirectorySample(directory: string): Promise<string | null> {
  let file: string | null;
  try {
    file = await findFirstJsonFile(directory);
  } catch {
    return "The advisory database directory could not be read.";
  }
  if (!file) return "The advisory database directory contains no OSV .json files.";
  try {
    if ((await stat(file)).size > PEEK_MAX_BYTES) {
      return "The advisory database directory could not be checked: its first record file is too large.";
    }
    if (!parseOsvRecord(JSON.parse(await readFile(file, "utf8")))) {
      return "The advisory database directory contains records that are not valid OSV entries.";
    }
  } catch {
    return "The advisory database directory contains files that could not be read or are not valid JSON.";
  }
  return null;
}

/**
 * Cheap status for when no comparison is needed: reports a missing/unset database, fully reads a
 * small database file (≤ 8 MiB) for its metadata, checks that a directory holds at least one
 * valid OSV record, and checks that a larger file starts like JSON. Empty or junk data is
 * `invalid`; a database that passed only the cheap check is `ok` with `validated: false`
 * (version/updatedAt stay null).
 */
export async function peekAdvisoryDb(
  env: Readonly<Record<string, string | undefined>>,
  now?: () => Date,
  signal?: AbortSignal,
): Promise<AdvisoryDbStatus> {
  const location = env[ADVISORY_DB_ENV]?.trim();
  if (!location) return emptyDb("missing", MISSING_NOTE).status;
  let info;
  try {
    info = await stat(location);
  } catch {
    return emptyDb(
      "missing",
      `The advisory database configured in ${ADVISORY_DB_ENV} was not found.`,
    ).status;
  }
  if (info.isFile() && info.size <= PEEK_MAX_BYTES) {
    return (await loadAdvisoryDb(env, now, signal)).status;
  }
  if (info.isDirectory()) {
    const problem = await checkDirectorySample(location);
    if (problem) return emptyDb("invalid", problem).status;
  } else if (!info.isFile()) {
    return emptyDb("invalid", "The advisory database path is neither a file nor a directory.")
      .status;
  } else if (!(await startsLikeJson(location))) {
    return emptyDb("invalid", "The advisory database file is not a JSON array or object.").status;
  }
  return {
    status: "ok",
    version: null,
    updatedAt: null,
    advisoryCount: 0,
    note: info.isDirectory()
      ? "An advisory database is configured and a sample record is valid OSV; it was not fully loaded because nothing needed comparing, so its version and freshness were not verified."
      : "An advisory database file is configured; it was not loaded because nothing needed comparing. Only its first bytes were checked; contents, version and freshness were not verified.",
    validated: false,
  };
}

/** Status only (for `pgard doctor` / `rules list`). */
export async function readAdvisoryDbStatus(
  env: Readonly<Record<string, string | undefined>>,
  now?: () => Date,
): Promise<AdvisoryDbStatus> {
  return (await loadAdvisoryDb(env, now)).status;
}
