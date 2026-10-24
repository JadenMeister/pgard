import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { compareVersions, isComparableVersion } from "./version.js";

export const ADVISORY_DB_ENV = "PGARD_ADVISORY_DB";
export const MAX_ADVISORY_AGE_DAYS = 30;
const MAX_DB_BYTES = 512 * 1024 * 1024;
const MAX_DB_FILES = 500_000;

export type Ecosystem = "npm" | "Go";

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface Advisory {
  id: string;
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
    if (!ecosystem || !name) return null;
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
 * after it. Unparsable range versions make the range unknown (not affected) — callers record
 * that as reduced coverage, never as safe.
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

async function collectJsonFiles(directory: string, files: string[]): Promise<void> {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (files.length >= MAX_DB_FILES) return;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) await collectJsonFiles(full, files);
    else if (entry.isFile() && entry.name.endsWith(".json")) files.push(full);
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
      await collectJsonFiles(location, files);
      for (const file of files) rawRecords.push(JSON.parse(await readFile(file, "utf8")));
    } else {
      if (info.size > MAX_DB_BYTES) {
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
  } catch {
    return emptyDb("invalid", "The advisory database could not be read or is not valid JSON.");
  }

  const index = new Map<string, Advisory[]>();
  let count = 0;
  let latestModified: string | null = null;
  for (const raw of rawRecords) {
    const advisory = parseOsvRecord(raw);
    if (!advisory) {
      return emptyDb(
        "invalid",
        "The advisory database contains records that are not valid OSV entries.",
      );
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
        : `${count} advisories, updated ${updatedIso.slice(0, 10)}.`,
    },
    index,
  };
}

/** Status only (for `pgard doctor` / `rules list`). */
export async function readAdvisoryDbStatus(
  env: Readonly<Record<string, string | undefined>>,
  now?: () => Date,
): Promise<AdvisoryDbStatus> {
  return (await loadAdvisoryDb(env, now)).status;
}
