import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
import { osvDataDir } from "../app-data.js";
import type { ReducedAdvisory } from "../osv/reduce.js";
import { ADVISORIES_FILE, ecosystemDir, type OsvMeta } from "../osv/store.js";
import type { Dependency, Ecosystem } from "../types.js";
import { evaluateAffected } from "./range.js";
import { advisorySeverity, strongestSeverity, type AdvisorySeverity } from "./severity.js";
import { versionScheme } from "./version.js";

/** Decompressed bytes of one advisory file we are willing to read (the real files are far smaller). */
export const MAX_ADVISORY_BYTES = 1024 * 1024 * 1024;
const MAX_LINE_CHARS = 2 * 1024 * 1024;

export interface DependencyMatch {
  dependency: Dependency;
  /** Stable primary id (GHSA first, then GO, then the rest by name). */
  advisoryId: string;
  /** Every other id of the same issue (CVE, GHSA, GO, ...), sorted. */
  aliases: string[];
  summary: string | null;
  affectedRange: string;
  fixedVersions: string[];
  severity: AdvisorySeverity;
  via: "range" | "version-list";
}

export interface NotTested {
  name: string;
  version: string;
  reason: string;
}

export interface MatchResult {
  matches: DependencyMatch[];
  /** Packages that have an advisory but could not be compared (unknown version form or scheme). */
  notTested: NotTested[];
  stats: {
    advisoriesRead: number;
    withdrawnSkipped: number;
    packagesChecked: number;
  };
  /** True when reading the advisories stopped early (time budget); matches may be missing. */
  isIncomplete: boolean;
}

export class AdvisoryDataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AdvisoryDataError";
  }
}

export interface MatchOptions {
  signal?: AbortSignal;
  /** Stops reading advisories after this many ms (default: no limit besides the byte cap). */
  timeBudgetMs?: number;
  now?: () => number;
}

interface Candidate {
  advisory: ReducedAdvisory;
  entry: ReducedAdvisory["affected"][number];
}

/** Counts decompressed bytes and fails past the cap, so a tampered file cannot expand without bound. */
function capBytes(limit: number): Transform {
  let seen = 0;
  return new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      seen += chunk.length;
      if (seen > limit)
        callback(new AdvisoryDataError("The advisory file is larger than expected."));
      else callback(null, chunk);
    },
  });
}

/**
 * Streams the stored advisories of one ecosystem and keeps only records that mention one of
 * `names`. Verifies the compressed file against `meta` (byte count and SHA-256) and throws
 * `AdvisoryDataError` if it differs, so a damaged or replaced file is never trusted. When the
 * time budget stops the read early the file is not read to its end, so neither can be verified;
 * the result is then flagged incomplete and the caller reports the area as partial.
 */
async function readCandidates(
  appDataDir: string,
  meta: OsvMeta,
  names: ReadonlySet<string>,
  options: MatchOptions,
): Promise<{
  byName: Map<string, Candidate[]>;
  advisoriesRead: number;
  withdrawnSkipped: number;
  isIncomplete: boolean;
}> {
  const file = path.join(ecosystemDir(osvDataDir(appDataDir), meta.ecosystem), ADVISORIES_FILE);
  const expected = meta.files[ADVISORIES_FILE];
  if (expected === undefined) throw new AdvisoryDataError("The advisory file is not listed.");
  const hash = createHash("sha256");
  const source = createReadStream(file);
  let compressedBytes = 0;
  source.on("data", (chunk) => {
    hash.update(chunk as Buffer);
    compressedBytes += (chunk as Buffer).length;
  });
  const gunzip = createGunzip();
  const guarded = capBytes(MAX_ADVISORY_BYTES);
  const byName = new Map<string, Candidate[]>();
  let advisoriesRead = 0;
  let withdrawnSkipped = 0;
  let isIncomplete = false;
  const now = options.now ?? Date.now;
  const startedAt = now();
  const consume = (async () => {
    const lines = createInterface({ input: guarded, crlfDelay: Infinity });
    let lineCount = 0;
    for await (const line of lines) {
      lineCount += 1;
      if (lineCount % 500 === 0) {
        if (options.signal?.aborted === true) {
          throw new DOMException("The dependency check was cancelled.", "AbortError");
        }
        if (options.timeBudgetMs !== undefined && now() - startedAt > options.timeBudgetMs) {
          isIncomplete = true;
          source.destroy();
          return;
        }
      }
      if (line === "" || line.length > MAX_LINE_CHARS) continue;
      let advisory: ReducedAdvisory;
      try {
        advisory = JSON.parse(line) as ReducedAdvisory;
      } catch {
        continue;
      }
      if (typeof advisory !== "object" || advisory === null || typeof advisory.id !== "string")
        continue;
      advisoriesRead += 1;
      if (typeof advisory.withdrawn === "string") {
        withdrawnSkipped += 1; // withdrawn: the database retracted it; never reported
        continue;
      }
      for (const entry of Array.isArray(advisory.affected) ? advisory.affected : []) {
        if (typeof entry?.name !== "string" || !names.has(entry.name)) continue;
        const list = byName.get(entry.name) ?? [];
        list.push({ advisory, entry });
        byName.set(entry.name, list);
      }
    }
  })();
  try {
    await Promise.all([
      pipeline(source, gunzip, guarded).catch((error: unknown) => {
        if (isIncomplete) return; // we destroyed the stream ourselves
        throw error;
      }),
      consume,
    ]);
  } catch (error) {
    source.destroy();
    gunzip.destroy();
    guarded.destroy();
    if (error instanceof Error && error.name === "AbortError") throw error;
    throw new AdvisoryDataError(
      error instanceof AdvisoryDataError ? error.message : "The advisory file could not be read.",
    );
  }
  if (
    !isIncomplete &&
    (compressedBytes !== expected.bytes || hash.digest("hex") !== expected.sha256)
  ) {
    throw new AdvisoryDataError("The advisory file does not match its recorded checksum.");
  }
  return { byName, advisoriesRead, withdrawnSkipped, isIncomplete };
}

// The primary id is the first of ALL ids of the issue (record ids and aliases) in this order, so it
// does not change when an update adds the record of an id that was already an alias: a CVE first,
// then GHSA, then GO, then the rest; within a kind the smallest.
const PREFERENCE = ["CVE-", "GHSA-", "GO-"];
function idRank(id: string): number {
  const index = PREFERENCE.findIndex((prefix) => id.startsWith(prefix));
  return index === -1 ? PREFERENCE.length : index;
}
const compareIds = (a: string, b: string): number =>
  idRank(a) - idRank(b) || (a < b ? -1 : a > b ? 1 : 0);

/** Groups advisories that share an id or alias: they describe one issue. */
function cluster<T extends { advisory: ReducedAdvisory }>(items: T[]): T[][] {
  const parent = items.map((_, index) => index);
  const find = (x: number): number => {
    let root = x;
    while (parent[root] !== root) root = parent[root] as number;
    parent[x] = root;
    return root;
  };
  const owner = new Map<string, number>();
  items.forEach((item, index) => {
    for (const token of [item.advisory.id, ...(item.advisory.aliases ?? [])]) {
      const first = owner.get(token);
      if (first === undefined) owner.set(token, index);
      else parent[find(index)] = find(first);
    }
  });
  const groups = new Map<number, T[]>();
  items.forEach((item, index) => {
    const root = find(index);
    groups.set(root, [...(groups.get(root) ?? []), item]);
  });
  return [...groups.values()];
}

/**
 * Matches `dependencies` of one ecosystem against the stored OSV data of `meta`. Offline: only
 * local files are read. A package whose version (or whose advisory ranges) the ecosystem's scheme
 * cannot read is reported in `notTested`, never as clean.
 */
export async function matchDependencies(
  appDataDir: string,
  meta: OsvMeta,
  dependencies: readonly Dependency[],
  options: MatchOptions = {},
): Promise<MatchResult> {
  const ecosystem: Ecosystem = meta.ecosystem;
  const scheme = versionScheme(ecosystem);
  const names = new Set(dependencies.filter((d) => d.ecosystem === ecosystem).map((d) => d.name));
  if (scheme === null) {
    return {
      matches: [],
      notTested: dependencies.map((d) => ({
        name: d.name,
        version: d.version,
        reason: `no version scheme for ${ecosystem}`,
      })),
      stats: { advisoriesRead: 0, withdrawnSkipped: 0, packagesChecked: 0 },
      isIncomplete: false,
    };
  }
  const read = await readCandidates(appDataDir, meta, names, options);
  const matches: DependencyMatch[] = [];
  const notTested: NotTested[] = [];
  let packagesChecked = 0;
  for (const dependency of dependencies) {
    if (dependency.ecosystem !== ecosystem) continue;
    packagesChecked += 1;
    const candidates = read.byName.get(dependency.name) ?? [];
    if (candidates.length === 0) continue;
    const installed = scheme.parse(dependency.version);
    if (installed === null) {
      notTested.push({
        name: dependency.name,
        version: dependency.version,
        reason: `"${dependency.version}" is not a ${ecosystem === "Go" ? "Go module" : "semver"} version`,
      });
      continue;
    }
    const hits: (Candidate & {
      verdict: Extract<ReturnType<typeof evaluateAffected>, { verdict: "affected" }>;
    })[] = [];
    let unknown: string | null = null;
    for (const candidate of candidates) {
      const verdict = evaluateAffected(candidate.entry, installed, scheme);
      if (verdict.verdict === "affected") hits.push({ ...candidate, verdict });
      else if (verdict.verdict === "unknown") unknown = verdict.reason;
    }
    // Always recorded: an advisory that could not be compared is a gap even next to a match.
    if (unknown !== null) {
      notTested.push({ name: dependency.name, version: dependency.version, reason: unknown });
    }
    for (const group of cluster(hits)) {
      const ids = [
        ...new Set(group.flatMap((h) => [h.advisory.id, ...(h.advisory.aliases ?? [])])),
      ].sort(compareIds);
      const primary = ids[0] as string;
      const fixed = [...new Set(group.flatMap((h) => h.verdict.fixed))].sort((a, b) => {
        const left = scheme.parse(a);
        const right = scheme.parse(b);
        return left !== null && right !== null ? scheme.compare(left, right) : a < b ? -1 : 1;
      });
      const lead =
        group.find((h) => h.advisory.id === primary) ?? (group[0] as (typeof group)[number]);
      const summary = group
        .map((h) => h.advisory.summary)
        .find((s) => typeof s === "string" && s !== "");
      matches.push({
        dependency,
        advisoryId: primary,
        aliases: ids.filter((id) => id !== primary),
        summary: summary ?? null,
        affectedRange: lead.verdict.range,
        fixedVersions: fixed,
        severity: strongestSeverity(group.map((h) => advisorySeverity(h.advisory))),
        via: lead.verdict.via,
      });
    }
  }
  matches.sort(
    (a, b) =>
      a.dependency.path.localeCompare(b.dependency.path) ||
      a.dependency.name.localeCompare(b.dependency.name) ||
      a.dependency.version.localeCompare(b.dependency.version) ||
      a.advisoryId.localeCompare(b.advisoryId),
  );
  return {
    matches,
    notTested,
    stats: {
      advisoriesRead: read.advisoriesRead,
      withdrawnSkipped: read.withdrawnSkipped,
      packagesChecked,
    },
    isIncomplete: read.isIncomplete,
  };
}
