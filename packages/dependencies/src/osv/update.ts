import { rm } from "node:fs/promises";
import path from "node:path";
import { osvDataDir } from "../app-data.js";
import type { Ecosystem } from "../types.js";
import {
  downloadToFile,
  DownloadError,
  osvArchiveUrl,
  type DownloadOptions,
  type DownloadResult,
} from "./download.js";
import { isMalwareId, reduceAdvisory } from "./reduce.js";
import {
  ADVISORIES_FILE,
  UpdateLockedError,
  acquireUpdateLock,
  GzipLineWriter,
  MALWARE_FILE,
  STORE_SCHEMA,
  makeStagingDir,
  readMeta,
  removeLeftovers,
  swapIntoPlace,
  writeMeta,
  type OsvMeta,
} from "./store.js";
import { forEachZipEntry, ZipError, type ZipLimits } from "./zip.js";

export const OSV_ECOSYSTEMS: readonly Ecosystem[] = ["npm", "Go"];

export interface UpdateOptions {
  appDataDir: string;
  ecosystems?: readonly Ecosystem[];
  fetch?: typeof fetch;
  now?: () => number;
  signal?: AbortSignal;
  maxArchiveBytes?: number;
  timeoutMs?: number;
  idleTimeoutMs?: number;
  allowedHosts?: readonly string[];
  zipLimits?: ZipLimits;
  /** Accept data that is older than, or much smaller than, the installed data. Default: refuse. */
  force?: boolean;
  onProgress?: (ecosystem: Ecosystem, receivedBytes: number, totalBytes: number | null) => void;
}

export type UpdateOutcome =
  | {
      ecosystem: Ecosystem;
      ok: true;
      meta: OsvMeta;
      downloadMs: number;
      indexMs: number;
    }
  | {
      ecosystem: Ecosystem;
      ok: false;
      error: string;
      /** Set when the new data was refused because it would replace newer or larger data. */
      refusal?: "older-data" | "smaller-data";
    };

/**
 * The new archive is refused when it holds fewer than this share of the installed record count.
 * OSV exports only grow (withdrawn records stay in the export marked withdrawn), so a real drop is
 * a sign of a truncated or replayed archive. Half leaves room for a large clean-up by OSV while
 * still catching a rollback to a much older snapshot; `--force` accepts a deliberate change.
 */
export const MIN_RECORD_SHARE = 0.5;

export class RollbackRefusedError extends Error {
  constructor(
    message: string,
    readonly reason: "older-data" | "smaller-data",
  ) {
    super(message);
    this.name = "RollbackRefusedError";
  }
}

/** A full timestamp (`2026-10-27T00:00:00Z`) so two dates on the same day are still told apart. */
const stamp = (iso: string): string => iso.slice(0, 19) + (iso.length > 19 ? "Z" : "");

const isCount = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value) && value >= 0;

function parseTime(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const time = Date.parse(value);
  return Number.isNaN(time) ? null : time;
}

/**
 * Throws {@link RollbackRefusedError} when `next` would replace newer or much larger data. A part
 * of the installed metadata that is missing or malformed (hand-edited file) counts as unknown and
 * that part of the check is skipped.
 */
export function assertNotRollback(installed: OsvMeta | null, next: OsvMeta): void {
  if (installed === null) return;
  const oldMax = installed.modifiedRange?.max;
  const newMax = next.modifiedRange?.max;
  const oldTime = parseTime(oldMax);
  const newTime = parseTime(newMax);
  if (oldTime !== null && newTime !== null && newTime < oldTime) {
    throw new RollbackRefusedError(
      `The downloaded data is older than the installed data (newest record ${stamp(String(newMax))} against ${stamp(String(oldMax))} installed), so it was not installed.`,
      "older-data",
    );
  }
  const oldAdvisories: unknown = installed.counts?.advisories;
  const oldMalware: unknown = installed.counts?.malware;
  if (isCount(oldAdvisories) && isCount(oldMalware)) {
    const oldCount = oldAdvisories + oldMalware;
    const newCount = next.counts.advisories + next.counts.malware;
    if (oldCount > 0 && newCount < oldCount * MIN_RECORD_SHARE) {
      throw new RollbackRefusedError(
        `The downloaded data has far fewer records (${newCount}) than the installed data (${oldCount}; newest record ${oldTime === null ? "unknown" : stamp(String(oldMax))}), so it was not installed.`,
        "smaller-data",
      );
    }
  }
}

function describeFailure(error: unknown): string {
  if (
    error instanceof DownloadError ||
    error instanceof ZipError ||
    error instanceof UpdateLockedError
  ) {
    return error.message;
  }
  if (error instanceof RollbackRefusedError) return error.message;
  if (error instanceof Error && error.name === "AbortError") return "Cancelled.";
  return "Could not store the data (disk error or unexpected format).";
}

async function updateOne(ecosystem: Ecosystem, options: UpdateOptions): Promise<UpdateOutcome> {
  const osvDir = osvDataDir(options.appDataDir);
  const now = options.now ?? Date.now;
  let stagingDir: string | null = null;
  const writers: GzipLineWriter[] = [];
  try {
    stagingDir = await makeStagingDir(osvDir, ecosystem);
    const archivePath = path.join(stagingDir, "archive.zip");
    const downloadOptions: DownloadOptions = {
      fetch: options.fetch ?? fetch,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
      ...(options.maxArchiveBytes === undefined ? {} : { maxBytes: options.maxArchiveBytes }),
      ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
      ...(options.idleTimeoutMs === undefined ? {} : { idleTimeoutMs: options.idleTimeoutMs }),
      ...(options.allowedHosts === undefined ? {} : { allowedHosts: options.allowedHosts }),
      onProgress: (received, total) => options.onProgress?.(ecosystem, received, total),
    };
    const download: DownloadResult = await downloadToFile(
      osvArchiveUrl(ecosystem),
      archivePath,
      downloadOptions,
    );
    const fetchedAt = new Date(now()).toISOString();

    const indexStart = Date.now();
    const advisories = new GzipLineWriter(path.join(stagingDir, ADVISORIES_FILE));
    const malware = new GzipLineWriter(path.join(stagingDir, MALWARE_FILE));
    writers.push(advisories, malware);
    const counts = { entries: 0, advisories: 0, malware: 0, withdrawn: 0, skipped: 0 };
    let min: string | null = null;
    let max: string | null = null;
    await forEachZipEntry(
      archivePath,
      async ({ data }) => {
        counts.entries += 1;
        let raw: unknown;
        try {
          raw = JSON.parse(data.toString("utf8"));
        } catch {
          throw new ZipError("A record in the archive is not valid JSON.");
        }
        const reduced = reduceAdvisory(raw, ecosystem);
        if (reduced === null) {
          counts.skipped += 1;
          return;
        }
        if (min === null || reduced.modified < min) min = reduced.modified;
        if (max === null || reduced.modified > max) max = reduced.modified;
        if (reduced.withdrawn !== undefined) counts.withdrawn += 1;
        const line = JSON.stringify(reduced);
        if (isMalwareId(reduced.id)) {
          counts.malware += 1;
          await malware.writeLine(line);
        } else {
          counts.advisories += 1;
          await advisories.writeLine(line);
        }
      },
      options.zipLimits,
    );
    if (counts.advisories + counts.malware === 0) {
      throw new ZipError("The archive holds no usable records.");
    }
    const files = {
      [ADVISORIES_FILE]: await advisories.close(),
      [MALWARE_FILE]: await malware.close(),
    };
    writers.length = 0;
    const indexMs = Date.now() - indexStart;
    await rm(archivePath, { force: true });
    const meta: OsvMeta = {
      schema: STORE_SCHEMA,
      ecosystem,
      sourceUrl: download.url,
      fetchedAt,
      archive: {
        bytes: download.bytes,
        sha256: download.sha256,
        lastModified: download.lastModified,
        etag: download.etag,
      },
      counts,
      modifiedRange: min === null || max === null ? null : { min, max },
      files,
    };
    if (options.force !== true) assertNotRollback(await readMeta(osvDir, ecosystem), meta);
    await writeMeta(stagingDir, meta);
    await swapIntoPlace(osvDir, ecosystem, stagingDir);
    stagingDir = null;
    return { ecosystem, ok: true, meta, downloadMs: download.durationMs, indexMs };
  } catch (error) {
    for (const writer of writers) writer.abort();
    return {
      ecosystem,
      ok: false,
      error: describeFailure(error),
      ...(error instanceof RollbackRefusedError ? { refusal: error.reason } : {}),
    };
  } finally {
    if (stagingDir !== null)
      await rm(stagingDir, { recursive: true, force: true }).catch(() => undefined);
  }
}

/**
 * `pgard advisories update`: for each ecosystem, download the OSV bulk export, verify the zip
 * (central directory, every entry's CRC-32 and size), store a compact index and swap it in
 * atomically. A failure for one ecosystem leaves that ecosystem's previous data untouched.
 * Package names are never sent: the only request is a GET of a fixed archive URL.
 */
export async function updateOsvData(options: UpdateOptions): Promise<UpdateOutcome[]> {
  const ecosystems = options.ecosystems ?? OSV_ECOSYSTEMS;
  const osvDir = osvDataDir(options.appDataDir);
  let release: () => Promise<void>;
  try {
    release = await acquireUpdateLock(osvDir, options.now);
  } catch (error) {
    return ecosystems.map((ecosystem) => ({
      ecosystem,
      ok: false as const,
      error: describeFailure(error),
    }));
  }
  try {
    await removeLeftovers(osvDir);
    const outcomes: UpdateOutcome[] = [];
    for (const ecosystem of ecosystems) {
      outcomes.push(await updateOne(ecosystem, options));
    }
    return outcomes;
  } finally {
    await release();
  }
}
