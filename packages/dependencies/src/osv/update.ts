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
  | { ecosystem: Ecosystem; ok: false; error: string };

function describeFailure(error: unknown): string {
  if (
    error instanceof DownloadError ||
    error instanceof ZipError ||
    error instanceof UpdateLockedError
  ) {
    return error.message;
  }
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
    await writeMeta(stagingDir, meta);
    await swapIntoPlace(osvDir, ecosystem, stagingDir);
    stagingDir = null;
    return { ecosystem, ok: true, meta, downloadMs: download.durationMs, indexMs };
  } catch (error) {
    for (const writer of writers) writer.abort();
    return { ecosystem, ok: false, error: describeFailure(error) };
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
