import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { once } from "node:events";
import { mkdir, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { createGzip, type Gzip } from "node:zlib";
import type { Ecosystem } from "../types.js";

export const OSV_META_FILE = "meta.json";
export const ADVISORIES_FILE = "advisories.jsonl.gz";
export const MALWARE_FILE = "malware.jsonl.gz";
export const STORE_SCHEMA = 1;

export interface FileRecord {
  bytes: number;
  sha256: string;
}

/** `meta.json`: everything needed to show age and to check the stored files without the network. */
export interface OsvMeta {
  schema: typeof STORE_SCHEMA;
  ecosystem: Ecosystem;
  sourceUrl: string;
  fetchedAt: string;
  archive: FileRecord & { lastModified: string | null; etag: string | null };
  counts: {
    entries: number;
    advisories: number;
    malware: number;
    withdrawn: number;
    skipped: number;
  };
  /** Smallest and largest `modified` among the stored records (RFC 3339), or null if none. */
  modifiedRange: { min: string; max: string } | null;
  files: Record<string, FileRecord>;
}

/** Gzipped JSON-lines writer with backpressure and a hash of the compressed bytes. */
export class GzipLineWriter {
  private readonly gzip: Gzip = createGzip({ level: 6 });
  private readonly out;
  private readonly hash = createHash("sha256");
  private bytes = 0;
  private readonly finished: Promise<void>;
  private failure: Error | null = null;

  constructor(filePath: string) {
    this.out = createWriteStream(filePath, { flags: "wx", mode: 0o600 });
    this.gzip.on("data", (chunk: Buffer) => {
      this.hash.update(chunk);
      this.bytes += chunk.length;
    });
    this.gzip.pipe(this.out);
    this.finished = new Promise((resolve, reject) => {
      this.out.once("finish", resolve);
      this.out.once("error", reject);
      this.gzip.once("error", reject);
    });
    this.finished.catch((error: unknown) => {
      this.failure = error instanceof Error ? error : new Error(String(error));
    });
  }

  async writeLine(line: string): Promise<void> {
    if (this.failure !== null) throw this.failure;
    if (!this.gzip.write(`${line}\n`)) {
      // `finished` only ever rejects before the end: it wakes this wait on a stream error.
      await Promise.race([once(this.gzip, "drain"), this.finished]);
    }
    if (this.failure !== null) throw this.failure;
  }

  async close(): Promise<FileRecord> {
    if (this.failure !== null) throw this.failure;
    this.gzip.end();
    await this.finished;
    return { bytes: this.bytes, sha256: this.hash.digest("hex") };
  }

  abort(): void {
    this.gzip.destroy();
    this.out.destroy();
  }
}

export async function sha256OfFile(filePath: string): Promise<FileRecord> {
  const hash = createHash("sha256");
  let bytes = 0;
  for await (const chunk of createReadStream(filePath)) {
    hash.update(chunk as Buffer);
    bytes += (chunk as Buffer).length;
  }
  return { bytes, sha256: hash.digest("hex") };
}

export function ecosystemDir(osvDir: string, ecosystem: Ecosystem): string {
  return path.join(osvDir, ecosystem);
}

/**
 * Replaces `<osvDir>/<ecosystem>` with the fully written staging directory. The old directory is
 * renamed aside first and restored if the second rename fails, so a failure leaves the old data.
 */
export async function swapIntoPlace(
  osvDir: string,
  ecosystem: Ecosystem,
  stagingDir: string,
): Promise<void> {
  const finalDir = ecosystemDir(osvDir, ecosystem);
  const asideDir = path.join(osvDir, `.old-${ecosystem}-${process.pid}-${Date.now()}`);
  let hadOld = true;
  try {
    await rename(finalDir, asideDir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    hadOld = false;
  }
  try {
    await rename(stagingDir, finalDir);
  } catch (error) {
    if (hadOld) await rename(asideDir, finalDir).catch(() => undefined);
    throw error;
  }
  if (hadOld) await rm(asideDir, { recursive: true, force: true }).catch(() => undefined);
}

export async function writeMeta(directory: string, meta: OsvMeta): Promise<void> {
  await writeFile(path.join(directory, OSV_META_FILE), `${JSON.stringify(meta, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
}

export const LOCK_FILE = ".update.lock";
/** A lock older than this is stale even if its pid is alive (the pid may have been reused). */
const LOCK_MAX_AGE_MS = 60 * 60 * 1000;
const TAKEOVER_MAX_AGE_MS = 60 * 1000;

export class UpdateLockedError extends Error {
  constructor() {
    super("Another `pgard advisories update` is already running. Wait for it to finish.");
    this.name = "UpdateLockedError";
  }
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Takes the update lock (`O_EXCL` file holding the pid). A lock whose process is gone, or that is
 * older than an hour, is stale and replaced. Returns a release function.
 */
export async function acquireUpdateLock(
  osvDir: string,
  now: () => number = Date.now,
): Promise<() => Promise<void>> {
  await mkdir(osvDir, { recursive: true, mode: 0o700 });
  const lockPath = path.join(osvDir, LOCK_FILE);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    try {
      await writeFile(lockPath, `${process.pid}\n`, { flag: "wx", mode: 0o600 });
      return async () => {
        // Remove the lock only if it is still ours (a stale-lock takeover may have replaced it).
        const current = await readFile(lockPath, "utf8").catch(() => "");
        if (Number.parseInt(current, 10) === process.pid) {
          await rm(lockPath, { force: true }).catch(() => undefined);
        }
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    let holder = Number.NaN;
    let ageMs = 0;
    try {
      holder = Number.parseInt(await readFile(lockPath, "utf8"), 10);
      ageMs = now() - (await stat(lockPath)).mtimeMs;
    } catch {
      continue; // released between the two calls: try again
    }
    const isLive = Number.isInteger(holder) && holder > 0 && isProcessAlive(holder);
    if (isLive && ageMs < LOCK_MAX_AGE_MS) throw new UpdateLockedError();
    // Taking a stale lock over is itself exclusive: only the run that holds the takeover marker
    // may remove it, and only if it is still the very lock judged stale. Everyone then competes on
    // the atomic create above, so exactly one run wins.
    const marker = `${lockPath}.takeover`;
    try {
      await writeFile(marker, `${process.pid}\n`, { flag: "wx", mode: 0o600 });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const markerAge = now() - ((await stat(marker).catch(() => null))?.mtimeMs ?? now());
      if (markerAge < TAKEOVER_MAX_AGE_MS) throw new UpdateLockedError();
      await rm(marker, { force: true }); // left by a crashed run
      continue;
    }
    try {
      const current = Number.parseInt(await readFile(lockPath, "utf8").catch(() => ""), 10);
      if (current === holder) await rm(lockPath, { force: true });
    } finally {
      await rm(marker, { force: true });
    }
  }
  throw new UpdateLockedError();
}

/**
 * Removes staging and aside directories left by an interrupted run. Call it only while holding
 * the update lock: otherwise it would delete a live update's staging directory.
 */
export async function removeLeftovers(osvDir: string): Promise<void> {
  let names: string[];
  try {
    names = await readdir(osvDir);
  } catch {
    return;
  }
  for (const name of names) {
    if (name.startsWith(".staging-") || name.startsWith(".old-")) {
      await rm(path.join(osvDir, name), { recursive: true, force: true }).catch(() => undefined);
    }
  }
}

export async function makeStagingDir(osvDir: string, ecosystem: Ecosystem): Promise<string> {
  await mkdir(osvDir, { recursive: true, mode: 0o700 });
  const dir = path.join(osvDir, `.staging-${ecosystem}-${process.pid}-${Date.now()}`);
  await mkdir(dir, { mode: 0o700 });
  return dir;
}

export async function readMeta(osvDir: string, ecosystem: Ecosystem): Promise<OsvMeta | null> {
  try {
    const text = await readFile(path.join(ecosystemDir(osvDir, ecosystem), OSV_META_FILE), "utf8");
    const value = JSON.parse(text) as Partial<OsvMeta>;
    if (
      value.schema !== STORE_SCHEMA ||
      value.ecosystem !== ecosystem ||
      typeof value.fetchedAt !== "string" ||
      typeof value.files !== "object" ||
      value.files === null
    ) {
      return null;
    }
    return value as OsvMeta;
  } catch {
    return null;
  }
}

export async function filesMatchMeta(osvDir: string, meta: OsvMeta): Promise<boolean> {
  for (const [name, record] of Object.entries(meta.files)) {
    try {
      const stats = await stat(path.join(ecosystemDir(osvDir, meta.ecosystem), name));
      if (!stats.isFile() || stats.size !== record.bytes) return false;
    } catch {
      return false;
    }
  }
  return true;
}
