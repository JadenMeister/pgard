import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { osvDataDir } from "../app-data.js";
import type { ReducedAdvisory } from "../osv/reduce.js";
import {
  ADVISORIES_FILE,
  MALWARE_FILE,
  OSV_META_FILE,
  STORE_SCHEMA,
  type OsvMeta,
} from "../osv/store.js";
import type { Ecosystem } from "../types.js";

export interface FixtureOptions {
  fetchedAt?: string;
  modifiedMax?: string;
  /** Write a wrong checksum into meta.json (a damaged store). */
  badChecksum?: boolean;
  /** Raw JSON lines to append (malformed records). */
  extraLines?: string[];
}

/**
 * Writes a small OSV store for tests into `<appDataDir>/advisories/osv/<ecosystem>`. Tests pass a
 * temporary directory; the real per-user store is never touched.
 */
export async function writeOsvFixture(
  appDataDir: string,
  ecosystem: Ecosystem,
  advisories: readonly ReducedAdvisory[],
  options: FixtureOptions = {},
): Promise<void> {
  const directory = path.join(osvDataDir(appDataDir), ecosystem);
  await mkdir(directory, { recursive: true });
  const text = [...advisories.map((a) => JSON.stringify(a)), ...(options.extraLines ?? [])].join(
    "\n",
  );
  const gz = gzipSync(Buffer.from(`${text}\n`));
  const sha256 =
    options.badChecksum === true ? "0".repeat(64) : createHash("sha256").update(gz).digest("hex");
  await writeFile(path.join(directory, ADVISORIES_FILE), gz);
  const empty = gzipSync(Buffer.from(""));
  await writeFile(path.join(directory, MALWARE_FILE), empty);
  const meta: OsvMeta = {
    schema: STORE_SCHEMA,
    ecosystem,
    sourceUrl: "https://example.invalid/fixture.zip",
    fetchedAt: options.fetchedAt ?? new Date().toISOString(),
    archive: { bytes: 1, sha256: "a".repeat(64), lastModified: null, etag: null },
    counts: {
      entries: advisories.length,
      advisories: advisories.length,
      malware: 0,
      withdrawn: 0,
      skipped: 0,
    },
    modifiedRange: {
      min: "2026-01-01T00:00:00Z",
      max: options.modifiedMax ?? options.fetchedAt ?? new Date().toISOString(),
    },
    files: {
      [ADVISORIES_FILE]: { bytes: gz.length, sha256 },
      [MALWARE_FILE]: {
        bytes: empty.length,
        sha256: createHash("sha256").update(empty).digest("hex"),
      },
    },
  };
  await writeFile(path.join(directory, OSV_META_FILE), JSON.stringify(meta, null, 2));
}

export function advisory(
  id: string,
  name: string,
  events: Record<string, string>[],
  extra: Partial<ReducedAdvisory> = {},
): ReducedAdvisory {
  return {
    id,
    modified: "2026-10-20T00:00:00Z",
    affected: [{ name, ranges: [{ type: "SEMVER", events }] }],
    ...extra,
  };
}
