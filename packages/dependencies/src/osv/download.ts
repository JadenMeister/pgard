import { createHash } from "node:crypto";
import { once } from "node:events";
import { createWriteStream } from "node:fs";
import type { Ecosystem } from "../types.js";

/**
 * The official OSV export bucket (https://google.github.io/osv.dev/data/): per ecosystem,
 * `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`. This is the only host
 * PGARD downloads advisory data from, and it is pinned: other hosts, other schemes and redirects
 * to them are refused.
 */
export const OSV_EXPORT_HOST = "osv-vulnerabilities.storage.googleapis.com";
export const ALLOWED_DOWNLOAD_HOSTS: readonly string[] = [OSV_EXPORT_HOST];

export function osvArchiveUrl(ecosystem: Ecosystem): string {
  return `https://${OSV_EXPORT_HOST}/${ecosystem}/all.zip`;
}

export const MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024;
export const DOWNLOAD_TIMEOUT_MS = 15 * 60 * 1000;
const MAX_REDIRECTS = 3;

export class DownloadError extends Error {
  readonly code: "host" | "scheme" | "redirect" | "http" | "size" | "timeout" | "network";
  constructor(code: DownloadError["code"], message: string) {
    super(message);
    this.name = "DownloadError";
    this.code = code;
  }
}

export interface DownloadOptions {
  fetch: typeof fetch;
  signal?: AbortSignal;
  maxBytes?: number;
  timeoutMs?: number;
  allowedHosts?: readonly string[];
  onProgress?: (receivedBytes: number, totalBytes: number | null) => void;
}

export interface DownloadResult {
  url: string;
  bytes: number;
  sha256: string;
  lastModified: string | null;
  etag: string | null;
  durationMs: number;
}

function checkUrl(url: URL, allowedHosts: readonly string[]): void {
  if (url.protocol !== "https:")
    throw new DownloadError("scheme", "Only https downloads are allowed.");
  if (url.username !== "" || url.password !== "" || url.port !== "") {
    throw new DownloadError("host", "The download address must not carry credentials or a port.");
  }
  if (!allowedHosts.includes(url.hostname)) {
    throw new DownloadError("host", `Downloads from ${url.hostname.slice(0, 80)} are not allowed.`);
  }
}

/**
 * Streams `sourceUrl` into `destination` while hashing it. Every hop, including redirects, must be
 * https on an allowlisted host. Nothing but the URL is sent: no query, no cookies, no package names.
 */
export async function downloadToFile(
  sourceUrl: string,
  destination: string,
  options: DownloadOptions,
): Promise<DownloadResult> {
  const allowedHosts = options.allowedHosts ?? ALLOWED_DOWNLOAD_HOSTS;
  const maxBytes = options.maxBytes ?? MAX_ARCHIVE_BYTES;
  const timeout = AbortSignal.timeout(options.timeoutMs ?? DOWNLOAD_TIMEOUT_MS);
  const signal =
    options.signal === undefined ? timeout : AbortSignal.any([timeout, options.signal]);
  const startedAt = Date.now();
  try {
    let url = new URL(sourceUrl);
    let response: Response | null = null;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
      checkUrl(url, allowedHosts);
      response = await options.fetch(url.href, {
        method: "GET",
        redirect: "manual",
        credentials: "omit",
        headers: { accept: "application/zip" },
        signal,
      });
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        await response.body?.cancel().catch(() => undefined);
        if (location === null || hop === MAX_REDIRECTS) {
          throw new DownloadError("redirect", "Too many or invalid redirects.");
        }
        url = new URL(location, url);
        continue;
      }
      break;
    }
    if (response === null || !response.ok || response.body === null) {
      throw new DownloadError("http", `The server answered ${response?.status ?? "nothing"}.`);
    }
    const declared = Number(response.headers.get("content-length"));
    const declaredLength = Number.isFinite(declared) && declared > 0 ? declared : null;
    if (declaredLength !== null && declaredLength > maxBytes) {
      await response.body.cancel().catch(() => undefined);
      throw new DownloadError("size", "The archive is larger than the allowed size.");
    }

    const hash = createHash("sha256");
    const file = createWriteStream(destination, { flags: "wx", mode: 0o600 });
    let received = 0;
    try {
      const reader = response.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > maxBytes) {
          await reader.cancel().catch(() => undefined);
          throw new DownloadError("size", "The archive is larger than the allowed size.");
        }
        hash.update(value);
        if (!file.write(value)) {
          await once(file, "drain");
        }
        options.onProgress?.(received, declaredLength);
      }
    } finally {
      await new Promise<void>((resolve) => file.end(resolve));
    }
    if (declaredLength !== null && received !== declaredLength) {
      throw new DownloadError("network", "The download ended before the announced size.");
    }
    if (received === 0) throw new DownloadError("network", "The download was empty.");
    return {
      url: url.href,
      bytes: received,
      sha256: hash.digest("hex"),
      lastModified: response.headers.get("last-modified"),
      etag: response.headers.get("etag"),
      durationMs: Date.now() - startedAt,
    };
  } catch (error) {
    if (error instanceof DownloadError) throw error;
    if (timeout.aborted) throw new DownloadError("timeout", "The download timed out.");
    if (options.signal?.aborted) throw error;
    throw new DownloadError("network", "The download failed.");
  }
}
