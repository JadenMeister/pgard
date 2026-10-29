import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { gunzipSync } from "node:zlib";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { osvDataDir } from "../app-data.js";
import { makeZip, osvRecord, type TestZipEntry } from "../test-support/zip.js";
import { downloadToFile, DownloadError, OSV_EXPORT_HOST, osvArchiveUrl } from "./download.js";
import { readAdvisoryStatus } from "./status.js";
import { GzipLineWriter, acquireUpdateLock, removeLeftovers, swapIntoPlace } from "./store.js";
import { updateOsvData } from "./update.js";
import { DEFAULT_ZIP_LIMITS, forEachZipEntry, ZipError } from "./zip.js";

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), "pgard-osv-test-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const goodEntries: TestZipEntry[] = [
  {
    name: "GHSA-aaaa-bbbb-cccc.json",
    content: osvRecord("GHSA-aaaa-bbbb-cccc", "left-pad", {
      database_specific: { severity: "HIGH" },
    }),
  },
  {
    name: "MAL-2026-1.json",
    content: osvRecord("MAL-2026-1", "evil-pkg", { modified: "2026-10-25T00:00:00Z" }),
  },
  {
    name: "GHSA-wd.json",
    content: osvRecord("GHSA-wd", "other", {
      withdrawn: "2026-01-01T00:00:00Z",
      modified: "2026-01-02T00:00:00Z",
    }),
  },
  {
    name: "GHSA-other-eco.json",
    content: JSON.stringify({
      id: "GHSA-other-eco",
      modified: "2026-10-01T00:00:00Z",
      affected: [{ package: { ecosystem: "PyPI", name: "x" } }],
    }),
  },
];

interface Served {
  status?: number;
  body?: Buffer;
  headers?: Record<string, string>;
}

/** A fetch fake that records requests and answers per URL. */
function fakeFetch(answer: (url: string) => Served) {
  const calls: { url: string; init: RequestInit | undefined }[] = [];
  const impl: typeof fetch = async (input, init) => {
    const url = String(input);
    calls.push({ url, init });
    const served = answer(url);
    return new Response(served.body === undefined ? null : new Uint8Array(served.body), {
      status: served.status ?? 200,
      headers: {
        ...(served.body === undefined ? {} : { "content-length": String(served.body.length) }),
        ...served.headers,
      },
    });
  };
  return { impl, calls };
}

const sha256 = (buffer: Buffer): string => createHash("sha256").update(buffer).digest("hex");
const readJsonl = async (file: string): Promise<Record<string, unknown>[]> =>
  gunzipSync(await readFile(file))
    .toString("utf8")
    .trim()
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line) as Record<string, unknown>);

describe("updateOsvData", () => {
  it("stores a verified compact index, separates MAL- records and records provenance", async () => {
    const archive = makeZip(goodEntries);
    const { impl, calls } = fakeFetch(() => ({
      body: archive,
      headers: { "last-modified": "Mon, 26 Oct 2026 07:48:28 GMT" },
    }));
    const outcomes = await updateOsvData({
      appDataDir: dir,
      ecosystems: ["npm"],
      fetch: impl,
      now: () => Date.parse("2026-10-26T12:00:00Z"),
    });
    const outcome = outcomes[0]!;
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const { meta } = outcome;
    expect(meta.sourceUrl).toBe(`https://${OSV_EXPORT_HOST}/npm/all.zip`);
    expect(meta.fetchedAt).toBe("2026-10-26T12:00:00.000Z");
    expect(meta.archive).toMatchObject({ bytes: archive.length, sha256: sha256(archive) });
    expect(meta.counts).toEqual({
      entries: 4,
      advisories: 2,
      malware: 1,
      withdrawn: 1,
      skipped: 1,
    });
    expect(meta.modifiedRange).toEqual({
      min: "2026-01-02T00:00:00Z",
      max: "2026-10-25T00:00:00Z",
    });

    const ecosystemDir = path.join(osvDataDir(dir), "npm");
    expect((await readdir(ecosystemDir)).sort()).toEqual([
      "advisories.jsonl.gz",
      "malware.jsonl.gz",
      "meta.json",
    ]);
    const advisories = await readJsonl(path.join(ecosystemDir, "advisories.jsonl.gz"));
    expect(advisories.map((a) => a["id"])).toEqual(["GHSA-aaaa-bbbb-cccc", "GHSA-wd"]);
    expect(advisories[0]).toMatchObject({
      label: "HIGH",
      summary: "summary of GHSA-aaaa-bbbb-cccc",
    });
    expect(JSON.stringify(advisories)).not.toContain("must not be stored");
    const malware = await readJsonl(path.join(ecosystemDir, "malware.jsonl.gz"));
    expect(malware.map((a) => a["id"])).toEqual(["MAL-2026-1"]);
    for (const [name, record] of Object.entries(meta.files)) {
      const bytes = await readFile(path.join(ecosystemDir, name));
      expect(record).toEqual({ bytes: bytes.length, sha256: sha256(bytes) });
    }
    // The only request: a plain GET of the fixed URL, no query, no body, no cookies.
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip");
    expect(calls[0]!.init).toMatchObject({
      method: "GET",
      credentials: "omit",
      redirect: "manual",
    });
    expect(calls[0]!.init?.body).toBeUndefined();
    expect(Object.keys(calls[0]!.init?.headers as Record<string, string>)).toEqual(["accept"]);
    // The downloaded archive and staging directories are gone.
    expect(await readdir(osvDataDir(dir))).toEqual(["npm"]);
  });

  it("works against a local HTTP server through an injected fetch", async () => {
    const archive = makeZip(goodEntries);
    const seen: string[] = [];
    const server: Server = createServer((request, response) => {
      seen.push(`${request.method} ${request.url} cookie=${request.headers.cookie ?? ""}`);
      response.writeHead(200, {
        "content-type": "application/zip",
        "content-length": archive.length,
      });
      response.end(archive);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const { port } = server.address() as AddressInfo;
      const toLocal: typeof fetch = (input, init) =>
        fetch(
          String(input).replace(`https://${OSV_EXPORT_HOST}`, `http://127.0.0.1:${port}`),
          init,
        );
      const [outcome] = await updateOsvData({
        appDataDir: dir,
        ecosystems: ["npm"],
        fetch: toLocal,
      });
      expect(outcome?.ok).toBe(true);
      expect(seen).toEqual(["GET /npm/all.zip cookie="]);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it("keeps the old data when the new archive fails its checksum", async () => {
    const first = fakeFetch(() => ({ body: makeZip(goodEntries) }));
    await updateOsvData({ appDataDir: dir, ecosystems: ["npm"], fetch: first.impl });
    const metaPath = path.join(osvDataDir(dir), "npm", "meta.json");
    const before = await readFile(metaPath, "utf8");
    const advisoriesBefore = await readFile(
      path.join(osvDataDir(dir), "npm", "advisories.jsonl.gz"),
    );

    const corrupt = makeZip([{ ...goodEntries[0]!, badCrc: true }, goodEntries[1]!]);
    const [outcome] = await updateOsvData({
      appDataDir: dir,
      ecosystems: ["npm"],
      fetch: fakeFetch(() => ({ body: corrupt })).impl,
    });
    expect(outcome).toMatchObject({ ok: false, error: "An entry failed its checksum." });
    expect(await readFile(metaPath, "utf8")).toBe(before);
    expect(await readFile(path.join(osvDataDir(dir), "npm", "advisories.jsonl.gz"))).toEqual(
      advisoriesBefore,
    );
    expect(await readdir(osvDataDir(dir))).toEqual(["npm"]); // no staging leftovers
  });

  it("keeps the old data for truncated, non-zip, empty, 404 and invalid-JSON downloads", async () => {
    await updateOsvData({
      appDataDir: dir,
      ecosystems: ["npm"],
      fetch: fakeFetch(() => ({ body: makeZip(goodEntries) })).impl,
    });
    const metaPath = path.join(osvDataDir(dir), "npm", "meta.json");
    const before = await readFile(metaPath, "utf8");
    const archive = makeZip(goodEntries);
    const attempts: Served[] = [
      { body: archive.subarray(0, archive.length - 30) },
      { body: Buffer.from("<html>not a zip</html>") },
      { body: Buffer.alloc(0) },
      { status: 404, body: Buffer.from("nope") },
      { body: makeZip([{ name: "GHSA-x.json", content: "{ broken" }]) },
      { body: makeZip([{ name: "../evil.json", content: osvRecord("X", "x") }]) },
      { body: makeZip([{ name: "GHSA-y.json", content: JSON.stringify({ id: "n/a" }) }]) },
    ];
    for (const attempt of attempts) {
      const [outcome] = await updateOsvData({
        appDataDir: dir,
        ecosystems: ["npm"],
        fetch: fakeFetch(() => attempt).impl,
      });
      expect(outcome?.ok, JSON.stringify(Object.keys(attempt))).toBe(false);
      expect(await readFile(metaPath, "utf8")).toBe(before);
    }
    expect(await readdir(osvDataDir(dir))).toEqual(["npm"]);
  });

  it("fails an announced-length mismatch without replacing data", async () => {
    const archive = makeZip(goodEntries);
    const { impl } = fakeFetch(() => ({
      body: archive,
      headers: { "content-length": String(archive.length + 10) },
    }));
    const [outcome] = await updateOsvData({ appDataDir: dir, ecosystems: ["npm"], fetch: impl });
    expect(outcome?.ok).toBe(false);
    expect(await readdir(osvDataDir(dir))).toEqual([]);
  });

  it("updates each ecosystem independently", async () => {
    const { impl } = fakeFetch((url) =>
      url.includes("/npm/") ? { body: makeZip(goodEntries) } : { status: 500 },
    );
    const outcomes = await updateOsvData({ appDataDir: dir, fetch: impl });
    expect(outcomes.map((o) => [o.ecosystem, o.ok])).toEqual([
      ["npm", true],
      ["Go", false],
    ]);
  });
});

describe("download allowlist and caps", () => {
  const archive = makeZip(goodEntries);
  const target = path.join("x", "y");

  it("pins the official host and https", async () => {
    expect(osvArchiveUrl("npm")).toBe(
      "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
    );
    expect(osvArchiveUrl("Go")).toBe(
      "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
    );
    const calls = fakeFetch(() => ({ body: archive }));
    for (const url of [
      "https://evil.example.com/npm/all.zip",
      "https://osv-vulnerabilities.storage.googleapis.com.evil.com/npm/all.zip",
      "https://user:pw@osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
      "https://osv-vulnerabilities.storage.googleapis.com:8443/npm/all.zip",
      "http://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
      "file:///etc/passwd",
    ]) {
      await expect(
        downloadToFile(url, path.join(dir, "a.zip"), { fetch: calls.impl }),
      ).rejects.toBeInstanceOf(DownloadError);
    }
    expect(calls.calls).toHaveLength(0); // refused before any request
    void target;
  });

  it("refuses redirects to other hosts, to http, and redirect loops", async () => {
    for (const location of [
      "https://evil.example.com/npm/all.zip",
      "http://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
      "//evil.example.com/x",
    ]) {
      const { impl, calls } = fakeFetch((url) =>
        url.startsWith("https://osv-vulnerabilities")
          ? { status: 302, headers: { location } }
          : { body: archive },
      );
      await expect(
        downloadToFile(osvArchiveUrl("npm"), path.join(dir, "r.zip"), { fetch: impl }),
      ).rejects.toMatchObject({ name: "DownloadError" });
      expect(calls.map((c) => new URL(c.url).hostname)).toEqual([OSV_EXPORT_HOST]);
    }
    const loop = fakeFetch(() => ({ status: 302, headers: { location: osvArchiveUrl("npm") } }));
    await expect(
      downloadToFile(osvArchiveUrl("npm"), path.join(dir, "l.zip"), { fetch: loop.impl }),
    ).rejects.toMatchObject({ code: "redirect" });
  });

  it("follows a redirect that stays on the pinned host", async () => {
    const { impl } = fakeFetch((url) =>
      url.endsWith("/npm/all.zip")
        ? { status: 302, headers: { location: `https://${OSV_EXPORT_HOST}/npm/moved.zip` } }
        : { body: archive },
    );
    const result = await downloadToFile(osvArchiveUrl("npm"), path.join(dir, "ok.zip"), {
      fetch: impl,
    });
    expect(result.url).toContain("moved.zip");
    expect(result.bytes).toBe(archive.length);
  });

  it("enforces the size cap from the announced length and from the stream", async () => {
    const announced = fakeFetch(() => ({ body: archive }));
    await expect(
      downloadToFile(osvArchiveUrl("npm"), path.join(dir, "s1.zip"), {
        fetch: announced.impl,
        maxBytes: archive.length - 1,
      }),
    ).rejects.toMatchObject({ code: "size" });
    const streamed: typeof fetch = async () =>
      new Response(new Uint8Array(archive), { status: 200 }); // no content-length
    await expect(
      downloadToFile(osvArchiveUrl("npm"), path.join(dir, "s2.zip"), {
        fetch: streamed,
        maxBytes: archive.length - 1,
      }),
    ).rejects.toMatchObject({ code: "size" });
    await expect(
      downloadToFile(osvArchiveUrl("npm"), path.join(dir, "s3.zip"), {
        fetch: streamed,
        maxBytes: archive.length,
      }),
    ).resolves.toMatchObject({ bytes: archive.length });
  });

  it("does not read the body of an archive announced as too large", async () => {
    let pulls = 0;
    const announced: typeof fetch = async () =>
      new Response(
        new ReadableStream<Uint8Array>(
          {
            pull(controller) {
              pulls += 1;
              controller.enqueue(new Uint8Array(10));
            },
          },
          { highWaterMark: 0 },
        ),
        { status: 200, headers: { "content-length": "1000" } },
      );
    await expect(
      downloadToFile(osvArchiveUrl("npm"), path.join(dir, "big.zip"), {
        fetch: announced,
        maxBytes: 100,
      }),
    ).rejects.toMatchObject({ code: "size" });
    expect(pulls).toBe(0);
  });

  it("times out a stalled download", async () => {
    const stalled: typeof fetch = (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("aborted", "AbortError")),
        );
      });
    await expect(
      downloadToFile(osvArchiveUrl("npm"), path.join(dir, "t.zip"), {
        fetch: stalled,
        timeoutMs: 30,
      }),
    ).rejects.toMatchObject({ code: "timeout" });
    // A body that stalls mid-stream is also covered by the timeout.
    const stalledBody: typeof fetch = async (_input, init) => {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array([1, 2, 3]));
          init?.signal?.addEventListener("abort", () =>
            controller.error(new DOMException("aborted", "AbortError")),
          );
        },
      });
      return new Response(stream, { status: 200 });
    };
    await expect(
      downloadToFile(osvArchiveUrl("npm"), path.join(dir, "t2.zip"), {
        fetch: stalledBody,
        timeoutMs: 30,
      }),
    ).rejects.toMatchObject({ code: "timeout" });
  });
});

describe("zip verification", () => {
  const write = async (name: string, data: Buffer): Promise<string> => {
    const file = path.join(dir, name);
    const { writeFile } = await import("node:fs/promises");
    await writeFile(file, data);
    return file;
  };

  it("reads zip64 archives, stored entries and verifies each entry", async () => {
    const entries: TestZipEntry[] = [
      { name: "A-1.json", content: '{"id":"A-1"}' },
      { name: "B-2.json", content: '{"id":"B-2"}', stored: true },
    ];
    for (const zip64 of [false, true]) {
      const file = await write(`z${zip64}.zip`, makeZip(entries, { zip64 }));
      const seen: string[] = [];
      const result = await forEachZipEntry(
        file,
        ({ name, data }) => void seen.push(`${name}=${data.toString()}`),
      );
      expect(seen).toEqual(['A-1.json={"id":"A-1"}', 'B-2.json={"id":"B-2"}']);
      expect(result.entryCount).toBe(2);
    }
  });

  it("rejects zip bombs, oversized entries and too many entries by limits", async () => {
    const file = await write(
      "b.zip",
      makeZip([
        { name: "A.json", content: "x".repeat(5000) },
        { name: "B.json", content: "y".repeat(5000) },
      ]),
    );
    await expect(
      forEachZipEntry(file, () => undefined, { ...DEFAULT_ZIP_LIMITS, maxTotalBytes: 8000 }),
    ).rejects.toBeInstanceOf(ZipError);
    await expect(
      forEachZipEntry(file, () => undefined, { ...DEFAULT_ZIP_LIMITS, maxEntryBytes: 4000 }),
    ).rejects.toBeInstanceOf(ZipError);
    await expect(
      forEachZipEntry(file, () => undefined, { ...DEFAULT_ZIP_LIMITS, maxEntries: 1 }),
    ).rejects.toBeInstanceOf(ZipError);
  });

  it("rejects an entry whose announced size is wrong even when its checksum matches", async () => {
    const file = await write(
      "lie.zip",
      makeZip([{ name: "A.json", content: '{"id":"A-1"}', stored: true, lieSize: true }]),
    );
    await expect(forEachZipEntry(file, () => undefined)).rejects.toMatchObject({
      message: "An entry has the wrong size.",
    });
  });

  it("rejects a lying size and a flipped data byte", async () => {
    const good = makeZip([
      { name: "A.json", content: '{"id":"A-1","pad":"aaaaaaaaaaaaaaaaaaaa"}', stored: true },
    ]);
    const flipped = Buffer.from(good);
    flipped[40] = (flipped[40] ?? 0) ^ 0xff;
    await expect(
      forEachZipEntry(await write("f.zip", flipped), () => undefined),
    ).rejects.toMatchObject({ message: "An entry failed its checksum." });
  });
});

describe("advisory status (staleness)", () => {
  it("reports none, fresh, stale and damaged from local metadata only", async () => {
    const day = 24 * 60 * 60 * 1000;
    const fetched = Date.parse("2026-10-20T00:00:00Z");
    expect((await readAdvisoryStatus(dir, fetched)).overall).toBe("none");
    const asGo = makeZip(
      goodEntries.map((e) => ({
        ...e,
        content: e.content.replace('"ecosystem":"npm"', '"ecosystem":"Go"'),
      })),
    );
    const { impl } = fakeFetch((url) => ({
      body: url.includes("/Go/") ? asGo : makeZip(goodEntries),
    }));
    await updateOsvData({ appDataDir: dir, fetch: impl, now: () => fetched });
    const fresh = await readAdvisoryStatus(dir, fetched + 2 * day + 5);
    expect(fresh).toMatchObject({ overall: "fresh" });
    expect(fresh.ecosystems.map((e) => [e.ecosystem, e.ageDays, e.fetchedAt])).toEqual([
      ["npm", 2, "2026-10-20T00:00:00.000Z"],
      ["Go", 2, "2026-10-20T00:00:00.000Z"],
    ]);
    expect((await readAdvisoryStatus(dir, fetched + 6 * day)).overall).toBe("fresh");
    expect((await readAdvisoryStatus(dir, fetched + 7 * day)).overall).toBe("stale");
    expect((await readAdvisoryStatus(dir, fetched - day)).ecosystems[0]?.ageDays).toBe(0);
    const file = path.join(osvDataDir(dir), "npm", "advisories.jsonl.gz");
    const { truncate } = await import("node:fs/promises");
    await truncate(file, 3);
    expect((await readAdvisoryStatus(dir, fetched)).overall).toBe("damaged");
    await rm(path.join(osvDataDir(dir), "Go"), { recursive: true });
    expect((await readAdvisoryStatus(dir, fetched)).overall).toBe("none");
    expect((await stat(osvDataDir(dir))).isDirectory()).toBe(true);
  });
});

describe("swapIntoPlace", () => {
  it("restores the old directory when the new one cannot be moved in", async () => {
    const { mkdir, writeFile } = await import("node:fs/promises");
    const osv = path.join(dir, "osv");
    await mkdir(path.join(osv, "npm"), { recursive: true });
    await writeFile(path.join(osv, "npm", "meta.json"), "old");
    await expect(swapIntoPlace(osv, "npm", path.join(osv, ".staging-missing"))).rejects.toThrow();
    expect(await readFile(path.join(osv, "npm", "meta.json"), "utf8")).toBe("old");
    expect((await readdir(osv)).sort()).toEqual(["npm"]);
  });
});

describe("zip structure attacks", () => {
  const write = async (name: string, data: Buffer): Promise<string> => {
    const { writeFile } = await import("node:fs/promises");
    const file = path.join(dir, name);
    await writeFile(file, data);
    return file;
  };
  const rec = (id: string): TestZipEntry => ({ name: `${id}.json`, content: `{"id":"${id}"}` });

  it("rejects encrypted entries", async () => {
    const file = await write("enc.zip", makeZip([{ ...rec("A"), encrypted: true }]));
    await expect(forEachZipEntry(file, () => undefined)).rejects.toMatchObject({
      message: "Encrypted entries are not supported.",
    });
  });

  it("rejects an entry that claims more compressed bytes than allowed, without reading them", async () => {
    const file = await write(
      "claim.zip",
      makeZip([{ ...rec("A"), claimCompressedSize: 900 * 1024 * 1024 }]),
    );
    await expect(forEachZipEntry(file, () => undefined)).rejects.toMatchObject({
      message: "An entry is larger than allowed.",
    });
    // Under the per-entry cap but past the end of the data: out of range.
    const past = await write(
      "past.zip",
      makeZip([{ ...rec("A"), claimCompressedSize: 20 * 1024 * 1024 }]),
    );
    await expect(forEachZipEntry(past, () => undefined)).rejects.toMatchObject({
      message: "An entry overlaps another or is out of range.",
    });
  });

  it("rejects overlapping and repeated entries", async () => {
    // B's central record points at A's local header: the same bytes would be read twice.
    const overlap = await write(
      "overlap.zip",
      makeZip([rec("A"), { ...rec("B"), claimOffsetOfEntry: 0 }]),
    );
    await expect(forEachZipEntry(overlap, () => undefined)).rejects.toMatchObject({
      message: "An entry overlaps another or is out of range.",
    });
    const many = Array.from({ length: 200 }, (_, index) => ({
      ...rec(`E${index}`),
      claimOffsetOfEntry: index === 0 ? undefined : 0,
    }));
    await expect(
      forEachZipEntry(await write("many.zip", makeZip(many)), () => undefined),
    ).rejects.toBeInstanceOf(ZipError);
    const dup = await write("dup.zip", makeZip([rec("A"), rec("A")]));
    await expect(forEachZipEntry(dup, () => undefined)).rejects.toMatchObject({
      message: "The archive repeats an entry name.",
    });
  });

  it("rejects a local header whose name or method differs from the central directory", async () => {
    const name = await write("name.zip", makeZip([{ ...rec("A"), localName: "B.json" }]));
    await expect(forEachZipEntry(name, () => undefined)).rejects.toMatchObject({
      message: "A local header does not match the central directory.",
    });
    const method = await write("method.zip", makeZip([{ ...rec("A"), localMethod: 0 }]));
    await expect(forEachZipEntry(method, () => undefined)).rejects.toMatchObject({
      message: "A local header does not match the central directory.",
    });
  });
});

describe("disk errors, idle timeout and writers", () => {
  const body = Buffer.alloc(200_000, 1);

  it("fails a download whose destination cannot be written, instead of hanging", async () => {
    const { impl } = fakeFetch(() => ({ body }));
    await expect(
      downloadToFile(osvArchiveUrl("npm"), path.join(dir, "missing-dir", "a.zip"), { fetch: impl }),
    ).rejects.toMatchObject({ code: "disk" });
  });

  it("gives up when the server goes silent between chunks", async () => {
    const stalled: typeof fetch = async () =>
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new Uint8Array([1, 2, 3]));
          },
        }),
        { status: 200 },
      );
    await expect(
      downloadToFile(osvArchiveUrl("npm"), path.join(dir, "idle.zip"), {
        fetch: stalled,
        idleTimeoutMs: 40,
      }),
    ).rejects.toMatchObject({ code: "timeout" });
  });

  it("a line writer on an unwritable file rejects instead of hanging", async () => {
    const writer = new GzipLineWriter(path.join(dir, "missing-dir", "x.gz"));
    const run = (async () => {
      for (let index = 0; index < 200_000; index += 1) {
        await writer.writeLine(`{"line":${index},"pad":"${"x".repeat(200)}"}`);
      }
      await writer.close();
    })();
    await expect(
      Promise.race([
        run,
        new Promise((_, reject) => setTimeout(() => reject(new Error("hung")), 5000)),
      ]),
    ).rejects.toThrow(/^(?!hung)/);
  });
});

describe("update lock and leftovers", () => {
  const deadPid = (): number => {
    const child = spawnSync(process.execPath, ["-e", ""]);
    return child.pid;
  };

  it("removeLeftovers deletes staging and aside directories only", async () => {
    const { mkdir } = await import("node:fs/promises");
    const osv = osvDataDir(dir);
    for (const name of [".staging-npm-1-1", ".old-Go-1-1", "npm"])
      await mkdir(path.join(osv, name), { recursive: true });
    await removeLeftovers(osv);
    expect(await readdir(osv)).toEqual(["npm"]);
  });

  it("a running update's staging directory is not deleted by a second update", async () => {
    const { mkdir } = await import("node:fs/promises");
    const osv = osvDataDir(dir);
    const live = path.join(osv, ".staging-npm-live");
    await mkdir(live, { recursive: true });
    const release = await acquireUpdateLock(osv);
    const { impl, calls } = fakeFetch(() => ({ body: makeZip(goodEntries) }));
    const outcomes = await updateOsvData({ appDataDir: dir, ecosystems: ["npm"], fetch: impl });
    expect(outcomes[0]).toMatchObject({ ok: false });
    expect((outcomes[0] as { error: string }).error).toContain("already running");
    expect(calls).toHaveLength(0);
    expect((await readdir(osv)).sort()).toEqual([".staging-npm-live", ".update.lock"]);
    await release();
    expect(await readdir(osv)).toEqual([".staging-npm-live"]);
  });

  it("replaces a stale lock from a dead process and cleans its leftovers", async () => {
    const { mkdir, writeFile } = await import("node:fs/promises");
    const osv = osvDataDir(dir);
    await mkdir(path.join(osv, ".staging-npm-dead"), { recursive: true });
    await writeFile(path.join(osv, ".update.lock"), `${deadPid()}\n`);
    const { impl } = fakeFetch(() => ({ body: makeZip(goodEntries) }));
    const [outcome] = await updateOsvData({ appDataDir: dir, ecosystems: ["npm"], fetch: impl });
    expect(outcome?.ok).toBe(true);
    expect(await readdir(osv)).toEqual(["npm"]);
  });

  it("takes over a lock older than one hour even if its pid is alive", async () => {
    const { mkdir, utimes, writeFile } = await import("node:fs/promises");
    const osv = osvDataDir(dir);
    await mkdir(osv, { recursive: true });
    const lock = path.join(osv, ".update.lock");
    await writeFile(lock, `${process.pid}\n`);
    const fresh = acquireUpdateLock(osv);
    await expect(fresh).rejects.toThrow(/already running/);
    const old = new Date(Date.now() - 2 * 60 * 60 * 1000);
    await utimes(lock, old, old);
    const release = await acquireUpdateLock(osv);
    expect(await readFile(lock, "utf8")).toBe(`${process.pid}\n`);
    await release();
    expect(await readdir(osv)).toEqual([]);
  });

  it("does not remove a lock that now belongs to another run", async () => {
    const { mkdir, writeFile } = await import("node:fs/promises");
    const osv = osvDataDir(dir);
    await mkdir(osv, { recursive: true });
    const release = await acquireUpdateLock(osv);
    await writeFile(path.join(osv, ".update.lock"), "999999\n"); // taken over by another run
    await release();
    expect(await readFile(path.join(osv, ".update.lock"), "utf8")).toBe("999999\n");
  });

  it("racing takeovers of a stale lock leave exactly one winner", async () => {
    const { mkdir, writeFile } = await import("node:fs/promises");
    const osv = osvDataDir(dir);
    await mkdir(osv, { recursive: true });
    await writeFile(path.join(osv, ".update.lock"), `${deadPid()}\n`);
    const results = await Promise.allSettled(
      Array.from({ length: 6 }, () => acquireUpdateLock(osv)),
    );
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect((await readdir(osv)).filter((name) => name.includes("stale"))).toEqual([]);
  });

  it("releases the lock after a failed update", async () => {
    const { impl } = fakeFetch(() => ({ status: 500 }));
    await updateOsvData({ appDataDir: dir, ecosystems: ["npm"], fetch: impl });
    expect(await readdir(osvDataDir(dir))).toEqual([]);
  });
});

describe("lock edge cases", () => {
  const prepare = async (content: string, ageMs = 0): Promise<{ osv: string; lock: string }> => {
    const { mkdir, utimes, writeFile } = await import("node:fs/promises");
    const osv = osvDataDir(dir);
    await mkdir(osv, { recursive: true });
    const lock = path.join(osv, ".update.lock");
    await writeFile(lock, content);
    if (ageMs > 0) {
      const old = new Date(Date.now() - ageMs);
      await utimes(lock, old, old);
    }
    return { osv, lock };
  };
  const hours = (count: number): number => count * 60 * 60 * 1000;
  const deadPid = (): number => spawnSync(process.execPath, ["-e", ""]).pid;

  it("an empty lock file, fresh or 2 hours old, does not block updates", async () => {
    for (const ageMs of [0, hours(2)]) {
      const { osv, lock } = await prepare("", ageMs);
      const release = await acquireUpdateLock(osv);
      expect(await readFile(lock, "utf8")).toBe(`${process.pid}\n`);
      await release();
      expect(await readdir(osv)).toEqual([]);
    }
  });

  it("garbage lock contents do not block updates", async () => {
    for (const garbage of ["not a pid", "12abc\n", "\u0000\u0000", "-5", "99999999999999999999"]) {
      const { osv } = await prepare(garbage);
      const release = await acquireUpdateLock(osv);
      await release();
      expect(await readdir(osv)).toEqual([]);
    }
  });

  it("names the lock file in the already-running message", async () => {
    const { osv, lock } = await prepare(`${process.pid}\n`);
    await expect(acquireUpdateLock(osv)).rejects.toThrow(lock);
  });

  it("never removes a lock that another run created after this one judged it stale", async () => {
    const { osv, lock } = await prepare(`${deadPid()}\n`);
    const fresh = `${process.pid}\n`;
    await expect(
      acquireUpdateLock(osv, Date.now, {
        afterJudgedStale: async () => {
          const { writeFile } = await import("node:fs/promises");
          await writeFile(lock, fresh); // another run took over first
        },
      }),
    ).rejects.toThrow(/already running/);
    expect(await readFile(lock, "utf8")).toBe(fresh);
  });

  it("a recent takeover marker blocks the takeover and is never overwritten", async () => {
    const { osv, lock } = await prepare(`${deadPid()}\n`);
    const { writeFile } = await import("node:fs/promises");
    const marker = `${lock}.takeover`;
    await writeFile(marker, "424242\n");
    await expect(acquireUpdateLock(osv)).rejects.toThrow(/already running/);
    expect(await readFile(marker, "utf8")).toBe("424242\n");
    expect(await readFile(lock, "utf8")).toMatch(/^\d+\n$/);
  });

  it("an old takeover marker (from a crashed run) is cleared and the takeover proceeds", async () => {
    const { osv, lock } = await prepare(`${deadPid()}\n`);
    const { utimes, writeFile } = await import("node:fs/promises");
    const marker = `${lock}.takeover`;
    await writeFile(marker, "424242\n");
    const old = new Date(Date.now() - 5 * 60 * 1000);
    await utimes(marker, old, old);
    const release = await acquireUpdateLock(osv);
    await release();
    expect(await readdir(osv)).toEqual([]);
  });
});

describe("rollback protection", () => {
  const entries = (modified: string, count: number): TestZipEntry[] =>
    Array.from({ length: count }, (_, index) => ({
      name: `GHSA-r${index}.json`,
      content: osvRecord(`GHSA-r${index}`, `pkg-${index}`, { modified }),
    }));
  const serve = (body: Buffer) => fakeFetch(() => ({ body })).impl;
  const run = (body: Buffer, extra: { force?: boolean; now?: number } = {}) =>
    updateOsvData({
      appDataDir: dir,
      ecosystems: ["npm"],
      fetch: serve(body),
      now: () => extra.now ?? Date.parse("2026-10-28T00:00:00Z"),
      ...(extra.force === undefined ? {} : { force: extra.force }),
    });
  const advisoriesFile = () => path.join(osvDataDir(dir), "npm", "advisories.jsonl.gz");

  it("accepts the first install", async () => {
    const [outcome] = await run(makeZip(entries("2024-01-01T00:00:00Z", 2)));
    expect(outcome?.ok).toBe(true);
  });

  it("refuses older data, keeps the installed data and names both dates", async () => {
    await run(makeZip(entries("2026-10-27T00:00:00Z", 2)));
    const before = await readFile(advisoriesFile());
    const [outcome] = await run(makeZip(entries("2024-01-01T00:00:00Z", 2)));
    expect(outcome?.ok).toBe(false);
    if (outcome === undefined || outcome.ok) return;
    expect(outcome.refusal).toBe("older-data");
    expect(outcome.error).toContain("2024-01-01");
    expect(outcome.error).toContain("2026-10-27");
    expect(await readFile(advisoriesFile())).toEqual(before);
    const status = await readAdvisoryStatus(dir, Date.parse("2026-10-28T00:00:00Z"));
    expect(status.ecosystems.find((e) => e.ecosystem === "npm")?.modifiedMax).toBe(
      "2026-10-27T00:00:00Z",
    );
    expect((await readdir(path.join(osvDataDir(dir), "npm"))).sort()).not.toContain("archive.zip");
  });

  it("refuses a big drop in the record count", async () => {
    await run(makeZip(entries("2026-10-27T00:00:00Z", 10)));
    const before = await readFile(advisoriesFile());
    const [outcome] = await run(makeZip(entries("2026-10-27T00:00:00Z", 4)));
    expect(outcome?.ok).toBe(false);
    if (outcome === undefined || outcome.ok) return;
    expect(outcome.refusal).toBe("smaller-data");
    expect(outcome.error).toContain("(4)");
    expect(outcome.error).toContain("(10;");
    expect(await readFile(advisoriesFile())).toEqual(before);
  });

  it("accepts a small drop and the same newest date", async () => {
    await run(makeZip(entries("2026-10-27T00:00:00Z", 10)));
    const [outcome] = await run(makeZip(entries("2026-10-27T00:00:00Z", 6)));
    expect(outcome?.ok).toBe(true);
  });

  it("treats corrupt installed metadata as unknown instead of failing", async () => {
    await run(makeZip(entries("2026-10-27T00:00:00Z", 10)));
    const metaFile = path.join(osvDataDir(dir), "npm", "meta.json");
    const meta = JSON.parse(await readFile(metaFile, "utf8")) as Record<string, any>;
    meta.counts = { ...meta.counts, advisories: "1000", malware: null };
    meta.modifiedRange = { min: 5, max: "not a date" };
    await writeFile(metaFile, JSON.stringify(meta));
    const [outcome] = await run(makeZip(entries("2024-01-01T00:00:00Z", 2)));
    expect(outcome?.ok).toBe(true);
    // Missing parts (no counts object, no range) are unknown as well.
    const again = JSON.parse(await readFile(metaFile, "utf8")) as Record<string, any>;
    delete again.counts;
    delete again.modifiedRange;
    await writeFile(metaFile, JSON.stringify(again));
    const [second] = await run(makeZip(entries("2023-01-01T00:00:00Z", 1)));
    expect(second?.ok).toBe(true);
  });

  it("names full timestamps in the older-data message", async () => {
    await run(makeZip(entries("2026-10-27T10:00:00Z", 2)));
    const [outcome] = await run(makeZip(entries("2026-10-27T01:00:00Z", 2)));
    expect(outcome?.ok).toBe(false);
    if (outcome === undefined || outcome.ok) return;
    expect(outcome.error).toContain("2026-10-27T01:00:00Z");
    expect(outcome.error).toContain("2026-10-27T10:00:00Z");
  });

  it("accepts older data with force", async () => {
    await run(makeZip(entries("2026-10-27T00:00:00Z", 2)));
    const [outcome] = await run(makeZip(entries("2024-01-01T00:00:00Z", 2)), { force: true });
    expect(outcome?.ok).toBe(true);
  });

  it("reports data as stale by the age of its newest record, not only by fetchedAt", async () => {
    await run(makeZip(entries("2026-09-01T00:00:00Z", 2)));
    const now = Date.parse("2026-10-28T00:00:00Z");
    const status = await readAdvisoryStatus(dir, now);
    const npm = status.ecosystems.find((e) => e.ecosystem === "npm");
    expect(npm?.ageDays).toBe(0);
    expect(npm?.dataAgeDays).toBe(57);
    expect(npm?.state).toBe("stale");
    expect(status.overall).toBe("none");
  });

  it("gives a data version, and null (not a crash) when meta lacks the archive checksum", async () => {
    await run(makeZip(entries("2026-10-27T00:00:00Z", 2)));
    const now = Date.parse("2026-10-28T00:00:00Z");
    const before = await readAdvisoryStatus(dir, now);
    expect(before.ecosystems.find((e) => e.ecosystem === "npm")?.dataVersion).toMatch(
      /^1:[0-9a-f]{12}$/,
    );
    const metaFile = path.join(osvDataDir(dir), "npm", "meta.json");
    const meta = JSON.parse(await readFile(metaFile, "utf8")) as Record<string, unknown>;
    delete meta.archive;
    await writeFile(metaFile, JSON.stringify(meta));
    const after = await readAdvisoryStatus(dir, now);
    expect(after.ecosystems.find((e) => e.ecosystem === "npm")?.dataVersion).toBeNull();
  });
});
