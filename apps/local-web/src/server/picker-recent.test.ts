import {
  mkdtempSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
  chmodSync,
  readFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createWebStorage, RECENT_FILE, SETTINGS_FILE, type WebStorage } from "@pgard/result-store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PickerCandidate, PickerRecentResponse } from "../shared/picker-types.js";
import { repoCandidate } from "./test-support/fake-inspector.js";
import {
  apiGet,
  apiPost,
  FAKE_ROOT,
  json,
  startHarness,
  waitFor,
  type Harness,
} from "./test-support/web-harness.js";

let harness: Harness | null = null;
let dataDir: string;
let storage: WebStorage;
beforeEach(() => {
  dataDir = mkdtempSync(path.join(tmpdir(), "pgard-recent-"));
  storage = createWebStorage({ dir: path.join(dataDir, "pgard") });
});
afterEach(async () => {
  await harness?.close();
  harness = null;
  rmSync(dataDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

const ENTRY = (index: number, repoPath = `/home/u/code/shop${index}`) => ({
  entryId: `${String(index).padStart(22, "r")}`,
  path: repoPath,
  repo: "acme/shop",
  lastUsedAt: new Date(Date.now() - index * 1000).toISOString(),
});

const recent = async (h: Harness): Promise<PickerRecentResponse> =>
  json(await apiGet(h.server, "/api/picker/recent")) as unknown as PickerRecentResponse;

async function start(options: { noStore?: boolean } = {}): Promise<Harness> {
  harness = await startHarness({ picker: { storage: options.noStore ? null : storage } });
  return harness;
}

describe("recent list (T9, design tests 6 and 15)", () => {
  it("is empty and never touches the disk with --no-store", async () => {
    const h = await start({ noStore: true });
    expect(await recent(h)).toEqual({ entries: [], validating: false, ignored: false });
    expect(h.inspector.runs).toHaveLength(0);
  });

  it("answers at once with validating: true while the inspector revalidates, then the fresh entries", async () => {
    await storage.writeRecent([ENTRY(1), ENTRY(2, "/etc/shadow")]);
    const h = await start();
    h.inspector.mode = "manual";
    const first = await recent(h);
    expect(first).toMatchObject({ entries: [], validating: true });
    expect(h.inspector.runs[0]?.job).toMatchObject({ kind: "recent" });
    // Entries are displayed from the fresh inspection, never from stored text.
    const fresh = repoCandidate("shop1", { repo: ["real", "fresh-name"] });
    h.inspector.runs[0]?.emit({
      t: "recent",
      entryId: ENTRY(1).entryId,
      outcome: { status: "candidate", candidate: fresh },
    });
    h.inspector.runs[0]?.emit({
      t: "recent",
      entryId: ENTRY(2).entryId,
      outcome: { status: "outside_scope" },
    });
    h.inspector.runs[0]?.emit({
      t: "done",
      stoppedBy: null,
      elapsedMs: 3,
      visited: 0,
      skipped: [],
    });
    h.inspector.runs[0]?.finish({ status: "finished" });
    const done = await waitFor(
      () => recent(h),
      (value) => !value.validating,
    );
    expect(done.entries).toHaveLength(2);
    const [inScope, outside] = done.entries as [
      PickerRecentResponse["entries"][number],
      PickerRecentResponse["entries"][number],
    ];
    expect(inScope).toMatchObject({
      source: "recent",
      selectable: true,
      remote: { status: "github", repo: "real/fresh-name" },
      entryId: ENTRY(1).entryId,
    });
    expect(outside).toMatchObject({
      selectable: false,
      blocked: { code: "outside_scope" },
      displayPath: "/etc/shadow",
    });
  });

  it("turns an entry the inspector never answered into an unreadable card after the budget, and others still validate", async () => {
    await storage.writeRecent([ENTRY(1), ENTRY(2)]);
    const h = await start();
    h.inspector.mode = "manual";
    await recent(h);
    h.inspector.runs[0]?.emit({
      t: "recent",
      entryId: ENTRY(1).entryId,
      outcome: { status: "candidate", candidate: repoCandidate("shop1") },
    });
    h.inspector.runs[0]?.finish({ status: "killed", reason: "deadline" });
    const done = await waitFor(
      () => recent(h),
      (value) => !value.validating,
    );
    expect(done.entries.map((entry) => entry.blocked?.code ?? "ok")).toEqual(["ok", "unreadable"]);
  });

  it("caches for 30 seconds and revalidates at most once per second", async () => {
    await storage.writeRecent([ENTRY(1)]);
    const h = await start();
    const first = await recent(h);
    expect(first.validating).toBe(true);
    await waitFor(
      () => recent(h),
      (value) => !value.validating,
    );
    expect(h.inspector.runs).toHaveLength(1);
    h.clock.now += 29_000;
    await recent(h);
    expect(h.inspector.runs).toHaveLength(1); // cached
    h.clock.now += 2_000;
    await recent(h);
    expect(h.inspector.runs).toHaveLength(2); // past 30 s
    await waitFor(
      () => recent(h),
      (value) => !value.validating,
    );
    // A request within one second of the last start never starts another.
    h.clock.now += 31_000;
    await recent(h);
    await waitFor(
      () => recent(h),
      (value) => !value.validating,
    );
    const runs = h.inspector.runs.length;
    h.clock.now += 400;
    await recent(h);
    expect(h.inspector.runs).toHaveLength(runs);
  });

  it("answers inspector_busy when children are stuck", async () => {
    await storage.writeRecent([ENTRY(1)]);
    const h = await start();
    h.inspector.isBusy = true;
    const response = await apiGet(h.server, "/api/picker/recent");
    expect(response.status).toBe(503);
  });

  it("removes an entry from the file (an unknown id is a 200 no-op)", async () => {
    await storage.writeRecent([ENTRY(1), ENTRY(2)]);
    const h = await start();
    await waitFor(
      () => recent(h),
      (value) => !value.validating,
    );
    const removed = await apiPost(h.server, "/api/picker/recent/remove", {
      entryId: ENTRY(1).entryId,
    });
    expect(removed.status).toBe(200);
    const stored = await storage.readRecent();
    expect(stored.status === "ok" && stored.value.map((entry) => entry.entryId)).toEqual([
      ENTRY(2).entryId,
    ]);
    expect(
      (await apiPost(h.server, "/api/picker/recent/remove", { entryId: "zzzzzzzzzzzzzzzzzzzzzz" }))
        .status,
    ).toBe(200);
  });

  it("writes a recent entry only after a confirm, newest first, one per path", async () => {
    const h = await start();
    h.inspector.repos.set("shop", [repoCandidate("shop")]);
    expect((await storage.readRecent()).status).toBe("missing");
    h.clock.now = Date.now(); // the stored dates are checked against the real clock (90 days)
    const started = json(
      await apiPost(h.server, "/api/picker/search", { source: "drop", name: "shop", epoch: 1 }),
    ) as { searchId: string };
    const found = (await waitFor(
      async () => json(await apiGet(h.server, `/api/picker/search?id=${started.searchId}`)),
      (value) => value.status !== "running",
    )) as unknown as { candidates: PickerCandidate[] };
    // A search alone writes nothing.
    expect((await storage.readRecent()).status).toBe("missing");
    const candidate = found.candidates[0] as PickerCandidate;
    await apiPost(h.server, "/api/picker/confirm", {
      candidateId: candidate.candidateId,
      shown: candidate.shown,
      epoch: 1,
    });
    const stored = await waitFor(
      () => storage.readRecent(),
      (value) => value.status === "ok",
    );
    expect(stored.status === "ok" && stored.value).toMatchObject([
      { path: "/home/u/code/shop", repo: "acme/shop" },
    ]);
    expect(statSync(path.join(storage.dir, RECENT_FILE)).mode & 0o777).toBe(0o600);
    expect(statSync(storage.dir).mode & 0o777).toBe(0o700);
  });

  it("does not write the recent list with --no-store", async () => {
    const h = await start({ noStore: true });
    h.inspector.repos.set("shop", [repoCandidate("shop")]);
    h.clock.now += 2_000;
    const started = json(
      await apiPost(h.server, "/api/picker/search", { source: "drop", name: "shop", epoch: 1 }),
    ) as { searchId: string };
    const found = (await waitFor(
      async () => json(await apiGet(h.server, `/api/picker/search?id=${started.searchId}`)),
      (value) => value.status !== "running",
    )) as unknown as { candidates: PickerCandidate[] };
    const candidate = found.candidates[0] as PickerCandidate;
    expect(
      (
        await apiPost(h.server, "/api/picker/confirm", {
          candidateId: candidate.candidateId,
          shown: candidate.shown,
          epoch: 1,
        })
      ).status,
    ).toBe(200);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect((await storage.readRecent()).status).toBe("missing");
  });

  it("ignores a damaged or newer file with a notice and never overwrites it", async () => {
    await storage.writeRecent([ENTRY(1)]);
    const file = path.join(storage.dir, RECENT_FILE);
    const newer = JSON.stringify({ schemaVersion: "2.0", entries: [], future: true });
    writeFileSync(file, newer);
    const h = await start();
    expect(await recent(h)).toEqual({ entries: [], validating: false, ignored: true });
    // A confirm does not replace it either.
    h.inspector.repos.set("shop", [repoCandidate("shop")]);
    h.clock.now += 2_000;
    const started = json(
      await apiPost(h.server, "/api/picker/search", { source: "drop", name: "shop", epoch: 1 }),
    ) as { searchId: string };
    const found = (await waitFor(
      async () => json(await apiGet(h.server, `/api/picker/search?id=${started.searchId}`)),
      (value) => value.status !== "running",
    )) as unknown as { candidates: PickerCandidate[] };
    const candidate = found.candidates[0] as PickerCandidate;
    await apiPost(h.server, "/api/picker/confirm", {
      candidateId: candidate.candidateId,
      shown: candidate.shown,
      epoch: 1,
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(readFileSync(file, "utf8")).toBe(newer);
  });

  it("shows tampered entries as blocked, never selectable: outside scope, gone, a non-repository", async () => {
    await storage.writeRecent([
      ENTRY(1, "/Users/other/code/shop"),
      ENTRY(2, `${FAKE_ROOT.path}/gone`),
      ENTRY(3, `${FAKE_ROOT.path}/plain`),
    ]);
    const h = await start();
    h.inspector.recent.set(`${FAKE_ROOT.path}/gone`, { status: "gone" });
    h.inspector.recent.set(`${FAKE_ROOT.path}/plain`, {
      status: "candidate",
      candidate: repoCandidate("plain", {
        remote: { status: "unreadable" },
        block: { code: "not_a_git_root", paths: [] },
      }),
    });
    await recent(h);
    const done = await waitFor(
      () => recent(h),
      (value) => !value.validating,
    );
    expect(done.entries.map((entry) => [entry.selectable, entry.blocked?.code])).toEqual([
      [false, "outside_scope"],
      [false, "not_a_git_root"],
      [false, "not_a_git_root"],
    ]);
    // None of them can be confirmed.
    for (const entry of done.entries) {
      const response = await apiPost(h.server, "/api/picker/confirm", {
        candidateId: entry.candidateId,
        shown: entry.shown,
        epoch: 1,
      });
      expect(response.status).toBe(409);
    }
    expect(h.server.state.project).toBeNull();
  });
});

describe("settings and recent files (design test 15)", () => {
  const entries = (count: number) =>
    Array.from({ length: count }, (_, index) => ({
      entryId: `${String(index).padStart(22, "e")}`,
      path: `/home/u/code/p${index}`,
      repo: "acme/shop",
      lastUsedAt: new Date(Date.now() - index * 1000).toISOString(),
    }));

  it("creates both files 0600 in a 0700 folder", async () => {
    expect((await storage.writeSettings(["/home/u/code"])).ok).toBe(true);
    expect((await storage.writeRecent(entries(1))).ok).toBe(true);
    expect(statSync(storage.dir).mode & 0o777).toBe(0o700);
    for (const name of [SETTINGS_FILE, RECENT_FILE]) {
      expect(statSync(path.join(storage.dir, name)).mode & 0o777).toBe(0o600);
    }
  });

  it("refuses a symlinked web folder or file, and a group- or world-writable file", async () => {
    await storage.writeRecent(entries(1));
    const file = path.join(storage.dir, RECENT_FILE);
    chmodSync(file, 0o660);
    expect(await storage.readRecent()).toEqual({ status: "ignored", reason: "unsafe" });
    chmodSync(file, 0o600);
    rmSync(file);
    const target = path.join(dataDir, "elsewhere.json");
    writeFileSync(target, JSON.stringify({ schemaVersion: "1.0", entries: [] }));
    symlinkSync(target, file);
    expect((await storage.readRecent()).status).toBe("ignored");
    expect((await storage.writeRecent(entries(1))).ok).toBe(false);
    expect(readFileSync(target, "utf8")).toContain("entries");
    // A symlinked folder.
    const other = createWebStorage({ dir: path.join(dataDir, "other") });
    await other.writeSettings(["/home/u/code"]);
    const real = path.join(dataDir, "real-web");
    rmSync(other.dir, { recursive: true });
    const { mkdirSync } = await import("node:fs");
    mkdirSync(real, { mode: 0o700 });
    symlinkSync(real, other.dir);
    expect((await other.readSettings()).status).toBe("ignored");
    expect((await other.writeSettings(["/home/u/code"])).ok).toBe(false);
  });

  it("ignores oversized, malformed and unknown-major files and never overwrites them", async () => {
    await storage.writeSettings(["/home/u/code"]);
    const file = path.join(storage.dir, SETTINGS_FILE);
    for (const content of [
      "x".repeat(70 * 1024),
      "{not json",
      JSON.stringify({ schemaVersion: "2.0", searchRoots: [] }),
      JSON.stringify({ schemaVersion: "1.0", searchRoots: [{ path: "relative/dir" }] }),
      JSON.stringify({ schemaVersion: "1.0", searchRoots: [{ path: "/a/b", extra: 1 }] }),
    ]) {
      writeFileSync(file, content);
      expect((await storage.readSettings()).status).toBe("ignored");
      expect((await storage.writeSettings(["/home/u/code"])).ok).toBe(false);
      expect(readFileSync(file, "utf8")).toBe(content);
    }
  });

  it("truncates 21 entries to 20 and drops entries older than 90 days", async () => {
    await storage.writeRecent(entries(21));
    const stored = await storage.readRecent();
    expect(stored.status === "ok" && stored.value.length).toBe(20);
    const old = {
      ...entries(1)[0]!,
      lastUsedAt: new Date(Date.now() - 91 * 86_400_000).toISOString(),
    };
    await storage.writeRecent([old, ...entries(2).slice(1)]);
    const afterwards = await storage.readRecent();
    expect(
      afterwards.status === "ok" && afterwards.value.some((entry) => entry.entryId === old.entryId),
    ).toBe(false);
  });

  it("keeps one entry per path, newest first, and clear() removes the whole web folder", async () => {
    const [first] = entries(1);
    const duplicate = {
      ...first!,
      entryId: "d".repeat(22),
      lastUsedAt: new Date(Date.now() + 5_000).toISOString(),
    };
    await storage.writeRecent([first!, duplicate]);
    const stored = await storage.readRecent();
    expect(stored.status === "ok" && stored.value.map((entry) => entry.entryId)).toEqual([
      duplicate.entryId,
    ]);
    await storage.writeSettings(["/home/u/code"]);
    const cleared = await storage.clear();
    expect(cleared).toEqual({ removed: 2, warnings: [] });
    expect((await storage.readRecent()).status).toBe("missing");
    expect((await storage.readSettings()).status).toBe("missing");
  });
});
