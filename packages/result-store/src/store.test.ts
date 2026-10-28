import {
  lstat,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
  utimes,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { SCHEMA_VERSION, type ScanResult } from "@pgard/findings";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  MAX_RESULT_FILE_BYTES,
  RETENTION_MAX_AGE_DAYS,
  RETENTION_MAX_SCANS_PER_REPO,
  createResultStore,
  type ResultStore,
} from "./store.js";

const isPosix = process.platform !== "win32";
const DAY = 86_400_000;
const REPO_ID = 4242;

function makeResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    schemaVersion: SCHEMA_VERSION,
    scanId: "scan-1",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "owner/name", revision: "abc", webOrigin: null },
    authorization: {
      decision: "allowed",
      checks: [
        { id: "repository", status: "passed", reason: "ok" },
        { id: "github_identity", status: "passed", reason: "ok" },
        { id: "owner_approval", status: "passed", reason: "ok" },
        { id: "current_access", status: "passed", reason: "ok" },
        { id: "contribution", status: "passed", reason: "ok" },
      ],
    },
    coverage: [
      { area: "source:typescript", scope: "code", status: "completed", ruleIds: [], note: null },
    ],
    findings: [],
    advisoryDb: { version: null, updatedAt: null },
    ...overrides,
  };
}

let base: string;
let dir: string;
let clock: number;
let store: ResultStore;

function newStore(): ResultStore {
  return createResultStore({ dir, now: () => clock });
}

async function repoFiles(): Promise<string[]> {
  return (await readdir(path.join(dir, "repos", String(REPO_ID)))).filter((n) =>
    n.endsWith(".json"),
  );
}

beforeEach(async () => {
  base = await mkdtemp(path.join(os.tmpdir(), "pgard-store-"));
  dir = path.join(base, "pgard");
  clock = Date.UTC(2026, 9, 26);
  store = newStore();
});

afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

describe("save and list", () => {
  it("list with a limit opens only that many usable files and counts the rest", async () => {
    store = createResultStore({ dir, now: () => clock, maxScansPerRepo: 50 });
    for (let i = 0; i < 12; i += 1) {
      clock += 1000;
      await store.save(makeResult({ scanId: `s${i}` }), { repositoryId: REPO_ID });
    }
    const limited = await store.list(REPO_ID, { limit: 5 });
    expect(limited.scans.map((scan) => scan.result.scanId)).toEqual([
      "s11",
      "s10",
      "s9",
      "s8",
      "s7",
    ]);
    expect(limited.unread).toBe(7);
    const filtered = await store.list(REPO_ID, {
      limit: 3,
      isUsable: (scan) => scan.result.scanId !== "s11",
    });
    expect(filtered.scans.map((scan) => scan.result.scanId)).toEqual(["s10", "s9", "s8"]);
    expect(filtered.rejected).toBe(1);
    const all = await store.list(REPO_ID);
    expect(all.scans).toHaveLength(12);
    expect(all.unread).toBe(0);
  });

  it("round-trips a result through the reader", async () => {
    const saved = await store.save(makeResult(), { repositoryId: REPO_ID });
    expect(saved.ok).toBe(true);
    const listed = await store.list(REPO_ID);
    expect(listed.warnings).toEqual([]);
    expect(listed.scans).toHaveLength(1);
    expect(listed.scans[0]?.result.scanId).toBe("scan-1");
    expect(listed.scans[0]?.sourceVersion).toBe(SCHEMA_VERSION);
    if (saved.ok) {
      const loaded = await store.load(REPO_ID, saved.file);
      expect(loaded.ok).toBe(true);
    }
  });

  it("keys by repository id only and never writes an absolute path", async () => {
    await store.save(makeResult(), { repositoryId: REPO_ID });
    const names = await readdir(path.join(dir, "repos"));
    expect(names).toEqual([String(REPO_ID)]);
    const [file] = await repoFiles();
    const text = await readFile(path.join(dir, "repos", String(REPO_ID), file ?? ""), "utf8");
    expect(text).not.toContain(base);
  });

  it("writes C1 and bidi characters as \\uXXXX escapes and reads them back (#368)", async () => {
    const note = "a\u009b31m‮b⁦c";
    const result = makeResult({
      coverage: [{ area: "a", scope: "code", status: "completed", ruleIds: [], note }],
    });
    const saved = await store.save(result, { repositoryId: REPO_ID });
    expect(saved.ok).toBe(true);
    const [file] = await repoFiles();
    const text = await readFile(path.join(dir, "repos", String(REPO_ID), file ?? ""), "utf8");
    expect(text).not.toMatch(/[\u0080-\u009f‮⁦]/);
    expect(text).toContain("a\\u009b31m\\u202eb\\u2066c");
    const listed = await store.list(REPO_ID);
    expect(listed.scans[0]?.result.coverage[0]?.note).toBe(note);
  });

  it("refuses a result that contains a forbidden local path", async () => {
    const result = makeResult({
      findings: [],
      coverage: [
        {
          area: "a",
          scope: "code",
          status: "completed",
          ruleIds: [],
          note: "see /home/dev/project/x",
        },
      ],
    });
    const saved = await store.save(result, {
      repositoryId: REPO_ID,
      forbidSubstrings: ["/home/dev/project"],
    });
    expect(saved).toMatchObject({ ok: false, error: { code: "contains_local_path" } });
    await expect(stat(dir)).rejects.toThrow();
  });

  it("also refuses the JSON-escaped form of a forbidden path (Windows backslashes)", async () => {
    const result = makeResult({
      coverage: [
        {
          area: "a",
          scope: "code",
          status: "completed",
          ruleIds: [],
          note: "C:\\Users\\ann\\x",
        },
      ],
    });
    expect(
      await store.save(result, { repositoryId: REPO_ID, forbidSubstrings: ["C:\\Users\\ann"] }),
    ).toMatchObject({ ok: false, error: { code: "contains_local_path" } });
  });

  it("rejects an invalid repository id", async () => {
    for (const id of [0, -1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
      const saved = await store.save(makeResult(), { repositoryId: id });
      expect(saved).toMatchObject({ ok: false, error: { code: "invalid_input" } });
    }
  });
});

describe("the authorization gate", () => {
  it("stores only results the gate allowed", async () => {
    const blocked = makeResult({
      overallStatus: "blocked",
      authorization: {
        decision: "blocked",
        checks: makeResult().authorization.checks.map((c, i) =>
          i === 1 ? { ...c, status: "failed" as const } : c,
        ),
      },
    });
    expect(await store.save(blocked, { repositoryId: REPO_ID })).toMatchObject({
      ok: false,
      error: { code: "not_allowed" },
    });
    // A forged "allowed" decision with a failed check is still refused.
    const forged = makeResult({
      authorization: { ...blocked.authorization, decision: "allowed" },
    });
    expect(await store.save(forged, { repositoryId: REPO_ID })).toMatchObject({
      ok: false,
      error: { code: "not_allowed" },
    });
    // An allowed authorization missing a check is refused.
    const short = makeResult();
    short.authorization.checks = short.authorization.checks.slice(0, 4);
    expect(await store.save(short, { repositoryId: REPO_ID })).toMatchObject({ ok: false });
    // An allowed gate on a failed or blocked scan status.
    expect(
      await store.save(makeResult({ overallStatus: "blocked" }), { repositoryId: REPO_ID }),
    ).toMatchObject({ ok: false });
    await expect(stat(path.join(dir, "repos"))).rejects.toThrow();
    expect(
      await store.save(makeResult({ overallStatus: "failed" }), { repositoryId: REPO_ID }),
    ).toMatchObject({ ok: false, error: { code: "not_allowed" } });
  });

  it("stores nothing that could stand in for an authorization", async () => {
    await store.save(makeResult(), { repositoryId: REPO_ID });
    const [file] = await repoFiles();
    const text = await readFile(path.join(dir, "repos", String(REPO_ID), file ?? ""), "utf8");
    expect(text).not.toMatch(/token|password|secret/i);
  });
});

describe.skipIf(!isPosix)("permissions and atomicity", () => {
  it("creates directories 0700 and files 0600", async () => {
    const saved = await store.save(makeResult(), { repositoryId: REPO_ID });
    expect(saved.ok).toBe(true);
    for (const d of [dir, path.join(dir, "repos"), path.join(dir, "repos", String(REPO_ID))]) {
      expect((await stat(d)).mode & 0o777).toBe(0o700);
    }
    const [file] = await repoFiles();
    expect((await stat(path.join(dir, "repos", String(REPO_ID), file ?? ""))).mode & 0o777).toBe(
      0o600,
    );
  });

  it("tightens a loose existing directory", async () => {
    await mkdir(dir, { mode: 0o755 });
    await store.save(makeResult(), { repositoryId: REPO_ID });
    expect((await stat(dir)).mode & 0o777).toBe(0o700);
  });

  it("leaves no temp file behind and never exposes a partial file", async () => {
    await store.save(makeResult(), { repositoryId: REPO_ID });
    const names = await readdir(path.join(dir, "repos", String(REPO_ID)));
    expect(names.filter((n) => n.startsWith(".tmp-"))).toEqual([]);
    expect(names).toHaveLength(1);
  });

  it("removes its temp file when the final step is refused", async () => {
    const saved = await store.save(makeResult(), { repositoryId: REPO_ID });
    if (!saved.ok) throw new Error("setup");
    const target = path.join(dir, "repos", String(REPO_ID), saved.file);
    await writeFile(target, "not json", { mode: 0o600 });
    const again = await store.save(makeResult(), { repositoryId: REPO_ID });
    expect(again).toMatchObject({ ok: false, error: { code: "would_overwrite" } });
    const names = await readdir(path.join(dir, "repos", String(REPO_ID)));
    expect(names.filter((n) => n.startsWith(".tmp-"))).toEqual([]);
    expect(await readFile(target, "utf8")).toBe("not json");
  });

  it("removes stale temp files on prune but keeps fresh ones", async () => {
    await store.save(makeResult(), { repositoryId: REPO_ID });
    const repoDir = path.join(dir, "repos", String(REPO_ID));
    const stale = path.join(repoDir, ".tmp-1-stale");
    const fresh = path.join(repoDir, ".tmp-1-fresh");
    await writeFile(stale, "x", { mode: 0o600 });
    await writeFile(fresh, "x", { mode: 0o600 });
    const old = new Date(clock - 2 * 3_600_000);
    await utimes(stale, old, old);
    await utimes(fresh, new Date(clock), new Date(clock));
    await store.prune(REPO_ID);
    const names = await readdir(repoDir);
    expect(names).not.toContain(".tmp-1-stale");
    expect(names).toContain(".tmp-1-fresh");
  });
});

describe.skipIf(!isPosix)("symlink refusal", () => {
  it("does not follow a symlinked store directory", async () => {
    const elsewhere = path.join(base, "elsewhere");
    await mkdir(elsewhere);
    await symlink(elsewhere, dir);
    const saved = await store.save(makeResult(), { repositoryId: REPO_ID });
    expect(saved).toMatchObject({ ok: false, error: { code: "symlink" } });
    expect(await readdir(elsewhere)).toEqual([]);
  });

  it("does not follow a symlinked repos or repository directory", async () => {
    const elsewhere = path.join(base, "elsewhere");
    await mkdir(elsewhere);
    await mkdir(dir, { mode: 0o700 });
    await symlink(elsewhere, path.join(dir, "repos"));
    expect(await store.save(makeResult(), { repositoryId: REPO_ID })).toMatchObject({
      ok: false,
      error: { code: "symlink" },
    });
    await rm(path.join(dir, "repos"));
    await mkdir(path.join(dir, "repos"), { mode: 0o700 });
    await symlink(elsewhere, path.join(dir, "repos", String(REPO_ID)));
    expect(await store.save(makeResult(), { repositoryId: REPO_ID })).toMatchObject({
      ok: false,
      error: { code: "symlink" },
    });
    expect(await readdir(elsewhere)).toEqual([]);
  });

  it("does not write through a symlink planted at the result file name", async () => {
    const saved = await store.save(makeResult(), { repositoryId: REPO_ID });
    if (!saved.ok) throw new Error("setup");
    const target = path.join(dir, "repos", String(REPO_ID), saved.file);
    const victim = path.join(base, "victim.txt");
    await writeFile(victim, "precious");
    await rm(target);
    await symlink(victim, target);
    const again = await store.save(makeResult(), { repositoryId: REPO_ID });
    expect(again).toMatchObject({ ok: false, error: { code: "symlink" } });
    expect(await readFile(victim, "utf8")).toBe("precious");
  });

  it("skips a symlinked result file when listing, with a warning", async () => {
    await store.save(makeResult(), { repositoryId: REPO_ID });
    const repoDir = path.join(dir, "repos", String(REPO_ID));
    const [real] = await repoFiles();
    const link = path.join(repoDir, "0000000000001-aaaaaaaaaaaaaaaa.json");
    await symlink(path.join(repoDir, real ?? ""), link);
    const listed = await store.list(REPO_ID);
    expect(listed.scans).toHaveLength(1);
    expect(listed.warnings).toHaveLength(1);
  });

  describe("clear never follows links", () => {
    let elsewhere: string;
    let victim: string;
    beforeEach(async () => {
      elsewhere = path.join(base, "elsewhere");
      victim = path.join(elsewhere, "1111111111111-aaaaaaaaaaaaaaaa.json");
      await mkdir(elsewhere);
      await writeFile(victim, JSON.stringify(makeResult()), { mode: 0o600 });
    });

    it("a symlinked store root", async () => {
      await symlink(elsewhere, dir);
      const outcome = await store.clear();
      expect(outcome.removed).toBe(0);
      expect(outcome.warnings).toHaveLength(1);
      expect(await readFile(victim, "utf8")).toContain("scan-1");
    });

    it("a symlinked repos directory", async () => {
      await mkdir(dir, { mode: 0o700 });
      await symlink(elsewhere, path.join(dir, "repos"));
      const outcome = await store.clear();
      expect(outcome.removed).toBe(0);
      expect(outcome.warnings).toHaveLength(1);
      expect(await readFile(victim, "utf8")).toContain("scan-1");
    });

    it("a symlinked repository directory, by id and for all", async () => {
      await mkdir(path.join(dir, "repos"), { recursive: true, mode: 0o700 });
      await symlink(elsewhere, path.join(dir, "repos", String(REPO_ID)));
      for (const options of [{}, { repositoryId: REPO_ID }, { repoName: "owner/name" }]) {
        const outcome = await store.clear(options);
        expect(outcome.removed).toBe(0);
        expect(outcome.warnings).toHaveLength(1);
        expect(await readFile(victim, "utf8")).toContain("scan-1");
      }
    });

    it("a directory owned by another user", async () => {
      await store.save(makeResult(), { repositoryId: REPO_ID });
      const foreign = createResultStore({ dir, now: () => clock, getuid: () => 0x7ffffff0 });
      const outcome = await foreign.clear();
      expect(outcome.removed).toBe(0);
      expect(outcome.warnings).toHaveLength(1);
      expect(await repoFiles()).toHaveLength(1);
      expect(await foreign.save(makeResult(), { repositoryId: REPO_ID })).toMatchObject({
        ok: false,
        error: { code: "wrong_owner" },
      });
    });
  });

  it("clear by id only touches that id, and ignores non-numeric directories", async () => {
    await store.save(makeResult({ scanId: "a" }), { repositoryId: 1 });
    await store.save(makeResult({ scanId: "b" }), { repositoryId: 2 });
    const stray = path.join(dir, "repos", "notes");
    await mkdir(stray, { mode: 0o700 });
    await writeFile(path.join(stray, "keep.txt"), "keep");
    expect(await store.clear({ repositoryId: 2 })).toMatchObject({ removed: 1 });
    expect((await store.list(1)).scans).toHaveLength(1);
    expect(await store.clear()).toMatchObject({ removed: 1 });
    expect(await readFile(path.join(stray, "keep.txt"), "utf8")).toBe("keep");
  });

  it("clear with a bad id deletes nothing", async () => {
    await store.save(makeResult(), { repositoryId: 1 });
    const outcome = await store.clear({ repositoryId: -3 });
    expect(outcome.removed).toBe(0);
    expect(outcome.warnings).toHaveLength(1);
    expect((await store.list(1)).scans).toHaveLength(1);
  });

  it("clear by name deletes only matched result files, not other files in the directory", async () => {
    await store.save(makeResult({ scanId: "a" }), { repositoryId: 1 });
    await store.save(
      makeResult({
        scanId: "b",
        target: { repo: "other/repo", revision: null, webOrigin: null },
      }),
      { repositoryId: 2 },
    );
    const other = path.join(dir, "repos", "2", "note.txt");
    const tmp = path.join(dir, "repos", "2", ".tmp-1-x");
    await writeFile(other, "keep");
    await writeFile(tmp, "keep");
    expect(await store.clear({ repoName: "owner/name" })).toMatchObject({ removed: 1 });
    expect(await readFile(other, "utf8")).toBe("keep");
    expect(await readFile(tmp, "utf8")).toBe("keep");
    expect((await store.list(2)).scans).toHaveLength(1);
  });

  it("refuses a store path that is a regular file", async () => {
    // Directory path that is a regular file.
    await writeFile(dir, "file");
    expect(await store.save(makeResult(), { repositoryId: REPO_ID })).toMatchObject({
      ok: false,
      error: { code: "not_directory" },
    });
  });
});

describe("retention", () => {
  it("keeps the newest 20 scans per repository", async () => {
    for (let i = 0; i < RETENTION_MAX_SCANS_PER_REPO + 5; i += 1) {
      clock += 1000;
      await store.save(makeResult({ scanId: `scan-${i}` }), { repositoryId: REPO_ID });
    }
    const files = await repoFiles();
    expect(files).toHaveLength(RETENTION_MAX_SCANS_PER_REPO);
    const listed = await store.list(REPO_ID);
    expect(listed.scans[0]?.result.scanId).toBe(`scan-${RETENTION_MAX_SCANS_PER_REPO + 4}`);
    expect(listed.scans.map((s) => s.result.scanId)).not.toContain("scan-0");
  });

  it("drops scans older than 90 days", async () => {
    await store.save(makeResult({ scanId: "old" }), { repositoryId: REPO_ID });
    clock += (RETENTION_MAX_AGE_DAYS - 1) * DAY;
    await store.save(makeResult({ scanId: "mid" }), { repositoryId: REPO_ID });
    expect((await store.list(REPO_ID)).scans).toHaveLength(2);
    clock += 2 * DAY;
    const saved = await store.save(makeResult({ scanId: "new" }), { repositoryId: REPO_ID });
    expect(saved).toMatchObject({ ok: true, pruned: 1 });
    const ids = (await store.list(REPO_ID)).scans.map((s) => s.result.scanId);
    expect(ids).toEqual(["new", "mid"]);
  });

  it("never prunes the file just written, even with 20 future-dated files", async () => {
    const repoDir = path.join(dir, "repos", String(REPO_ID));
    await mkdir(repoDir, { recursive: true, mode: 0o700 });
    for (let i = 0; i < RETENTION_MAX_SCANS_PER_REPO; i += 1) {
      const future = String(clock + 400 * DAY + i).padStart(13, "0");
      await writeFile(
        path.join(repoDir, `${future}-ffffffffffff${i.toString(16).padStart(4, "0")}.json`),
        JSON.stringify(makeResult({ scanId: `future-${i}` })),
        { mode: 0o600 },
      );
    }
    const saved = await store.save(makeResult({ scanId: "fresh" }), { repositoryId: REPO_ID });
    expect(saved).toMatchObject({ ok: true, pruned: 1 });
    if (!saved.ok) return;
    expect(await repoFiles()).toContain(saved.file);
    expect(await repoFiles()).toHaveLength(RETENTION_MAX_SCANS_PER_REPO);
  });

  it("does not let future-dated files crowd out real scans", async () => {
    const repoDir = path.join(dir, "repos", String(REPO_ID));
    await mkdir(repoDir, { recursive: true, mode: 0o700 });
    for (let i = 0; i < RETENTION_MAX_SCANS_PER_REPO; i += 1) {
      const future = String(clock + 400 * DAY + i).padStart(13, "0");
      await writeFile(
        path.join(repoDir, `${future}-ffffffffffff${i.toString(16).padStart(4, "0")}.json`),
        JSON.stringify(makeResult({ scanId: `future-${i}` })),
        { mode: 0o600 },
      );
    }
    for (let i = 0; i < 5; i += 1) {
      clock += 1000;
      await store.save(makeResult({ scanId: `real-${i}` }), { repositoryId: REPO_ID });
    }
    const ids = (await store.list(REPO_ID)).scans.map((s) => s.result.scanId);
    expect(ids.filter((id) => id.startsWith("real-"))).toHaveLength(5);
    expect(ids).toHaveLength(RETENTION_MAX_SCANS_PER_REPO);
  });

  it("keeps a scan exactly at the age limit", async () => {
    await store.save(makeResult({ scanId: "edge" }), { repositoryId: REPO_ID });
    clock += RETENTION_MAX_AGE_DAYS * DAY;
    expect(await store.prune(REPO_ID)).toBe(0);
  });

  it("prunes each repository on its own", async () => {
    for (let i = 0; i < 22; i += 1) {
      clock += 1000;
      await store.save(makeResult({ scanId: `a-${i}` }), { repositoryId: 1 });
    }
    clock += 1000;
    await store.save(makeResult({ scanId: "b" }), { repositoryId: 2 });
    expect((await store.list(1)).scans).toHaveLength(20);
    expect((await store.list(2)).scans).toHaveLength(1);
  });

  it("documents its limits as constants", () => {
    expect(RETENTION_MAX_SCANS_PER_REPO).toBe(20);
    expect(RETENTION_MAX_AGE_DAYS).toBe(90);
  });
});

describe("corrupt, oversized and newer files", () => {
  async function plant(name: string, content: string | Buffer): Promise<string> {
    const repoDir = path.join(dir, "repos", String(REPO_ID));
    await mkdir(repoDir, { recursive: true, mode: 0o700 });
    const file = path.join(repoDir, name);
    await writeFile(file, content, { mode: 0o600 });
    return file;
  }

  it("skips corrupt and oversized files with a warning and still lists the rest", async () => {
    await store.save(makeResult(), { repositoryId: REPO_ID });
    await plant("0000000000002-bbbbbbbbbbbbbbbb.json", "{ not json");
    await plant("0000000000003-cccccccccccccccc.json", JSON.stringify({ schemaVersion: "9.0" }));
    await plant(
      "0000000000004-dddddddddddddddd.json",
      Buffer.alloc(MAX_RESULT_FILE_BYTES + 1, 0x20),
    );
    const listed = await store.list(REPO_ID);
    expect(listed.scans).toHaveLength(1);
    expect(listed.warnings).toHaveLength(3);
    expect(listed.warnings.join("\n")).toContain("larger than");
  });

  it("does not parse a file above the size cap", async () => {
    const file = await plant(
      "0000000000004-dddddddddddddddd.json",
      Buffer.alloc(MAX_RESULT_FILE_BYTES + 1, 0x7b),
    );
    expect(file).toBeTruthy();
    const loaded = await store.load(REPO_ID, "0000000000004-dddddddddddddddd.json");
    expect(loaded).toMatchObject({ ok: false, error: { code: "too_large" } });
  });

  it("does not read outside the repository directory through a crafted name", async () => {
    await store.save(makeResult(), { repositoryId: REPO_ID });
    const outside = path.join(dir, "repos", "x.json");
    await writeFile(outside, JSON.stringify(makeResult()), { mode: 0o600 });
    expect(await store.load(REPO_ID, "../x.json")).toMatchObject({
      ok: false,
      error: { code: "invalid_input" },
    });
  });

  it("rejects file names that are not store files", async () => {
    for (const name of ["../x.json", "a.json", "0000000000004-dddddddddddddddd.json/../../x"]) {
      expect(await store.load(REPO_ID, name)).toMatchObject({ ok: false });
    }
  });

  it("never overwrites a file with a newer schema minor", async () => {
    const first = await store.save(makeResult(), { repositoryId: REPO_ID });
    if (!first.ok) throw new Error("setup");
    const file = path.join(dir, "repos", String(REPO_ID), first.file);
    const newer = { ...makeResult(), schemaVersion: "1.7", futureField: { keep: "me" } };
    const original = JSON.stringify(newer);
    await writeFile(file, original);
    const again = await store.save(makeResult(), { repositoryId: REPO_ID });
    expect(again).toMatchObject({ ok: false, error: { code: "would_overwrite" } });
    expect(await readFile(file, "utf8")).toBe(original);
    // The newer file is still readable and reports its version.
    const listed = await store.list(REPO_ID);
    expect(listed.scans[0]?.sourceVersion).toBe("1.7");
  });

  it("overwrites an identical-version file of the same scan (idempotent)", async () => {
    await store.save(makeResult(), { repositoryId: REPO_ID });
    expect(await store.save(makeResult(), { repositoryId: REPO_ID })).toMatchObject({ ok: true });
    expect(await repoFiles()).toHaveLength(1);
  });
});

describe("concurrent saves", () => {
  it("keeps every file intact when many saves race", async () => {
    const outcomes = await Promise.all(
      Array.from({ length: 12 }, (_, i) =>
        newStore().save(makeResult({ scanId: `race-${i}` }), { repositoryId: REPO_ID }),
      ),
    );
    expect(outcomes.every((o) => o.ok)).toBe(true);
    const listed = await store.list(REPO_ID);
    expect(listed.warnings).toEqual([]);
    expect(listed.scans).toHaveLength(12);
    const names = await readdir(path.join(dir, "repos", String(REPO_ID)));
    expect(names.filter((n) => n.startsWith(".tmp-"))).toEqual([]);
  });

  it("keeps the retention bound when saves race past it", async () => {
    await Promise.all(
      Array.from({ length: 30 }, (_, i) =>
        newStore().save(makeResult({ scanId: `r-${i}` }), { repositoryId: REPO_ID }),
      ),
    );
    await store.prune(REPO_ID);
    expect((await repoFiles()).length).toBeLessThanOrEqual(RETENTION_MAX_SCANS_PER_REPO);
    expect((await store.list(REPO_ID)).warnings).toEqual([]);
  });

  it("lets exactly one process claim the first-run notice", async () => {
    const claims = await Promise.all(
      Array.from({ length: 8 }, () => newStore().claimFirstRunNotice()),
    );
    expect(claims.filter(Boolean)).toHaveLength(1);
    expect(await store.claimFirstRunNotice()).toBe(false);
  });
});

describe("clear", () => {
  it("removes everything with no options and reports the count", async () => {
    await store.save(makeResult({ scanId: "a" }), { repositoryId: 1 });
    await store.save(makeResult({ scanId: "b" }), { repositoryId: 2 });
    const outcome = await store.clear();
    expect(outcome).toEqual({ removed: 2, baselinesRemoved: 0, warnings: [] });
    expect((await store.list(1)).scans).toEqual([]);
    await expect(stat(path.join(dir, "repos"))).rejects.toThrow();
  });

  it("is a no-op when the store does not exist", async () => {
    expect(await store.clear()).toEqual({ removed: 0, baselinesRemoved: 0, warnings: [] });
    await expect(stat(dir)).rejects.toThrow();
  });

  it("clears one repository by id or by stored name, case-insensitively", async () => {
    await store.save(makeResult({ scanId: "a" }), { repositoryId: 1 });
    await store.save(
      makeResult({ scanId: "b", target: { repo: "Other/Repo", revision: null, webOrigin: null } }),
      {
        repositoryId: 2,
      },
    );
    expect(await store.clear({ repoName: "other/repo" })).toMatchObject({ removed: 1 });
    expect((await store.list(1)).scans).toHaveLength(1);
    expect(await store.clear({ repositoryId: 1 })).toMatchObject({ removed: 1 });
    expect((await store.list(1)).scans).toHaveLength(0);
  });

  it("keeps the first-run marker so the notice is not repeated", async () => {
    await store.claimFirstRunNotice();
    await store.save(makeResult(), { repositoryId: REPO_ID });
    await store.clear();
    expect(await store.claimFirstRunNotice()).toBe(false);
  });
});
