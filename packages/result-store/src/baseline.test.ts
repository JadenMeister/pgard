import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { SCHEMA_VERSION, type Finding, type ScanResult } from "@pgard/findings";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createResultStore, type ResultStore } from "./store.js";

const isPosix = process.platform !== "win32";
const REPO_ID = 4242;

function makeFinding(): Finding {
  return {
    id: "f1",
    ruleId: "PG-SQL-001",
    title: "t",
    category: "injection",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    location: { kind: "file", path: "src/db.ts", line: 3, url: null, commit: null },
    evidence: "e",
    impact: "i",
    recommendation: "r",
    references: { cwe: [], owasp: [], cve: [] },
    sources: ["code"],
  };
}

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
    findings: [makeFinding()],
    advisoryDb: { version: null, updatedAt: null },
    ...overrides,
  };
}

let base: string;
let dir: string;
let clock: number;
let store: ResultStore;
const repoDir = () => path.join(dir, "repos", String(REPO_ID));
const baselineFile = () => path.join(repoDir(), "baseline.json");

beforeEach(async () => {
  base = await mkdtemp(path.join(os.tmpdir(), "pgard-baseline-"));
  dir = path.join(base, "pgard");
  clock = Date.UTC(2026, 9, 26, 10, 0, 0);
  store = createResultStore({ dir, now: () => clock });
});

afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

describe("baseline storage", () => {
  it("reports no baseline before one is set, even without a store directory", async () => {
    expect(await store.getBaseline(REPO_ID)).toEqual({ ok: true, baseline: null });
  });

  it("round-trips a baseline through the reader with the time it was set", async () => {
    expect(await store.setBaseline(makeResult(), { repositoryId: REPO_ID })).toEqual({ ok: true });
    const loaded = await store.getBaseline(REPO_ID);
    expect(loaded.ok).toBe(true);
    if (loaded.ok) {
      expect(loaded.baseline?.setAt.toISOString()).toBe("2026-10-26T10:00:00.000Z");
      expect(loaded.baseline?.result.scanId).toBe("scan-1");
      expect(loaded.baseline?.result.findings).toHaveLength(1);
      expect(loaded.baseline?.sourceVersion).toBe(SCHEMA_VERSION);
    }
  });

  it("replaces an earlier baseline", async () => {
    await store.setBaseline(makeResult({ scanId: "one" }), { repositoryId: REPO_ID });
    clock += 1000;
    await store.setBaseline(makeResult({ scanId: "two" }), { repositoryId: REPO_ID });
    const loaded = await store.getBaseline(REPO_ID);
    expect(loaded.ok && loaded.baseline?.result.scanId).toBe("two");
  });

  it.skipIf(!isPosix)("writes the file 0600 in a 0700 directory", async () => {
    await store.setBaseline(makeResult(), { repositoryId: REPO_ID });
    expect((await stat(baselineFile())).mode & 0o777).toBe(0o600);
    expect((await stat(repoDir())).mode & 0o777).toBe(0o700);
    expect((await stat(dir)).mode & 0o777).toBe(0o700);
  });

  it("is kept per repository", async () => {
    await store.setBaseline(makeResult(), { repositoryId: REPO_ID });
    expect(await store.getBaseline(REPO_ID + 1)).toEqual({ ok: true, baseline: null });
  });

  it("clears only the baseline, and says whether there was one", async () => {
    await store.save(makeResult({ scanId: "kept" }), { repositoryId: REPO_ID });
    await store.setBaseline(makeResult(), { repositoryId: REPO_ID });
    expect(await store.clearBaseline(REPO_ID)).toEqual({ ok: true, removed: true });
    expect(await store.clearBaseline(REPO_ID)).toEqual({ ok: true, removed: false });
    expect(await store.getBaseline(REPO_ID)).toEqual({ ok: true, baseline: null });
    expect((await store.list(REPO_ID)).scans).toHaveLength(1);
  });

  it("is not a scan: listing and findNewest ignore it", async () => {
    await store.setBaseline(makeResult(), { repositoryId: REPO_ID });
    const listed = await store.list(REPO_ID);
    expect(listed.scans).toEqual([]);
    expect(listed.warnings).toEqual([]);
    expect((await store.findNewest(REPO_ID, () => null)).scan).toBeNull();
  });

  it("survives retention pruning of old scans", async () => {
    const small = createResultStore({ dir, now: () => clock, maxScansPerRepo: 1 });
    await small.setBaseline(makeResult({ scanId: "base" }), { repositoryId: REPO_ID });
    for (const id of ["a", "b", "c"]) {
      clock += 1000;
      await small.save(makeResult({ scanId: id }), { repositoryId: REPO_ID });
    }
    clock += 200 * 86_400_000;
    await small.prune(REPO_ID);
    const loaded = await small.getBaseline(REPO_ID);
    expect(loaded.ok && loaded.baseline?.result.scanId).toBe("base");
  });

  it("refuses a result the gate did not allow, and a blocked or failed one", async () => {
    const blocked = makeResult({
      authorization: { decision: "blocked", checks: makeResult().authorization.checks },
      overallStatus: "blocked",
    });
    expect(await store.setBaseline(blocked, { repositoryId: REPO_ID })).toMatchObject({
      ok: false,
      error: { code: "not_allowed" },
    });
    expect(
      await store.setBaseline(makeResult({ overallStatus: "failed" }), { repositoryId: REPO_ID }),
    ).toMatchObject({ ok: false, error: { code: "not_allowed" } });
    expect(await store.getBaseline(REPO_ID)).toEqual({ ok: true, baseline: null });
  });

  it("refuses a result that contains a forbidden local path", async () => {
    const leaky = makeResult({
      coverage: [{ ...makeResult().coverage[0]!, note: "/home/me/proj" }],
    });
    expect(
      await store.setBaseline(leaky, {
        repositoryId: REPO_ID,
        forbidSubstrings: ["/home/me/proj"],
      }),
    ).toMatchObject({ ok: false, error: { code: "contains_local_path" } });
  });

  it("requires a repository id", async () => {
    expect(await store.setBaseline(makeResult(), { repositoryId: 0 })).toMatchObject({
      ok: false,
      error: { code: "invalid_input" },
    });
  });
});

describe("a damaged or foreign baseline file", () => {
  async function plant(text: string): Promise<void> {
    await store.save(makeResult({ scanId: "x" }), { repositoryId: REPO_ID });
    await writeFile(baselineFile(), text, { mode: 0o600 });
  }

  it("is an error, not 'no baseline', and never read as one", async () => {
    await plant("{not json");
    expect(await store.getBaseline(REPO_ID)).toMatchObject({
      ok: false,
      error: { code: "invalid_input" },
    });
    await plant(JSON.stringify({ kind: "something-else", version: 1 }));
    expect((await store.getBaseline(REPO_ID)).ok).toBe(false);
  });

  it("may be replaced by a new baseline", async () => {
    await plant("{not json");
    expect(await store.setBaseline(makeResult(), { repositoryId: REPO_ID })).toEqual({ ok: true });
    expect((await store.getBaseline(REPO_ID)).ok).toBe(true);
  });

  it("is not replaced when it was written by a newer schema", async () => {
    await store.setBaseline(makeResult(), { repositoryId: REPO_ID });
    const text = (await readFile(baselineFile(), "utf8")).replace(
      `"schemaVersion":"${SCHEMA_VERSION}"`,
      '"schemaVersion":"1.9"',
    );
    await writeFile(baselineFile(), text);
    expect(await store.setBaseline(makeResult(), { repositoryId: REPO_ID })).toMatchObject({
      ok: false,
      error: { code: "would_overwrite" },
    });
    expect(await readFile(baselineFile(), "utf8")).toBe(text);
  });
});

describe.skipIf(!isPosix)("symlink refusal", () => {
  it("does not write through a symlinked baseline file", async () => {
    await store.save(makeResult({ scanId: "x" }), { repositoryId: REPO_ID });
    const target = path.join(base, "elsewhere.txt");
    await writeFile(target, "keep");
    await symlink(target, baselineFile());
    expect(await store.setBaseline(makeResult(), { repositoryId: REPO_ID })).toMatchObject({
      ok: false,
      error: { code: "symlink" },
    });
    expect(await readFile(target, "utf8")).toBe("keep");
  });

  it("does not read through a symlinked baseline file", async () => {
    await store.setBaseline(makeResult(), { repositoryId: REPO_ID });
    const copy = path.join(base, "copy.json");
    await writeFile(copy, await readFile(baselineFile(), "utf8"));
    await rm(baselineFile());
    await symlink(copy, baselineFile());
    expect(await store.getBaseline(REPO_ID)).toMatchObject({
      ok: false,
      error: { code: "symlink" },
    });
  });

  it("removes the link, never its target, when clearing", async () => {
    await store.save(makeResult({ scanId: "x" }), { repositoryId: REPO_ID });
    const target = path.join(base, "elsewhere.txt");
    await writeFile(target, "keep");
    await symlink(target, baselineFile());
    expect(await store.clearBaseline(REPO_ID)).toEqual({ ok: true, removed: true });
    expect(await readFile(target, "utf8")).toBe("keep");
  });

  it("does not use a symlinked repository directory", async () => {
    await store.save(makeResult({ scanId: "x" }), { repositoryId: REPO_ID });
    await rm(repoDir(), { recursive: true });
    await writeFile(path.join(base, "marker"), "");
    await symlink(base, repoDir());
    expect(await store.setBaseline(makeResult(), { repositoryId: REPO_ID })).toMatchObject({
      ok: false,
      error: { code: "symlink" },
    });
    expect(await readdir(base)).not.toContain("baseline.json");
  });
});

describe("history clear", () => {
  it("removes the baseline together with the results and counts it", async () => {
    await store.save(makeResult({ scanId: "a" }), { repositoryId: REPO_ID });
    await store.setBaseline(makeResult(), { repositoryId: REPO_ID });
    await store.setBaseline(makeResult(), { repositoryId: REPO_ID + 1 });
    const outcome = await store.clear();
    expect(outcome).toEqual({ removed: 1, baselinesRemoved: 2, warnings: [] });
    expect(await store.getBaseline(REPO_ID)).toEqual({ ok: true, baseline: null });
    await expect(readdir(path.join(dir, "repos"))).rejects.toThrow();
  });

  it("with a repository id removes only that repository's baseline", async () => {
    await store.setBaseline(makeResult(), { repositoryId: REPO_ID });
    await store.setBaseline(makeResult(), { repositoryId: REPO_ID + 1 });
    expect(await store.clear({ repositoryId: REPO_ID })).toMatchObject({ baselinesRemoved: 1 });
    expect((await store.getBaseline(REPO_ID + 1)).ok).toBe(true);
    const other = await store.getBaseline(REPO_ID + 1);
    expect(other.ok && other.baseline).not.toBeNull();
  });

  it("with a repository name removes the baseline of that name only", async () => {
    await store.setBaseline(makeResult(), { repositoryId: REPO_ID });
    await store.setBaseline(
      makeResult({ target: { repo: "other/repo", revision: null, webOrigin: null } }),
      {
        repositoryId: REPO_ID + 1,
      },
    );
    expect(await store.clear({ repoName: "OWNER/name" })).toMatchObject({
      removed: 0,
      baselinesRemoved: 1,
    });
    expect(await store.getBaseline(REPO_ID)).toEqual({ ok: true, baseline: null });
    const kept = await store.getBaseline(REPO_ID + 1);
    expect(kept.ok && kept.baseline).not.toBeNull();
  });

  it("leaves a baseline it cannot match in place and says so", async () => {
    await store.save(makeResult({ scanId: "x" }), { repositoryId: REPO_ID });
    await writeFile(baselineFile(), "{not json", { mode: 0o600 });
    const outcome = await store.clear({ repoName: "owner/name" });
    expect(outcome.baselinesRemoved).toBe(0);
    expect(outcome.warnings.join(" ")).toContain("baseline");
    expect(await readdir(repoDir())).toContain("baseline.json");
  });
});

describe("hardening", () => {
  it("is not used for another repository id, even when the file is moved there", async () => {
    await store.setBaseline(makeResult(), { repositoryId: REPO_ID });
    await store.save(makeResult({ scanId: "x" }), { repositoryId: REPO_ID + 1 });
    await copyFile(baselineFile(), path.join(dir, "repos", String(REPO_ID + 1), "baseline.json"));
    expect(await store.getBaseline(REPO_ID + 1)).toMatchObject({
      ok: false,
      error: { code: "invalid_input", message: expect.stringContaining("another repository") },
    });
  });

  it("refuses a file without a repository id", async () => {
    await store.setBaseline(makeResult(), { repositoryId: REPO_ID });
    const text = (await readFile(baselineFile(), "utf8")).replace(`"repositoryId":${REPO_ID},`, "");
    await writeFile(baselineFile(), text);
    expect((await store.getBaseline(REPO_ID)).ok).toBe(false);
  });

  it.skipIf(!isPosix)("refuses a file that other users can write", async () => {
    await store.setBaseline(makeResult(), { repositoryId: REPO_ID });
    for (const mode of [0o620, 0o602, 0o666]) {
      await chmod(baselineFile(), mode);
      expect(await store.getBaseline(REPO_ID)).toMatchObject({
        ok: false,
        error: { code: "permissions" },
      });
    }
    await chmod(baselineFile(), 0o644);
    expect((await store.getBaseline(REPO_ID)).ok).toBe(true);
  });

  it.skipIf(!isPosix)("reports a failed clear instead of 'there was none'", async () => {
    await store.save(makeResult({ scanId: "x" }), { repositoryId: REPO_ID });
    // A directory where the file should be: unlink fails with something other than "absent".
    await mkdir(baselineFile());
    await writeFile(path.join(baselineFile(), "x"), "");
    expect((await store.clearBaseline(REPO_ID)).ok).toBe(false);
  });

  it("refuses a result over the size cap", async () => {
    const big = makeResult({
      findings: Array.from({ length: 100 }, (_, index) => ({
        ...makeFinding(),
        id: `f${index}`,
        evidence: "x".repeat(90_000),
      })),
    });
    expect(await store.setBaseline(big, { repositoryId: REPO_ID })).toMatchObject({
      ok: false,
      error: { code: "too_large" },
    });
    expect(await store.getBaseline(REPO_ID)).toEqual({ ok: true, baseline: null });
  });

  it("refuses a result whose gate did not pass every check, whatever its status says", async () => {
    const checks = makeResult().authorization.checks;
    const failedCheck = makeResult({
      authorization: {
        decision: "allowed",
        checks: checks.map((check) =>
          check.id === "owner_approval" ? { ...check, status: "failed" as const } : check,
        ),
      },
    });
    const blockedDecision = makeResult({ authorization: { decision: "blocked", checks } });
    const missingCheck = makeResult({
      authorization: { decision: "allowed", checks: checks.slice(1) },
    });
    for (const result of [failedCheck, blockedDecision, missingCheck]) {
      expect(await store.setBaseline(result, { repositoryId: REPO_ID })).toMatchObject({
        ok: false,
        error: { code: "not_allowed" },
      });
    }
  });

  it("is not replaced by a result of the wrong status either", async () => {
    expect(
      await store.setBaseline(makeResult({ overallStatus: "blocked" }), { repositoryId: REPO_ID }),
    ).toMatchObject({ ok: false, error: { code: "not_allowed" } });
  });
});
