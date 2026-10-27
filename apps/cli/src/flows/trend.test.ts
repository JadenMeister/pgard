import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createResultStore, type ResultStore } from "@pgard/result-store";
import {
  ALLOWED,
  createTestContext,
  createTestDeps,
  createTestIo,
  testFinding,
  testResult,
} from "../test-support.js";
import type { AuthorizationOutcome } from "@pgard/scan-core";
import { loadTrend } from "./trend.js";

const REPO_ID = 77;
const outcome = {
  summary: ALLOWED,
  repo: "owner/name",
  revision: "abc",
  repositoryId: REPO_ID,
} as unknown as AuthorizationOutcome;
const NOW = Date.UTC(2026, 9, 28);
const DAY = 86_400_000;

let base: string;
let store: ResultStore;
let clock: number;

function context(env: Record<string, string> = {}, open: () => ResultStore | null = () => store) {
  const captured = createTestIo({ env });
  return createTestContext(captured, createTestDeps({ openResultStore: open }));
}

async function save(id: string, titles: string[], repoName = "owner/name") {
  clock += DAY;
  const result = testResult({
    scanId: id,
    target: { repo: repoName, revision: "abc", webOrigin: null },
    findings: titles.map((title, index) =>
      testFinding({ id: `${id}-${index}`, title, severity: index % 2 === 0 ? "high" : "low" }),
    ),
  });
  const saved = await store.save(result, { repositoryId: REPO_ID });
  expect(saved.ok).toBe(true);
}

beforeEach(async () => {
  base = await mkdtemp(path.join(os.tmpdir(), "pgard-trend-"));
  clock = NOW - 10 * DAY;
  store = createResultStore({ dir: path.join(base, "pgard"), now: () => clock });
});

afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

describe("loadTrend", () => {
  it("is disabled with --no-store or PGARD_NO_STORE=1 and never opens the store", async () => {
    const open = () => {
      throw new Error("must not open the store");
    };
    expect(await loadTrend(context({}, open), outcome, true)).toEqual({ kind: "disabled" });
    expect(await loadTrend(context({ PGARD_NO_STORE: "1" }, open), outcome, false)).toEqual({
      kind: "disabled",
    });
  });

  it("is unavailable without a store directory or a repository id", async () => {
    expect(
      await loadTrend(
        context({}, () => null),
        outcome,
        false,
      ),
    ).toMatchObject({
      kind: "unavailable",
      why: "no-store-dir",
    });
    expect(await loadTrend(context(), null, false)).toMatchObject({
      kind: "unavailable",
      why: "no-repository",
    });
  });

  it("is an empty history when nothing is stored", async () => {
    expect(await loadTrend(context(), outcome, false, null, () => NOW)).toMatchObject({
      kind: "ready",
      scans: [],
      diff: null,
    });
  });

  it("returns oldest-first counts and the newest-vs-previous comparison", async () => {
    await save("a", ["one", "two"]);
    await save("b", ["one", "two", "three"]);
    const trend = await loadTrend(context(), outcome, false, null, () => NOW);
    if (trend.kind !== "ready") throw new Error("expected ready");
    expect(trend.scans.map((scan) => scan.total)).toEqual([2, 3]);
    expect(trend.scans[0]?.savedAt).toBeLessThan(trend.scans[1]?.savedAt ?? 0);
    expect(trend.diff?.newCount).toBe(1);
    expect(trend.now).toBe(NOW);
    // Counts only: no titles, paths or repository names travel in the data.
    expect(JSON.stringify(trend)).not.toMatch(/owner|one|users\.ts/);
  });

  it("says when the current scan is not among the stored ones", async () => {
    await save("a", ["x"]);
    await save("b", ["x"]);
    const stored = await loadTrend(context(), outcome, false, "b");
    expect(stored).toMatchObject({ kind: "ready", isCurrentStored: true });
    const missing = await loadTrend(context(), outcome, false, "not-saved");
    expect(missing).toMatchObject({ kind: "ready", isCurrentStored: false });
  });

  it("skips scans from a newer schema minor and counts them", async () => {
    await save("a", ["x"]);
    await save("b", ["x"]);
    const fake = {
      list: async () => {
        const listed = await store.list(REPO_ID);
        return {
          ...listed,
          scans: listed.scans.map((scan, index) =>
            index === 0 ? { ...scan, sourceVersion: "99.0" } : scan,
          ),
        };
      },
    } as unknown as ResultStore;
    const trend = await loadTrend(
      context({}, () => fake),
      outcome,
      false,
    );
    if (trend.kind !== "ready") throw new Error("expected ready");
    expect(trend.scans).toHaveLength(1);
    expect(trend.newerSkipped).toBe(1);
  });

  it("keeps at most 20 scans", async () => {
    store = createResultStore({
      dir: path.join(base, "pgard"),
      now: () => clock,
      maxScansPerRepo: 30,
    });
    for (let i = 0; i < 25; i += 1) await save(`s${i}`, ["x"]);
    const trend = await loadTrend(context(), outcome, false);
    if (trend.kind !== "ready") throw new Error("expected ready");
    expect(trend.scans).toHaveLength(20);
  });

  it("counts hostile stored names and paths without ever returning them", async () => {
    await save("a", ["x"], "evil‮/\u001b[2Jrepo");
    await save("b", ["x"], "evil‮/\u001b[2Jrepo");
    const trend = await loadTrend(context(), outcome, false);
    expect(JSON.stringify(trend)).not.toContain("evil");
  });

  it("turns an unreadable store into a short reason and never throws", async () => {
    const throwing = {
      list: async () => {
        throw new Error(`boom ${String.fromCharCode(27)}[2J‮`);
      },
    } as unknown as ResultStore;
    const trend = await loadTrend(
      context({}, () => throwing),
      outcome,
      false,
    );
    expect(trend).toMatchObject({ kind: "unavailable", why: "unreadable" });
    if (trend.kind === "unavailable") {
      expect(trend.reason).not.toMatch(/[\u001b‮]/u);
      expect(trend.reason.length).toBeLessThanOrEqual(100);
    }
  });

  it("reports corrupt files: only-corrupt is unreadable, mixed is skipped", async () => {
    await save("a", ["x"]);
    const repoDir = path.join(base, "pgard", "repos", String(REPO_ID));
    const [file] = (await readdir(repoDir)).filter((name) => name.endsWith(".json"));
    await writeFile(path.join(repoDir, file ?? ""), "{ not json");
    const onlyCorrupt = await loadTrend(context(), outcome, false);
    expect(onlyCorrupt).toMatchObject({ kind: "unavailable", why: "unreadable" });
    await save("b", ["x"]);
    const mixed = await loadTrend(context(), outcome, false);
    expect(mixed).toMatchObject({ kind: "ready", skipped: 1 });
  });
});
