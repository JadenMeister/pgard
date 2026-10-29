import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Coverage, Finding } from "@pgard/findings";
import { createResultStore, type ListOptions, type ResultStore } from "@pgard/result-store";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { TREND_MAX_POINTS, type TrendResponse } from "../shared/api-types.js";
import { startLocalWebServer } from "./create-server.js";
import { setAuth } from "./session/session-state.js";
import {
  apiGet,
  fakeDeps,
  json,
  outcome,
  result,
  send,
  startHarness,
  TOKEN,
  type Harness,
} from "./test-support/web-harness.js";

/**
 * The Trend route against a result store in a temporary directory (never the per-user folder).
 * Scans are saved with an injected clock, so their order and dates are exact.
 */
const REPO_ID = 77;
const NOW = Date.UTC(2026, 9, 28, 12);
const DAY = 86_400_000;

let base: string;
let clock: number;
let store: ResultStore;
let harness: Harness | null = null;

function finding(id: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id,
    ruleId: "PG-SQL-001",
    title: `Finding ${id}`,
    category: "injection",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    location: { kind: "file", path: `src/${id}.ts`, line: 3, url: null, commit: null },
    evidence: "concat (value redacted)",
    impact: "Query may change",
    recommendation: "Use parameters",
    references: { cwe: [], owasp: [], cve: [] },
    sources: ["code"],
    ...overrides,
  };
}

async function save(
  scanId: string,
  findings: Finding[],
  options: {
    repositoryId?: number;
    coverage?: Coverage[];
    overallStatus?: "completed" | "partial";
  } = {},
): Promise<void> {
  clock += DAY;
  const saved = await store.save(
    result({
      scanId,
      findings,
      coverage: options.coverage ?? completeCoverage,
      overallStatus: options.overallStatus ?? "completed",
    }),
    { repositoryId: options.repositoryId ?? REPO_ID },
  );
  expect(saved.ok).toBe(true);
}

const completeCoverage: Coverage[] = [
  {
    area: "source:typescript",
    scope: "code",
    status: "completed",
    ruleIds: ["PG-SQL-001"],
    note: null,
  },
];

const partialCoverage: Coverage[] = [
  { area: "source:typescript", scope: "code", status: "completed", ruleIds: [], note: null },
  { area: "source:java", scope: "code", status: "partial", ruleIds: [], note: "2 files skipped" },
];

async function start(
  options: {
    open?: () => ResultStore | null;
    isStoreDisabled?: boolean;
    repositoryId?: number;
  } = {},
): Promise<Harness> {
  harness = await startHarness({
    fixedRoot: "/home/u/code/shop",
    deps: {
      openResultStore: options.open ?? (() => store),
      ...(options.isStoreDisabled === undefined
        ? {}
        : { isStoreDisabled: options.isStoreDisabled }),
      now: () => NOW,
    },
  });
  verify(harness, options.repositoryId ?? REPO_ID);
  return harness;
}

function verify(target: Harness, repositoryId: number | null): void {
  setAuth(target.server.state, {
    status: "done",
    outcome: outcome(null, repositoryId === null ? {} : { repositoryId }),
    finishedAt: NOW,
    message: null,
  });
}

async function readTrend(target: Harness): Promise<TrendResponse> {
  const response = await apiGet(target.server, "/api/trend");
  expect(response.status).toBe(200);
  return JSON.parse(response.body) as TrendResponse;
}

beforeEach(async () => {
  base = await mkdtemp(path.join(os.tmpdir(), "pgard-web-trend-"));
  clock = NOW - 10 * DAY;
  store = createResultStore({ dir: path.join(base, "pgard"), now: () => clock });
});

afterEach(async () => {
  await harness?.close();
  harness = null;
  await rm(base, { recursive: true, force: true });
});

describe("GET /api/trend: access", () => {
  it("needs the session token and our Host, like every API route", async () => {
    const running = await start();
    expect((await send(running.server, "GET", "/api/trend")).status).toBe(401);
    const wrongHost = await send(running.server, "GET", "/api/trend", {
      headers: { "x-pgard-token": TOKEN, host: "localhost" },
    });
    expect(wrongHost.status).toBe(421);
    expect(
      (
        await send(running.server, "GET", "/api/trend", {
          headers: { "x-pgard-token": TOKEN, "sec-fetch-site": "cross-site" },
        })
      ).status,
    ).toBe(403);
  });

  it("is read only: no other method is routed", async () => {
    const running = await start();
    const post = await send(running.server, "POST", "/api/trend", {
      headers: {
        "x-pgard-token": TOKEN,
        origin: `http://127.0.0.1:${running.server.port}`,
        "content-type": "application/json",
      },
      body: "{}",
    });
    expect(post.status).toBe(404);
  });

  it("answers 409 no_project in picker mode before a project is confirmed", async () => {
    harness = await startHarness({ deps: { openResultStore: () => store } });
    const response = await apiGet(harness.server, "/api/trend");
    expect(response.status).toBe(409);
    expect(json(response)).toMatchObject({ error: { code: "no_project" } });
  });
});

describe("GET /api/trend: honest states", () => {
  it("says the store is off and never opens it (flag)", async () => {
    let opened = 0;
    const running = await start({
      isStoreDisabled: true,
      open: () => {
        opened += 1;
        return store;
      },
    });
    expect(await readTrend(running)).toEqual({ kind: "disabled" });
    expect(opened).toBe(0);
  });

  it("says the store is off and never opens it (PGARD_NO_STORE=1)", async () => {
    let opened = 0;
    const server = await startLocalWebServer({
      projectRoot: "/home/u/code/shop",
      presetTargetPort: null,
      env: { PGARD_NO_STORE: "1" },
      assets: new Map(),
      deps: fakeDeps({
        openResultStore: () => {
          opened += 1;
          return store;
        },
      }),
      token: TOKEN,
    });
    try {
      setAuth(server.state, {
        status: "done",
        outcome: outcome(null, { repositoryId: REPO_ID }),
        finishedAt: NOW,
        message: null,
      });
      const response = await apiGet(server, "/api/trend");
      expect(JSON.parse(response.body)).toEqual({ kind: "disabled" });
      expect(opened).toBe(0);
    } finally {
      await server.close();
    }
  });

  it("asks for verification before it reads anything", async () => {
    let opened = 0;
    harness = await startHarness({
      fixedRoot: "/home/u/code/shop",
      deps: {
        openResultStore: () => {
          opened += 1;
          return store;
        },
      },
    });
    expect(await readTrend(harness)).toEqual({ kind: "unavailable", why: "not-verified" });
    // A blocked check, and an allowed one without a repository id, do not count as verified.
    setAuth(harness.server.state, {
      status: "done",
      outcome: outcome("owner_approval", { repositoryId: REPO_ID }),
      finishedAt: NOW,
      message: null,
    });
    expect(await readTrend(harness)).toEqual({ kind: "unavailable", why: "not-verified" });
    verify(harness, null);
    expect(await readTrend(harness)).toEqual({ kind: "unavailable", why: "not-verified" });
    expect(opened).toBe(0);
  });

  it("says there is no store folder", async () => {
    const running = await start({ open: () => null });
    expect(await readTrend(running)).toEqual({ kind: "unavailable", why: "no-store-dir" });
  });

  it("is ready with no points before any scan is stored, and with one point after one", async () => {
    const running = await start();
    expect(await readTrend(running)).toMatchObject({ kind: "ready", points: [] });
    await save("a", [finding("a")]);
    const one = await readTrend(running);
    if (one.kind !== "ready") throw new Error("expected ready");
    expect(one.points).toHaveLength(1);
    expect(one.points[0]?.change).toBeNull();
  });

  it("says unreadable when the store cannot be read", async () => {
    const broken = {
      list: async () => {
        throw new Error("EACCES /Users/someone/Library/secret");
      },
    } as unknown as ResultStore;
    const running = await start({ open: () => broken });
    const response = await apiGet(running.server, "/api/trend");
    expect(JSON.parse(response.body)).toEqual({ kind: "unavailable", why: "unreadable" });
    expect(response.body).not.toContain("secret");
  });
});

describe("GET /api/trend: data", () => {
  it("counts only this repository, oldest first, with changes between consecutive scans", async () => {
    await save("a", [finding("a"), finding("b", { severity: "low" })]);
    await save("other-repo", [finding("zz")], { repositoryId: 88 });
    await save("b", [finding("a"), finding("c", { severity: "critical" })]);
    const running = await start();
    const trend = await readTrend(running);
    if (trend.kind !== "ready") throw new Error("expected ready");
    expect(trend.points).toHaveLength(2);
    expect(trend.points[0]).toMatchObject({
      total: 2,
      severity: { critical: 0, high: 1, medium: 0, low: 1, info: 0 },
      coverage: "completed",
      change: null,
    });
    expect(trend.points[1]).toMatchObject({
      total: 2,
      severity: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
      change: { new: 1, noLongerReported: 1, unchanged: 1, notComparable: 0 },
    });
    expect(trend.points[0]!.savedAt).toBeLessThan(trend.points[1]!.savedAt);
    // The other repository has its own history, reachable only through its own verified id.
    verify(running, 88);
    const other = await readTrend(running);
    if (other.kind !== "ready") throw new Error("expected ready");
    expect(other.points).toHaveLength(1);
    expect(other.points[0]?.total).toBe(1);
  });

  it("never takes the repository id from the request", async () => {
    await save("other-repo", [finding("zz")], { repositoryId: 88 });
    const running = await start();
    for (const query of ["?repositoryId=88", "?repo=88&id=88"]) {
      const response = await apiGet(running.server, `/api/trend${query}`);
      expect(JSON.parse(response.body)).toMatchObject({ kind: "ready", points: [] });
    }
  });

  it("marks partial coverage and not-tested scans instead of passing them off as complete", async () => {
    await save("a", [finding("a"), finding("b")]);
    await save("b", [finding("a")], { coverage: partialCoverage, overallStatus: "partial" });
    await save("c", [], {
      coverage: [
        { area: "source:typescript", scope: "code", status: "not_tested", ruleIds: [], note: null },
      ],
      overallStatus: "partial",
    });
    const running = await start();
    const trend = await readTrend(running);
    if (trend.kind !== "ready") throw new Error("expected ready");
    expect(trend.points.map((point) => point.coverage)).toEqual([
      "completed",
      "partial",
      "not_tested",
    ]);
    expect(trend.points[1]?.incompleteAreas).toBe(1);
    // The comparison involving a partial scan keeps unverifiable findings out of "no longer reported".
    expect(trend.points[2]?.change?.noLongerReported).toBe(0);
    expect(trend.points[2]?.change?.notComparable).toBe(1);
  });

  it("counts ignored and baselined findings apart from the severity counts", async () => {
    await save("a", [
      finding("a"),
      finding("b", {
        suppression: { reason: "accepted", source: "pgard.config.json" },
      }),
      finding("c", { inBaseline: true }),
    ]);
    const running = await start();
    const trend = await readTrend(running);
    if (trend.kind !== "ready") throw new Error("expected ready");
    expect(trend.points[0]).toMatchObject({ total: 1, ignored: 1, baselined: 1 });
  });

  it("leaves out scans dated in the future so they cannot reverse the order", async () => {
    await save("a", [finding("a")]);
    await save("b", [finding("a"), finding("b")]);
    const real = clock;
    clock = NOW + 40 * DAY;
    await save("future", []);
    clock = real;
    const running = await start();
    const trend = await readTrend(running);
    if (trend.kind !== "ready") throw new Error("expected ready");
    expect(trend.futureSkipped).toBe(1);
    expect(trend.points.map((point) => point.total)).toEqual([1, 2]);
    expect(trend.points[1]?.change).toMatchObject({ new: 1, noLongerReported: 0 });
  });

  it("counts scans from a newer schema and leaves them out", async () => {
    await save("a", [finding("a")]);
    await save("b", [finding("a")]);
    const real = store;
    const newer = {
      list: (id: number, options?: ListOptions) =>
        real.list(id, {
          ...options,
          isUsable: (scan) =>
            options?.isUsable?.({
              ...scan,
              sourceVersion: scan.result.scanId === "b" ? "99.0" : scan.sourceVersion,
            }) ?? true,
        }),
    } as unknown as ResultStore;
    const running = await start({ open: () => newer });
    const trend = await readTrend(running);
    if (trend.kind !== "ready") throw new Error("expected ready");
    expect(trend.points).toHaveLength(1);
    expect(trend.newerSkipped).toBe(1);
  });

  it("is bounded: at most 20 points, a small body, and no paths or scan ids", async () => {
    store = createResultStore({
      dir: path.join(base, "pgard"),
      now: () => clock,
      maxScansPerRepo: 100,
    });
    // Start early enough that all 25 are dated before "now".
    clock = NOW - 40 * DAY;
    for (let index = 0; index < 25; index += 1) {
      await save(`scan-id-${index}`, [finding(`file-${index}`)]);
    }
    const running = await start();
    const response = await apiGet(running.server, "/api/trend");
    const trend = JSON.parse(response.body) as TrendResponse;
    if (trend.kind !== "ready") throw new Error("expected ready");
    expect(trend.points).toHaveLength(TREND_MAX_POINTS);
    expect(trend.unread).toBe(5);
    expect(response.body.length).toBeLessThan(16 * 1024);
    expect(response.body).not.toContain(base);
    expect(response.body).not.toContain("scan-id-");
    expect(response.body).not.toContain("src/");
    expect(response.body).not.toMatch(/\/(Users|home|tmp|private|var)\//);
    // The newest 20 are kept, oldest first.
    expect(trend.points.map((point) => point.savedAt)).toEqual(
      [...trend.points.map((point) => point.savedAt)].sort((a, b) => a - b),
    );
  });

  it("discards an answer read for a project that changed meanwhile", async () => {
    await save("a", [finding("a")]);
    let running: Harness | null = null;
    const racing = {
      list: async (id: number, options?: ListOptions) => {
        const listed = await store.list(id, options);
        // A new authorization (another project) lands while the files were being read.
        verify(running as Harness, 88);
        return listed;
      },
    } as unknown as ResultStore;
    running = await start({ open: () => racing });
    const response = await apiGet(running.server, "/api/trend");
    expect(response.status).toBe(409);
    expect(json(response)).toMatchObject({ error: { code: "project_changed" } });
  });
});
