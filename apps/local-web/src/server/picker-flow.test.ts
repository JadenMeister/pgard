import { afterEach, describe, expect, it } from "vitest";
import type { AuthorizationOutcome, OwnerApprovalRemedy } from "@pgard/scan-core";
import { createInMemoryCredentialStore, type CredentialStore } from "@pgard/scan-core";
import type { PickerCandidate, PickerSearchResponse } from "../shared/picker-types.js";
import { repoCandidate } from "./test-support/fake-inspector.js";
import {
  apiGet,
  apiPost,
  fakeDeps,
  json,
  outcome,
  result,
  startHarness,
  waitFor,
  type Harness,
} from "./test-support/web-harness.js";

let harness: Harness | null = null;
afterEach(async () => {
  await harness?.close();
  harness = null;
});

const epochOf = (h: Harness): number => h.server.state.projectEpoch;

async function start(options: Parameters<typeof startHarness>[0] = {}): Promise<Harness> {
  harness = await startHarness(options);
  harness.inspector.repos.set("shop", [repoCandidate("shop")]);
  harness.inspector.repos.set("blog", [
    repoCandidate("blog", { repo: ["acme", "blog"], ino: 300 }),
  ]);
  return harness;
}

async function search(
  h: Harness,
  name: string,
  source: "drop" | "typed" = "typed",
): Promise<PickerSearchResponse & { searchId: string }> {
  h.clock.now += 2_000; // clear the one-search-per-second limit
  const started = await apiPost(h.server, "/api/picker/search", {
    source,
    name,
    epoch: epochOf(h),
  });
  expect(started.status).toBe(200);
  const { searchId } = json(started) as { searchId: string };
  const done = await waitFor(
    async () => json(await apiGet(h.server, `/api/picker/search?id=${searchId}`)),
    (value) => value.status !== "running",
  );
  return { ...(done as unknown as PickerSearchResponse), searchId };
}

async function confirm(
  h: Harness,
  candidate: PickerCandidate,
  overrides: Record<string, unknown> = {},
) {
  return apiPost(h.server, "/api/picker/confirm", {
    candidateId: candidate.candidateId,
    shown: candidate.shown,
    epoch: epochOf(h),
    ...overrides,
  });
}

async function select(h: Harness, name: string): Promise<PickerCandidate> {
  const found = await search(h, name);
  const candidate = found.candidates[0] as PickerCandidate;
  const confirmed = await confirm(h, candidate);
  expect(confirmed.status).toBe(200);
  return candidate;
}

describe("name validation through the API (design test 3)", () => {
  const bad: Array<[string, unknown, string]> = [
    ["an empty name", "", "typed"],
    ["one typed character", "a", "typed"],
    ["dot", ".", "drop"],
    ["dot dot", "..", "drop"],
    ["a path", "a/b", "typed"],
    ["NUL", "sh\0p", "typed"],
    ["a control character", "sh\u0001p", "typed"],
    ["a right-to-left override", "ab‮cd", "typed"],
    ["256 units", "x".repeat(256), "typed"],
    ["a lone surrogate", "ab\ud800cd", "typed"],
    ["a number", 7, "typed"],
  ];
  for (const [label, name, source] of bad) {
    it(`answers 400 bad_name for ${label}, saying why and what to do`, async () => {
      const h = await start();
      const response = await apiPost(h.server, "/api/picker/search", { source, name, epoch: 1 });
      expect(response.status).toBe(400);
      const error = json(response).error as { code: string; message: string };
      expect(error.code).toBe("bad_name");
      expect(error.message).toContain("Type or drop only the folder's own name, not a path.");
      expect(h.inspector.runs).toHaveLength(0);
    });
  }

  it("answers bad_source, bad_request and bad_id for malformed fields", async () => {
    const h = await start();
    const code = async (path: string, body: unknown): Promise<string> =>
      (json(await apiPost(h.server, path, body)).error as { code: string }).code;
    expect(await code("/api/picker/search", { source: "path", name: "shop", epoch: 1 })).toBe(
      "bad_source",
    );
    expect(await code("/api/picker/search", { source: "typed", name: "shop", epoch: 1.5 })).toBe(
      "bad_request",
    );
    expect(
      await code("/api/picker/search", { source: "typed", name: "shop", epoch: 2 ** 60 }),
    ).toBe("bad_request");
    expect(await code("/api/picker/search", [1, 2])).toBe("bad_request");
    expect(await code("/api/picker/search/cancel", { searchId: "short" })).toBe("bad_id");
    expect(await code("/api/picker/confirm", { candidateId: "a/../b", shown: "x", epoch: 1 })).toBe(
      "bad_id",
    );
    expect(await code("/api/picker/recent/remove", { entryId: 5 })).toBe("bad_id");
    expect(await code("/api/picker/scope/toggle", { rootId: "nope", enabled: true })).toBe(
      "bad_id",
    );
    expect(
      await code("/api/picker/scope/toggle", { rootId: "AAAAAAAAAAAAAAAAAAAAAA", enabled: "yes" }),
    ).toBe("bad_request");
    const get = await apiGet(h.server, "/api/picker/search?id=bad");
    expect((json(get).error as { code: string }).code).toBe("bad_id");
  });
});

describe("search", () => {
  it("returns candidates with the real path, owner/name and no URL or remote name", async () => {
    const h = await start();
    const found = await search(h, "shop");
    expect(found.status).toBe("done");
    expect(found.candidates).toHaveLength(1);
    const candidate = found.candidates[0] as PickerCandidate;
    expect(candidate).toMatchObject({
      name: "shop",
      displayPath: "~/code/shop",
      displayPathEscaped: null,
      collision: null,
      remote: { status: "github", repo: "acme/shop" },
      selectable: true,
      blocked: null,
      source: "scope",
    });
    expect(candidate.candidateId).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it("shows no match as an empty, finished search", async () => {
    const h = await start();
    const found = await search(h, "missing");
    expect(found).toMatchObject({ status: "done", candidates: [], uninspected: 0 });
  });

  it("shows blocked candidates with a fixed reason, fix and every failing path", async () => {
    const h = await start();
    h.inspector.repos.set("locked", [
      repoCandidate("locked", {
        block: {
          code: "group_or_world_writable",
          paths: ["/home/u/code", "/home/u/code/my dir/.git"],
        },
      }),
      repoCandidate("orphan", {
        remote: { status: "none" },
        block: { code: "no_remote", paths: [] },
      }),
    ]);
    const found = await search(h, "locked");
    const [locked, orphan] = found.candidates as [PickerCandidate, PickerCandidate];
    expect(locked.selectable).toBe(false);
    expect(locked.blocked).toMatchObject({
      code: "group_or_world_writable",
      paths: ["~/code", "~/code/my dir/.git"],
      fix: "chmod go-w ~/code ~/'code/my dir/.git'",
    });
    expect(orphan.blocked).toMatchObject({ code: "no_remote", paths: [] });
    expect(orphan.remote).toEqual({ status: "none" });
  });

  it("blocks a hostile name as unsafe_display with an escaped form, never the raw text", async () => {
    const h = await start();
    h.inspector.repos.set("evil", [
      repoCandidate("ev‮il\u0007", { parents: [] }),
      repoCandidate("x".repeat(500), { ino: 900 }),
    ]);
    const found = await search(h, "evil");
    for (const candidate of found.candidates) {
      expect(candidate.blocked?.code).toBe("unsafe_display");
      expect(candidate.selectable).toBe(false);
      expect(candidate.displayPathEscaped).not.toBeNull();
      expect(candidate.displayPath).not.toContain("‮");
      expect(candidate.displayPath).not.toContain("\u0007");
    }
    expect(found.candidates[0]?.displayPathEscaped).toContain("\\u{202e}");
    expect(found.candidates[1]?.displayPathEscaped).toMatch(/\(\d+ characters\)/);
  });

  it("marks two candidates with the same display path with a short tag from the fingerprint", async () => {
    const h = await start();
    h.inspector.repos.set("twin", [
      repoCandidate("twin", { ino: 400 }),
      { ...repoCandidate("twin", { ino: 500 }), segments: [{ name: "twin", dev: 1, ino: 501 }] },
    ]);
    const found = await search(h, "twin");
    const tags = found.candidates.map((candidate) => candidate.collision?.tag);
    expect(tags[0]).toMatch(/^[0-9a-f]{6}$/);
    expect(tags[1]).toMatch(/^[0-9a-f]{6}$/);
    expect(tags[0]).not.toBe(tags[1]);
  });

  it("allows one search at a time (a new one cancels the old) and one per second", async () => {
    const h = await start();
    h.inspector.mode = "manual";
    h.clock.now += 2_000;
    const first = json(
      await apiPost(h.server, "/api/picker/search", { source: "typed", name: "shop", epoch: 1 }),
    ) as { searchId: string };
    h.clock.now += 100;
    const tooSoon = await apiPost(h.server, "/api/picker/search", {
      source: "typed",
      name: "blog",
      epoch: 1,
    });
    expect(tooSoon.status).toBe(429);
    expect((json(tooSoon).error as { code: string }).code).toBe("search_too_soon");
    h.clock.now += 2_000;
    await apiPost(h.server, "/api/picker/search", { source: "typed", name: "blog", epoch: 1 });
    expect(h.inspector.runs[0]?.isCancelled).toBe(true);
    const old = json(await apiGet(h.server, `/api/picker/search?id=${first.searchId}`));
    expect(old.status).toBe("cancelled");
  });

  it("answers inspector_busy (503) when earlier children are stuck, and a clock that moved back counts as too soon", async () => {
    const h = await start();
    h.inspector.isBusy = true;
    h.clock.now += 2_000;
    const busy = await apiPost(h.server, "/api/picker/search", {
      source: "typed",
      name: "shop",
      epoch: 1,
    });
    expect(busy.status).toBe(503);
    expect((json(busy).error as { code: string }).code).toBe("inspector_busy");
    h.inspector.isBusy = false;
    h.clock.now += 2_000;
    expect(
      (await apiPost(h.server, "/api/picker/search", { source: "typed", name: "shop", epoch: 1 }))
        .status,
    ).toBe(200);
    h.clock.now -= 5_000;
    expect(
      (await apiPost(h.server, "/api/picker/search", { source: "typed", name: "shop", epoch: 1 }))
        .status,
    ).toBe(429);
  });

  it("cancels a running search, which is a no-op for finished or unknown searches", async () => {
    const h = await start();
    h.inspector.mode = "manual";
    h.clock.now += 2_000;
    const { searchId } = json(
      await apiPost(h.server, "/api/picker/search", { source: "typed", name: "shop", epoch: 1 }),
    ) as { searchId: string };
    const cancelled = await apiPost(h.server, "/api/picker/search/cancel", { searchId });
    expect(json(cancelled)).toEqual({ status: "cancelled" });
    expect(h.inspector.runs[0]?.isCancelled).toBe(true);
    expect((await apiPost(h.server, "/api/picker/search/cancel", { searchId })).status).toBe(200);
    expect(
      (await apiPost(h.server, "/api/picker/search/cancel", { searchId: "BBBBBBBBBBBBBBBBBBBBBB" }))
        .status,
    ).toBe(200);
  });

  it("answers partial with the real elapsed time and not-inspected cards, never dropping a folder silently", async () => {
    const h = await start();
    h.inspector.mode = "manual";
    h.clock.now += 2_000;
    const { searchId } = json(
      await apiPost(h.server, "/api/picker/search", { source: "typed", name: "shop", epoch: 1 }),
    ) as { searchId: string };
    const run = h.inspector.runs[0]!;
    const inspected = repoCandidate("shop-one");
    const pending = repoCandidate("shop-two", { ino: 700 });
    run.emit({ t: "found", key: 0, rootIndex: 0, segments: inspected.segments });
    run.emit({ t: "found", key: 1, rootIndex: 0, segments: pending.segments });
    run.emit({ t: "visited", n: 321 });
    run.emit({ t: "inspected", key: 0, candidate: inspected });
    run.finish({ status: "killed", reason: "deadline" });
    const finished = (await waitFor(
      async () => json(await apiGet(h.server, `/api/picker/search?id=${searchId}`)),
      (value) => value.status !== "running",
    )) as unknown as PickerSearchResponse;
    expect(finished).toMatchObject({
      status: "partial",
      stoppedAfterSeconds: 8,
      stoppedBy: "time",
      uninspected: 1,
      visited: 321,
    });
    expect(finished.candidates).toHaveLength(2);
    expect(finished.candidates[1]).toMatchObject({
      selectable: false,
      blocked: { code: "not_inspected" },
    });
  });

  it("reports the child's own early stop (entry limit, 20 candidates) as partial", async () => {
    const h = await start();
    h.inspector.mode = "manual";
    h.clock.now += 2_000;
    const { searchId } = json(
      await apiPost(h.server, "/api/picker/search", { source: "typed", name: "shop", epoch: 1 }),
    ) as { searchId: string };
    h.inspector.runs[0]?.emit({
      t: "done",
      stoppedBy: "entries",
      elapsedMs: 2_345,
      visited: 50_001,
      skipped: [{ reason: "symlink", count: 2 }],
    });
    h.inspector.runs[0]?.finish({ status: "finished" });
    const finished = (await waitFor(
      async () => json(await apiGet(h.server, `/api/picker/search?id=${searchId}`)),
      (value) => value.status !== "running",
    )) as unknown as PickerSearchResponse;
    expect(finished).toMatchObject({
      status: "partial",
      stoppedBy: "entries",
      stoppedAfterSeconds: 2.3,
      skipped: [{ reason: "symlink", count: 2 }],
    });
  });

  it("answers failed when the inspector breaks, and unknown_search for an unknown id", async () => {
    const h = await start();
    h.inspector.mode = "manual";
    h.clock.now += 2_000;
    const { searchId } = json(
      await apiPost(h.server, "/api/picker/search", { source: "typed", name: "shop", epoch: 1 }),
    ) as { searchId: string };
    h.inspector.runs[0]?.finish({ status: "failed" });
    await waitFor(
      async () => json(await apiGet(h.server, `/api/picker/search?id=${searchId}`)),
      (value) => value.status === "failed",
    );
    const unknown = await apiGet(h.server, "/api/picker/search?id=CCCCCCCCCCCCCCCCCCCCCC");
    expect(unknown.status).toBe(404);
    expect((json(unknown).error as { code: string }).code).toBe("unknown_search");
  });

  it("keeps at most 5 finished searches and 100 candidates", async () => {
    const h = await start();
    const ids: string[] = [];
    for (let index = 0; index < 7; index += 1) ids.push((await search(h, "shop")).searchId);
    expect((await apiGet(h.server, `/api/picker/search?id=${ids[0]}`)).status).toBe(404);
    expect((await apiGet(h.server, `/api/picker/search?id=${ids[6]}`)).status).toBe(200);
    h.inspector.repos.set(
      "many",
      Array.from({ length: 20 }, (_, index) =>
        repoCandidate(`many${index}`, { ino: 1_000 + index * 3 }),
      ),
    );
    for (let index = 0; index < 8; index += 1) await search(h, "many");
    expect(h.server.state.picker.candidates.size).toBeLessThanOrEqual(100);
  });

  it("lets the browser switch a search folder off for the session, but never add one", async () => {
    const h = await start();
    const scope = json(await apiGet(h.server, "/api/picker/scope")) as {
      roots: Array<{ id: string; label: string; enabled: boolean }>;
      addCommand: string;
    };
    expect(scope.roots).toEqual([
      { id: expect.stringMatching(/^[A-Za-z0-9_-]{22}$/), label: "~/code", enabled: true },
    ]);
    expect(scope.addCommand).toBe("pgard web scope add <folder>");
    const toggled = json(
      await apiPost(h.server, "/api/picker/scope/toggle", {
        rootId: scope.roots[0]?.id,
        enabled: false,
      }),
    ) as { roots: Array<{ enabled: boolean }> };
    expect(toggled.roots[0]?.enabled).toBe(false);
    // With the only folder off nothing is searched.
    const found = await search(h, "shop");
    expect(found.candidates).toEqual([]);
    expect(h.inspector.runs).toHaveLength(0);
    // The scope never accepts a path.
    const added = await apiPost(h.server, "/api/picker/scope/toggle", {
      rootId: "/etc",
      enabled: true,
    });
    expect(added.status).toBe(400);
    expect(JSON.stringify(json(await apiGet(h.server, "/api/picker/scope")))).not.toContain("/etc");
  });
});

describe("confirm (T7)", () => {
  const code = (response: Awaited<ReturnType<typeof apiPost>>): string =>
    (json(response).error as { code: string }).code;

  it("selects the project only after a fresh inspection that matches what was shown", async () => {
    const h = await start();
    const found = await search(h, "shop");
    const candidate = found.candidates[0] as PickerCandidate;
    const confirmed = await confirm(h, candidate);
    expect(json(confirmed)).toEqual({
      project: { name: "shop", repo: "acme/shop" },
      projectEpoch: 2,
    });
    expect(h.server.state.project?.root).toBe("/home/u/code/shop");
    const session = json(await apiGet(h.server, "/api/session"));
    expect(session).toMatchObject({
      mode: "picker",
      project: { name: "shop", repo: "acme/shop" },
      projectEpoch: 2,
    });
    // It re-inspected with the full job (Git checks included), not a cached answer.
    expect(h.inspector.runs.at(-1)?.job).toMatchObject({ kind: "inspect", mode: "full" });
  });

  it("does not run the authorization gate by itself", async () => {
    let verified = 0;
    const h = await start({
      deps: {
        verifyProject: async () => {
          verified += 1;
          return outcome();
        },
      },
    });
    await select(h, "shop");
    expect(verified).toBe(0);
    expect(h.server.state.auth.status).toBe("idle");
  });

  it("is idempotent: confirming the selected candidate again gives the same result", async () => {
    const h = await start();
    const candidate = await select(h, "shop");
    const again = await apiPost(h.server, "/api/picker/confirm", {
      candidateId: candidate.candidateId,
      shown: candidate.shown,
      epoch: 2,
    });
    expect(json(again)).toEqual({ project: { name: "shop", repo: "acme/shop" }, projectEpoch: 2 });
    expect(epochOf(h)).toBe(2);
  });

  it("refuses unknown, blocked, mismatching and expired candidates and selects nothing", async () => {
    const h = await start();
    h.inspector.repos.set("orphan", [
      repoCandidate("orphan", {
        remote: { status: "none" },
        block: { code: "no_remote", paths: [] },
      }),
    ]);
    const good = (await search(h, "shop")).candidates[0] as PickerCandidate;
    const blocked = (await search(h, "orphan")).candidates[0] as PickerCandidate;
    expect(
      code(
        await apiPost(h.server, "/api/picker/confirm", {
          candidateId: "DDDDDDDDDDDDDDDDDDDDDD",
          shown: "x",
          epoch: 1,
        }),
      ),
    ).toBe("unknown_candidate");
    const blockedResponse = await confirm(h, blocked);
    expect(blockedResponse.status).toBe(409);
    expect(code(blockedResponse)).toBe("candidate_blocked");
    expect(code(await confirm(h, good, { shown: "0".repeat(32) }))).toBe("candidate_changed");
    expect(h.server.state.project).toBeNull();
    // Expired: older than 10 minutes.
    h.clock.now += 10 * 60 * 1000 + 1;
    expect(code(await confirm(h, good))).toBe("candidate_expired");
    expect(h.server.state.project).toBeNull();
  });

  it("fails closed when the clock moved back before the candidate was made", async () => {
    const h = await start();
    const good = (await search(h, "shop")).candidates[0] as PickerCandidate;
    h.clock.now -= 60_000;
    expect(code(await confirm(h, good))).toBe("candidate_expired");
  });

  it("answers candidate_changed when the re-inspection differs from what the user saw", async () => {
    const h = await start();
    const good = (await search(h, "shop")).candidates[0] as PickerCandidate;
    // Another repository now has the folder.
    h.inspector.inspectOverride = (raw) => ({
      ...raw,
      remote: { status: "github", owner: "evil", name: "shop" },
    });
    expect(code(await confirm(h, good))).toBe("candidate_changed");
    // The identity of .git changed.
    h.inspector.inspectOverride = (raw) => ({
      ...raw,
      gitIdentity: { gitDev: 1, gitIno: 999, configDev: 1, configIno: 1 },
    });
    expect(code(await confirm(h, good))).toBe("candidate_changed");
    // The folder is gone or replaced (renamed, symlink, different directory).
    h.inspector.inspectOverride = null;
    h.inspector.inspectChanged = true;
    expect(code(await confirm(h, good))).toBe("candidate_changed");
    // It became unsafe (group-writable).
    h.inspector.inspectChanged = false;
    h.inspector.inspectOverride = (raw) => ({
      ...raw,
      block: { code: "group_or_world_writable", paths: ["/home/u/code"] },
    });
    expect(code(await confirm(h, good))).toBe("candidate_changed");
    expect(h.server.state.project).toBeNull();
  });

  it("answers unreadable (nothing selected) when the re-inspection could not finish in time", async () => {
    const h = await start();
    const good = (await search(h, "shop")).candidates[0] as PickerCandidate;
    h.inspector.mode = "manual";
    const pending = confirm(h, good);
    await waitFor(
      () => h.inspector.runs.length,
      (count) => count >= 2,
    );
    h.inspector.runs.at(-1)?.finish({ status: "killed", reason: "deadline" });
    const response = await pending;
    expect(response.status).toBe(409);
    expect(code(response)).toBe("unreadable");
    expect(h.server.state.project).toBeNull();
  });

  it("refuses while a scan runs (scan_running) or a check runs (auth_running)", async () => {
    const h = await start();
    await select(h, "shop");
    const other = (await search(h, "blog")).candidates[0] as PickerCandidate;
    h.server.state.scan.status = "running";
    expect(code(await confirm(h, other))).toBe("scan_running");
    h.server.state.scan.status = "idle";
    h.server.state.auth = { ...h.server.state.auth, status: "running" };
    expect(code(await confirm(h, other))).toBe("auth_running");
    h.server.state.auth = { ...h.server.state.auth, status: "idle" };
    h.server.state.ownerApprovalRecheck = true;
    expect(code(await confirm(h, other))).toBe("auth_running");
  });

  it("answers project_changed for a stale or missing epoch and when the project changes under the request", async () => {
    const h = await start();
    const good = (await search(h, "shop")).candidates[0] as PickerCandidate;
    expect(code(await confirm(h, good, { epoch: 7 }))).toBe("project_changed");
    expect(
      code(
        await apiPost(h.server, "/api/picker/confirm", {
          candidateId: good.candidateId,
          shown: good.shown,
        }),
      ),
    ).toBe("project_changed");
    expect(code(await confirm(h, good, { epoch: "2" }))).toBe("bad_request");
    // The project changes (another tab) while the re-inspection runs.
    h.inspector.mode = "manual";
    const pending = confirm(h, good);
    await waitFor(
      () => h.inspector.runs.length,
      (count) => count >= 1,
    );
    h.server.state.projectEpoch += 1;
    h.inspector.runs.at(-1)?.emit({
      t: "inspected",
      key: 0,
      candidate: { ...h.inspector.repos.get("shop")![0]!, rootIndex: 0 },
    });
    h.inspector.runs
      .at(-1)
      ?.emit({ t: "done", stoppedBy: null, elapsedMs: 1, visited: 0, skipped: [] });
    h.inspector.runs.at(-1)?.finish({ status: "finished" });
    const response = await pending;
    expect(code(response)).toBe("project_changed");
    expect(h.server.state.project).toBeNull();
  });
});

describe("state reset and in-flight work (T12, design test 11)", () => {
  async function authorized(h: Harness): Promise<void> {
    await apiPost(h.server, "/api/auth/verify", { epoch: epochOf(h) });
    await waitFor(
      async () => json(await apiGet(h.server, "/api/auth")),
      (value) => value.status === "done",
    );
  }

  it("answers no_project for project routes before the first confirm, while the others work", async () => {
    const h = await start();
    const needing: Array<[string, string, unknown?]> = [
      ["POST", "/api/auth/verify", { epoch: 1 }],
      ["POST", "/api/auth/owner-approval", { epoch: 1 }],
      ["GET", "/api/ports"],
      ["POST", "/api/ports/probe", { port: 3000, epoch: 1 }],
      ["POST", "/api/target/confirm", { port: 3000, isConfirmed: true, epoch: 1 }],
      ["POST", "/api/scan", { scopes: ["code"], epoch: 1 }],
      ["GET", "/api/reports/html"],
      ["GET", "/api/reports/pdf"],
    ];
    for (const [method, path, body] of needing) {
      const response =
        method === "GET" ? await apiGet(h.server, path) : await apiPost(h.server, path, body);
      expect(response.status, path).toBe(409);
      expect((json(response).error as { code: string }).code, path).toBe("no_project");
    }
    const working: Array<[string, string, unknown?]> = [
      ["GET", "/api/session"],
      ["GET", "/api/auth"],
      ["POST", "/api/auth/sign-out", {}],
      ["POST", "/api/auth/cancel", {}],
      ["GET", "/api/target"],
      ["POST", "/api/target/clear", {}],
      ["GET", "/api/scan"],
      ["POST", "/api/scan/cancel", {}],
      ["GET", "/api/rule-texts"],
    ];
    for (const [method, path, body] of working) {
      const response =
        method === "GET" ? await apiGet(h.server, path) : await apiPost(h.server, path, body);
      expect(response.status, path).toBe(200);
    }
    expect((await apiGet(h.server, "/api/nothing")).status).toBe(404);
    expect(json(await apiGet(h.server, "/api/session"))).toMatchObject({
      project: null,
      mode: "picker",
      projectEpoch: 1,
    });
  });

  it("clears authorization, target, probe, scan and report when another project is confirmed", async () => {
    const h = await start({ deps: { runScan: async () => result() } });
    await select(h, "shop");
    await authorized(h);
    await apiPost(h.server, "/api/ports/probe", { port: 3000, epoch: epochOf(h) });
    await apiPost(h.server, "/api/target/confirm", {
      port: 3000,
      isConfirmed: true,
      epoch: epochOf(h),
    });
    await apiPost(h.server, "/api/scan", { scopes: ["code"], epoch: epochOf(h) });
    await waitFor(
      async () => json(await apiGet(h.server, "/api/scan")),
      (value) => value.status === "done",
    );
    expect((await apiGet(h.server, "/api/reports/html")).status).toBe(200);
    expect(json(await apiGet(h.server, "/api/target"))).not.toBeNull();

    await select(h, "blog");
    expect(h.server.state.project?.repo).toEqual({ owner: "acme", name: "blog" });
    expect(json(await apiGet(h.server, "/api/auth")).status).toBe("idle");
    expect(json(await apiGet(h.server, "/api/target"))).toBeNull();
    expect(json(await apiGet(h.server, "/api/scan"))).toMatchObject({
      status: "idle",
      result: null,
    });
    expect(h.server.state.lastProbe).toBeNull();
    const report = await apiGet(h.server, "/api/reports/html");
    expect(report.status).toBe(409);
    // A stale epoch from the old view is refused.
    const stale = await apiPost(h.server, "/api/scan", { scopes: ["code"], epoch: 2 });
    expect(stale.status).toBe(409);
    expect((json(stale).error as { code: string }).code).toBe("project_changed");
  });

  it("clears back to no project, refused while a scan or check runs", async () => {
    const h = await start();
    await select(h, "shop");
    h.server.state.scan.status = "running";
    const refused = await apiPost(h.server, "/api/picker/clear", { epoch: 2 });
    expect((json(refused).error as { code: string }).code).toBe("scan_running");
    h.server.state.scan.status = "idle";
    const cleared = await apiPost(h.server, "/api/picker/clear", { epoch: 2 });
    expect(json(cleared)).toEqual({ projectEpoch: 3 });
    expect(h.server.state.project).toBeNull();
    expect((await apiPost(h.server, "/api/picker/clear", { epoch: 2 })).status).toBe(409);
  });

  it("cancels a check that waits for the GitHub sign-in, after which a confirm succeeds", async () => {
    let signal: AbortSignal | undefined;
    const h = await start({
      deps: {
        verifyProject: (_root, deps) =>
          new Promise<AuthorizationOutcome>(() => {
            signal = deps.signal; // never resolves, like a device flow nobody answers
          }),
      },
    });
    await select(h, "shop");
    await apiPost(h.server, "/api/auth/verify", { epoch: epochOf(h) });
    expect(json(await apiGet(h.server, "/api/auth")).status).toBe("running");
    const other = (await search(h, "blog")).candidates[0] as PickerCandidate;
    expect((json(await confirm(h, other)).error as { code: string }).code).toBe("auth_running");
    const cancelled = await apiPost(h.server, "/api/auth/cancel", {});
    expect(cancelled.status).toBe(200);
    expect(json(cancelled).status).toBe("idle");
    expect(signal?.aborted).toBe(true);
    expect((await confirm(h, other)).status).toBe(200);
    // With nothing running it is a 200 no-op.
    const noop = await apiPost(h.server, "/api/auth/cancel", {});
    expect(noop.status).toBe(200);
    expect(json(noop).status).toBe("idle");
  });

  /** A dependency released by the test, so the handler is in flight when the project changes. */
  function deferred<T>() {
    let release: (value: T) => void = () => undefined;
    const promise = new Promise<T>((resolve) => {
      release = resolve;
    });
    return { promise, release };
  }

  function changeProject(h: Harness): void {
    // A direct state change, as another tab would cause (the routes refuse it while work runs).
    h.server.state.project = { ...h.server.state.project!, root: "/home/u/code/blog" };
    h.server.state.projectEpoch += 1;
  }

  it("discards a verify that finishes after the project changed", async () => {
    const gate = deferred<AuthorizationOutcome>();
    const h = await start({ deps: { verifyProject: () => gate.promise } });
    await select(h, "shop");
    await apiPost(h.server, "/api/auth/verify", { epoch: epochOf(h) });
    changeProject(h);
    gate.release(outcome());
    await waitFor(
      () => h.server.state.auth.status,
      (status) => status !== "running",
    );
    expect(h.server.state.auth.status).toBe("idle");
    expect(h.server.state.auth.outcome).toBeNull();
  });

  it("discards a scan that finishes after the project changed", async () => {
    const gate = deferred<ReturnType<typeof result>>();
    const h = await start({ deps: { runScan: () => gate.promise } });
    await select(h, "shop");
    await authorized(h);
    await apiPost(h.server, "/api/scan", { scopes: ["code"], epoch: epochOf(h) });
    changeProject(h);
    gate.release(result());
    await waitFor(
      () => h.server.state.scan.status,
      (status) => status !== "running",
    );
    expect(h.server.state.scan.result).toBeNull();
  });

  it("answers project_changed for an owner-approval re-check that returns after the project changed", async () => {
    const gate = deferred<{ status: "failed"; reason: string; remedy: null }>();
    const install: AuthorizationOutcome = {
      ...outcome("owner_approval"),
      remedy: {
        kind: "install_app",
        missing: "installation",
        account: { login: "me", type: "User" },
        url: "https://github.com/apps/pgard/installations/new",
        canApprove: "yes",
        unavailableReason: null,
      } satisfies OwnerApprovalRemedy,
    };
    const h = await start({
      deps: { verifyProject: async () => install, recheckOwnerApproval: () => gate.promise },
    });
    await select(h, "shop");
    await authorized(h);
    const pending = apiPost(h.server, "/api/auth/owner-approval", { epoch: epochOf(h) });
    await waitFor(() => h.server.state.ownerApprovalRecheck, Boolean);
    changeProject(h);
    gate.release({ status: "failed", reason: "x", remedy: null });
    const response = await pending;
    expect(response.status).toBe(409);
    expect((json(response).error as { code: string }).code).toBe("project_changed");
  });

  it("answers project_changed for a probe, a target confirmation and a report render that finish after the project changed", async () => {
    const identity =
      deferred<Awaited<ReturnType<ReturnType<typeof fakeDeps>["probeLocalService"]>>>();
    const report = deferred<string>();
    const h = await start({
      deps: {
        probeLocalService: () => identity.promise,
        renderReport: (async () => report.promise) as never,
        runScan: async () => result(),
      },
    });
    await select(h, "shop");
    await authorized(h);
    const probe = apiPost(h.server, "/api/ports/probe", { port: 3000, epoch: epochOf(h) });
    await waitFor(() => Promise.resolve(true), Boolean);
    await new Promise((resolve) => setTimeout(resolve, 20));
    changeProject(h);
    identity.release({
      port: 3000,
      url: "http://127.0.0.1:3000/",
      status: 200,
      title: "t",
      inferredTechnologies: [],
      isHttp: true,
      redirectStop: null,
      error: null,
    });
    const probed = await probe;
    expect((json(probed).error as { code: string }).code).toBe("project_changed");
    expect(h.server.state.lastProbe).toBeNull();
    // A report render started under the old project.
    h.server.state.scan.result = result();
    const render = apiGet(h.server, "/api/reports/html");
    await new Promise((resolve) => setTimeout(resolve, 20));
    changeProject(h);
    report.release("<html></html>");
    const rendered = await render;
    expect(rendered.status).toBe(409);
    expect((json(rendered).error as { code: string }).code).toBe("project_changed");
  });

  it("answers project_changed for a target confirmation whose credential read finishes after the project changed", async () => {
    const gate = deferred<void>();
    const store: CredentialStore = createInMemoryCredentialStore();
    const slow: CredentialStore = {
      ...store,
      get: async (key: Parameters<CredentialStore["get"]>[0]) => {
        await gate.promise;
        return store.get(key);
      },
    } as CredentialStore;
    const h = await start({ deps: { credentialStore: slow } });
    await select(h, "shop");
    // Let the confirmation reach its first await, then change the project and release it.
    h.server.state.auth = {
      status: "done",
      outcome: outcome(),
      finishedAt: h.clock.now,
      message: null,
    };
    // The keychain is only read when an account was recorded for the check.
    h.server.state.authAccount = { login: "me", userId: 1 };
    const pending = apiPost(h.server, "/api/target/confirm", {
      port: 3000,
      isConfirmed: true,
      epoch: epochOf(h),
    });
    await new Promise((resolve) => setTimeout(resolve, 20));
    changeProject(h);
    gate.release();
    const response = await pending;
    expect((json(response).error as { code: string }).code).toBe("project_changed");
  });

  it("discards a search that completes after the project changed", async () => {
    const h = await start();
    h.inspector.mode = "manual";
    h.clock.now += 2_000;
    const { searchId } = json(
      await apiPost(h.server, "/api/picker/search", { source: "typed", name: "shop", epoch: 1 }),
    ) as { searchId: string };
    h.server.state.projectEpoch += 1;
    h.inspector.runs[0]?.finish({ status: "finished" });
    const finished = await waitFor(
      async () => json(await apiGet(h.server, `/api/picker/search?id=${searchId}`)),
      (value) => value.status !== "running",
    );
    expect(finished.status).toBe("cancelled");
    expect(finished.candidates).toEqual([]);
  });
});

describe("identity re-check before every run (T7)", () => {
  async function selected(): Promise<{ h: Harness; calls: string[] }> {
    const calls: string[] = [];
    const h = await start({
      deps: {
        verifyProject: async (_root, deps) => {
          calls.push(`verify:${JSON.stringify(deps.expectedRepo)}`);
          return outcome(null, { repositoryId: 4242 });
        },
        runScan: async (request) => {
          calls.push(`scan:${JSON.stringify(request.expectedRepo)}`);
          return result();
        },
      },
    });
    await select(h, "shop");
    return { h, calls };
  }

  it("passes the confirmed owner/name to the gate and pins the numeric id once known", async () => {
    const { h, calls } = await selected();
    await apiPost(h.server, "/api/auth/verify", { epoch: epochOf(h) });
    await waitFor(
      async () => json(await apiGet(h.server, "/api/auth")),
      (value) => value.status === "done",
    );
    await apiPost(h.server, "/api/scan", { scopes: ["code"], epoch: epochOf(h) });
    await waitFor(
      async () => json(await apiGet(h.server, "/api/scan")),
      (value) => value.status === "done",
    );
    expect(calls[0]).toBe('verify:{"owner":"acme","name":"shop","repositoryId":null}');
    expect(calls[1]).toBe('scan:{"owner":"acme","name":"shop","repositoryId":4242}');
  });

  const runs: Array<[string, string, unknown]> = [
    ["verify", "/api/auth/verify", {}],
    ["scan", "/api/scan", { scopes: ["code"] }],
  ];
  for (const [label, path, body] of runs) {
    it(`refuses a ${label} when the folder changed after the confirm (nothing starts)`, async () => {
      const { h, calls } = await selected();
      h.inspector.inspectChanged = true;
      const response = await apiPost(h.server, path, { ...(body as object), epoch: epochOf(h) });
      expect(response.status).toBe(409);
      expect((json(response).error as { code: string }).code).toBe("candidate_changed");
      expect(calls).toEqual([]);
      expect(h.server.state.auth.status).toBe("idle");
      expect(h.server.state.scan.status).toBe("idle");
      // Re-checks run with the short budget and without Git.
      expect(h.inspector.runs.at(-1)).toMatchObject({
        job: { kind: "inspect", mode: "recheck" },
        options: { hardMs: 2_000 },
      });
    });

    it(`refuses a ${label} when ownership or write bits changed`, async () => {
      const { h, calls } = await selected();
      h.inspector.inspectOverride = (raw) => ({
        ...raw,
        block: { code: "not_owned_by_you", paths: ["/home/u/code"] },
      });
      const response = await apiPost(h.server, path, { ...(body as object), epoch: epochOf(h) });
      expect((json(response).error as { code: string }).code).toBe("candidate_changed");
      expect(calls).toEqual([]);
    });

    it(`answers unreadable for a ${label} when the re-check cannot finish in time`, async () => {
      const { h, calls } = await selected();
      h.inspector.mode = "manual";
      const pending = apiPost(h.server, path, { ...(body as object), epoch: epochOf(h) });
      await waitFor(
        () => h.inspector.runs.length,
        (count) => count >= 3,
      );
      h.inspector.runs.at(-1)?.finish({ status: "killed", reason: "deadline" });
      const response = await pending;
      expect((json(response).error as { code: string }).code).toBe("unreadable");
      expect(calls).toEqual([]);
    });
  }

  it("refuses an owner-approval re-check when the folder changed", async () => {
    const install: AuthorizationOutcome = {
      ...outcome("owner_approval"),
      remedy: {
        kind: "install_app",
        missing: "installation",
        account: { login: "me", type: "User" },
        url: "https://github.com/apps/pgard/installations/new",
        canApprove: "yes",
        unavailableReason: null,
      },
    };
    let rechecks = 0;
    const h = await start({
      deps: {
        verifyProject: async () => install,
        recheckOwnerApproval: async () => {
          rechecks += 1;
          return { status: "failed", reason: "x", remedy: null };
        },
      },
    });
    await select(h, "shop");
    await apiPost(h.server, "/api/auth/verify", { epoch: epochOf(h) });
    await waitFor(
      async () => json(await apiGet(h.server, "/api/auth")),
      (value) => value.status === "done",
    );
    h.inspector.inspectChanged = true;
    const response = await apiPost(h.server, "/api/auth/owner-approval", { epoch: epochOf(h) });
    expect((json(response).error as { code: string }).code).toBe("candidate_changed");
    expect(rechecks).toBe(0);
    expect(h.server.state.ownerApprovalRecheck).toBe(false);
  });
});

describe("fixed mode keeps today's behavior", () => {
  it("needs no epoch and sends no expected repository to the gate", async () => {
    let seen: unknown = "unset";
    const h = await start({
      fixedRoot: "/work/my-project",
      deps: {
        verifyProject: async (_root, deps) => {
          seen = deps.expectedRepo;
          return outcome();
        },
      },
    });
    const verify = await apiPost(h.server, "/api/auth/verify", {});
    expect(verify.status).toBe(200);
    await waitFor(
      async () => json(await apiGet(h.server, "/api/auth")),
      (value) => value.status === "done",
    );
    expect(seen).toBeUndefined();
    expect(h.inspector.runs).toHaveLength(0);
  });
});
