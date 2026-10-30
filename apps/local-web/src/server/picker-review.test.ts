import { mkdirSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { PickerCandidate, PickerSearchResponse } from "../shared/picker-types.js";
import { shellQuoteHomePath } from "./picker/candidates.js";
import { runInspectorJob } from "./picker/inspect.js";
import type { ChildMessage } from "./picker/protocol.js";
import {
  createInspectorDeps,
  createRepo,
  createScopeTree,
  GITHUB_REMOTES,
  type ScopeTree,
} from "./picker/test-support/fixtures.js";
import { repoCandidate } from "./test-support/fake-inspector.js";
import {
  apiGet,
  apiPost,
  json,
  send,
  startHarness,
  SESSION,
  TOKEN,
  waitFor,
  type Harness,
} from "./test-support/web-harness.js";

let harness: Harness | null = null;
let tree: ScopeTree | null = null;
afterEach(async () => {
  await harness?.close();
  harness = null;
  tree?.cleanup();
  tree = null;
});

async function search(h: Harness, name: string): Promise<PickerSearchResponse> {
  h.clock.now += 2_000;
  const started = await apiPost(h.server, "/api/picker/search", {
    source: "typed",
    name,
    epoch: h.server.state.projectEpoch,
  });
  const { searchId } = json(started) as { searchId: string };
  return (await waitFor(
    async () => json(await apiGet(h.server, `/api/picker/search?id=${searchId}`)),
    (value) => value.status !== "running",
  )) as unknown as PickerSearchResponse;
}

describe("T11: invisible and look-alike characters are never shown as safe", () => {
  // One example of each class the shared display sanitizer does not strip.
  const classes: Array<[string, string]> = [
    ["word joiner U+2060", "sh⁠op"],
    ["invisible times U+2062", "sh⁢op"],
    ["soft hyphen U+00AD", "sh­op"],
    ["combining grapheme joiner U+034F", "sh͏op"],
    ["Hangul choseong filler U+115F", "shᅟop"],
    ["Hangul filler U+3164", "shㅤop"],
    ["Mongolian vowel separator U+180E", "sh᠎op"],
    ["variation selector U+FE0F", "sh️op"],
    ["variation selector supplement U+E0100", "sh\u{e0100}op"],
    ["tag character U+E0041", "sh\u{e0041}op"],
    ["zero width joiner U+200D", "sh‍op"],
    ["byte order mark U+FEFF", "sh﻿op"],
    ["private use U+E000", "shop"],
    ["Braille pattern blank U+2800", "sh\u2800op"],
    ["Hangul filler U+FFA0", "sh\uffa0op"],
    ["no-break space U+00A0", "sh\u00a0op"],
    ["ideographic space U+3000", "sh\u3000op"],
    ["en space U+2002", "sh\u2002op"],
  ];
  for (const [label, name] of classes) {
    it(`blocks ${label} as unsafe_display with an escaped form`, async () => {
      harness = await startHarness();
      harness.inspector.repos.set("target", [repoCandidate(name)]);
      const found = await search(harness, "target");
      const candidate = found.candidates[0] as PickerCandidate;
      expect(candidate.blocked?.code).toBe("unsafe_display");
      expect(candidate.selectable).toBe(false);
      expect(candidate.displayPathEscaped).toMatch(/\\u\{[0-9a-f]+\}/);
      const confirmed = await apiPost(harness.server, "/api/picker/confirm", {
        candidateId: candidate.candidateId,
        shown: candidate.shown,
        epoch: 1,
      });
      expect(confirmed.status).toBe(409);
    });
  }

  it("marks an NFC name and its NFD form as a collision with a tag each", async () => {
    harness = await startHarness();
    harness.inspector.repos.set("target", [
      repoCandidate("café", { ino: 400 }),
      repoCandidate("café", { ino: 500 }),
    ]);
    const found = await search(harness, "target");
    const tags = found.candidates.map((candidate) => candidate.collision?.tag);
    expect(tags[0]).toMatch(/^[0-9a-f]{6}$/);
    expect(tags[1]).toMatch(/^[0-9a-f]{6}$/);
    expect(tags[0]).not.toBe(tags[1]);
  });

  it("marks names that differ only by case as a collision too", async () => {
    harness = await startHarness();
    harness.inspector.repos.set("target", [
      repoCandidate("Shop", { ino: 400 }),
      repoCandidate("shop", { ino: 500 }),
    ]);
    const found = await search(harness, "target");
    expect(found.candidates.every((candidate) => candidate.collision !== null)).toBe(true);
  });
});

describe("the chmod fix command keeps ~ expandable", () => {
  it("emits ~/'...' instead of '~/...'", () => {
    expect(shellQuoteHomePath("~/my code")).toBe("~/'my code'");
    expect(shellQuoteHomePath("~/code")).toBe("~/code");
    expect(shellQuoteHomePath("~")).toBe("~");
    expect(shellQuoteHomePath("/opt/my dir")).toBe("'/opt/my dir'");
    expect(shellQuoteHomePath("~/it's")).toBe("~/'it'\\''s'");
  });

  it("is what the candidate shows", async () => {
    harness = await startHarness();
    harness.inspector.repos.set("target", [
      repoCandidate("target", {
        block: { code: "group_or_world_writable", paths: ["/home/u/code", "/home/u/code/my dir"] },
      }),
    ]);
    const found = await search(harness, "target");
    expect(found.candidates[0]?.blocked?.fix).toBe("chmod go-w ~/code ~/'code/my dir'");
  });
});

describe("inspector messages must answer what the walk reported", () => {
  it("ignores an inspection for an unknown key, a second one, or another chain, and caps found", async () => {
    harness = await startHarness();
    harness.inspector.mode = "manual";
    harness.clock.now += 2_000;
    const started = await apiPost(harness.server, "/api/picker/search", {
      source: "typed",
      name: "shop",
      epoch: 1,
    });
    const { searchId } = json(started) as { searchId: string };
    const run = harness.inspector.runs[0]!;
    const real = repoCandidate("shop", { ino: 100 });
    const forged = repoCandidate("forged", { ino: 900 });
    run.emit({ t: "found", key: 0, rootIndex: 0, segments: real.segments });
    // Not reported by the walk: dropped.
    run.emit({ t: "inspected", key: 7, candidate: forged });
    // Reported key, but another chain: dropped.
    run.emit({ t: "inspected", key: 0, candidate: forged });
    run.emit({ t: "inspected", key: 0, candidate: real });
    // A second answer for the same key: dropped.
    run.emit({
      t: "inspected",
      key: 0,
      candidate: { ...real, remote: { status: "github", owner: "evil", name: "x" } },
    });
    for (let key = 1; key < 40; key += 1) {
      run.emit({
        t: "found",
        key,
        rootIndex: 0,
        segments: repoCandidate(`n${key}`, { ino: 1_000 + key * 3 }).segments,
      });
    }
    run.emit({ t: "done", stoppedBy: null, elapsedMs: 1, visited: 1, skipped: [] });
    run.finish({ status: "finished" });
    const finished = (await waitFor(
      async () => json(await apiGet(harness!.server, `/api/picker/search?id=${searchId}`)),
      (value) => value.status !== "running",
    )) as unknown as PickerSearchResponse;
    expect(finished.candidates).toHaveLength(20);
    expect(finished.candidates[0]).toMatchObject({
      remote: { status: "github", repo: "acme/shop" },
      selectable: true,
    });
    expect(JSON.stringify(finished)).not.toContain("forged");
    expect(JSON.stringify(finished)).not.toContain("evil");
  });
});

describe("middleware matrix for POST /api/auth/cancel", () => {
  it("needs the token, our Host and Origin, JSON, and sends no CORS header", async () => {
    harness = await startHarness();
    const port = harness.server.port;
    const post = (headers: Record<string, string>, body = "{}") =>
      send(harness!.server, "POST", "/api/auth/cancel", { headers, body });
    const good = {
      "x-pgard-session": SESSION,
      origin: `http://127.0.0.1:${port}`,
      "content-type": "application/json",
    };
    const without = (key: string): Record<string, string> => {
      const copy = { ...good } as Record<string, string>;
      delete copy[key];
      return copy;
    };
    const cases: Array<[string, Awaited<ReturnType<typeof post>>, number]> = [
      ["no token", await post(without("x-pgard-session")), 401],
      ["wrong token", await post({ ...good, "x-pgard-session": "nope" }), 401],
      ["rebound host", await post({ ...good, host: `evil.example:${port}` }), 421],
      ["foreign origin", await post({ ...good, origin: "http://evil.example" }), 403],
      ["missing origin", await post(without("origin")), 403],
      ["cross-site", await post({ ...good, "sec-fetch-site": "cross-site" }), 403],
      ["wrong content type", await post({ ...good, "content-type": "text/plain" }), 415],
      ["too large", await post(good, JSON.stringify({ pad: "x".repeat(17 * 1024) })), 413],
      ["fine", await post(good), 200],
    ];
    for (const [label, response, status] of cases) {
      expect(response.status, label).toBe(status);
      expect(
        Object.keys(response.headers).some((key) => key.startsWith("access-control-")),
        label,
      ).toBe(false);
    }
  });
});

describe.skipIf(process.platform === "win32")("walk limits and recent rules", () => {
  async function recentOutcome(entryPath: string): Promise<string[]> {
    const { deps, messages } = createInspectorDeps();
    await runInspectorJob(deps, {
      kind: "recent",
      roots: [tree!.rootStat],
      entries: [{ entryId: "a".repeat(22), path: entryPath }],
    });
    return (messages as ChildMessage[]).flatMap((m) =>
      m.t === "recent" ? [m.outcome.status] : [],
    );
  }

  it("never reads a whole huge directory: it asks for one entry more than the cap", async () => {
    tree = createScopeTree();
    for (let index = 0; index < 8; index += 1) mkdirSync(path.join(tree.root, `d${index}`));
    const requested: Array<number | undefined> = [];
    const { deps, messages } = createInspectorDeps({
      limits: { maxEntriesPerDirectory: 3 },
      fs: {
        ...createInspectorDeps().deps.fs,
        readdir: async (target, limit) => {
          requested.push(limit);
          const all = await createInspectorDeps().deps.fs.readdir(target, limit);
          return all;
        },
      },
    });
    await runInspectorJob(deps, {
      kind: "search",
      roots: [tree.rootStat],
      name: "xx",
      source: "typed",
      platform: process.platform,
    });
    expect(requested[0]).toBe(4);
    const done = messages.find((m) => m.t === "done");
    expect(
      done?.t === "done" && done.skipped.some((entry) => entry.reason === "folder_too_large"),
    ).toBe(true);
  });

  it("revalidates a recent entry with the walk's rules: skip list, dot folders, nested repositories", async () => {
    tree = createScopeTree();
    createRepo(path.join(tree.root, "work", "shop"), { remotes: GITHUB_REMOTES });
    createRepo(path.join(tree.root, ".hidden", "shop"), { remotes: GITHUB_REMOTES });
    createRepo(path.join(tree.root, "node_modules", "shop"), { remotes: GITHUB_REMOTES });
    createRepo(path.join(tree.root, "outer"), { remotes: GITHUB_REMOTES });
    createRepo(path.join(tree.root, "outer", "vendor", "inner"), { remotes: GITHUB_REMOTES });
    createRepo(path.join(tree.root, "a", "b", "c", "d", "e", "deep"), { remotes: GITHUB_REMOTES });
    expect(await recentOutcome(path.join(tree.root, "work", "shop"))).toEqual(["candidate"]);
    expect(await recentOutcome(path.join(tree.root, ".hidden", "shop"))).toEqual(["outside_scope"]);
    expect(await recentOutcome(path.join(tree.root, "node_modules", "shop"))).toEqual([
      "outside_scope",
    ]);
    expect(await recentOutcome(path.join(tree.root, "outer", "vendor", "inner"))).toEqual([
      "outside_scope",
    ]);
    expect(await recentOutcome(path.join(tree.root, "a", "b", "c", "d", "e", "deep"))).toEqual([
      "outside_scope",
    ]);
  });
});
