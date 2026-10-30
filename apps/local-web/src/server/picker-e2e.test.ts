import { chmodSync, mkdirSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { runScan, verifyProject } from "@pgard/scan-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createMockGitHub,
  ME,
  ownerInstallation,
  sessionProvider,
  userRepository,
  type MockGitHubState,
} from "../../../../packages/policy/src/test-support/mock-github.js";
import type { PickerCandidate, PickerSearchResponse } from "../shared/picker-types.js";
import { createInspectorHost } from "./picker/inspector-host.js";
import { createRepo, createScopeTree, type ScopeTree } from "./picker/test-support/fixtures.js";
import {
  apiGet,
  apiPost,
  fakeDeps,
  json,
  startHarness,
  waitFor,
  type Harness,
  type RawResponse,
} from "./test-support/web-harness.js";

/**
 * End to end with the real inspector child process, real temporary repositories and the real
 * authorization gate and scan engine, with an in-memory GitHub (no real account, no network).
 */
const AUTHOR = { name: "Me Person", email: "me@example.com" };

let tree: ScopeTree;
let harness: Harness | null = null;
afterEach(async () => {
  await harness?.close();
  harness = null;
  tree?.cleanup();
  vi.restoreAllMocks();
});

interface GitHubWorld {
  state: MockGitHubState;
  sessions: number;
}

/** `ME` owns `me/<name>`, installed the App for it and has a commit in it. */
function allowedState(): MockGitHubState {
  return {
    user: ME,
    repository: userRepository({ fullName: "me/shop" }),
    installations: [ownerInstallation()],
    installationRepositories: { 77: [555] },
    pulls: {},
    commits: {},
    compare: {},
  };
}

async function start(world: GitHubWorld): Promise<Harness> {
  tree = createScopeTree();
  const { session } = createMockGitHub(world.state);
  const provider = sessionProvider(async () => {
    world.sessions += 1;
    return session;
  });
  harness = await startHarness({
    deps: {
      verifyProject,
      runScan,
      createSessionProvider: () => provider as never,
    },
    picker: {
      // The real inspector child process (the built `dist` copy when running from sources).
      inspector: createInspectorHost(),
      roots: [tree.rootStat],
      homeDir: path.dirname(tree.root),
      platform: process.platform,
    },
  });
  return harness;
}

async function search(h: Harness, name: string, source: "drop" | "typed" = "drop") {
  h.clock.now += 2_000;
  const started = await apiPost(h.server, "/api/picker/search", {
    source,
    name,
    epoch: h.server.state.projectEpoch,
  });
  expect(started.status).toBe(200);
  const { searchId } = json(started) as { searchId: string };
  const done = await waitFor(
    async () => json(await apiGet(h.server, `/api/picker/search?id=${searchId}`)),
    (value) => value.status !== "running",
    600,
  );
  return done as unknown as PickerSearchResponse;
}

const confirm = (h: Harness, candidate: PickerCandidate): Promise<RawResponse> =>
  apiPost(h.server, "/api/picker/confirm", {
    candidateId: candidate.candidateId,
    shown: candidate.shown,
    epoch: h.server.state.projectEpoch,
  });

async function runGate(h: Harness): Promise<Record<string, unknown>> {
  const started = await apiPost(h.server, "/api/auth/verify", {
    epoch: h.server.state.projectEpoch,
  });
  expect(started.status).toBe(200);
  return waitFor(
    async () => json(await apiGet(h.server, "/api/auth")),
    (value) => value.status !== "running",
    600,
  );
}

describe.skipIf(process.platform === "win32")("pgard web end to end", () => {
  it("picks a repository by name, confirms, passes the five checks, scans and downloads a report", async () => {
    const world: GitHubWorld = { state: allowedState(), sessions: 0 };
    const h = await start(world);
    const dir = createRepo(path.join(tree.root, "work", "shop"), {
      remotes: { origin: "https://github.com/me/shop.git" },
      author: AUTHOR,
    });
    writeFileSync(path.join(dir, "index.js"), "console.log('hello');\n");
    world.state.commits = {};
    // The contribution check needs a pull request or verified commit; a merged PR is simplest.
    const head = (await import("node:child_process"))
      .execFileSync("git", ["rev-parse", "HEAD"], {
        cwd: dir,
        encoding: "utf8",
        timeout: 60_000,
        killSignal: "SIGKILL",
      })
      .trim();
    world.state.pulls = {
      [head]: [
        {
          number: 1,
          userId: ME.id,
          mergedAt: "2026-10-01T00:00:00Z",
          baseRef: "main",
          baseRepositoryId: 555,
        },
      ],
    };
    world.state.compare = { [head]: "ahead" };

    const found = await search(h, "shop");
    expect(found.status).toBe("done");
    expect(found.candidates).toHaveLength(1);
    const candidate = found.candidates[0] as PickerCandidate;
    expect(candidate).toMatchObject({
      name: "shop",
      displayPath: "~/scope/work/shop",
      remote: { status: "github", repo: "me/shop" },
      selectable: true,
    });
    // Nothing happened on GitHub before the user confirmed.
    expect(world.sessions).toBe(0);
    expect((await confirm(h, candidate)).status).toBe(200);
    expect(world.sessions).toBe(0);

    const auth = await runGate(h);
    expect(auth.status).toBe("done");
    expect((auth.summary as { decision: string }).decision).toBe("allowed");

    await apiPost(h.server, "/api/scan", { scopes: ["code"], epoch: h.server.state.projectEpoch });
    const scan = await waitFor(
      async () => json(await apiGet(h.server, "/api/scan")),
      (value) => value.status !== "running",
      600,
    );
    expect(scan.status).toBe("done");
    expect((scan.result as { overallStatus: string }).overallStatus).toBe("completed");
    const report = await apiGet(h.server, "/api/reports/html");
    expect(report.status).toBe(200);
    expect(report.headers["content-disposition"]).toMatch(/pgard-report-me-shop-/);
    // The report and the scan result never carry the real path.
    expect(JSON.stringify(scan)).not.toContain(tree.root);
    expect(report.body).not.toContain(tree.root);
  }, 60_000);

  it("a private repository outside the App installation ends in the blocked current_access state with install guidance, and nothing is scanned", async () => {
    const world: GitHubWorld = {
      state: {
        user: ME,
        repository: null, // GitHub answers 404 for a private repository the App does not cover
        installations: [],
        installationRepositories: {},
        pulls: {},
        commits: {},
        compare: {},
        accounts: { me: { id: ME.id, login: "me", type: "User" } },
      },
      sessions: 0,
    };
    const h = await start(world);
    createRepo(path.join(tree.root, "private-app"), {
      remotes: { origin: "https://github.com/me/private-app.git" },
      author: AUTHOR,
    });
    const candidate = (await search(h, "private-app")).candidates[0] as PickerCandidate;
    expect((await confirm(h, candidate)).status).toBe(200);
    const auth = await runGate(h);
    const checks = (auth.summary as { checks: Array<{ id: string; status: string }> }).checks;
    expect(checks.find((check) => check.id === "current_access")?.status).toBe("failed");
    expect(auth.remedy).toMatchObject({ kind: "install_app" });

    await apiPost(h.server, "/api/scan", {
      scopes: ["code", "history"],
      epoch: h.server.state.projectEpoch,
    });
    const scan = await waitFor(
      async () => json(await apiGet(h.server, "/api/scan")),
      (value) => value.status !== "running",
      600,
    );
    const scanResult = scan.result as { overallStatus: string; findings: unknown[] };
    expect(scanResult.overallStatus).toBe("blocked");
    expect(scanResult.findings).toEqual([]);
    expect((await apiGet(h.server, "/api/reports/html")).status).toBe(409);
  }, 60_000);

  it("a repository with a non-github.com remote is blocked in the picker and never reaches authorization", async () => {
    const world: GitHubWorld = { state: allowedState(), sessions: 0 };
    const h = await start(world);
    createRepo(path.join(tree.root, "gitlab-app"), {
      remotes: { origin: "https://user:topsecret@gitlab.example.com/me/gitlab-app.git" },
    });
    const found = await search(h, "gitlab-app");
    const candidate = found.candidates[0] as PickerCandidate;
    expect(candidate).toMatchObject({
      selectable: false,
      remote: { status: "not_github" },
      blocked: { code: "remote_not_github" },
    });
    expect(JSON.stringify(found)).not.toContain("topsecret");
    expect(JSON.stringify(found)).not.toContain("gitlab.example.com");
    const refused = await confirm(h, candidate);
    expect(refused.status).toBe(409);
    expect((json(refused).error as { code: string }).code).toBe("candidate_blocked");
    expect(h.server.state.project).toBeNull();
    expect(world.sessions).toBe(0);
  }, 30_000);

  it("shows the other path and owner/name for the wrong one of two same-named folders, so the user can go back", async () => {
    const world: GitHubWorld = { state: allowedState(), sessions: 0 };
    const h = await start(world);
    createRepo(path.join(tree.root, "client-a", "app"), {
      remotes: { origin: "https://github.com/me/app-a.git" },
    });
    createRepo(path.join(tree.root, "client-b", "app"), {
      remotes: { origin: "https://github.com/me/app-b.git" },
    });
    const found = await search(h, "app");
    expect(found.candidates).toHaveLength(2);
    const byRepo = new Map(
      found.candidates.map((candidate) => [
        candidate.remote.status === "github" ? candidate.remote.repo : "",
        candidate,
      ]),
    );
    expect([...byRepo.keys()].sort()).toEqual(["me/app-a", "me/app-b"]);
    expect(byRepo.get("me/app-a")?.displayPath).toBe("~/scope/client-a/app");
    expect(byRepo.get("me/app-b")?.displayPath).toBe("~/scope/client-b/app");
    // The user sees the other path and repository, goes back (confirms nothing) and picks again.
    expect(h.server.state.project).toBeNull();
    const second = byRepo.get("me/app-b") as PickerCandidate;
    const confirmed = await confirm(h, second);
    expect(json(confirmed)).toMatchObject({ project: { name: "app", repo: "me/app-b" } });
    expect(h.server.state.project?.root).toBe(path.join(tree.root, "client-b", "app"));
  }, 30_000);

  it("stops a swapped directory before the scan starts (TOCTOU between confirm and scan)", async () => {
    const world: GitHubWorld = { state: allowedState(), sessions: 0 };
    const h = await start(world);
    createRepo(path.join(tree.root, "shop"), {
      remotes: { origin: "https://github.com/me/shop.git" },
    });
    const candidate = (await search(h, "shop")).candidates[0] as PickerCandidate;
    expect((await confirm(h, candidate)).status).toBe(200);
    // Swap the directory for another repository after the user confirmed. The old one stays, so the
    // new directory cannot reuse its inode number.
    renameSync(path.join(tree.root, "shop"), path.join(tree.root, "old-shop"));
    createRepo(path.join(tree.root, "shop"), {
      remotes: { origin: "https://github.com/evil/shop.git" },
    });
    const refused = await apiPost(h.server, "/api/scan", {
      scopes: ["code"],
      epoch: h.server.state.projectEpoch,
    });
    expect(refused.status).toBe(409);
    expect((json(refused).error as { code: string }).code).toBe("candidate_changed");
    expect(world.sessions).toBe(0);
    expect(h.server.state.scan.status).toBe("idle");
  }, 30_000);

  it("blocks at the gate when the remote is rewritten in place (same inodes): expectedRepo", async () => {
    const world: GitHubWorld = { state: allowedState(), sessions: 0 };
    const h = await start(world);
    const dir = createRepo(path.join(tree.root, "shop"), {
      remotes: { origin: "https://github.com/me/shop.git" },
      author: AUTHOR,
    });
    const candidate = (await search(h, "shop")).candidates[0] as PickerCandidate;
    expect((await confirm(h, candidate)).status).toBe(200);
    // Same directory, same .git, same .git/config inode: only the remote differs. The identity
    // re-check cannot see it; the gate must, before any GitHub call.
    writeFileSync(
      path.join(dir, ".git", "config"),
      '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://github.com/evil/shop.git\n',
    );
    const started = await apiPost(h.server, "/api/auth/verify", {
      epoch: h.server.state.projectEpoch,
    });
    expect(started.status).toBe(200);
    const auth = await waitFor(
      async () => json(await apiGet(h.server, "/api/auth")),
      (value) => value.status !== "running",
      600,
    );
    const checks = (
      auth.summary as { checks: Array<{ id: string; status: string; reason: string }> }
    ).checks;
    expect(checks[0]).toMatchObject({
      id: "repository",
      status: "failed",
      reason: "The repository changed since you confirmed it.",
    });
    expect((auth.summary as { decision: string }).decision).toBe("blocked");
    expect(world.sessions).toBe(0);
    await apiPost(h.server, "/api/scan", { scopes: ["code"], epoch: h.server.state.projectEpoch });
    const scan = await waitFor(
      async () => json(await apiGet(h.server, "/api/scan")),
      (value) => value.status !== "running",
      600,
    );
    expect((scan.result as { overallStatus: string }).overallStatus).toBe("blocked");
    expect(world.sessions).toBe(0);
  }, 30_000);

  it("never leaks the name, path, remote URL or token in any response, stdout or stderr (design test 16)", async () => {
    const world: GitHubWorld = { state: allowedState(), sessions: 0 };
    const h = await start(world);
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const consoleSpies = (["log", "info", "warn", "error", "debug"] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    );
    const secretName = "zq-distinct-9x";
    createRepo(path.join(tree.root, secretName), {
      remotes: { origin: "https://hunter2:secret-credential@leak-host.example.com/me/zq.git" },
    });
    // An fs error on a fixture: an unreadable folder in the scope.
    const locked = path.join(tree.root, "locked-dir");
    mkdirSync(locked);
    chmodSync(locked, 0o000);
    const responses: RawResponse[] = [];
    try {
      const found = await search(h, secretName);
      responses.push({ status: 200, headers: {}, body: JSON.stringify(found) });
      responses.push(await apiGet(h.server, "/api/picker/scope"));
      responses.push(await apiGet(h.server, "/api/picker/recent"));
      responses.push(await apiGet(h.server, "/api/session"));
      responses.push(
        await apiPost(h.server, "/api/picker/search", {
          source: "typed",
          name: secretName,
          epoch: 1,
        }),
      ); // search_too_soon
      responses.push(
        await apiPost(h.server, "/api/picker/search", {
          source: "typed",
          name: `${secretName}/x`,
          epoch: 1,
        }),
      ); // bad_name
      responses.push(await confirm(h, found.candidates[0] as PickerCandidate)); // candidate_blocked
      responses.push(
        await apiPost(h.server, "/api/picker/confirm", {
          candidateId: "zzzzzzzzzzzzzzzzzzzzzz",
          shown: secretName,
          epoch: 1,
        }),
      );
      const none = await search(h, "missing-zq-name");
      responses.push({ status: 200, headers: {}, body: JSON.stringify(none) });
    } finally {
      chmodSync(locked, 0o755);
    }
    const allowedKeys = new Set(["displayPath", "displayPathEscaped", "name", "repo"]);
    const strip = (value: unknown): unknown => {
      if (Array.isArray(value)) return value.map(strip);
      if (value !== null && typeof value === "object") {
        return Object.fromEntries(
          Object.entries(value)
            .filter(([key]) => !allowedKeys.has(key))
            .map(([key, inner]) => [key, strip(inner)]),
        );
      }
      return value;
    };
    const forbidden = [
      secretName,
      "missing-zq-name",
      tree.root,
      path.dirname(tree.root),
      "secret-credential",
      "hunter2",
      "leak-host.example.com",
      "origin",
      "https://",
      "test-token-0123456789abcdefghijklmnop",
    ];
    for (const response of responses) {
      const text = JSON.stringify(strip(JSON.parse(response.body)));
      for (const needle of forbidden) expect(text, needle).not.toContain(needle);
    }
    const allowed = JSON.stringify(responses[0]);
    expect(allowed).toContain(secretName); // in the fields meant to carry it
    expect(allowed).not.toContain("secret-credential");
    expect(allowed).not.toContain("leak-host.example.com");
    // Nothing was printed anywhere.
    for (const spy of [stdout, stderr, ...consoleSpies]) {
      for (const call of spy.mock.calls) {
        const text = String(call[0]);
        for (const needle of forbidden.slice(0, 7)) expect(text, needle).not.toContain(needle);
      }
    }
  }, 60_000);
});
