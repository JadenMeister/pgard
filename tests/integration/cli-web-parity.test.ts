/**
 * Integration: the CLI and the local web dashboard must produce the same ScanResult for the same
 * repository. Both frontends run the real scan-core pipeline (real authorization gate, real
 * source and history analyzers) against a throwaway Git repository. GitHub is replaced by the
 * policy package's in-memory mock; nothing here touches the network.
 */
import http from "node:http";
import type { ScanResult } from "@pgard/findings";
import type { GitHubSessionProvider } from "@pgard/github-auth";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createDefaultDeps, main, type CliDeps } from "../../apps/cli/src/app.js";
import { exitCodeForStatus } from "../../apps/cli/src/exit-codes.js";
import { createTestIo, noInterrupts } from "../../apps/cli/src/test-support.js";
import {
  createDefaultServerDeps,
  startLocalWebServer,
  type LocalWebServer,
  type ServerDeps,
} from "../../apps/local-web/src/server/create-server.js";
import {
  createGitFixture,
  type GitFixture,
} from "../../packages/git-history/src/test-support/git-fixture.js";
import {
  ME,
  createMockGitHub,
  ownerInstallation,
  userRepository,
  type MockGitHubState,
} from "../../packages/policy/src/test-support/mock-github.js";

const TOKEN = "parity-token-0123456789abcdefghijklmnop";
const FIXED_NOW = new Date("2026-10-24T12:00:00.000Z");
const FIXED_SCAN_ID = "scan-parity-0001";
const ENV: Record<string, string> = {};

// Runtime-assembled fake values so nothing secret-looking is committed to this repository.
const join = (...parts: string[]) => parts.join("");
const REMOVED_TOKEN = join("ghp", "_", "R3mOv3dT0k3n", "AbCdEfGhIjKl", "MnOpQrStUvWxYz");
const SQL_VULN =
  'import { Pool } from "pg";\nconst pool = new Pool();\nexport const q = (req) => pool.query(`SELECT * FROM t WHERE id = ${req.query.id}`);\n';
const LOCKFILE = JSON.stringify(
  {
    name: "app",
    version: "1.0.0",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": { name: "app", version: "1.0.0", dependencies: { pg: "8.11.0" } },
      "node_modules/pg": { version: "8.11.0" },
    },
  },
  null,
  2,
);

type ScanFn = ServerDeps["runScan"];

let fixture: GitFixture | null = null;
let server: LocalWebServer | null = null;
let fetchSpy: ReturnType<typeof vi.fn>;

beforeEach(() => {
  // Any real network call (e.g. a device flow reaching GitHub) fails the test.
  fetchSpy = vi.fn(async () => {
    throw new Error("network access is not allowed in this test");
  });
  vi.stubGlobal("fetch", fetchSpy);
});

afterEach(async () => {
  vi.unstubAllGlobals();
  await server?.close();
  server = null;
  fixture?.cleanup();
  fixture = null;
});

/**
 * Repository `me/app` with a SQL-injection pattern in the working tree, a lockfile, and a GitHub
 * token that was committed and then removed (only the history scan can still see it).
 */
function createProject(): { root: string; head: string } {
  fixture = createGitFixture({ remotes: { origin: "git@github.com:me/app.git" } });
  const me = { authorName: ME.name ?? "Me Person", authorEmail: ME.email ?? "me@example.com" };
  fixture.commit({
    ...me,
    files: {
      "src/db.ts": SQL_VULN,
      "package.json": '{ "name": "app", "version": "1.0.0", "dependencies": { "pg": "8.11.0" } }\n',
      "package-lock.json": `${LOCKFILE}\n`,
      "deploy.sh": `export GH="${REMOVED_TOKEN}"\n`,
    },
  });
  const head = fixture.commit({ ...me, remove: ["deploy.sh"], files: {} });
  return { root: fixture.root, head };
}

/** GitHub state under which the real gate allows the scan (owner, approved, verified commit). */
function allowedState(head: string): MockGitHubState {
  return {
    user: ME,
    repository: userRepository(),
    installations: [ownerInstallation()],
    installationRepositories: { 77: [555] },
    pulls: {},
    commits: { [head]: { sha: head, authorId: ME.id, committerId: ME.id, isVerified: true } },
    compare: { [head]: "identical" },
  };
}

/** Same as allowed, but the owner never installed the PGARD GitHub App. */
function deniedState(head: string): MockGitHubState {
  return { ...allowedState(head), installations: [] };
}

/** A session provider backed by the in-memory mock; each frontend gets its own instance. */
function mockSessionProvider(state: MockGitHubState): {
  provider: GitHubSessionProvider;
  calls: string[];
} {
  const { session, calls } = createMockGitHub(state);
  const provider = Object.assign(async () => session, {
    invalidate: () => undefined,
    signOut: () => undefined,
  });
  return { provider, calls };
}

/**
 * Wraps the real runScan: records the result the frontend received and pins the clock and scan
 * id (frontend-supplied values would still win, so this cannot hide a frontend difference).
 */
function recordingRunScan(real: ScanFn): { runScan: ScanFn; results: ScanResult[] } {
  const results: ScanResult[] = [];
  const runScan: ScanFn = async (request, deps) => {
    const result = await real(request, {
      now: () => FIXED_NOW,
      createScanId: () => FIXED_SCAN_ID,
      ...deps,
    });
    results.push(result);
    return result;
  };
  return { runScan, results };
}

type SessionFactory = CliDeps["createSessionProvider"] | null;

async function scanWithCli(
  root: string,
  createSessionProvider: SessionFactory,
): Promise<{ result: ScanResult; exitCode: number; stdout: string }> {
  const defaults = createDefaultDeps();
  const recorder = recordingRunScan(defaults.runScan);
  const deps: CliDeps = {
    ...defaults,
    runScan: recorder.runScan,
    ...(createSessionProvider === null ? {} : { createSessionProvider }),
  };
  const captured = createTestIo({ cwd: root, env: ENV });
  const exitCode = await main(["scan"], captured.io, { deps, interrupts: noInterrupts });
  expect(recorder.results).toHaveLength(1);
  return { result: recorder.results[0]!, exitCode, stdout: captured.stdout() };
}

function request(
  port: number,
  method: string,
  urlPath: string,
  body?: unknown,
): Promise<{ status: number; json: unknown }> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path: urlPath,
        headers: {
          host: `127.0.0.1:${port}`,
          "x-pgard-token": TOKEN,
          ...(method === "GET"
            ? {}
            : { origin: `http://127.0.0.1:${port}`, "content-type": "application/json" }),
        },
      },
      (res) => {
        let text = "";
        res.on("data", (chunk: Buffer) => (text += chunk.toString()));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, json: JSON.parse(text) }));
      },
    );
    req.on("error", reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

async function scanWithWeb(
  root: string,
  createSessionProvider: SessionFactory,
): Promise<{ result: ScanResult; received: ScanResult }> {
  const defaults = createDefaultServerDeps();
  const recorder = recordingRunScan(defaults.runScan);
  const deps: ServerDeps = {
    ...defaults,
    runScan: recorder.runScan,
    ...(createSessionProvider === null ? {} : { createSessionProvider }),
  };
  server = await startLocalWebServer({
    projectRoot: root,
    presetTargetPort: null,
    env: ENV,
    assets: new Map(),
    deps,
    token: TOKEN,
  });
  const started = await request(server.port, "POST", "/api/scan", { scopes: ["code", "history"] });
  expect(started.status).toBe(200);

  const deadline = Date.now() + 20_000;
  for (;;) {
    const polled = await request(server.port, "GET", "/api/scan");
    expect(polled.status).toBe(200);
    const status = polled.json as { status: string; result: ScanResult | null };
    if (status.status !== "running") {
      expect(status.status).toBe("done");
      expect(status.result).not.toBeNull();
      expect(recorder.results).toHaveLength(1);
      // `result` is what the browser sees over the API; `received` is what the server got.
      return { result: status.result!, received: recorder.results[0]! };
    }
    if (Date.now() > deadline) throw new Error("web scan did not finish in time");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

/** The ScanResult as JSON, without the per-run fields the contract allows to differ. */
function comparable(result: ScanResult): unknown {
  const { scanId: _scanId, startedAt: _startedAt, finishedAt: _finishedAt, ...rest } = result;
  return JSON.parse(JSON.stringify(rest)) as unknown;
}

describe("CLI and local web parity", () => {
  it("produce the same ScanResult for an allowed code + history scan", async () => {
    const { root, head } = createProject();
    const cliGitHub = mockSessionProvider(allowedState(head));
    const webGitHub = mockSessionProvider(allowedState(head));

    const cli = await scanWithCli(root, () => cliGitHub.provider);
    const web = await scanWithWeb(root, () => webGitHub.provider);

    // The scan really ran: allowed by the real gate, with code and history findings.
    expect(cli.result.authorization.decision).toBe("allowed");
    expect(cli.result.target).toEqual({ repo: "me/app", revision: head, webOrigin: null });
    expect(cli.result.requestedScopes).toEqual(["code", "history"]);
    const ruleIds = cli.result.findings.map((finding) => finding.ruleId);
    expect(ruleIds.some((id) => id.startsWith("PG-SQL"))).toBe(true);
    expect(ruleIds).toContain("PG-SECRET-003");
    expect(JSON.stringify(cli.result)).not.toContain(REMOVED_TOKEN);
    expect(JSON.stringify(cli.result)).not.toContain(root);
    // Dependency advisories are not available in every build, which makes the scan "partial".
    expect(["completed", "partial"]).toContain(cli.result.overallStatus);
    expect(cli.exitCode).toBe(exitCodeForStatus(cli.result.overallStatus));

    expect(comparable(web.result)).toEqual(comparable(cli.result));
    // With the clock and id pinned, the whole document matches, and the API returns it unchanged.
    expect(web.result).toEqual(JSON.parse(JSON.stringify(cli.result)));
    expect(web.result).toEqual(JSON.parse(JSON.stringify(web.received)));

    // Both frontends asked GitHub the same questions.
    expect(webGitHub.calls).toEqual(cliGitHub.calls);
    expect(cliGitHub.calls.length).toBeGreaterThan(0);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("produce the same blocked result when the gate denies the scan", async () => {
    const { root, head } = createProject();
    const cliGitHub = mockSessionProvider(deniedState(head));
    const webGitHub = mockSessionProvider(deniedState(head));

    const cli = await scanWithCli(root, () => cliGitHub.provider);
    const web = await scanWithWeb(root, () => webGitHub.provider);

    expect(cli.result.overallStatus).toBe("blocked");
    expect(cli.result.authorization.decision).toBe("blocked");
    expect(
      cli.result.authorization.checks.find((check) => check.id === "owner_approval")?.status,
    ).toBe("failed");
    expect(cli.result.findings).toEqual([]);
    expect(cli.exitCode).toBe(3);

    expect(comparable(web.result)).toEqual(comparable(cli.result));
    expect(web.result).toEqual(JSON.parse(JSON.stringify(cli.result)));
    expect(webGitHub.calls).toEqual(cliGitHub.calls);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("produce the same blocked result with the real sign-in when no GitHub App is configured", async () => {
    const { root } = createProject();

    // Default deps: the real device-flow provider, which refuses without a client id.
    const cli = await scanWithCli(root, null);
    const web = await scanWithWeb(root, null);

    expect(cli.result.overallStatus).toBe("blocked");
    const identity = cli.result.authorization.checks.find(
      (check) => check.id === "github_identity",
    );
    expect(identity?.status).not.toBe("passed");
    expect(identity?.reason).toContain("PGARD_GITHUB_APP_CLIENT_ID");
    expect(cli.stdout).toContain("PGARD_GITHUB_APP_CLIENT_ID");

    expect(comparable(web.result)).toEqual(comparable(cli.result));
    expect(web.result).toEqual(JSON.parse(JSON.stringify(cli.result)));
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
