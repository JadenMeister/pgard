/**
 * Integration: the CLI and the local web dashboard must produce the same ScanResult for the same
 * repository. Both frontends run the real scan-core pipeline (real authorization gate, real
 * source and history analyzers) against a throwaway Git repository. GitHub is replaced by the
 * policy package's in-memory mock; nothing here touches the network.
 */
import http from "node:http";
import { splitFindingsByContext, type ScanResult } from "@pgard/findings";
import {
  DEFAULT_GITHUB_APP_CLIENT_ID,
  createDeviceFlowSessionProvider,
  createInMemoryCredentialStore,
  resolveGitHubAppClientId,
  type GitHubSessionProvider,
} from "@pgard/github-auth";
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
  orgInstallation,
  orgMembership,
  orgRepository,
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
const VENDORED_PASSWORD = join("Xq9", "!vR2", "#mT7", "pLw4");
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
 * Repository `me/app` with a SQL-injection pattern in the working tree (also in a test file), a
 * lockfile (ignored: PGARD has no vulnerability database), and a GitHub token that was committed and then removed (only the history scan can
 * still see it).
 */
function createProject(remote = "git@github.com:me/app.git"): { root: string; head: string } {
  fixture = createGitFixture({ remotes: { origin: remote } });
  const me = { authorName: ME.name ?? "Me Person", authorEmail: ME.email ?? "me@example.com" };
  fixture.commit({
    ...me,
    files: {
      "src/db.ts": SQL_VULN,
      // The same pattern in a test file: reported in the separate test or fixture group.
      "src/db.test.ts": SQL_VULN,
      "package.json": '{ "name": "app", "version": "1.0.0", "dependencies": { "pg": "8.11.0" } }\n',
      "package-lock.json": `${LOCKFILE}\n`,
      "deploy.sh": `export GH="${REMOVED_TOKEN}"\n`,
      // A committed dependency with a high-entropy credential: shown as a suggestion, together
      // with one PG-HYGIENE-001 suggestion for the committed node_modules/ directory.
      "node_modules/pkg/index.js": `const DB_PASSWORD = "${VENDORED_PASSWORD}";\nmodule.exports = DB_PASSWORD;\n`,
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

/**
 * Repository `acme/app` owned by an organization: the App installation on `acme` includes it, and
 * `ME` has the given membership role.
 */
function orgState(head: string, role: string): MockGitHubState {
  return {
    ...allowedState(head),
    repository: orgRepository(),
    installations: [orgInstallation()],
    installationRepositories: { 88: [555] },
    memberships: { acme: orgMembership({ role }) },
  };
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
    existing: async () => session,
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
  env: Record<string, string> = ENV,
): Promise<{ result: ScanResult; exitCode: number; stdout: string }> {
  const defaults = createDefaultDeps();
  const recorder = recordingRunScan(defaults.runScan);
  const deps: CliDeps = {
    ...defaults,
    runScan: recorder.runScan,
    ...(createSessionProvider === null ? {} : { createSessionProvider }),
  };
  const captured = createTestIo({ cwd: root, env });
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

/** How long the web side may poll for a finished scan before failing with its own message. */
const WEB_SCAN_DEADLINE_MS = 20_000;
/** Above the polling deadline, so a hung scan reports the deadline, not Vitest's timeout. */
const PARITY_TEST_TIMEOUT_MS = 30_000;

async function scanWithWeb(
  root: string,
  createSessionProvider: SessionFactory,
  env: Record<string, string> = ENV,
): Promise<{ result: ScanResult; received: ScanResult }> {
  const defaults = {
    ...createDefaultServerDeps(),
    credentialStore: createInMemoryCredentialStore(),
  };
  const recorder = recordingRunScan(defaults.runScan);
  const deps: ServerDeps = {
    ...defaults,
    runScan: recorder.runScan,
    ...(createSessionProvider === null ? {} : { createSessionProvider }),
  };
  server = await startLocalWebServer({
    projectRoot: root,
    presetTargetPort: null,
    env,
    assets: new Map(),
    deps,
    token: TOKEN,
  });
  const started = await request(server.port, "POST", "/api/scan", { scopes: ["code", "history"] });
  expect(started.status).toBe(200);

  const deadline = Date.now() + WEB_SCAN_DEADLINE_MS;
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

/**
 * Runs `pgard project verify` and the dashboard's authorization check (on the server that
 * `scanWithWeb` started) and returns what each one shows.
 */
async function verifyWithBoth(
  root: string,
  createSessionProvider: NonNullable<SessionFactory>,
): Promise<{ cliStdout: string; cliCode: number; webSummary: unknown }> {
  const captured = createTestIo({ cwd: root, env: ENV });
  const cliCode = await main(["project", "verify"], captured.io, {
    deps: { ...createDefaultDeps(), createSessionProvider },
    interrupts: noInterrupts,
  });
  if (server === null) throw new Error("scanWithWeb must start the server first");
  expect((await request(server.port, "POST", "/api/auth/verify")).status).toBe(200);
  const deadline = Date.now() + WEB_SCAN_DEADLINE_MS;
  for (;;) {
    const polled = await request(server.port, "GET", "/api/auth");
    const status = polled.json as { status: string; summary: unknown };
    if (status.status === "done") {
      return { cliStdout: captured.stdout(), cliCode, webSummary: status.summary };
    }
    if (Date.now() > deadline) throw new Error("web verify did not finish in time");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

/** The ScanResult as JSON, without the per-run fields the contract allows to differ. */
function comparable(result: ScanResult): unknown {
  const { scanId: _scanId, startedAt: _startedAt, finishedAt: _finishedAt, ...rest } = result;
  return JSON.parse(JSON.stringify(rest)) as unknown;
}

/**
 * The real device-flow provider with the client id from the resolver and an in-memory keychain,
 * so tests never touch the OS keychain. Global fetch is the spy that throws.
 */
const realProvider: NonNullable<SessionFactory> = ({ env, onUserCode, onNotice, signal }) =>
  createDeviceFlowSessionProvider({
    clientId: resolveGitHubAppClientId(env).clientId,
    onUserCode,
    onNotice,
    credentialStore: createInMemoryCredentialStore(),
    ...(signal === undefined ? {} : { signal }),
  });

describe("CLI and local web parity", { timeout: PARITY_TEST_TIMEOUT_MS }, () => {
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
    // Findings in test files are kept, marked and grouped separately by both frontends.
    const sql = cli.result.findings.filter((finding) => finding.ruleId.startsWith("PG-SQL"));
    expect(sql.find((finding) => finding.location.path === "src/db.ts")?.context).toBeUndefined();
    expect(sql.find((finding) => finding.location.path === "src/db.test.ts")).toMatchObject({
      context: "test",
      confidence: "low",
    });
    expect(cli.stdout).toContain("In test or fixture code (1)");
    // The credential in committed node_modules/ is kept (rule and severity unchanged) but moved to
    // the suggestions, next to the single PG-HYGIENE-001 suggestion; neither is a headline finding.
    expect(
      cli.result.findings.find((finding) => finding.location.path === "node_modules/pkg/index.js"),
    ).toMatchObject({
      ruleId: "PG-SECRET-002",
      severity: "high",
      context: "vendored",
      confidence: "low",
    });
    const hygiene = cli.result.findings.filter((finding) => finding.ruleId === "PG-HYGIENE-001");
    expect(hygiene).toHaveLength(1);
    expect(hygiene[0]).toMatchObject({ severity: "info", context: "vendored" });
    expect(hygiene[0]?.evidence).toContain("node_modules/ (1 tracked file)");
    const cliGroups = splitFindingsByContext(cli.result.findings);
    const webGroups = splitFindingsByContext(web.result.findings);
    expect(cliGroups.vendored).toHaveLength(2);
    expect(webGroups.vendored.map((finding) => finding.id)).toEqual(
      cliGroups.vendored.map((finding) => finding.id),
    );
    expect(cli.stdout).toContain(
      `Findings by severity (${cliGroups.primary.length} total) - plus 1 in test or fixture code, 2 suggestions in vendored code (1 high)`,
    );
    expect(
      cliGroups.primary.some((finding) => finding.location.path?.startsWith("node_modules")),
    ).toBe(false);
    const suggestions = cli.stdout.indexOf("Suggestions: in third-party/vendored code (2)");
    expect(suggestions).toBeGreaterThan(cli.stdout.indexOf("In test or fixture code (1)"));
    expect(cli.stdout.indexOf("node_modules/pkg/index.js:1")).toBeGreaterThan(suggestions);
    expect(JSON.stringify(cli.result)).not.toContain(VENDORED_PASSWORD);
    expect(JSON.stringify(cli.result)).not.toContain(REMOVED_TOKEN);
    expect(JSON.stringify(cli.result)).not.toContain(root);
    // Every selected area completes, so the full scan is "completed" and exits 0. There is no
    // vulnerability database: no dependency coverage, no advisory data.
    expect(cli.result.overallStatus).toBe("completed");
    expect(cli.exitCode).toBe(0);
    expect(cli.exitCode).toBe(exitCodeForStatus(cli.result.overallStatus));
    expect(
      cli.result.coverage.filter(
        (entry) => entry.status !== "completed" && entry.status !== "not_selected",
      ),
    ).toEqual([]);
    expect(cli.result.coverage.some((entry) => entry.area.startsWith("dependencies"))).toBe(false);
    expect(cli.result.advisoryDb).toEqual({ version: null, updatedAt: null });
    expect(ruleIds.some((id) => id.startsWith("PG-DEP"))).toBe(false);

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

  it("allow an organization owner's scan with the same owner-approval reason", async () => {
    const { root, head } = createProject("git@github.com:acme/app.git");
    const cliGitHub = mockSessionProvider(orgState(head, "admin"));
    const webGitHub = mockSessionProvider(orgState(head, "admin"));

    const cli = await scanWithCli(root, () => cliGitHub.provider);
    const web = await scanWithWeb(root, () => webGitHub.provider);

    const reason =
      'me is an owner of the organization "acme", and the organization\'s PGARD GitHub App installation includes acme/app.';
    expect(cli.result.authorization.decision).toBe("allowed");
    expect(cli.result.target.repo).toBe("acme/app");
    expect(cli.result.authorization.checks.find((check) => check.id === "owner_approval")).toEqual({
      id: "owner_approval",
      status: "passed",
      reason,
    });
    // The organization owner is exempt from a separate contribution (#47).
    const contribution = `me is an owner of the organization "acme"; a separate contribution is not required. Local HEAD is linked to acme/app by commit ${head.slice(0, 12)}.`;
    expect(cli.result.authorization.checks.find((check) => check.id === "contribution")).toEqual({
      id: "contribution",
      status: "passed",
      reason: contribution,
    });
    const verify = await verifyWithBoth(root, () => cliGitHub.provider);
    expect(verify.cliCode).toBe(0);
    expect(verify.cliStdout).toContain(`[passed] owner approval: ${reason}`);
    expect(verify.cliStdout).toContain(`[passed] contribution: ${contribution}`);
    expect(verify.webSummary).toEqual(JSON.parse(JSON.stringify(cli.result.authorization)));

    expect(comparable(web.result)).toEqual(comparable(cli.result));
    expect(web.result).toEqual(JSON.parse(JSON.stringify(cli.result)));
    expect(webGitHub.calls).toEqual(cliGitHub.calls);
    expect(cliGitHub.calls).toContain("membership:acme");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("block an organization member's scan with the same reason", async () => {
    const { root, head } = createProject("git@github.com:acme/app.git");
    const cliGitHub = mockSessionProvider(orgState(head, "member"));
    const webGitHub = mockSessionProvider(orgState(head, "member"));

    const cli = await scanWithCli(root, () => cliGitHub.provider);
    const web = await scanWithWeb(root, () => webGitHub.provider);

    const reason =
      "me is not an owner of acme (role: member); an organization owner must run the scan.";
    expect(cli.result.overallStatus).toBe("blocked");
    expect(cli.exitCode).toBe(3);
    expect(cli.result.findings).toEqual([]);
    expect(cli.result.authorization.checks.find((check) => check.id === "owner_approval")).toEqual({
      id: "owner_approval",
      status: "failed",
      reason,
    });
    expect(cli.stdout).toContain(`[failed] owner approval: ${reason}`);
    const verify = await verifyWithBoth(root, () => cliGitHub.provider);
    expect(verify.cliCode).toBe(3);
    expect(verify.cliStdout).toContain(`[failed] owner approval: ${reason}`);
    expect(verify.webSummary).toEqual(JSON.parse(JSON.stringify(cli.result.authorization)));

    expect(comparable(web.result)).toEqual(comparable(cli.result));
    expect(web.result).toEqual(JSON.parse(JSON.stringify(cli.result)));
    expect(webGitHub.calls).toEqual(cliGitHub.calls);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("allow the verified personal owner without a separate contribution, with the same reason", async () => {
    const { root, head } = createProject();
    // No merged PR and no signed commit: only the owner exemption (#47) can pass contribution.
    // HEAD is on the default branch, which links the local code to me/app.
    const ownerOnly = (): MockGitHubState => ({ ...allowedState(head), commits: {} });
    const cliGitHub = mockSessionProvider(ownerOnly());
    const webGitHub = mockSessionProvider(ownerOnly());

    const cli = await scanWithCli(root, () => cliGitHub.provider);
    const web = await scanWithWeb(root, () => webGitHub.provider);

    const reason = `me owns me/app (verified by GitHub account id); a separate contribution is not required. Local HEAD is linked to me/app by commit ${head.slice(0, 12)}.`;
    expect(cli.result.authorization.decision).toBe("allowed");
    expect(cli.exitCode).toBe(0);
    expect(cli.result.authorization.checks.find((check) => check.id === "contribution")).toEqual({
      id: "contribution",
      status: "passed",
      reason,
    });
    const verify = await verifyWithBoth(root, () => cliGitHub.provider);
    expect(verify.cliCode).toBe(0);
    expect(verify.cliStdout).toContain(`[passed] contribution: ${reason}`);
    expect(verify.webSummary).toEqual(JSON.parse(JSON.stringify(cli.result.authorization)));

    expect(comparable(web.result)).toEqual(comparable(cli.result));
    expect(web.result).toEqual(JSON.parse(JSON.stringify(cli.result)));
    expect(webGitHub.calls).toEqual(cliGitHub.calls);
    expect(cliGitHub.calls.some((call) => /^(pulls|commit):/.test(call))).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("block a collaborator without a contribution with the same full reason and guidance", async () => {
    const { root } = createProject("git@github.com:maintainer/app.git");
    const collaborator = (): MockGitHubState => ({
      user: ME,
      repository: userRepository({
        fullName: "maintainer/app",
        owner: { id: 3003, login: "maintainer", type: "User" },
      }),
      installations: [{ id: 77, targetType: "User", account: { id: 3003, login: "maintainer" } }],
      installationRepositories: { 77: [555] },
      pulls: {},
      commits: {},
      compare: {},
    });
    const cliGitHub = mockSessionProvider(collaborator());
    const webGitHub = mockSessionProvider(collaborator());

    const cli = await scanWithCli(root, () => cliGitHub.provider);
    const web = await scanWithWeb(root, () => webGitHub.provider);

    const reason =
      'No qualifying contribution found among 2 local commits. A pull request by the signed-in user merged into the default branch, or a signature-verified commit by them in the default branch, is required; author name/email, unmerged PRs, PRs into other branches and local-only commits do not count. To qualify, get a pull request merged into "main", or sign your commits (GitHub shows them as Verified) and push them to "main".';
    expect(cli.result.overallStatus).toBe("blocked");
    expect(cli.exitCode).toBe(3);
    expect(cli.result.authorization.checks.find((check) => check.id === "contribution")).toEqual({
      id: "contribution",
      status: "failed",
      reason,
    });
    // Shown in full (not truncated) by the scan output, `project verify` and the dashboard API.
    expect(cli.stdout).toContain(`[failed] contribution: ${reason}`);
    const verify = await verifyWithBoth(root, () => cliGitHub.provider);
    expect(verify.cliCode).toBe(3);
    expect(verify.cliStdout).toContain(`[failed] contribution: ${reason}`);
    expect(verify.webSummary).toEqual(JSON.parse(JSON.stringify(cli.result.authorization)));

    expect(comparable(web.result)).toEqual(comparable(cli.result));
    expect(web.result).toEqual(JSON.parse(JSON.stringify(cli.result)));
    expect(webGitHub.calls).toEqual(cliGitHub.calls);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("produce the same blocked result with the real sign-in for the built-in App when GitHub is unreachable", async () => {
    const { root } = createProject();

    const cli = await scanWithCli(root, realProvider);
    const web = await scanWithWeb(root, realProvider);

    expect(cli.result.overallStatus).toBe("blocked");
    expect(cli.exitCode).toBe(3);
    const identity = cli.result.authorization.checks.find(
      (check) => check.id === "github_identity",
    );
    expect(identity?.status).toBe("unverifiable");
    expect(identity?.reason).toBe(
      "GitHub identity could not be verified: Could not reach GitHub for sign-in.",
    );
    expect(cli.stdout).not.toContain("PGARD_GITHUB_APP_CLIENT_ID");

    expect(comparable(web.result)).toEqual(comparable(cli.result));
    expect(web.result).toEqual(JSON.parse(JSON.stringify(cli.result)));
    // Both frontends asked GitHub for a device code as the built-in PGARD App, and nothing else.
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    for (const [url, init] of fetchSpy.mock.calls as [string, { body?: string }][]) {
      expect(url).toBe("https://github.com/login/device/code");
      expect(new URLSearchParams(init.body ?? "").get("client_id")).toBe(
        DEFAULT_GITHUB_APP_CLIENT_ID,
      );
    }
  });

  it("block scan and verify with the same reason when the override is malformed", async () => {
    const { root } = createProject();
    const badEnv = { PGARD_GITHUB_APP_CLIENT_ID: '"bad id"' };

    const cli = await scanWithCli(root, realProvider, badEnv);
    const web = await scanWithWeb(root, realProvider, badEnv);

    expect(cli.result.overallStatus).toBe("blocked");
    expect(cli.exitCode).toBe(3);
    expect(cli.result.findings).toEqual([]);
    const identity = cli.result.authorization.checks.find(
      (check) => check.id === "github_identity",
    );
    expect(identity).toEqual({
      id: "github_identity",
      status: "unverifiable",
      reason:
        "PGARD_GITHUB_APP_CLIENT_ID is set but is not a valid client id; unset it to use the built-in PGARD App.",
    });
    expect(cli.stdout).toContain(
      "PGARD_GITHUB_APP_CLIENT_ID is set but is not a valid client id; unset it to use the built-in PGARD App.",
    );
    expect(comparable(web.result)).toEqual(comparable(cli.result));

    const verify = createTestIo({ cwd: root, env: badEnv });
    const verifyCode = await main(["project", "verify"], verify.io, {
      deps: { ...createDefaultDeps(), createSessionProvider: realProvider },
      interrupts: noInterrupts,
    });
    expect(verifyCode).toBe(3);
    expect(verify.stdout()).toContain("Authorization: blocked");
    expect(verify.stdout()).toContain(
      "PGARD_GITHUB_APP_CLIENT_ID is set but is not a valid client id; unset it to use the built-in PGARD App.",
    );
    for (const output of [
      cli.stdout,
      verify.stdout(),
      verify.stderr(),
      JSON.stringify(web.result),
    ]) {
      expect(output).not.toContain("bad id");
    }
    // Nothing reached GitHub, so no other App was ever asked for a sign-in.
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
