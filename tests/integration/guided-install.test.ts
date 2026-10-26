/**
 * Integration: the guided GitHub App install in the CLI, against the real authorization gate
 * (scan-core + policy), a throwaway Git repository and the policy package's in-memory GitHub.
 * The browser opener, the clock and the 5 s wait are fakes; nothing touches the network, no
 * browser is opened and nothing is installed.
 */
import http from "node:http";
import type { AuthorizationSummary, ScanResult } from "@pgard/findings";
import {
  createInMemoryCredentialStore,
  GitHubAuthError,
  guidedInstallRemedy,
  recheckOwnerApproval as realRecheck,
  runScan as realRunScan,
  verifyProject as realVerify,
  type AuthorizationOutcome,
} from "@pgard/scan-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { InterruptSource } from "../../apps/cli/src/adapters/cancel.js";
import { main, type CliDeps } from "../../apps/cli/src/app.js";
import {
  INSTALL_POLL_INTERVAL_MS,
  WAITING_FOR_INSTALL_MESSAGE,
} from "../../apps/cli/src/flows/guided-install.js";
import { createTestDeps, createTestIo, noInterrupts } from "../../apps/cli/src/test-support.js";
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

const PERSONAL_INSTALL_URL =
  "https://github.com/apps/pgard-jadenmeister/installations/new/permissions?suggested_target_id=1001&repository_ids%5B%5D=555";
const ORG_INSTALL_URL =
  "https://github.com/apps/pgard-jadenmeister/installations/new/permissions?suggested_target_id=42&repository_ids%5B%5D=555";

let fixture: GitFixture | null = null;

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new Error("network access is not allowed in this test");
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  fixture?.cleanup();
  fixture = null;
});

function project(remote = "git@github.com:me/app.git"): { root: string; head: string } {
  fixture = createGitFixture({ remotes: { origin: remote } });
  const head = fixture.commit({
    authorName: "Me Person",
    authorEmail: "me@example.com",
    files: { "src/index.ts": "export const x = 1;\n" },
  });
  return { root: fixture.root, head };
}

/** Repository identity, access and a verified contribution are fine; the App is not installed. */
function notInstalled(head: string, overrides: Partial<MockGitHubState> = {}): MockGitHubState {
  return {
    user: ME,
    repository: userRepository(),
    installations: [],
    installationRepositories: {},
    pulls: {},
    commits: { [head]: { sha: head, authorId: ME.id, committerId: ME.id, isVerified: true } },
    compare: { [head]: "identical" },
    ...overrides,
  };
}

function installForOwner(state: MockGitHubState): void {
  state.installations = [ownerInstallation()];
  state.installationRepositories = { 77: [555] };
}

interface Harness {
  deps: CliDeps;
  openBrowser: ReturnType<typeof vi.fn>;
  sleeps: () => number;
  verifyCalls: () => number;
  scanResults: ScanResult[];
  rechecks: () => number;
}

/**
 * CLI deps with the real gate. `onSleep(n)` runs at the n-th 5 s wait (1-based), where a test
 * installs the App or changes GitHub state; each wait advances the fake clock by 5 s.
 */
function harness(state: MockGitHubState, onSleep: (count: number) => void = () => {}): Harness {
  const { session } = createMockGitHub(state);
  const provider = Object.assign(async () => session, {
    invalidate: () => undefined,
    signOut: () => undefined,
    existing: async () => session,
  });
  let clock = 1_000_000;
  let sleeps = 0;
  let verifyCalls = 0;
  let rechecks = 0;
  const scanResults: ScanResult[] = [];
  const openBrowser = vi.fn(async () => true);
  const deps = createTestDeps({
    findGitRoot: async () => fixture?.root ?? null,
    createSessionProvider: () => provider,
    verifyProject: async (root, authorization) => {
      verifyCalls += 1;
      return realVerify(root, authorization);
    },
    runScan: async (request, scanDeps) => {
      const result = await realRunScan(request, scanDeps);
      scanResults.push(result);
      return result;
    },
    recheckOwnerApproval: async (root, authorization) => {
      rechecks += 1;
      return realRecheck(root, authorization);
    },
    openBrowser,
    now: () => clock,
    sleep: async (ms) => {
      expect(ms).toBe(INSTALL_POLL_INTERVAL_MS);
      sleeps += 1;
      clock += ms;
      onSleep(sleeps);
    },
  });
  return {
    deps,
    openBrowser,
    sleeps: () => sleeps,
    verifyCalls: () => verifyCalls,
    scanResults,
    rechecks: () => rechecks,
  };
}

async function run(
  argv: string[],
  deps: CliDeps,
  options: {
    stdoutIsTTY?: boolean;
    env?: Record<string, string>;
    interrupts?: InterruptSource;
  } = {},
) {
  const captured = createTestIo({ cwd: fixture?.root ?? "/", env: options.env ?? {} });
  (captured.io.stdout as { isTTY?: boolean }).isTTY = options.stdoutIsTTY ?? true;
  const exitCode = await main(argv, captured.io, {
    deps,
    interrupts: options.interrupts ?? noInterrupts,
  });
  return { exitCode, stdout: captured.stdout(), stderr: captured.stderr() };
}

describe("guided install: personal repository owner", () => {
  it("project verify: opens the install page, waits, then passes the full re-authorization", async () => {
    const { head } = project();
    const state = notInstalled(head);
    const h = harness(state, (count) => {
      if (count === 2) installForOwner(state);
    });
    const result = await run(["project", "verify"], h.deps);
    expect(result.exitCode).toBe(0);
    expect(h.openBrowser).toHaveBeenCalledExactlyOnceWith(PERSONAL_INSTALL_URL);
    expect(result.stderr).toContain(`1. Open ${PERSONAL_INSTALL_URL}`);
    expect(result.stderr).toContain('"Only select repositories" (me/app) or "All repositories"');
    expect(result.stderr).toContain("PGARD cannot install it for you");
    expect(result.stderr).toContain(WAITING_FOR_INSTALL_MESSAGE);
    expect(h.sleeps()).toBe(2);
    expect(h.rechecks()).toBe(2);
    // Two complete authorizations: the blocked one and a fresh one after the install.
    expect(h.verifyCalls()).toBe(2);
    expect(result.stdout).toContain("No PGARD GitHub App installation");
    expect(result.stdout.trimEnd()).toMatch(/allowed/i);
  });

  it("project verify: blocks when access was revoked while installing (proves the full re-auth)", async () => {
    const { head } = project();
    const state = notInstalled(head);
    const h = harness(state, (count) => {
      if (count === 1) {
        installForOwner(state);
        state.repository = userRepository({
          permissions: { admin: false, maintain: false, push: false, triage: false, pull: false },
        });
      }
    });
    const result = await run(["project", "verify"], h.deps);
    expect(result.exitCode).toBe(3);
    expect(h.verifyCalls()).toBe(2);
    expect(result.stdout).toContain("The signed-in user has no read access to me/app.");
  });

  it("scan: continues the scan after the install, through runScan's own full gate", async () => {
    const { head } = project();
    const state = notInstalled(head);
    const h = harness(state, (count) => {
      if (count === 1) installForOwner(state);
    });
    const result = await run(["scan", "code"], h.deps);
    expect(result.exitCode).toBe(0);
    expect(h.scanResults.map((scan) => scan.overallStatus)).toEqual(["blocked", "completed"]);
    expect(h.scanResults[1]?.authorization.decision).toBe("allowed");
    expect(h.openBrowser).toHaveBeenCalledExactlyOnceWith(PERSONAL_INSTALL_URL);
  });

  it("scan: stays blocked when access was revoked while installing", async () => {
    const { head } = project();
    const state = notInstalled(head);
    const h = harness(state, () => {
      installForOwner(state);
      state.repository = null;
    });
    const result = await run(["scan", "code"], h.deps);
    expect(result.exitCode).toBe(3);
    expect(h.scanResults.map((scan) => scan.overallStatus)).toEqual(["blocked", "blocked"]);
  });

  it("scan web: guides before any port is probed, then re-runs the full authorization", async () => {
    const { head } = project();
    const state = notInstalled(head, { repository: userRepository() });
    const h = harness(state, () => {
      installForOwner(state);
      state.repository = null;
    });
    const result = await run(["scan", "web"], h.deps);
    expect(result.exitCode).toBe(3);
    expect(h.verifyCalls()).toBe(2);
    expect(h.scanResults).toHaveLength(0);
  });

  it("prints the link without opening a browser when --no-browser is given", async () => {
    const { head } = project();
    const state = notInstalled(head);
    const h = harness(state, () => installForOwner(state));
    const result = await run(["project", "verify", "--no-browser"], h.deps);
    expect(result.exitCode).toBe(0);
    expect(h.openBrowser).not.toHaveBeenCalled();
    expect(result.stderr).toContain(PERSONAL_INSTALL_URL);
  });

  it("prints the link and blocks without waiting when stdout is not a terminal", async () => {
    const { head } = project();
    const h = harness(notInstalled(head));
    const result = await run(["scan", "code"], h.deps, { stdoutIsTTY: false });
    expect(result.exitCode).toBe(3);
    expect(result.stderr).toContain(PERSONAL_INSTALL_URL);
    expect(result.stderr).toContain("does not wait for the installation");
    expect(h.openBrowser).not.toHaveBeenCalled();
    expect(h.sleeps()).toBe(0);
    expect(h.scanResults).toHaveLength(1);
  });
});

describe("guided install: waiting ends", () => {
  // 120 real owner-approval re-checks (each runs the local repository checks): allow more time.
  it("blocks after 10 minutes without an installation", async () => {
    const { head } = project();
    const h = harness(notInstalled(head));
    const result = await run(["project", "verify"], h.deps);
    expect(result.exitCode).toBe(3);
    expect(h.sleeps()).toBe(120);
    expect(h.verifyCalls()).toBe(1);
    expect(result.stderr).toContain("Stopped waiting after 10 minutes.");
    expect(result.stderr).toContain("No PGARD GitHub App installation");
  }, 60_000);

  it("ends the wait without a new sign-in when the session is gone, then re-authorizes", async () => {
    const { head } = project();
    const state = notInstalled(head);
    const h = harness(state);
    const { session } = createMockGitHub(state);
    // `interactive` stands for the device flow; the re-check may only use `existing`.
    const interactive = vi.fn(async () => session);
    const existing = vi.fn(async () => null);
    h.deps.createSessionProvider = () =>
      Object.assign(interactive, {
        invalidate: () => undefined,
        signOut: () => undefined,
        existing,
      });
    const result = await run(["project", "verify"], h.deps);
    expect(result.exitCode).toBe(3);
    expect(existing).toHaveBeenCalledTimes(1);
    expect(h.rechecks()).toBe(1);
    // One sign-in per full authorization (the blocked one and the fresh one), none for the wait.
    expect(h.verifyCalls()).toBe(2);
    expect(interactive).toHaveBeenCalledTimes(2);
    expect(result.stderr).toContain(
      "Owner approval could not be confirmed. Running the full authorization again...",
    );
    expect(result.stderr).not.toContain("Owner approval changed");
  });

  it("says owner approval could not be confirmed (not changed) on a rate limit", async () => {
    const { head } = project();
    const state = notInstalled(head);
    const h = harness(state, () => {
      state.failWith = new GitHubAuthError("rate_limited", "rate limited", 429);
    });
    const result = await run(["project", "verify"], h.deps);
    expect(result.exitCode).toBe(3);
    expect(h.rechecks()).toBe(1);
    expect(h.verifyCalls()).toBe(2);
    expect(result.stderr).toContain(
      "Owner approval could not be confirmed. Running the full authorization again...",
    );
    expect(result.stderr).not.toContain("Owner approval changed");
  });

  it("cancels with exit 130 when Ctrl+C is confirmed while waiting", async () => {
    const { head } = project();
    const listeners: (() => void)[] = [];
    const interrupts: InterruptSource = {
      on: (_event, listener) => listeners.push(listener),
      off: () => undefined,
    };
    const h = harness(notInstalled(head), (count) => {
      if (count === 3) {
        listeners.forEach((listener) => listener());
        listeners.forEach((listener) => listener());
      }
    });
    const result = await run(["project", "verify"], h.deps, { interrupts });
    expect(result.exitCode).toBe(130);
    expect(h.sleeps()).toBe(3);
    expect(h.verifyCalls()).toBe(1);
    expect(result.stderr).toContain("Stopped waiting for the PGARD GitHub App installation.");
  });
});

describe("guided install: organizations and configuration", () => {
  const ORG_REMOTE = "git@github.com:acme/app.git";

  it("guides an active organization owner and re-runs the full authorization", async () => {
    const { head } = project(ORG_REMOTE);
    const state = notInstalled(head, {
      repository: orgRepository(),
      memberships: { acme: orgMembership() },
    });
    const h = harness(state, () => {
      state.installations = [orgInstallation()];
      state.installationRepositories = { 88: [555] };
    });
    const result = await run(["project", "verify"], h.deps);
    expect(result.exitCode).toBe(0);
    expect(h.openBrowser).toHaveBeenCalledExactlyOnceWith(ORG_INSTALL_URL);
    expect(h.verifyCalls()).toBe(2);
  });

  /** Org repo, App not installed on the org, and GitHub refuses the membership (403) for now. */
  function orgBeforeInstall(head: string): MockGitHubState {
    return notInstalled(head, {
      repository: orgRepository(),
      memberships: { acme: new GitHubAuthError("forbidden", "forbidden", 403) },
    });
  }

  function installOnOrg(state: MockGitHubState, role: string): void {
    state.installations = [orgInstallation()];
    state.installationRepositories = { 88: [555] };
    state.memberships = { acme: orgMembership({ role }) };
  }

  it("guides and waits when the membership cannot be read yet, then passes as an owner", async () => {
    const { head } = project(ORG_REMOTE);
    const state = orgBeforeInstall(head);
    const h = harness(state, (count) => {
      if (count === 2) installOnOrg(state, "admin");
    });
    const result = await run(["project", "verify"], h.deps);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain(
      `If you are an owner of acme, install the App on the install page; otherwise ask an owner to install it there: ${ORG_INSTALL_URL}`,
    );
    expect(result.stderr).toContain(WAITING_FOR_INSTALL_MESSAGE);
    expect(h.openBrowser).toHaveBeenCalledExactlyOnceWith(ORG_INSTALL_URL);
    expect(h.sleeps()).toBe(2);
    // The full gate ran again and checked the owner membership itself.
    expect(h.verifyCalls()).toBe(2);
    expect(result.stdout).toContain('me is an owner of the organization "acme"');
  });

  it("blocks after the install when the membership GitHub then shows is not an owner", async () => {
    const { head } = project(ORG_REMOTE);
    const state = orgBeforeInstall(head);
    const h = harness(state, () => installOnOrg(state, "member"));
    const result = await run(["scan", "code"], h.deps);
    expect(result.exitCode).toBe(3);
    expect(h.openBrowser).toHaveBeenCalledExactlyOnceWith(ORG_INSTALL_URL);
    expect(h.scanResults.map((scan) => scan.overallStatus)).toEqual(["blocked", "blocked"]);
    expect(
      h.scanResults[1]?.authorization.checks.find((check) => check.id === "owner_approval"),
    ).toMatchObject({
      status: "failed",
      reason: "me is not an owner of acme (role: member); an organization owner must run the scan.",
    });
  });

  it("dashboard: guides an unreadable membership the same way and re-checks", async () => {
    const { root, head } = project(ORG_REMOTE);
    const state = orgBeforeInstall(head);
    const { session } = createMockGitHub(state);
    const provider = Object.assign(async () => session, {
      invalidate: () => undefined,
      signOut: () => undefined,
      existing: async () => session,
    });
    // The server allows one re-check per 5 s; a fake clock steps over that.
    let clock = Date.now();
    const server = await startLocalWebServer({
      projectRoot: root,
      presetTargetPort: null,
      env: {},
      assets: new Map(),
      deps: {
        ...serverDepsWithFakeKeychain(),
        createSessionProvider: () => provider,
        now: () => clock,
      },
      token: WEB_TOKEN,
    });
    try {
      const blocked = await webVerify(server.port);
      expect(blocked.remedy).toMatchObject({ canApprove: "unknown", url: ORG_INSTALL_URL });
      const waiting = await webRequest(server.port, "POST", "/api/auth/owner-approval");
      expect(waiting.status).toBe(200);
      expect(waiting.json).toMatchObject({ status: "failed", remedy: { canApprove: "unknown" } });
      installOnOrg(state, "member");
      clock += 5_000;
      const recheck = await webRequest(server.port, "POST", "/api/auth/owner-approval");
      expect(recheck.json).toMatchObject({ status: "failed", remedy: null });
      const after = await webVerify(server.port);
      expect(after.summary.decision).toBe("blocked");
      expect(after.remedy).toBeNull();
    } finally {
      await server.close();
    }
  });

  it("dashboard: the re-check never starts a sign-in when the session is gone", async () => {
    const { root, head } = project();
    const { session } = createMockGitHub(notInstalled(head));
    // `interactive` stands for the device flow; the re-check may only use `existing`.
    const interactive = vi.fn(async () => session);
    const existing = vi.fn(async () => null);
    const provider = Object.assign(interactive, {
      invalidate: () => undefined,
      signOut: () => undefined,
      existing,
    });
    const server = await startLocalWebServer({
      projectRoot: root,
      presetTargetPort: null,
      env: {},
      assets: new Map(),
      deps: { ...serverDepsWithFakeKeychain(), createSessionProvider: () => provider },
      token: WEB_TOKEN,
    });
    try {
      const blocked = await webVerify(server.port);
      expect(blocked.remedy).toMatchObject({ canApprove: "yes" });
      expect(interactive).toHaveBeenCalledTimes(1);
      const recheck = await webRequest(server.port, "POST", "/api/auth/owner-approval");
      expect(recheck.status).toBe(200);
      // Unverifiable with no remedy: the panel ends the wait and runs the full check.
      expect(recheck.json).toEqual({
        status: "unverifiable",
        reason:
          "The GitHub sign-in is no longer available, so owner approval was not checked again.",
        remedy: null,
      });
      expect(existing).toHaveBeenCalledTimes(1);
      expect(interactive).toHaveBeenCalledTimes(1);
    } finally {
      await server.close();
    }
  });

  it("tells a member who is not an owner to ask an owner, without waiting or opening", async () => {
    const { head } = project(ORG_REMOTE);
    const h = harness(
      notInstalled(head, {
        repository: orgRepository(),
        memberships: { acme: orgMembership({ role: "member" }) },
      }),
    );
    const result = await run(["project", "verify"], h.deps);
    expect(result.exitCode).toBe(3);
    expect(result.stderr).toContain(
      `Ask an owner of acme to install the PGARD GitHub App: ${ORG_INSTALL_URL}`,
    );
    expect(h.openBrowser).not.toHaveBeenCalled();
    expect(h.sleeps()).toBe(0);
  });

  it("has no link when the client id is overridden without a slug", async () => {
    const { head } = project();
    const h = harness(notInstalled(head));
    const result = await run(["project", "verify"], h.deps, {
      env: { PGARD_GITHUB_APP_CLIENT_ID: "Iv23liForkApp" },
    });
    expect(result.exitCode).toBe(3);
    // Today's reason is kept, and the hint is added.
    expect(result.stdout).toContain(
      'No PGARD GitHub App installation on the owner account "me" was found for me/app.',
    );
    expect(result.stderr).toContain("Set PGARD_GITHUB_APP_SLUG to enable the guided install.");
    expect(result.stderr).not.toContain("/installations/new");
    expect(h.openBrowser).not.toHaveBeenCalled();
    expect(h.sleeps()).toBe(0);
  });

  it("uses PGARD_GITHUB_APP_SLUG for the install link", async () => {
    const { head } = project();
    const h = harness(notInstalled(head));
    const result = await run(["project", "verify"], h.deps, {
      stdoutIsTTY: false,
      env: { PGARD_GITHUB_APP_CLIENT_ID: "Iv23liForkApp", PGARD_GITHUB_APP_SLUG: "my-fork" },
    });
    expect(result.exitCode).toBe(3);
    expect(result.stderr).toContain(
      "https://github.com/apps/my-fork/installations/new/permissions?suggested_target_id=1001&repository_ids%5B%5D=555",
    );
  });

  it("offers nothing when another check fails too", async () => {
    const { head } = project();
    const h = harness(notInstalled(head, { commits: {}, compare: {} }));
    const result = await run(["project", "verify"], h.deps);
    expect(result.exitCode).toBe(3);
    expect(result.stderr).not.toContain("/installations/new");
    expect(h.sleeps()).toBe(0);
  });
});

/** Default dashboard deps with a fake keychain: tests never read the OS keychain. */
function serverDepsWithFakeKeychain(): ServerDeps {
  return { ...createDefaultServerDeps(), credentialStore: createInMemoryCredentialStore() };
}

const WEB_TOKEN = "guided-install-token-0123456789abcdefgh";

function webRequest(
  port: number,
  method: "GET" | "POST",
  urlPath: string,
): Promise<{ status: number; json: unknown }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path: urlPath,
        headers: {
          host: `127.0.0.1:${port}`,
          "x-pgard-token": WEB_TOKEN,
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
    if (method === "POST") req.write("{}");
    req.end();
  });
}

async function webVerify(
  port: number,
): Promise<{ summary: AuthorizationSummary; remedy: unknown }> {
  expect((await webRequest(port, "POST", "/api/auth/verify")).status).toBe(200);
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const polled = (await webRequest(port, "GET", "/api/auth")).json as {
      status: string;
      summary: AuthorizationSummary;
      remedy: unknown;
    };
    if (polled.status === "done") return polled;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("web verify did not finish in time");
}

describe("guided install: CLI and dashboard parity", () => {
  let web: LocalWebServer | null = null;
  afterEach(async () => {
    await web?.close();
    web = null;
  });

  it("shows the same remedy, and both re-run the full gate after the install", async () => {
    const { root, head } = project();
    const state = notInstalled(head);
    const { session } = createMockGitHub(state);
    const provider = Object.assign(async () => session, {
      invalidate: () => undefined,
      signOut: () => undefined,
      existing: async () => session,
    });

    // CLI: the remedy the gate produced for `pgard project verify` (not a terminal: no waiting).
    const cliOutcomes: AuthorizationOutcome[] = [];
    const cliDeps = createTestDeps({
      findGitRoot: async () => root,
      createSessionProvider: () => provider,
      verifyProject: async (projectRoot, authorization) => {
        const outcome = await realVerify(projectRoot, authorization);
        cliOutcomes.push(outcome);
        return outcome;
      },
    });
    let clock = Date.now();
    const cli = await run(["project", "verify"], cliDeps, { stdoutIsTTY: false });
    expect(cli.exitCode).toBe(3);
    const cliRemedy = guidedInstallRemedy(cliOutcomes[0]!);
    expect(cliRemedy?.url).toBe(PERSONAL_INSTALL_URL);
    expect(cli.stderr).toContain(PERSONAL_INSTALL_URL);

    // Dashboard: the same gate through the server's default deps.
    web = await startLocalWebServer({
      projectRoot: root,
      presetTargetPort: null,
      env: {},
      assets: new Map(),
      // The server allows one re-check per 5 s; a fake clock steps over that.
      deps: {
        ...serverDepsWithFakeKeychain(),
        createSessionProvider: () => provider,
        now: () => clock,
      },
      token: WEB_TOKEN,
    });
    const blocked = await webVerify(web.port);
    expect(blocked.summary).toEqual(cliOutcomes[0]!.summary);
    expect(blocked.remedy).toEqual(cliRemedy);

    // Still missing: the re-check keeps the remedy.
    const waiting = await webRequest(web.port, "POST", "/api/auth/owner-approval");
    expect(waiting.json).toMatchObject({ status: "failed", remedy: { url: PERSONAL_INSTALL_URL } });

    // Installed, but access revoked meanwhile: the re-check passes, the full gate does not.
    installForOwner(state);
    state.repository = userRepository({
      permissions: { admin: false, maintain: false, push: false, triage: false, pull: false },
    });
    clock += 5_000;
    const recheck = await webRequest(web.port, "POST", "/api/auth/owner-approval");
    expect(recheck.json).toMatchObject({ status: "passed", remedy: null });
    const after = await webVerify(web.port);
    expect(after.summary.decision).toBe("blocked");
    expect(after.summary.checks.find((check) => check.id === "current_access")?.status).toBe(
      "failed",
    );
    expect(after.remedy).toBeNull();

    // Access restored: the full gate allows it.
    state.repository = userRepository();
    expect((await webVerify(web.port)).summary.decision).toBe("allowed");
  });
});
