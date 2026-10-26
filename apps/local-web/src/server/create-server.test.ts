import http from "node:http";
import {
  SCHEMA_VERSION,
  type AuthorizationCheckId,
  type ScanRequest,
  type ScanResult,
} from "@pgard/findings";
import type { PortDiscoveryResult, ServiceIdentity } from "@pgard/http-local";
import {
  AUTHORIZATION_CHECK_ORDER,
  createDeviceFlowSessionProvider,
  createInMemoryCredentialStore,
  DEFAULT_GITHUB_APP_CLIENT_ID,
  type AuthorizationOutcome,
  type OwnerApprovalRemedy,
  type CredentialStore,
  type SignInNotice,
} from "@pgard/scan-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHtmlReport, renderReport } from "@pgard/report";
import type { ServerDeps } from "./deps.js";
import { reportDownloadName } from "./routes/api.js";
import { startLocalWebServer, type LocalWebServer } from "./create-server.js";

const TOKEN = "test-token-0123456789abcdefghijklmnop";

const IDENTITY: ServiceIdentity = {
  port: 3000,
  url: "http://127.0.0.1:3000/",
  status: 200,
  title: "Shop dev",
  inferredTechnologies: ["Express"],
  isHttp: true,
  redirectStop: null,
  error: null,
};

/**
 * A five-check outcome shaped like the one `authorizeProject` returns: every check passed, or the
 * named check failed (and the decision is blocked).
 */
function outcome(
  failing: AuthorizationCheckId | null = null,
  target: { repo: string | null; revision: string | null } = {
    repo: "owner/name",
    revision: "abc",
  },
): AuthorizationOutcome {
  return {
    summary: {
      decision: failing === null ? "allowed" : "blocked",
      checks: AUTHORIZATION_CHECK_ORDER.map((id) => ({
        id,
        status: id === failing ? "failed" : "passed",
        reason: id === failing ? "Check failed." : "Check passed.",
      })),
    },
    ...target,
  };
}

function result(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    schemaVersion: SCHEMA_VERSION,
    scanId: "scan-1",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:01.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "owner/name", revision: "abc", webOrigin: null },
    authorization: outcome().summary,
    coverage: [],
    findings: [],
    advisoryDb: { version: null, updatedAt: null },
    ...overrides,
  };
}

function fakeDeps(
  overrides: Partial<ServerDeps> = {},
): ServerDeps & { signOut: ReturnType<typeof vi.fn> } {
  const signOut = vi.fn();
  const provider = Object.assign(async () => ({}) as never, { invalidate: vi.fn(), signOut });
  return {
    verifyProject: async () => outcome("owner_approval"),
    runScan: async () => result(),
    recheckOwnerApproval: async () => {
      throw new Error("unexpected owner approval re-check");
    },
    createSessionProvider: () => provider as never,
    // A fake keychain: tests never touch the real OS keychain.
    credentialStore: createInMemoryCredentialStore(),
    webScanner: async () => ({ findings: [], coverage: [] }),
    probeLocalService: async () => IDENTITY,
    discoverListeningPorts: async () => ({
      ports: [{ port: 3000, processName: "node" }],
      method: "lsof",
      isComplete: false,
      isAvailable: true,
      note: null,
    }),
    renderReport,
    now: () => 1_000_000,
    ...overrides,
    signOut,
  };
}

interface RawResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function send(
  server: LocalWebServer,
  method: string,
  urlPath: string,
  options: { headers?: Record<string, string>; body?: string } = {},
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: "127.0.0.1",
        port: server.port,
        method,
        path: urlPath,
        headers: { host: `127.0.0.1:${server.port}`, ...options.headers },
      },
      (response) => {
        let body = "";
        response.on("data", (chunk: Buffer) => (body += chunk.toString()));
        response.on("end", () =>
          resolve({ status: response.statusCode ?? 0, headers: response.headers, body }),
        );
      },
    );
    request.on("error", reject);
    if (options.body !== undefined) request.write(options.body);
    request.end();
  });
}

function apiGet(server: LocalWebServer, urlPath: string): Promise<RawResponse> {
  return send(server, "GET", urlPath, { headers: { "x-pgard-token": TOKEN } });
}

function apiPost(
  server: LocalWebServer,
  urlPath: string,
  body: unknown = {},
): Promise<RawResponse> {
  return send(server, "POST", urlPath, {
    headers: {
      "x-pgard-token": TOKEN,
      origin: `http://127.0.0.1:${server.port}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

let server: LocalWebServer | null = null;
async function start(
  deps: ServerDeps,
  presetTargetPort: number | null = null,
  env: Record<string, string> = {},
): Promise<LocalWebServer> {
  server = await startLocalWebServer({
    projectRoot: "/work/my-project",
    presetTargetPort,
    env,
    assets: new Map([
      ["/", { body: Buffer.from("<html></html>"), contentType: "text/html; charset=utf-8" }],
    ]),
    deps,
    token: TOKEN,
  });
  return server;
}

afterEach(async () => {
  await server?.close();
  server = null;
});

async function waitFor<T>(read: () => Promise<T>, isDone: (value: T) => boolean): Promise<T> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const value = await read();
    if (isDone(value)) return value;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("timed out");
}

describe("local web server security", () => {
  it("binds to 127.0.0.1 and prints a URL with the token in the fragment", async () => {
    const running = await start(fakeDeps());
    expect(running.url).toBe(`http://127.0.0.1:${running.port}/#token=${TOKEN}`);
  });

  it("requires the session token on every API call", async () => {
    const running = await start(fakeDeps());
    expect((await send(running, "GET", "/api/session")).status).toBe(401);
    expect(
      (await send(running, "GET", "/api/session", { headers: { "x-pgard-token": "wrong" } }))
        .status,
    ).toBe(401);
    expect((await apiGet(running, "/api/session")).status).toBe(200);
  });

  it("rejects other Host headers (DNS rebinding) even with the token", async () => {
    const running = await start(fakeDeps());
    const response = await send(running, "GET", "/api/session", {
      headers: { host: `localhost:${running.port}`, "x-pgard-token": TOKEN },
    });
    expect(response.status).toBe(421);
    expect((await send(running, "GET", "/", { headers: { host: "evil.example" } })).status).toBe(
      421,
    );
  });

  it("rejects cross-origin and cross-site requests and state changes without Origin", async () => {
    const running = await start(fakeDeps());
    const foreign = await send(running, "GET", "/api/session", {
      headers: { "x-pgard-token": TOKEN, origin: "http://evil.example" },
    });
    expect(foreign.status).toBe(403);
    const crossSite = await send(running, "GET", "/api/session", {
      headers: { "x-pgard-token": TOKEN, "sec-fetch-site": "cross-site" },
    });
    expect(crossSite.status).toBe(403);
    const noOrigin = await send(running, "POST", "/api/auth/verify", {
      headers: { "x-pgard-token": TOKEN, "content-type": "application/json" },
      body: "{}",
    });
    expect(noOrigin.status).toBe(403);
  });

  it("never sends CORS headers and answers preflights with an error", async () => {
    const running = await start(fakeDeps());
    const preflight = await send(running, "OPTIONS", "/api/scan", {
      headers: { origin: "http://evil.example", "access-control-request-method": "POST" },
    });
    expect(preflight.status).toBeGreaterThanOrEqual(400);
    expect(preflight.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("sets no-store and a strict CSP on every response", async () => {
    const running = await start(fakeDeps());
    for (const response of [
      await send(running, "GET", "/"),
      await send(running, "GET", "/api/session"),
    ]) {
      expect(response.headers["cache-control"]).toBe("no-store");
      expect(response.headers["content-security-policy"]).toContain("default-src 'none'");
      expect(response.headers["x-frame-options"]).toBe("DENY");
    }
  });

  it("serves only built assets and has no file-reading route", async () => {
    const running = await start(fakeDeps());
    expect((await send(running, "GET", "/../../package.json")).status).toBe(404);
    expect((await send(running, "GET", "/%2e%2e/%2e%2e/etc/passwd")).status).toBe(404);
    expect((await apiGet(running, "/api/files?path=/etc/passwd")).status).toBe(404);
    expect((await send(running, "POST", "/")).status).toBe(405);
  });

  it("rejects non-JSON and oversized bodies", async () => {
    const running = await start(fakeDeps());
    const wrongType = await send(running, "POST", "/api/scan", {
      headers: {
        "x-pgard-token": TOKEN,
        origin: `http://127.0.0.1:${running.port}`,
        "content-type": "text/plain",
      },
      body: "scopes=code",
    });
    expect(wrongType.status).toBe(415);
    const huge = await apiPost(running, "/api/scan", {
      scopes: ["code"],
      padding: "x".repeat(20_000),
    });
    expect(huge.status).toBe(413);
  });

  it("exposes only the project name, never the absolute project path", async () => {
    const running = await start(fakeDeps());
    const body = (await apiGet(running, "/api/session")).body;
    expect(JSON.parse(body)).toMatchObject({
      projectName: "my-project",
      githubApp: { clientId: DEFAULT_GITHUB_APP_CLIENT_ID, source: "default" },
    });
    expect(body).not.toContain("/work/");
  });

  it("reports an env override as the GitHub App, and treats a blank one as unset", async () => {
    const session = async (env: Record<string, string>) => {
      const running = await start(fakeDeps(), null, env);
      const info = JSON.parse((await apiGet(running, "/api/session")).body).githubApp;
      await running.close();
      server = null;
      return info;
    };
    expect(await session({ PGARD_GITHUB_APP_CLIENT_ID: "Iv23liForkApp" })).toEqual({
      clientId: "Iv23liForkApp",
      slug: null,
      source: "env",
    });
    expect(await session({ PGARD_GITHUB_APP_CLIENT_ID: "  " })).toEqual({
      clientId: DEFAULT_GITHUB_APP_CLIENT_ID,
      slug: "pgard-jadenmeister",
      source: "default",
    });
  });

  it("warns when an overridden slug is mixed with the built-in client id", async () => {
    const warning = async (env: Record<string, string>) => {
      const running = await start(fakeDeps(), null, env);
      const info = JSON.parse((await apiGet(running, "/api/session")).body).githubAppWarning;
      await running.close();
      server = null;
      return info;
    };
    expect(await warning({ PGARD_GITHUB_APP_SLUG: "my-fork" })).toContain(
      "PGARD_GITHUB_APP_SLUG is set but PGARD_GITHUB_APP_CLIENT_ID is not",
    );
    expect(await warning({})).toBeNull();
    expect(
      await warning({ PGARD_GITHUB_APP_SLUG: "my-fork", PGARD_GITHUB_APP_CLIENT_ID: "Iv23liFork" }),
    ).toBeNull();
  });
});

const ALLOWED_VERIFY: ServerDeps["verifyProject"] = async () => outcome();

/** Runs the authorization check through the API and waits until it finishes. */
async function authorize(running: LocalWebServer): Promise<void> {
  await apiPost(running, "/api/auth/verify");
  await waitFor(
    () => apiGet(running, "/api/auth"),
    (response) => JSON.parse(response.body).status === "done",
  );
}

describe("local web port access authorization gate", () => {
  it("refuses to confirm a probe when the clock moved back since it was taken", async () => {
    let clock = 1_000_000;
    const running = await start(fakeDeps({ verifyProject: ALLOWED_VERIFY, now: () => clock }));
    await authorize(running);
    clock = 1_005_000;
    expect((await apiPost(running, "/api/ports/probe", { port: 3000 })).status).toBe(200);
    // Still inside the authorization window, but before the probe: fail closed.
    clock = 1_004_000;
    const backwards = await apiPost(running, "/api/target/confirm", {
      port: 3000,
      isConfirmed: true,
    });
    expect(backwards.status).toBe(409);
    expect(JSON.parse(backwards.body).error.code).toBe("probe_required");
    clock = 1_005_000;
    expect(
      (await apiPost(running, "/api/target/confirm", { port: 3000, isConfirmed: true })).status,
    ).toBe(200);
  });

  function spiedDeps(verifyProject?: ServerDeps["verifyProject"]) {
    const discoverListeningPorts = vi.fn(fakeDeps().discoverListeningPorts);
    const probeLocalService = vi.fn(async () => IDENTITY);
    const deps = fakeDeps({
      discoverListeningPorts,
      probeLocalService,
      ...(verifyProject ? { verifyProject } : {}),
    });
    return { deps, discoverListeningPorts, probeLocalService };
  }

  async function expectRefused(running: LocalWebServer): Promise<void> {
    for (const response of [
      await apiGet(running, "/api/ports"),
      await apiPost(running, "/api/ports/probe", { port: 3000 }),
      await apiPost(running, "/api/target/confirm", { port: 3000, isConfirmed: true }),
    ]) {
      expect(response.status).toBe(403);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe("authorization_required");
      expect(body.error.message).toMatch(/authoriz/i);
    }
  }

  it("refuses discovery and probes before any authorization check", async () => {
    const { deps, discoverListeningPorts, probeLocalService } = spiedDeps(ALLOWED_VERIFY);
    const running = await start(deps, 3000);
    await expectRefused(running);
    expect(discoverListeningPorts).not.toHaveBeenCalled();
    expect(probeLocalService).not.toHaveBeenCalled();
  });

  it("refuses discovery and probes after a blocked authorization", async () => {
    const { deps, discoverListeningPorts, probeLocalService } = spiedDeps();
    const running = await start(deps);
    await authorize(running);
    await expectRefused(running);
    const body = JSON.parse((await apiGet(running, "/api/ports")).body);
    expect(body.error.message).toContain("blocked");
    expect(discoverListeningPorts).not.toHaveBeenCalled();
    expect(probeLocalService).not.toHaveBeenCalled();
  });

  it("refuses while the check runs and after it fails", async () => {
    let finish: (allowed: boolean) => void = () => undefined;
    const { deps, discoverListeningPorts, probeLocalService } = spiedDeps(
      () =>
        new Promise((resolve, rejectVerify) => {
          finish = (allowed) =>
            allowed
              ? resolve(outcome(null, { repo: null, revision: null }))
              : rejectVerify(new Error("network"));
        }),
    );
    const running = await start(deps);
    await apiPost(running, "/api/auth/verify");
    await expectRefused(running);
    finish(false);
    await waitFor(
      () => apiGet(running, "/api/auth"),
      (response) => JSON.parse(response.body).status === "failed",
    );
    await expectRefused(running);
    expect(discoverListeningPorts).not.toHaveBeenCalled();
    expect(probeLocalService).not.toHaveBeenCalled();
  });

  it("allows discovery and probes after a passing authorization", async () => {
    const { deps, discoverListeningPorts, probeLocalService } = spiedDeps(ALLOWED_VERIFY);
    const running = await start(deps);
    await authorize(running);
    const ports = await apiGet(running, "/api/ports");
    expect(ports.status).toBe(200);
    expect(JSON.parse(ports.body).services).toHaveLength(1);
    expect((await apiPost(running, "/api/ports/probe", { port: 3000 })).status).toBe(200);
    expect(discoverListeningPorts).toHaveBeenCalledTimes(1);
    expect(probeLocalService).toHaveBeenCalledTimes(2);
  });

  it("closes the gate again on sign-out or a new check that is blocked", async () => {
    let failing: AuthorizationCheckId | null = null;
    const { deps, discoverListeningPorts, probeLocalService } = spiedDeps(async () =>
      outcome(failing),
    );
    const running = await start(deps);
    await authorize(running);
    expect((await apiGet(running, "/api/ports")).status).toBe(200);
    await apiPost(running, "/api/auth/sign-out");
    await expectRefused(running);
    await authorize(running);
    expect((await apiGet(running, "/api/ports")).status).toBe(200);
    failing = "current_access";
    await authorize(running);
    await expectRefused(running);
    expect(discoverListeningPorts).toHaveBeenCalledTimes(2);
    expect(probeLocalService).toHaveBeenCalledTimes(2);
  });

  it("requires all five checks passed, not just an allowed decision", async () => {
    const allowed = outcome();
    const malformed: AuthorizationOutcome[] = [
      { ...allowed, summary: { decision: "allowed", checks: [] } },
      { ...allowed, summary: { decision: "allowed", checks: allowed.summary.checks.slice(1) } },
      {
        ...allowed,
        summary: { decision: "allowed", checks: [...allowed.summary.checks].reverse() },
      },
      {
        ...allowed,
        summary: { decision: "allowed", checks: outcome("contribution").summary.checks },
      },
    ];
    let next = malformed[0]!;
    const { deps, discoverListeningPorts, probeLocalService } = spiedDeps(async () => next);
    const running = await start(deps);
    for (const candidate of malformed) {
      next = candidate;
      await authorize(running);
      await expectRefused(running);
    }
    expect(discoverListeningPorts).not.toHaveBeenCalled();
    expect(probeLocalService).not.toHaveBeenCalled();
  });

  /** A dependency call that waits until the test releases it; `called` settles when it starts. */
  function deferred<T>(value: T) {
    let release: () => void = () => undefined;
    let markCalled: () => void = () => undefined;
    const called = new Promise<void>((resolve) => (markCalled = resolve));
    const fn = vi.fn(
      () =>
        new Promise<T>((resolve) => {
          markCalled();
          release = () => resolve(value);
        }),
    );
    return { fn, called, release: () => release() };
  }

  const DISCOVERY: PortDiscoveryResult = {
    ports: [{ port: 3000, processName: "node" }],
    method: "lsof",
    isComplete: false,
    isAvailable: true,
    note: null,
  };

  it.each([
    ["signs out", (running: LocalWebServer) => apiPost(running, "/api/auth/sign-out")],
    ["re-verifies", (running: LocalWebServer) => authorize(running)],
  ])("sends no probe when the user %s while lsof runs", async (_label, interrupt) => {
    const lsof = deferred(DISCOVERY);
    const probeLocalService = vi.fn(async () => IDENTITY);
    const running = await start(
      fakeDeps({
        verifyProject: ALLOWED_VERIFY,
        discoverListeningPorts: lsof.fn,
        probeLocalService,
      }),
    );
    await authorize(running);
    const pending = apiGet(running, "/api/ports");
    await lsof.called;
    await interrupt(running);
    lsof.release();
    const response = await pending;
    expect(response.status).toBe(403);
    expect(JSON.parse(response.body).error.code).toBe("authorization_required");
    expect(lsof.fn).toHaveBeenCalledTimes(1);
    expect(probeLocalService).not.toHaveBeenCalled();
  });

  it("returns no port list when the user signs out while the probes run", async () => {
    const probe = deferred(IDENTITY);
    const running = await start(
      fakeDeps({ verifyProject: ALLOWED_VERIFY, probeLocalService: probe.fn }),
    );
    await authorize(running);
    const pending = apiGet(running, "/api/ports");
    await probe.called;
    await apiPost(running, "/api/auth/sign-out");
    probe.release();
    const response = await pending;
    expect(response.status).toBe(403);
    expect(JSON.parse(response.body).error.code).toBe("authorization_required");
    expect(response.body).not.toContain("Shop dev");
  });

  it.each([
    ["signs out", (running: LocalWebServer) => apiPost(running, "/api/auth/sign-out")],
    ["re-verifies", (running: LocalWebServer) => authorize(running)],
  ])("aborts probes in flight when the user %s", async (_label, interrupt) => {
    const signals: AbortSignal[] = [];
    let markCalled: () => void = () => undefined;
    const called = new Promise<void>((resolve) => (markCalled = resolve));
    // Like the real probe: it answers only when the service does, or "Cancelled." on abort.
    const probeLocalService = vi.fn(
      (_port: number, { signal }: { signal: AbortSignal }) =>
        new Promise<ServiceIdentity>((resolve) => {
          signals.push(signal);
          signal.addEventListener("abort", () =>
            resolve({ ...IDENTITY, status: null, isHttp: false, error: "Cancelled." }),
          );
          markCalled();
        }),
    );
    const running = await start(fakeDeps({ verifyProject: ALLOWED_VERIFY, probeLocalService }));
    await authorize(running);
    const pending = apiPost(running, "/api/ports/probe", { port: 3000 });
    await called;
    expect(signals[0]?.aborted).toBe(false);
    await interrupt(running);
    expect(signals[0]?.aborted).toBe(true);
    expect((await pending).status).toBe(403);
  });

  it("does not keep a probe that finished after sign-out", async () => {
    const probe = deferred(IDENTITY);
    const running = await start(
      fakeDeps({ verifyProject: ALLOWED_VERIFY, probeLocalService: probe.fn }),
    );
    await authorize(running);
    const pending = apiPost(running, "/api/ports/probe", { port: 3000 });
    await probe.called;
    await apiPost(running, "/api/auth/sign-out");
    probe.release();
    expect((await pending).status).toBe(403);
    // Authorized again: the probe from the signed-out session cannot be confirmed.
    await authorize(running);
    const confirm = await apiPost(running, "/api/target/confirm", {
      port: 3000,
      isConfirmed: true,
    });
    expect(confirm.status).toBe(409);
    expect(JSON.parse(confirm.body).error.code).toBe("probe_required");
  });

  it("does not confirm a probe made under an earlier authorization", async () => {
    const running = await start(fakeDeps({ verifyProject: ALLOWED_VERIFY }));
    await authorize(running);
    expect((await apiPost(running, "/api/ports/probe", { port: 3000 })).status).toBe(200);
    await authorize(running);
    const confirm = await apiPost(running, "/api/target/confirm", {
      port: 3000,
      isConfirmed: true,
    });
    expect(confirm.status).toBe(409);
    expect(JSON.parse(confirm.body).error.code).toBe("probe_required");
  });

  it("expires an allowed authorization after 30 minutes", async () => {
    let clock = 1_000_000;
    const { deps, discoverListeningPorts } = spiedDeps(ALLOWED_VERIFY);
    deps.now = () => clock;
    const running = await start(deps);
    await authorize(running);
    clock += 30 * 60 * 1000;
    expect((await apiGet(running, "/api/ports")).status).toBe(200);
    clock += 1;
    await expectRefused(running);
    const body = JSON.parse((await apiGet(running, "/api/ports")).body);
    expect(body.error.message).toContain("30 minutes");
    await authorize(running);
    expect((await apiGet(running, "/api/ports")).status).toBe(200);
    expect(discoverListeningPorts).toHaveBeenCalledTimes(2);
  });

  it("tells the browser when port access expires", async () => {
    let failing: AuthorizationCheckId | null = null;
    const { deps } = spiedDeps(async () => outcome(failing));
    const running = await start(deps);
    expect(JSON.parse((await apiGet(running, "/api/auth")).body).expiresAt).toBeNull();
    await authorize(running);
    const allowed = JSON.parse((await apiGet(running, "/api/auth")).body);
    expect(allowed.expiresAt).toBe(1_000_000 + 30 * 60 * 1000);
    failing = "owner_approval";
    await authorize(running);
    expect(JSON.parse((await apiGet(running, "/api/auth")).body).expiresAt).toBeNull();
  });

  it("closes the gate when the clock moves back before the check finished", async () => {
    let clock = 1_000_000;
    const { deps, discoverListeningPorts } = spiedDeps(ALLOWED_VERIFY);
    deps.now = () => clock;
    const running = await start(deps);
    await authorize(running);
    expect((await apiGet(running, "/api/ports")).status).toBe(200);
    clock -= 60 * 60 * 1000;
    await expectRefused(running);
    const body = JSON.parse((await apiGet(running, "/api/ports")).body);
    expect(body.error.message).toContain("clock moved back");
    expect(discoverListeningPorts).toHaveBeenCalledTimes(1);
  });

  it("ignores anything the client sends about authorization", async () => {
    const { deps, discoverListeningPorts, probeLocalService } = spiedDeps();
    const running = await start(deps);
    const response = await apiPost(running, "/api/ports/probe", {
      port: 3000,
      authorization: { decision: "allowed" },
      isAuthorized: true,
    });
    expect(response.status).toBe(403);
    expect(discoverListeningPorts).not.toHaveBeenCalled();
    expect(probeLocalService).not.toHaveBeenCalled();
  });
});

describe("local web target confirmation", () => {
  it("only confirms the port whose identity was just probed", async () => {
    let clock = 1_000_000;
    const running = await start(fakeDeps({ now: () => clock, verifyProject: ALLOWED_VERIFY }));
    await authorize(running);
    expect(
      (await apiPost(running, "/api/target/confirm", { port: 3000, isConfirmed: true })).status,
    ).toBe(409);
    expect((await apiPost(running, "/api/ports/probe", { port: 3000 })).status).toBe(200);
    expect(
      (await apiPost(running, "/api/target/confirm", { port: 3001, isConfirmed: true })).status,
    ).toBe(409);
    expect((await apiPost(running, "/api/target/confirm", { port: 3000 })).status).toBe(400);
    clock += 11 * 60 * 1000;
    expect(
      (await apiPost(running, "/api/target/confirm", { port: 3000, isConfirmed: true })).status,
    ).toBe(409);
    await apiPost(running, "/api/ports/probe", { port: 3000 });
    const confirmed = await apiPost(running, "/api/target/confirm", {
      port: 3000,
      isConfirmed: true,
    });
    expect(JSON.parse(confirmed.body)).toEqual({
      port: 3000,
      origin: "http://127.0.0.1:3000",
      title: "Shop dev",
    });
  });

  it("refuses ports that did not answer HTTP and invalid ports", async () => {
    const running = await start(
      fakeDeps({
        probeLocalService: async () => ({ ...IDENTITY, isHttp: false, status: null }),
        verifyProject: ALLOWED_VERIFY,
      }),
    );
    await authorize(running);
    await apiPost(running, "/api/ports/probe", { port: 3000 });
    expect(
      (await apiPost(running, "/api/target/confirm", { port: 3000, isConfirmed: true })).status,
    ).toBe(409);
    expect((await apiPost(running, "/api/ports/probe", { port: 70000 })).status).toBe(400);
    expect((await apiPost(running, "/api/ports/probe", { port: "3000" })).status).toBe(400);
  });
});

describe("local web scans", () => {
  it("runs scans through runScan with the server-side confirmed target only", async () => {
    const requests: ScanRequest[] = [];
    const running = await start(
      fakeDeps({
        verifyProject: ALLOWED_VERIFY,
        runScan: async (request) => {
          requests.push(request);
          return result({ requestedScopes: request.scopes });
        },
      }),
    );
    await apiPost(running, "/api/scan", {
      scopes: ["web", "code"],
      webTarget: { port: 9999, confirmedByUser: true },
    });
    await waitFor(
      () => apiGet(running, "/api/scan"),
      (response) => JSON.parse(response.body).status === "done",
    );
    expect(requests[0]).toEqual({
      projectRoot: "/work/my-project",
      scopes: ["code", "web"],
      webTarget: null,
    });

    await authorize(running);
    await apiPost(running, "/api/ports/probe", { port: 3000 });
    await apiPost(running, "/api/target/confirm", { port: 3000, isConfirmed: true });
    await apiPost(running, "/api/scan", { scopes: ["web"] });
    await waitFor(
      () => apiGet(running, "/api/scan"),
      (response) => JSON.parse(response.body).status === "done",
    );
    expect(requests[1]?.webTarget).toMatchObject({ port: 3000, confirmedByUser: true });
  });

  it("validates scopes and allows one scan at a time", async () => {
    let release: () => void = () => undefined;
    const running = await start(
      fakeDeps({
        runScan: () =>
          new Promise((resolve) => {
            release = () => resolve(result());
          }),
      }),
    );
    expect((await apiPost(running, "/api/scan", { scopes: [] })).status).toBe(400);
    expect((await apiPost(running, "/api/scan", { scopes: ["remote"] })).status).toBe(400);
    const removed = await apiPost(running, "/api/scan", { scopes: ["code", "dependencies"] });
    expect(removed.status).toBe(400);
    expect(removed.body).toContain("Valid scopes: code, history, web.");
    expect((await apiPost(running, "/api/scan", { scopes: ["code"] })).status).toBe(200);
    expect((await apiPost(running, "/api/scan", { scopes: ["code"] })).status).toBe(409);
    release();
  });

  it("shows the device code while the authorization check waits", async () => {
    let onUserCode:
      ((code: { userCode: string; verificationUri: string; expiresIn: number }) => void) | null =
      null;
    let finish: () => void = () => undefined;
    const deps = fakeDeps();
    deps.createSessionProvider = (options) => {
      onUserCode = options.onUserCode;
      return Object.assign(async () => ({}) as never, {
        invalidate: vi.fn(),
        signOut: deps.signOut,
      }) as never;
    };
    deps.verifyProject = () =>
      new Promise((resolve) => {
        onUserCode?.({
          userCode: "ABCD-1234",
          verificationUri: "https://github.com/login/device",
          expiresIn: 900,
        });
        finish = () => resolve(outcome("repository", { repo: null, revision: null }));
      });
    const running = await start(deps);
    await apiPost(running, "/api/auth/verify");
    const pending = JSON.parse((await apiGet(running, "/api/auth")).body);
    expect(pending).toMatchObject({ status: "running", deviceCode: { userCode: "ABCD-1234" } });
    finish();
    const done = await waitFor(
      () => apiGet(running, "/api/auth"),
      (response) => JSON.parse(response.body).status === "done",
    );
    expect(JSON.parse(done.body).deviceCode).toBeNull();
  });

  it("opens only a github.com device page through openGitHubPage, when one is given", async () => {
    let onUserCode:
      ((code: { userCode: string; verificationUri: string; expiresIn: number }) => void) | null =
      null;
    const deps = fakeDeps();
    deps.createSessionProvider = (options) => {
      onUserCode = options.onUserCode;
      return Object.assign(async () => ({}) as never, {
        invalidate: vi.fn(),
        signOut: deps.signOut,
      }) as never;
    };
    const openGitHubPage = vi.fn();
    server = await startLocalWebServer({
      projectRoot: "/work/my-project",
      presetTargetPort: null,
      env: {},
      assets: new Map(),
      deps,
      token: TOKEN,
      openGitHubPage,
    });
    const show = (verificationUri: string) =>
      onUserCode?.({ userCode: "ABCD-1234", verificationUri, expiresIn: 900 });
    show("https://github.com/login/device");
    show("https://evil.test/login/device");
    expect(openGitHubPage).toHaveBeenCalledExactlyOnceWith("https://github.com/login/device");
  });
});

describe("local web report download", () => {
  async function runScan(running: LocalWebServer): Promise<void> {
    await apiPost(running, "/api/scan", { scopes: ["code"] });
    await waitFor(
      () => apiGet(running, "/api/scan"),
      (response) => JSON.parse(response.body).status === "done",
    );
  }

  it("downloads the same HTML the file export renders, as an attachment", async () => {
    const scanResult = result({
      findings: [
        {
          id: "f1",
          ruleId: "PG-SECRET-002",
          title: "Secret in a tracked file",
          severity: "high",
          status: "suspected",
          category: "injection",
          references: { cwe: [], owasp: [], cve: [] },
          confidence: "low",
          location: { kind: "file", path: "src/a.ts", line: 3, commit: null, url: null },
          evidence: "credential assignment in a tracked file (value redacted)",
          impact: "impact",
          recommendation: "rotate",
          sources: ["code"],
        },
      ],
    });
    const running = await start(fakeDeps({ runScan: async () => scanResult }));
    await runScan(running);
    const response = await apiGet(running, "/api/reports/html");
    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toBe("text/html; charset=utf-8");
    expect(response.headers["content-disposition"]).toBe(
      'attachment; filename="pgard-report-owner-name-20261024000000.html"',
    );
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.headers["content-security-policy"]).toContain("default-src 'none'");
    expect(response.headers["x-content-type-options"]).toBe("nosniff");
    expect(response.body).toBe(renderHtmlReport(scanResult));
    // Redaction is preserved: the evidence is the already redacted text.
    expect(response.body).toContain("credential assignment in a tracked file (value redacted)");
  });

  it("serves only rule texts on /api/rule-texts and needs the token", async () => {
    const running = await start(fakeDeps());
    const response = await apiGet(running, "/api/rule-texts");
    expect(response.status).toBe(200);
    const texts = JSON.parse(response.body) as Record<string, { title: { ko: string } }>;
    expect(Object.keys(texts)).toContain("PG-SQL-001");
    expect(Object.keys(texts)).toContain("PG-WEB-013");
    expect(texts["PG-SQL-001"]?.title.ko).toMatch(/[가-힣]/);
    expect(Object.keys(texts["PG-SQL-001"] ?? {}).sort()).toEqual([
      "impact",
      "recommendation",
      "title",
    ]);
    expect((await send(running, "GET", "/api/rule-texts")).status).toBe(401);
  });

  it("renders the HTML report in Korean for ?lang=ko and rejects other languages", async () => {
    const scanResult = result({
      findings: [
        {
          id: "f1",
          ruleId: "PG-SQL-001",
          title: "SQL built from dynamic strings in pg/mysql2 query",
          severity: "high",
          status: "suspected",
          category: "injection",
          references: { cwe: [], owasp: [], cve: [] },
          confidence: "low",
          location: { kind: "file", path: "src/a.ts", line: 3, commit: null, url: null },
          evidence: "concat (value redacted)",
          impact: "x",
          recommendation: "y",
          sources: ["code"],
        },
      ],
    });
    const running = await start(fakeDeps({ runScan: async () => scanResult }));
    await runScan(running);
    const korean = await apiGet(running, "/api/reports/html?lang=ko");
    expect(korean.status).toBe(200);
    expect(korean.body).toContain('<html lang="ko">');
    expect(korean.body).toContain("pg/mysql2 쿼리에 동적 문자열로 만든 SQL");
    expect((await apiGet(running, "/api/reports/html?lang=fr")).status).toBe(400);
    expect((await apiGet(running, "/api/reports/html")).body).toContain('<html lang="en">');
  });

  it("downloads a PDF with the PDF content type", async () => {
    const running = await start(fakeDeps());
    await runScan(running);
    const response = await apiGet(running, "/api/reports/pdf");
    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toBe("application/pdf");
    expect(response.headers["content-disposition"]).toMatch(
      /^attachment; filename="pgard-report-owner-name-\d{14}\.pdf"$/,
    );
    expect(response.body.startsWith("%PDF-")).toBe(true);
  });

  it("needs the session token (and our Host) like every API call", async () => {
    const running = await start(fakeDeps());
    await runScan(running);
    const noToken = await send(running, "GET", "/api/reports/html");
    expect(noToken.status).toBe(401);
    expect(noToken.body).not.toContain("<html");
    const badToken = await send(running, "GET", "/api/reports/pdf", {
      headers: { "x-pgard-token": "wrong" },
    });
    expect(badToken.status).toBe(401);
    const badHost = await send(running, "GET", "/api/reports/html", {
      headers: { host: "evil.test", "x-pgard-token": TOKEN },
    });
    expect(badHost.status).toBe(421);
  });

  it("does not accept the token from the query string or a cookie", async () => {
    const running = await start(fakeDeps());
    await runScan(running);
    for (const format of ["html", "pdf"]) {
      const query = await send(running, "GET", `/api/reports/${format}?token=${TOKEN}`);
      expect(query.status).toBe(401);
      const cookie = await send(running, "GET", `/api/reports/${format}`, {
        headers: { cookie: `x-pgard-token=${TOKEN}; token=${TOKEN}` },
      });
      expect(cookie.status).toBe(401);
      expect(cookie.headers["content-disposition"]).toBeUndefined();
    }
  });

  it("refuses a foreign Origin and cross-site fetches even with the token", async () => {
    const running = await start(fakeDeps());
    await runScan(running);
    const foreign = await send(running, "GET", "/api/reports/html", {
      headers: { "x-pgard-token": TOKEN, origin: "http://evil.test" },
    });
    expect(foreign.status).toBe(403);
    expect(foreign.headers["content-disposition"]).toBeUndefined();
    const crossSite = await send(running, "GET", "/api/reports/pdf", {
      headers: { "x-pgard-token": TOKEN, "sec-fetch-site": "cross-site" },
    });
    expect(crossSite.status).toBe(403);
    const sameOrigin = await send(running, "GET", "/api/reports/html", {
      headers: {
        "x-pgard-token": TOKEN,
        origin: `http://127.0.0.1:${running.port}`,
        "sec-fetch-site": "same-origin",
      },
    });
    expect(sameOrigin.status).toBe(200);
  });

  it("refuses to export a blocked result", async () => {
    const running = await start(
      fakeDeps({ runScan: async () => result({ overallStatus: "blocked" }) }),
    );
    await runScan(running);
    for (const format of ["html", "pdf"]) {
      const response = await apiGet(running, `/api/reports/${format}`);
      expect(response.status).toBe(409);
      expect(JSON.parse(response.body).error.code).toBe("no_result");
      expect(response.headers["content-disposition"]).toBeUndefined();
    }
  });

  it("refuses without a scan result and for unknown formats; the path-writing route is gone", async () => {
    const running = await start(fakeDeps());
    expect((await apiGet(running, "/api/reports/html")).status).toBe(409);
    await runScan(running);
    expect((await apiGet(running, "/api/reports/docx")).status).toBe(404);
    expect(
      (await apiPost(running, "/api/reports", { format: "html", outputDir: "/tmp" })).status,
    ).toBe(404);
  });

  it("names the file with ASCII-safe characters only", () => {
    const named = (repo: string | null): string =>
      reportDownloadName(result({ target: { repo, revision: null, webOrigin: null } }), "html");
    expect(named("owner/na me")).toBe("pgard-report-owner-name-20261024000000.html");
    expect(named('own\u00e9r/\u00fcber"x\r\n.git')).toBe(
      "pgard-report-ownr-berx.git-20261024000000.html",
    );
    expect(named("../../etc/passwd")).toBe("pgard-report--..-etc-passwd-20261024000000.html");
    expect(named(null)).toBe("pgard-report-local-20261024000000.html");
    expect(named("\u20ac\u20ac")).toBe("pgard-report-local-20261024000000.html");
    expect(named("a".repeat(500))).toHaveLength(
      "pgard-report-".length + 80 + "-20261024000000.html".length,
    );
  });
});

describe("local web shutdown", () => {
  it("signs out and discards results on close", async () => {
    const deps = fakeDeps();
    const running = await start(deps);
    await apiPost(running, "/api/scan", { scopes: ["code"] });
    await waitFor(
      () => apiGet(running, "/api/scan"),
      (response) => JSON.parse(response.body).status === "done",
    );
    await running.close();
    server = null;
    expect(deps.signOut).toHaveBeenCalled();
    expect(running.state.scan.result).toBeNull();
    expect(running.state.confirmedTarget).toBeNull();
  });
});

/**
 * Provider that behaves like a pending device flow: announces a code, then waits until its
 * signal is aborted. Records every signal it was created with.
 */
function pendingDeviceFlowDeps(overrides: Partial<ServerDeps> = {}) {
  const signals: AbortSignal[] = [];
  const deps = fakeDeps(overrides);
  deps.createSessionProvider = (options) => {
    signals.push(options.signal);
    const provider = () =>
      new Promise<never>((_resolve, rejectSignIn) => {
        options.onUserCode({
          userCode: "WXYZ-9876",
          verificationUri: "https://github.com/login/device",
          expiresIn: 900,
        });
        options.signal.addEventListener("abort", () => rejectSignIn(new Error("aborted")), {
          once: true,
        });
      });
    return Object.assign(provider, { invalidate: vi.fn(), signOut: deps.signOut }) as never;
  };
  deps.runScan = async (_request, scanDeps) => {
    await scanDeps.authorization.getGitHubSession();
    return result();
  };
  return { deps, signals };
}

describe("local web device flow lifecycle", () => {
  it("shows the device code of a sign-in started by a scan and clears it afterwards", async () => {
    const { deps, signals } = pendingDeviceFlowDeps();
    const running = await start(deps);
    await apiPost(running, "/api/scan", { scopes: ["code"] });
    const waiting = await waitFor(
      () => apiGet(running, "/api/scan"),
      (response) => JSON.parse(response.body).deviceCode !== null,
    );
    expect(JSON.parse(waiting.body)).toMatchObject({
      status: "running",
      deviceCode: { userCode: "WXYZ-9876" },
    });
    // Cancel while the sign-in waits: cancelled at once, sign-in aborted, code cleared.
    const cancelled = JSON.parse((await apiPost(running, "/api/scan/cancel")).body);
    expect(cancelled).toMatchObject({ status: "cancelled", deviceCode: null });
    expect(signals[0]?.aborted).toBe(true);
    // A new scan can start right away (no 409) with a fresh, unaborted sign-in.
    expect((await apiPost(running, "/api/scan", { scopes: ["code"] })).status).toBe(200);
    expect(signals).toHaveLength(2);
    expect(signals[1]?.aborted).toBe(false);
  });

  it("stops a pending sign-in on sign-out and ignores the abandoned verify", async () => {
    const { deps, signals } = pendingDeviceFlowDeps();
    deps.verifyProject = async (_root, authorization) => {
      await authorization.getGitHubSession();
      return outcome();
    };
    const running = await start(deps);
    await apiPost(running, "/api/auth/verify");
    await waitFor(
      () => apiGet(running, "/api/auth"),
      (response) => JSON.parse(response.body).deviceCode !== null,
    );
    const signedOut = JSON.parse((await apiPost(running, "/api/auth/sign-out")).body);
    expect(signedOut).toMatchObject({ status: "idle", deviceCode: null });
    expect(signals[0]?.aborted).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(JSON.parse((await apiGet(running, "/api/auth")).body).status).toBe("idle");
  });

  it("aborts a pending sign-in when the server closes", async () => {
    const { deps, signals } = pendingDeviceFlowDeps();
    const running = await start(deps);
    await apiPost(running, "/api/scan", { scopes: ["code"] });
    await waitFor(
      () => apiGet(running, "/api/scan"),
      (response) => JSON.parse(response.body).deviceCode !== null,
    );
    await running.close();
    server = null;
    expect(signals.every((signal) => signal.aborted)).toBe(true);
  });
});

const KEYCHAIN_CLIENT_ID = "Iv23liWebTest";
const KEYCHAIN_ENV = { PGARD_GITHUB_APP_CLIENT_ID: KEYCHAIN_CLIENT_ID };
const GITHUB_ACCESS_TOKEN = ["ghu", "webSecretAccessTokenForTests00"].join("_");
const GITHUB_REFRESH_TOKEN = ["ghr", "webSecretRefreshTokenForTests0"].join("_");
const KEYCHAIN_KEY = { service: "pgard", account: `github:github.com:${KEYCHAIN_CLIENT_ID}` };

function keychainEntry(): string {
  return JSON.stringify({
    version: 1,
    host: "github.com",
    clientId: KEYCHAIN_CLIENT_ID,
    accessToken: GITHUB_ACCESS_TOKEN,
    expiresAt: Date.UTC(2099, 0, 1),
    refreshToken: GITHUB_REFRESH_TOKEN,
    refreshTokenExpiresAt: Date.UTC(2099, 0, 1),
    login: "octo",
    userId: 7,
    savedAt: 0,
  });
}

/**
 * Server deps with the real session provider over a fake keychain and a fake GitHub, and a
 * verifyProject that signs in and reads the user the way the gate does.
 */
function keychainDeps(store: CredentialStore) {
  let deviceCodeRequests = 0;
  const githubFetch = async (url: string) => {
    const json = (body: unknown) => ({ status: 200, ok: true, json: async () => body });
    if (url.endsWith("/login/device/code")) {
      deviceCodeRequests += 1;
      return json({
        device_code: "device-code-internal",
        user_code: "WEB1-2345",
        verification_uri: "https://github.com/login/device",
        expires_in: 900,
        interval: 5,
      });
    }
    if (url.endsWith("/login/oauth/access_token")) {
      return json({ access_token: GITHUB_ACCESS_TOKEN, refresh_token: GITHUB_REFRESH_TOKEN });
    }
    return json({ id: 7, login: "octo", name: null, email: null });
  };
  const deps = fakeDeps({
    credentialStore: store,
    createSessionProvider: (options) =>
      createDeviceFlowSessionProvider({
        ...options,
        clientId: KEYCHAIN_CLIENT_ID,
        credentialStore: store,
        fetch: githubFetch,
        sleep: async () => {},
      }),
    verifyProject: async (_root, authorization) => {
      const session = await authorization.getGitHubSession();
      const user = await session.client.getAuthenticatedUser();
      return { ...outcome(), account: { login: user.login, userId: user.id } };
    },
  });
  return { deps, deviceCodeRequests: () => deviceCodeRequests };
}

function expectNoGitHubToken(body: string): void {
  expect(body).not.toContain(GITHUB_ACCESS_TOKEN);
  expect(body).not.toContain(GITHUB_REFRESH_TOKEN);
  expect(body).not.toContain("device-code-internal");
}

describe("local web keychain sign-in", () => {
  it("closes port access when pgard login switched to another account", async () => {
    const store = createInMemoryCredentialStore();
    await store.set(KEYCHAIN_KEY, keychainEntry());
    const { deps } = keychainDeps(store);
    const running = await start(deps, null, KEYCHAIN_ENV);
    await authorize(running);
    expect((await apiGet(running, "/api/ports")).status).toBe(200);

    // `pgard login` in another terminal: same account, new token. Nothing changes.
    const entry = JSON.parse(keychainEntry());
    await store.set(
      KEYCHAIN_KEY,
      JSON.stringify({ ...entry, accessToken: ["ghu", "sameAccountNewToken00000000"].join("_") }),
    );
    expect((await apiGet(running, "/api/ports")).status).toBe(200);

    // ...then another account: the old account's allowed check no longer opens port access.
    await store.set(
      KEYCHAIN_KEY,
      JSON.stringify({
        ...entry,
        accessToken: ["ghu", "otherAccountToken00000000000"].join("_"),
        login: "hubot",
        userId: 8,
      }),
    );
    const ports = await apiGet(running, "/api/ports");
    expect(ports.status).toBe(403);
    expect(JSON.parse(ports.body).error.code).toBe("authorization_required");
    const auth = JSON.parse((await apiGet(running, "/api/auth")).body);
    expect(auth).toMatchObject({ status: "idle", summary: null, expiresAt: null });
    expect(auth.signInNotice).toContain("The GitHub account changed since the last check");
    expect((await apiPost(running, "/api/ports/probe", { port: 3000 })).status).toBe(403);
  });

  describe("each route notices an account switch on its own (#162)", () => {
    async function authorizedThenSwitched() {
      const store = createInMemoryCredentialStore();
      await store.set(KEYCHAIN_KEY, keychainEntry());
      const { deps } = keychainDeps(store);
      const running = await start(deps, null, KEYCHAIN_ENV);
      await authorize(running);
      const switchAccount = () =>
        store.set(
          KEYCHAIN_KEY,
          JSON.stringify({
            ...JSON.parse(keychainEntry()),
            accessToken: ["ghu", "otherAccountToken00000000000"].join("_"),
            login: "hubot",
            userId: 8,
          }),
        );
      return { running, switchAccount };
    }

    it("GET /api/auth resets the check", async () => {
      const { running, switchAccount } = await authorizedThenSwitched();
      await switchAccount();
      const auth = JSON.parse((await apiGet(running, "/api/auth")).body);
      expect(auth).toMatchObject({ status: "idle", summary: null, expiresAt: null });
      expect(auth.signInNotice).toContain("The GitHub account changed since the last check");
    });

    it("POST /api/ports/probe is refused", async () => {
      const { running, switchAccount } = await authorizedThenSwitched();
      await switchAccount();
      const probe = await apiPost(running, "/api/ports/probe", { port: 3000 });
      expect(probe.status).toBe(403);
      expect(JSON.parse(probe.body).error.code).toBe("authorization_required");
    });

    it("POST /api/target/confirm is refused after a probe made under the old account", async () => {
      const { running, switchAccount } = await authorizedThenSwitched();
      expect((await apiPost(running, "/api/ports/probe", { port: 3000 })).status).toBe(200);
      await switchAccount();
      const confirm = await apiPost(running, "/api/target/confirm", {
        port: 3000,
        isConfirmed: true,
      });
      expect(confirm.status).toBe(403);
      expect(JSON.parse(confirm.body).error.code).toBe("authorization_required");
    });
  });

  it("settles on the new account when pgard login replaced the sign-in during a refresh (#162)", async () => {
    const tokenA = ["ghu", "accountAExpiredToken00000"].join("_");
    const tokenARefreshed = ["ghu", "accountARefreshedToken000"].join("_");
    const tokenB = ["ghu", "accountBLoginToken0000000"].join("_");
    const store = createInMemoryCredentialStore();
    const entry = JSON.parse(keychainEntry());
    await store.set(
      KEYCHAIN_KEY,
      JSON.stringify({ ...entry, accessToken: tokenA, expiresAt: Date.UTC(2000, 0, 1) }),
    );
    const userOf: Record<string, { id: number; login: string }> = {
      [tokenARefreshed]: { id: 7, login: "octo" },
      [tokenB]: { id: 8, login: "hubot" },
    };
    const githubFetch = async (
      url: string,
      init: { body?: string; headers: Record<string, string> },
    ) => {
      const json = (body: unknown) => ({ status: 200, ok: true, json: async () => body });
      if (url.endsWith("/login/oauth/access_token")) {
        // `pgard login` (account B) saves its entry while GitHub rotates account A's token.
        await store.set(
          KEYCHAIN_KEY,
          JSON.stringify({
            ...entry,
            accessToken: tokenB,
            refreshToken: ["ghr", "accountBRefreshToken0000"].join("_"),
            login: "hubot",
            userId: 8,
          }),
        );
        return json({ access_token: tokenARefreshed, refresh_token: GITHUB_REFRESH_TOKEN });
      }
      const user = userOf[(init.headers.Authorization ?? "").replace("Bearer ", "")];
      return user
        ? json({ ...user, name: null, email: null })
        : { status: 401, ok: false, json: async () => ({}) };
    };
    let verifications = 0;
    const deps = fakeDeps({
      credentialStore: store,
      createSessionProvider: (options) =>
        createDeviceFlowSessionProvider({
          ...options,
          clientId: KEYCHAIN_CLIENT_ID,
          credentialStore: store,
          fetch: githubFetch,
          sleep: async () => {},
        }),
      verifyProject: async (_root, authorization) => {
        const session = await authorization.getGitHubSession();
        const user = await session.client.getAuthenticatedUser();
        verifications += 1;
        return { ...outcome(), account: { login: user.login, userId: user.id } };
      },
    });
    const running = await start(deps, null, KEYCHAIN_ENV);

    // First check: refreshes account A while the keychain flips to B (A's session is not stored).
    // Polling /api/auth would already reset it, so wait for the check to finish without polling.
    await apiPost(running, "/api/auth/verify");
    await waitFor(
      async () => verifications,
      (count) => count === 1,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    // The port route sees the keychain holds B, so A's check is reset...
    expect((await apiGet(running, "/api/ports")).status).toBe(403);
    // ...and the next check follows the keychain to B instead of reusing the cached A session.
    await authorize(running);
    expect((await apiGet(running, "/api/ports")).status).toBe(200);
    expect((await apiGet(running, "/api/ports")).status).toBe(200);
    const auth = JSON.parse((await apiGet(running, "/api/auth")).body);
    expect(auth.status).toBe("done");
    expect(auth.signInNotice).toContain("hubot");
  });

  it("ties the check to the account the gate ran with, not the one adopted last (#162)", async () => {
    const store = createInMemoryCredentialStore();
    const entry = JSON.parse(keychainEntry());
    // The keychain holds account B (id 8) ...
    await store.set(KEYCHAIN_KEY, JSON.stringify({ ...entry, login: "hubot", userId: 8 }));
    let notify: ((notice: SignInNotice) => void) | null = null;
    const provider = Object.assign(async () => ({}) as never, {
      invalidate: () => {},
      signOut: () => {},
    });
    const deps = fakeDeps({
      credentialStore: store,
      createSessionProvider: (options) => {
        notify = options.onNotice;
        return provider as never;
      },
      verifyProject: async () => {
        // ... and the provider adopts it while the gate itself ran as account A (id 7).
        notify?.({ kind: "reused", login: "hubot", userId: 8, isRefreshed: false });
        return { ...outcome(), account: { login: "octo", userId: 7 } };
      },
    });
    const running = await start(deps, null, KEYCHAIN_ENV);
    await apiPost(running, "/api/auth/verify");
    await new Promise((resolve) => setTimeout(resolve, 50));
    // The check ran as A, the keychain holds B: port access must be closed.
    const ports = await apiGet(running, "/api/ports");
    expect(ports.status).toBe(403);
    expect(JSON.parse(ports.body).error.code).toBe("authorization_required");
  });

  it("reuses the keychain sign-in on the server without a device code or sending the token", async () => {
    const store = createInMemoryCredentialStore();
    await store.set(KEYCHAIN_KEY, keychainEntry());
    const { deps, deviceCodeRequests } = keychainDeps(store);
    const running = await start(deps, null, KEYCHAIN_ENV);
    const bodies: string[] = [];
    const record = async (response: Promise<RawResponse>) => {
      const value = await response;
      bodies.push(value.body);
      return value;
    };

    await record(apiGet(running, "/api/session"));
    const before = JSON.parse((await record(apiGet(running, "/api/auth"))).body);
    expect(before.storedSignIn).toEqual({ status: "stored", login: "octo" });

    await record(apiPost(running, "/api/auth/verify"));
    const done = await waitFor(
      () => record(apiGet(running, "/api/auth")),
      (response) => JSON.parse(response.body).status === "done",
    );
    const auth = JSON.parse(done.body);
    expect(auth.deviceCode).toBeNull();
    expect(auth.summary.decision).toBe("allowed");
    expect(auth.signInNotice).toContain(
      "Using the GitHub sign-in for octo saved in the OS keychain",
    );
    expect(deviceCodeRequests()).toBe(0);

    await record(apiPost(running, "/api/scan", { scopes: ["code"] }));
    await record(apiGet(running, "/api/scan"));
    await record(apiPost(running, "/api/auth/sign-out", { removeStored: true }));
    for (const body of bodies) expectNoGitHubToken(body);
  });

  it("saves a dashboard device-flow sign-in to the keychain for the CLI to reuse", async () => {
    const store = createInMemoryCredentialStore();
    const { deps, deviceCodeRequests } = keychainDeps(store);
    const running = await start(deps, null, KEYCHAIN_ENV);
    await apiPost(running, "/api/auth/verify");
    const done = await waitFor(
      () => apiGet(running, "/api/auth"),
      (response) => JSON.parse(response.body).status === "done",
    );
    expectNoGitHubToken(done.body);
    expect(JSON.parse(done.body).storedSignIn).toEqual({ status: "stored", login: "octo" });
    expect(deviceCodeRequests()).toBe(1);
    expect(JSON.parse((await store.get(KEYCHAIN_KEY)) ?? "{}").login).toBe("octo");
  });

  it("ends only the dashboard session by default and keeps the keychain entry", async () => {
    const store = createInMemoryCredentialStore();
    await store.set(KEYCHAIN_KEY, keychainEntry());
    const { deps, deviceCodeRequests } = keychainDeps(store);
    const running = await start(deps, null, KEYCHAIN_ENV);
    await apiGet(running, "/api/session");
    const signedOut = JSON.parse((await apiPost(running, "/api/auth/sign-out")).body);
    expect(signedOut.signInNotice).toContain("Signed out of this dashboard session only");
    expect(signedOut.storedSignIn).toEqual({ status: "stored", login: "octo" });
    expect(store.size()).toBe(1);
    // The next check reuses the keychain sign-in, still without a device code.
    await apiPost(running, "/api/auth/verify");
    await waitFor(
      () => apiGet(running, "/api/auth"),
      (response) => JSON.parse(response.body).status === "done",
    );
    expect(deviceCodeRequests()).toBe(0);
  });

  it("removes the keychain entry only when asked explicitly", async () => {
    const store = createInMemoryCredentialStore();
    await store.set(KEYCHAIN_KEY, keychainEntry());
    const { deps } = keychainDeps(store);
    const running = await start(deps, null, KEYCHAIN_ENV);
    expect((await apiPost(running, "/api/auth/sign-out", { removeStored: "yes" })).status).toBe(
      400,
    );
    expect(store.size()).toBe(1);
    const removed = JSON.parse(
      (await apiPost(running, "/api/auth/sign-out", { removeStored: true })).body,
    );
    expect(removed.signInNotice).toContain("removed the saved GitHub sign-in from the OS keychain");
    expect(removed.signInNotice).toContain("https://github.com/settings/apps/authorizations");
    expect(removed.storedSignIn).toEqual({ status: "none" });
    expect(store.size()).toBe(0);
  });

  it("uses the built-in App's keychain entry when no override is set", async () => {
    const builtInKey = {
      service: "pgard",
      account: `github:github.com:${DEFAULT_GITHUB_APP_CLIENT_ID}`,
    };
    const store = createInMemoryCredentialStore();
    await store.set(
      builtInKey,
      keychainEntry().replace(KEYCHAIN_CLIENT_ID, DEFAULT_GITHUB_APP_CLIENT_ID),
    );
    // An override's entry is a different App's sign-in and is neither shown nor removed.
    await store.set(KEYCHAIN_KEY, keychainEntry());
    const running = await start(fakeDeps({ credentialStore: store }));
    await apiGet(running, "/api/session");
    const auth = JSON.parse((await apiGet(running, "/api/auth")).body);
    expect(auth.storedSignIn).toEqual({ status: "stored", login: "octo" });
    const removed = JSON.parse(
      (await apiPost(running, "/api/auth/sign-out", { removeStored: true })).body,
    );
    expect(removed.storedSignIn).toEqual({ status: "none" });
    expect(await store.get(builtInKey)).toBeNull();
    expect(await store.get(KEYCHAIN_KEY)).not.toBeNull();
  });

  it("exposes an invalid override and refuses to remove the built-in App's keychain entry", async () => {
    const builtInKey = {
      service: "pgard",
      account: `github:github.com:${DEFAULT_GITHUB_APP_CLIENT_ID}`,
    };
    const store = createInMemoryCredentialStore();
    await store.set(
      builtInKey,
      keychainEntry().replace(KEYCHAIN_CLIENT_ID, DEFAULT_GITHUB_APP_CLIENT_ID),
    );
    const running = await start(fakeDeps({ credentialStore: store }), null, {
      PGARD_GITHUB_APP_CLIENT_ID: '"bad id"',
    });
    const sessionBody = (await apiGet(running, "/api/session")).body;
    expect(JSON.parse(sessionBody).githubApp).toEqual({
      clientId: null,
      slug: null,
      source: "invalid",
      message:
        "PGARD_GITHUB_APP_CLIENT_ID is set but is not a valid client id; unset it to use the built-in PGARD App.",
    });
    expect(sessionBody).not.toContain("bad id");
    // The built-in App's entry is not shown as this App's sign-in...
    const auth = JSON.parse((await apiGet(running, "/api/auth")).body);
    expect(auth.storedSignIn).toEqual({ status: "unknown" });
    // ...and an explicit "remove from keychain" leaves it alone.
    const removed = JSON.parse(
      (await apiPost(running, "/api/auth/sign-out", { removeStored: true })).body,
    );
    expect(removed.signInNotice).toBe(
      "Signed out of this dashboard session. Nothing was removed from the OS keychain: PGARD_GITHUB_APP_CLIENT_ID is set but is not a valid client id; unset it to use the built-in PGARD App.",
    );
    expect(await store.get(builtInKey)).not.toBeNull();
  });
});

it("still shows and removes the keychain entry when only the slug override is malformed", async () => {
  const builtInKey = {
    service: "pgard",
    account: `github:github.com:${DEFAULT_GITHUB_APP_CLIENT_ID}`,
  };
  const store = createInMemoryCredentialStore();
  await store.set(
    builtInKey,
    keychainEntry().replace(KEYCHAIN_CLIENT_ID, DEFAULT_GITHUB_APP_CLIENT_ID),
  );
  const running = await start(fakeDeps({ credentialStore: store }), null, {
    PGARD_GITHUB_APP_SLUG: "Not A Slug!",
  });
  // Sign-in still blocks on the malformed slug...
  expect(JSON.parse((await apiGet(running, "/api/session")).body).githubApp.source).toBe("invalid");
  // ...but the slug plays no part in which keychain entry is shown or removed.
  expect(JSON.parse((await apiGet(running, "/api/auth")).body).storedSignIn).toEqual({
    status: "stored",
    login: "octo",
  });
  const removed = JSON.parse(
    (await apiPost(running, "/api/auth/sign-out", { removeStored: true })).body,
  );
  expect(removed.storedSignIn).toEqual({ status: "none" });
  expect(await store.get(builtInKey)).toBeNull();
});

const INSTALL_URL =
  "https://github.com/apps/pgard-jadenmeister/installations/new/permissions?suggested_target_id=1001&repository_ids%5B%5D=555";

/** Blocked only by owner approval, with the install remedy the policy package produces. */
function needsInstall(remedy: Partial<OwnerApprovalRemedy> = {}): AuthorizationOutcome {
  return {
    ...outcome("owner_approval"),
    remedy: {
      kind: "install_app",
      missing: "installation",
      account: { login: "me", type: "User" },
      url: INSTALL_URL,
      canApprove: "yes",
      unavailableReason: null,
      ...remedy,
    },
  };
}

describe("local web guided App install", () => {
  it("exposes the remedy on /api/auth only when owner approval is the only failed check", async () => {
    const appSlugs: (string | null | undefined)[] = [];
    let next = needsInstall();
    const running = await start(
      fakeDeps({
        verifyProject: async (_root, deps) => {
          appSlugs.push(deps.appSlug);
          return next;
        },
      }),
    );
    await authorize(running);
    const auth = JSON.parse((await apiGet(running, "/api/auth")).body);
    expect(auth.remedy).toEqual({
      kind: "install_app",
      missing: "installation",
      account: { login: "me", type: "User" },
      url: INSTALL_URL,
      canApprove: "yes",
      unavailableReason: null,
    });
    // The configured slug reaches the gate, which builds the link from GitHub ids.
    expect(appSlugs).toEqual(["pgard-jadenmeister"]);

    next = { ...needsInstall(), summary: outcome("contribution").summary };
    await authorize(running);
    expect(JSON.parse((await apiGet(running, "/api/auth")).body).remedy).toBeNull();

    next = outcome();
    await authorize(running);
    expect(JSON.parse((await apiGet(running, "/api/auth")).body).remedy).toBeNull();
  });

  it("exposes accessNote (no remedy) only for the exact all-repositories 404 shape", async () => {
    const statuses = ["passed", "passed", "unverifiable", "failed", "unverifiable"] as const;
    const hidden: AuthorizationOutcome = {
      summary: {
        decision: "blocked",
        checks: AUTHORIZATION_CHECK_ORDER.map((id, index) => ({
          id,
          status: statuses[index]!,
          reason: "x",
        })),
      },
      repo: "owner/name",
      revision: "abc",
      remedy: null,
      accessNote: "app_covers_all_repositories",
    };
    let next = hidden;
    const running = await start(fakeDeps({ verifyProject: async () => next }));
    await authorize(running);
    const auth = JSON.parse((await apiGet(running, "/api/auth")).body);
    expect(auth.accessNote).toBe("app_covers_all_repositories");
    expect(auth.remedy).toBeNull();

    next = { ...hidden, summary: outcome("contribution").summary };
    await authorize(running);
    expect(JSON.parse((await apiGet(running, "/api/auth")).body).accessNote).toBeNull();

    next = outcome();
    await authorize(running);
    expect(JSON.parse((await apiGet(running, "/api/auth")).body).accessNote).toBeNull();
  });

  it("never passes a link that is not https://github.com/ to the browser", async () => {
    const running = await start(
      fakeDeps({ verifyProject: async () => needsInstall({ url: "https://evil.test/install" }) }),
    );
    await authorize(running);
    const auth = JSON.parse((await apiGet(running, "/api/auth")).body);
    expect(auth.remedy).toMatchObject({ url: null, canApprove: "no" });
  });

  it("re-checks owner approval only while an install is pending for this user", async () => {
    const recheck = vi.fn<ServerDeps["recheckOwnerApproval"]>(async () => ({
      status: "passed",
      reason: "The PGARD GitHub App is installed.",
      remedy: null,
    }));
    let next = needsInstall({ canApprove: "no" });
    const running = await start(
      fakeDeps({ verifyProject: async () => next, recheckOwnerApproval: recheck }),
    );
    // Nothing checked yet, then an "ask an owner" remedy: nothing to wait for.
    expect((await apiPost(running, "/api/auth/owner-approval")).status).toBe(409);
    await authorize(running);
    expect((await apiPost(running, "/api/auth/owner-approval")).status).toBe(409);
    expect(recheck).not.toHaveBeenCalled();

    // An unreadable organization membership is guided like "yes".
    next = needsInstall({ canApprove: "unknown" });
    await authorize(running);
    const response = await apiPost(running, "/api/auth/owner-approval");
    expect(response.status).toBe(200);
    expect(JSON.parse(response.body)).toEqual({
      status: "passed",
      reason: "The PGARD GitHub App is installed.",
      remedy: null,
    });
    expect(recheck).toHaveBeenCalledTimes(1);
    expect(recheck.mock.calls[0]?.[1].appSlug).toBe("pgard-jadenmeister");
    // A passed re-check is not an authorization: port access still needs a new, allowed check.
    expect((await apiGet(running, "/api/ports")).status).toBe(403);
  });

  it("protects the re-check route like every other state-changing route", async () => {
    const recheck = vi.fn<ServerDeps["recheckOwnerApproval"]>();
    const running = await start(
      fakeDeps({ verifyProject: async () => needsInstall(), recheckOwnerApproval: recheck }),
    );
    await authorize(running);
    const noOrigin = await send(running, "POST", "/api/auth/owner-approval", {
      headers: { "x-pgard-token": TOKEN, "content-type": "application/json" },
      body: "{}",
    });
    expect(noOrigin.status).toBe(403);
    const noToken = await send(running, "POST", "/api/auth/owner-approval", {
      headers: {
        origin: `http://127.0.0.1:${running.port}`,
        "content-type": "application/json",
      },
      body: "{}",
    });
    expect(noToken.status).toBe(401);
    expect((await apiGet(running, "/api/auth/owner-approval")).status).toBe(404);
    expect(recheck).not.toHaveBeenCalled();
  });

  it("bounds re-checks: at most one per 5 s, only within 10 minutes of the check", async () => {
    let clock = 1_000_000;
    const recheck = vi.fn<ServerDeps["recheckOwnerApproval"]>(async () => ({
      status: "failed",
      reason: "No PGARD GitHub App installation.",
      remedy: needsInstall().remedy ?? null,
    }));
    const running = await start(
      fakeDeps({
        verifyProject: async () => needsInstall(),
        recheckOwnerApproval: recheck,
        now: () => clock,
      }),
    );
    await authorize(running);
    const auth = JSON.parse((await apiGet(running, "/api/auth")).body);
    expect(auth.installWaitEndsAt).toBe(1_000_000 + 10 * 60_000);

    const post = async () => {
      const response = await apiPost(running, "/api/auth/owner-approval");
      return { status: response.status, code: JSON.parse(response.body).error?.code };
    };
    expect((await post()).status).toBe(200);
    clock += 4_999;
    expect(await post()).toEqual({ status: 429, code: "recheck_too_soon" });
    clock += 1;
    expect((await post()).status).toBe(200);
    // A clock that moved back since the last re-check counts as too soon.
    clock -= 1_000;
    expect(await post()).toEqual({ status: 429, code: "recheck_too_soon" });
    expect(recheck).toHaveBeenCalledTimes(2);

    // The window is measured from when the check finished, inclusive, and fails closed.
    clock = 1_000_000 + 10 * 60_000;
    expect((await post()).status).toBe(200);
    clock += 1;
    expect(await post()).toEqual({ status: 409, code: "install_wait_expired" });
    clock = 999_999;
    expect(await post()).toEqual({ status: 409, code: "install_wait_expired" });
    expect(recheck).toHaveBeenCalledTimes(3);

    // A new check opens a new window.
    clock = 2_000_000;
    await authorize(running);
    expect(JSON.parse((await apiGet(running, "/api/auth")).body).installWaitEndsAt).toBe(
      2_000_000 + 10 * 60_000,
    );
    expect((await post()).status).toBe(200);
    expect(recheck).toHaveBeenCalledTimes(4);
  });

  it("runs one re-check at a time and releases the lock afterwards", async () => {
    let clock = 1_000_000;
    let release = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    const recheck = vi.fn<ServerDeps["recheckOwnerApproval"]>(async () => {
      await gate;
      return { status: "passed", reason: "Installed.", remedy: null };
    });
    const running = await start(
      fakeDeps({
        verifyProject: async () => needsInstall(),
        recheckOwnerApproval: recheck,
        now: () => clock,
      }),
    );
    await authorize(running);
    const first = apiPost(running, "/api/auth/owner-approval");
    await waitFor(
      async () => recheck.mock.calls.length,
      (calls) => calls === 1,
    );
    clock += 5_000;
    const second = await apiPost(running, "/api/auth/owner-approval");
    expect(second.status).toBe(409);
    expect(JSON.parse(second.body).error.code).toBe("recheck_running");
    release();
    expect((await first).status).toBe(200);
    clock += 5_000;
    expect((await apiPost(running, "/api/auth/owner-approval")).status).toBe(200);
    expect(recheck).toHaveBeenCalledTimes(2);
  });

  it("offers the install for a hidden private repository, with the same bounds, and re-runs the full check", async () => {
    let clock = 1_000_000;
    const hidden: AuthorizationOutcome = {
      ...needsInstall({ missing: "access", url: INSTALL_URL.split("&")[0] }),
      summary: {
        decision: "blocked",
        checks: AUTHORIZATION_CHECK_ORDER.map((id) => ({
          id,
          status:
            id === "current_access"
              ? "failed"
              : id === "owner_approval" || id === "contribution"
                ? "unverifiable"
                : "passed",
          reason: "r",
        })),
      },
    };
    const verifyProject = vi.fn(async () => hidden);
    const recheck = vi.fn<ServerDeps["recheckOwnerApproval"]>(async () => ({
      status: "failed",
      reason: "GitHub returned no access.",
      remedy: hidden.remedy ?? null,
    }));
    const running = await start(
      fakeDeps({ verifyProject, recheckOwnerApproval: recheck, now: () => clock }),
    );
    await authorize(running);
    const auth = JSON.parse((await apiGet(running, "/api/auth")).body);
    expect(auth.remedy).toMatchObject({ missing: "access", canApprove: "yes" });
    expect(auth.remedy.url).not.toContain("repository_ids");
    expect(auth.installWaitEndsAt).toBe(1_000_000 + 10 * 60_000);

    expect((await apiPost(running, "/api/auth/owner-approval")).status).toBe(200);
    clock += 4_999;
    expect((await apiPost(running, "/api/auth/owner-approval")).status).toBe(429);
    clock = 1_000_000 + 10 * 60_000 + 1;
    expect((await apiPost(running, "/api/auth/owner-approval")).status).toBe(409);
    expect(recheck).toHaveBeenCalledTimes(1);

    // Re-verifying runs the whole gate again; a passed re-check never opens port access itself.
    const calls = verifyProject.mock.calls.length;
    await authorize(running);
    expect(verifyProject.mock.calls.length).toBe(calls + 1);
    expect((await apiGet(running, "/api/ports")).status).toBe(403);
  });

  it("offers no wait deadline when nothing can be waited for", async () => {
    const running = await start(
      fakeDeps({ verifyProject: async () => needsInstall({ canApprove: "no" }) }),
    );
    await authorize(running);
    expect(JSON.parse((await apiGet(running, "/api/auth")).body).installWaitEndsAt).toBeNull();
  });
});
