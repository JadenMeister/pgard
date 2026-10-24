import http from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { ScanRequest, ScanResult } from "@pgard/findings";
import type { ServiceIdentity } from "@pgard/http-local";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ServerDeps } from "./deps.js";
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

function result(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    schemaVersion: "1.0",
    scanId: "scan-1",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:01.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "owner/name", revision: "abc", webOrigin: null },
    authorization: { decision: "allowed", checks: [] },
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
    verifyProject: async () => ({
      summary: { decision: "blocked", checks: [] },
      repo: "owner/name",
      revision: "abc",
    }),
    runScan: async () => result(),
    createSessionProvider: () => provider as never,
    webScanner: async () => ({ findings: [], coverage: [] }),
    probeLocalService: async () => IDENTITY,
    discoverListeningPorts: async () => ({
      ports: [{ port: 3000, processName: "node" }],
      method: "lsof",
      isComplete: false,
      isAvailable: true,
      note: null,
    }),
    writeReports: async () => [],
    isPathInsideDirectory: async () => false,
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
): Promise<LocalWebServer> {
  server = await startLocalWebServer({
    projectRoot: "/work/my-project",
    presetTargetPort,
    env: {},
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
      isClientIdConfigured: false,
    });
    expect(body).not.toContain("/work/");
  });
});

describe("local web target confirmation", () => {
  it("only confirms the port whose identity was just probed", async () => {
    let clock = 1_000_000;
    const running = await start(fakeDeps({ now: () => clock }));
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
      fakeDeps({ probeLocalService: async () => ({ ...IDENTITY, isHttp: false, status: null }) }),
    );
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
        finish = () =>
          resolve({ summary: { decision: "blocked", checks: [] }, repo: null, revision: null });
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
});

describe("local web reports", () => {
  it("requires an absolute existing directory and confirmation inside the repository", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "pgard-web-report-"));
    try {
      const writeReports = vi.fn(async () => [
        { format: "html" as const, filePath: path.join(directory, "r.html") },
      ]);
      let isInside = true;
      const running = await start(
        fakeDeps({ writeReports, isPathInsideDirectory: async () => isInside }),
      );
      expect(
        (await apiPost(running, "/api/reports", { format: "html", outputDir: directory })).status,
      ).toBe(409);
      await apiPost(running, "/api/scan", { scopes: ["code"] });
      await waitFor(
        () => apiGet(running, "/api/scan"),
        (response) => JSON.parse(response.body).status === "done",
      );
      expect(
        (await apiPost(running, "/api/reports", { format: "html", outputDir: "relative/dir" }))
          .status,
      ).toBe(400);
      expect(
        (
          await apiPost(running, "/api/reports", {
            format: "html",
            outputDir: path.join(directory, "missing"),
          })
        ).status,
      ).toBe(400);
      expect(
        (await apiPost(running, "/api/reports", { format: "docx", outputDir: directory })).status,
      ).toBe(400);
      const needsConfirmation = await apiPost(running, "/api/reports", {
        format: "html",
        outputDir: directory,
      });
      expect(JSON.parse(needsConfirmation.body).status).toBe("needs_confirmation");
      expect(writeReports).not.toHaveBeenCalled();
      const saved = await apiPost(running, "/api/reports", {
        format: "html",
        outputDir: directory,
        isInsideRepositoryConfirmed: true,
      });
      expect(JSON.parse(saved.body)).toEqual({
        status: "saved",
        files: [path.join(directory, "r.html")],
      });
      isInside = false;
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
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
      return { summary: { decision: "allowed", checks: [] }, repo: "owner/name", revision: "abc" };
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
