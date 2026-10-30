import http from "node:http";
import { SCHEMA_VERSION, type AuthorizationCheckId, type ScanResult } from "@pgard/findings";
import { EMPTY_PROJECT_SIGNALS, type ServiceIdentity } from "@pgard/http-local";
import { renderReport } from "@pgard/report";
import {
  AUTHORIZATION_CHECK_ORDER,
  createInMemoryCredentialStore,
  type AuthorizationOutcome,
} from "@pgard/scan-core";
import { vi } from "vitest";
import { startLocalWebServer, type LocalWebServer } from "../create-server.js";
import type { ServerDeps } from "../deps.js";
import type { PickerDeps } from "../picker/session.js";
import { createFakeInspector, type FakeInspector } from "./fake-inspector.js";

export const TOKEN = "test-token-0123456789abcdefghijklmnop";
/** The session secret the harness server starts with (as if the page had exchanged TOKEN). */
export const SESSION = "test-session-0123456789abcdefghijklmn";

export const IDENTITY: ServiceIdentity = {
  port: 3000,
  url: "http://127.0.0.1:3000/",
  status: 200,
  title: "Shop dev",
  inferredTechnologies: ["Express"],
  isHttp: true,
  redirectStop: null,
  error: null,
};

/** A five-check outcome shaped like the gate's: all passed, or the named check failed. */
export function outcome(
  failing: AuthorizationCheckId | null = null,
  extra: Partial<AuthorizationOutcome> = {},
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
    repo: "acme/shop",
    revision: "abc",
    ...extra,
  };
}

export function result(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    schemaVersion: SCHEMA_VERSION,
    scanBasis: { mode: "authorized", authorization: "verified", reason: null },
    scanId: "scan-1",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:01.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "acme/shop", revision: "abc", webOrigin: null },
    authorization: outcome().summary,
    coverage: [],
    findings: [],
    advisoryDb: { version: null, updatedAt: null },
    ...overrides,
  };
}

export function fakeDeps(overrides: Partial<ServerDeps> = {}): ServerDeps {
  const provider = Object.assign(async () => ({}) as never, {
    invalidate: vi.fn(),
    signOut: vi.fn(),
  });
  return {
    verifyProject: async () => outcome(),
    runScan: async () => result(),
    runCodeOnlyScan: async () => {
      throw new Error("unexpected code-only scan");
    },
    recheckOwnerApproval: async () => {
      throw new Error("unexpected owner approval re-check");
    },
    createSessionProvider: () => provider as never,
    credentialStore: createInMemoryCredentialStore(),
    webScanner: async () => ({ findings: [], coverage: [] }),
    probeLocalService: async () => IDENTITY,
    readProjectSignals: async () => EMPTY_PROJECT_SIGNALS,
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
  };
}

export interface RawResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

export function send(
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

export function apiGet(server: LocalWebServer, urlPath: string): Promise<RawResponse> {
  return send(server, "GET", urlPath, { headers: { "x-pgard-session": SESSION } });
}

export function apiPost(
  server: LocalWebServer,
  urlPath: string,
  body: unknown = {},
): Promise<RawResponse> {
  return send(server, "POST", urlPath, {
    headers: {
      "x-pgard-session": SESSION,
      origin: `http://127.0.0.1:${server.port}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

export const json = (response: RawResponse): Record<string, unknown> =>
  JSON.parse(response.body) as Record<string, unknown>;

export async function waitFor<T>(
  read: () => Promise<T> | T,
  isDone: (value: T) => boolean,
  attempts = 100,
): Promise<T> {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const value = await read();
    if (isDone(value)) return value;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("timed out");
}

export const FAKE_ROOT = { path: "/home/u/code", dev: 1, ino: 7 };
export const HOME = "/home/u";

export interface Harness {
  server: LocalWebServer;
  inspector: FakeInspector;
  clock: { now: number };
  close: () => Promise<void>;
}

/**
 * A server in picker mode (`projectRoot: null`) with a scripted inspector, or in fixed mode when
 * `fixedRoot` is given. `clock` drives `deps.now`.
 */
export async function startHarness(
  options: {
    fixedRoot?: string;
    deps?: Partial<ServerDeps>;
    picker?: Partial<PickerDeps>;
    ui?: "full" | "simple";
  } = {},
): Promise<Harness> {
  const inspector = createFakeInspector(FAKE_ROOT);
  const clock = { now: 1_000_000 };
  const server = await startLocalWebServer({
    projectRoot: options.fixedRoot ?? null,
    presetTargetPort: null,
    env: {},
    assets: new Map([
      ["/", { body: Buffer.from("<html></html>"), contentType: "text/html; charset=utf-8" }],
    ]),
    deps: fakeDeps({
      now: () => clock.now,
      picker: {
        inspector,
        storage: null,
        roots: [FAKE_ROOT],
        homeDir: HOME,
        platform: "linux",
        ...options.picker,
      },
      ...options.deps,
    }),
    token: TOKEN,
    sessionSecretForTests: SESSION,
    ...(options.ui === undefined ? {} : { ui: options.ui }),
  });
  return { server, inspector, clock, close: () => server.close() };
}
