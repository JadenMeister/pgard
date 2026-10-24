import { stat } from "node:fs/promises";
import path from "node:path";
import { SCAN_SCOPES, type ScanScope } from "@pgard/findings";
import {
  createConfirmedWebTarget,
  isValidPort,
  sanitizeDisplayText,
  type ServiceIdentity,
} from "@pgard/http-local";
import { isReportFormat, ReportWriteError } from "@pgard/report";
import { PGARD_VERSION, readGitHubAppClientId, ScanCancelledError } from "@pgard/scan-core";
import type {
  AuthStatus,
  PortListResponse,
  ReportResponse,
  ScanStatus,
  ServiceIdentityDto,
  SessionInfo,
  TargetInfo,
} from "../../shared/api-types.js";
import type { ServerDeps } from "../deps.js";
import type { GitHubSessionManager } from "../session/github-session.js";
import {
  MAX_PROGRESS_EVENTS,
  PROBE_CONFIRM_WINDOW_MS,
  type SessionState,
} from "../session/session-state.js";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export interface ApiContext {
  projectRoot: string;
  presetTargetPort: number | null;
  env: Readonly<Record<string, string | undefined>>;
  state: SessionState;
  deps: ServerDeps;
  github: GitHubSessionManager;
}

export type ApiHandler = (context: ApiContext, body: unknown) => Promise<unknown>;

function asRecord(body: unknown): Record<string, unknown> {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new ApiError(400, "bad_request", "Expected a JSON object.");
  }
  return body as Record<string, unknown>;
}

function readPort(body: unknown): number {
  const port = asRecord(body).port;
  if (!isValidPort(port))
    throw new ApiError(400, "bad_port", "port must be an integer from 1 to 65535.");
  return port;
}

function toIdentityDto(identity: ServiceIdentity): ServiceIdentityDto {
  return {
    port: identity.port,
    url: identity.url,
    status: identity.status,
    title: identity.title,
    inferredTechnologies: identity.inferredTechnologies,
    isHttp: identity.isHttp,
    hasUnfollowedRedirect: identity.redirectStop !== null,
    error: identity.error,
  };
}

function toTargetInfo(state: SessionState): TargetInfo | null {
  const target = state.confirmedTarget;
  return target === null ? null : { port: target.port, origin: target.origin, title: target.title };
}

function scanStatus(state: SessionState): ScanStatus {
  const { status, scopes, progress, result, message } = state.scan;
  // A scan can start the GitHub sign-in itself; the browser shows this code while it waits.
  return { status, scopes, progress, result, message, deviceCode: state.deviceCode };
}

function authStatus(state: SessionState): AuthStatus {
  const { status, summary, repo, message } = state.auth;
  return { status, deviceCode: state.deviceCode, summary, repo, message };
}

const getSession: ApiHandler = async (context) => {
  const info: SessionInfo = {
    version: PGARD_VERSION,
    projectName: sanitizeDisplayText(path.basename(context.projectRoot), 120),
    presetTargetPort: context.presetTargetPort,
    isClientIdConfigured: readGitHubAppClientId(context.env) !== null,
  };
  return info;
};

/** Starts the authorization check (device flow if needed); the browser polls `GET /api/auth`. */
const startVerify: ApiHandler = async (context) => {
  const { state } = context;
  if (state.auth.status === "running") return authStatus(state);
  const run: SessionState["auth"] = { status: "running", summary: null, repo: null, message: null };
  state.auth = run;
  void context.deps
    .verifyProject(context.projectRoot, { getGitHubSession: context.github.getGitHubSession })
    .then((outcome) => {
      if (state.auth !== run) return; // signed out or restarted meanwhile
      state.deviceCode = null;
      state.auth = { status: "done", summary: outcome.summary, repo: outcome.repo, message: null };
    })
    .catch(() => {
      if (state.auth !== run) return;
      state.deviceCode = null;
      state.auth = {
        status: "failed",
        summary: null,
        repo: null,
        message: "The authorization check could not complete.",
      };
    });
  return authStatus(state);
};

const getAuth: ApiHandler = async (context) => authStatus(context.state);

/** Drops the GitHub session and stops a pending sign-in (verify or scan). */
const signOut: ApiHandler = async (context) => {
  context.github.signOut();
  context.state.deviceCode = null;
  context.state.auth = { status: "idle", summary: null, repo: null, message: null };
  return authStatus(context.state);
};

const listPorts: ApiHandler = async (context) => {
  const discovery = await context.deps.discoverListeningPorts();
  const services = await Promise.all(
    discovery.ports.map(async (entry) => ({
      ...toIdentityDto(await context.deps.probeLocalService(entry.port)),
      processName: entry.processName,
    })),
  );
  const response: PortListResponse = {
    services: services.filter((service) => service.isHttp),
    isDiscoveryAvailable: discovery.isAvailable,
    note: discovery.note,
  };
  return response;
};

/** Probes one port and remembers the identity the user is about to see. */
const probePort: ApiHandler = async (context, body) => {
  const identity = await context.deps.probeLocalService(readPort(body));
  context.state.lastProbe = { identity, probedAt: context.deps.now() };
  return toIdentityDto(identity);
};

/**
 * Confirms the target. Only the port whose identity was just shown (via probe) can be confirmed,
 * and only if it answered HTTP. The browser never supplies the target object itself.
 */
const confirmTarget: ApiHandler = async (context, body) => {
  const port = readPort(body);
  if (asRecord(body).isConfirmed !== true) {
    throw new ApiError(400, "not_confirmed", "Explicit confirmation is required.");
  }
  const probe = context.state.lastProbe;
  if (
    probe === null ||
    probe.identity.port !== port ||
    context.deps.now() - probe.probedAt > PROBE_CONFIRM_WINDOW_MS
  ) {
    throw new ApiError(
      409,
      "probe_required",
      "Check the service identity again before confirming.",
    );
  }
  if (!probe.identity.isHttp) throw new ApiError(409, "not_http", "This port did not answer HTTP.");
  context.state.confirmedTarget = createConfirmedWebTarget(probe.identity, true);
  return toTargetInfo(context.state);
};

const getTarget: ApiHandler = async (context) => toTargetInfo(context.state);

const clearTarget: ApiHandler = async (context) => {
  context.state.confirmedTarget = null;
  return null;
};

function readScopes(body: unknown): ScanScope[] {
  const scopes = asRecord(body).scopes;
  if (!Array.isArray(scopes) || scopes.length === 0 || scopes.length > SCAN_SCOPES.length) {
    throw new ApiError(400, "bad_scopes", "Select at least one scan scope.");
  }
  const unique = [...new Set(scopes)];
  if (
    !unique.every((scope): scope is ScanScope =>
      (SCAN_SCOPES as readonly unknown[]).includes(scope),
    )
  ) {
    throw new ApiError(400, "bad_scopes", "Unknown scan scope.");
  }
  return SCAN_SCOPES.filter((scope) => unique.includes(scope));
}

/** Starts a scan through scan-core; the authorization gate runs inside `runScan` every time. */
const startScan: ApiHandler = async (context, body) => {
  const { state } = context;
  const scopes = readScopes(body);
  if (state.scan.status === "running")
    throw new ApiError(409, "scan_running", "A scan is already running.");
  const controller = new AbortController();
  state.scan = { status: "running", scopes, progress: [], result: null, message: null, controller };
  const webTarget = scopes.includes("web") ? state.confirmedTarget : null;
  void context.deps
    .runScan(
      { projectRoot: context.projectRoot, scopes, webTarget },
      {
        authorization: { getGitHubSession: context.github.getGitHubSession },
        webScanner: context.deps.webScanner,
        signal: controller.signal,
        env: context.env,
        onProgress: (event) => {
          if (state.scan.controller !== controller) return;
          if (state.scan.progress.length >= MAX_PROGRESS_EVENTS) state.scan.progress.shift();
          state.scan.progress.push({
            stage: event.stage,
            status: event.status,
            message:
              event.web === undefined
                ? sanitizeDisplayText(event.message, 300)
                : `${event.web.pagesVisited} page(s) checked`,
          });
        },
      },
    )
    .then((result) => {
      if (state.scan.controller !== controller) return;
      state.deviceCode = null;
      state.scan = { ...state.scan, status: "done", result, controller: null };
    })
    .catch((error: unknown) => {
      if (state.scan.controller !== controller) return;
      state.deviceCode = null;
      const isCancelled = error instanceof ScanCancelledError;
      state.scan = {
        ...state.scan,
        status: isCancelled ? "cancelled" : "failed",
        message: isCancelled
          ? "The scan was cancelled."
          : "The scan stopped because of an internal error.",
        controller: null,
      };
    });
  return scanStatus(state);
};

const getScan: ApiHandler = async (context) => scanStatus(context.state);

/**
 * Cancels immediately: the scan is marked cancelled right away (a scan stuck waiting for the
 * GitHub sign-in would otherwise never notice the abort), and a pending device flow is stopped.
 * The late result of the abandoned run is ignored.
 */
const cancelScan: ApiHandler = async (context) => {
  const { state } = context;
  const controller = state.scan.controller;
  if (controller === null) return scanStatus(state);
  controller.abort();
  context.github.abortPendingSignIn();
  state.deviceCode = null;
  state.scan = {
    ...state.scan,
    status: "cancelled",
    message: "The scan was cancelled.",
    controller: null,
  };
  return scanStatus(state);
};

const INSIDE_REPO_WARNING =
  "This directory is inside the Git repository. A report there could be committed and shared by mistake.";

/** Exports the current result server-side via @pgard/report (no overwrite, existing dir only). */
const exportReport: ApiHandler = async (context, body) => {
  const record = asRecord(body);
  const result = context.state.scan.result;
  if (result === null || result.overallStatus === "blocked") {
    throw new ApiError(409, "no_result", "There is no scan result to export.");
  }
  const { format, outputDir, isInsideRepositoryConfirmed } = record;
  if (typeof format !== "string" || !isReportFormat(format)) {
    throw new ApiError(400, "bad_format", "format must be html, pdf or both.");
  }
  if (typeof outputDir !== "string" || outputDir.length > 4096 || !path.isAbsolute(outputDir)) {
    throw new ApiError(400, "bad_output_dir", "Enter the absolute path of an existing directory.");
  }
  try {
    if (!(await stat(outputDir)).isDirectory()) throw new Error("not a directory");
  } catch {
    throw new ApiError(400, "bad_output_dir", "The directory does not exist.");
  }
  if (
    (await context.deps.isPathInsideDirectory(outputDir, context.projectRoot)) &&
    isInsideRepositoryConfirmed !== true
  ) {
    const response: ReportResponse = { status: "needs_confirmation", warning: INSIDE_REPO_WARNING };
    return response;
  }
  try {
    const written = await context.deps.writeReports(result, { format, outputDir });
    const response: ReportResponse = {
      status: "saved",
      files: written.map((entry) => entry.filePath),
    };
    return response;
  } catch (error) {
    if (error instanceof ReportWriteError) throw new ApiError(409, error.code, error.message);
    throw error;
  }
};

/** The complete API. Anything not listed here is a 404; there is no file-reading route. */
export const API_ROUTES: Readonly<Record<string, ApiHandler>> = {
  "GET /api/session": getSession,
  "GET /api/auth": getAuth,
  "POST /api/auth/verify": startVerify,
  "POST /api/auth/sign-out": signOut,
  "GET /api/ports": listPorts,
  "POST /api/ports/probe": probePort,
  "GET /api/target": getTarget,
  "POST /api/target/confirm": confirmTarget,
  "POST /api/target/clear": clearTarget,
  "GET /api/scan": getScan,
  "POST /api/scan": startScan,
  "POST /api/scan/cancel": cancelScan,
  "POST /api/reports": exportReport,
};
