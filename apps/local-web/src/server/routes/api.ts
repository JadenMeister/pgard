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
import {
  GITHUB_APP_AUTHORIZATIONS_URL,
  isAuthorizationAllowed,
  PGARD_VERSION,
  resolveGitHubAppClientId,
  removeStoredSignIn,
  ScanCancelledError,
} from "@pgard/scan-core";
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
import { readStoredSignInDto } from "../session/stored-sign-in.js";
import {
  isWithinWindow,
  MAX_PROGRESS_EVENTS,
  PORT_ACCESS_WINDOW_MS,
  PROBE_CONFIRM_WINDOW_MS,
  setAuth,
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
  const { status, outcome, finishedAt, message } = state.auth;
  const isAllowed = status === "done" && outcome !== null && isAuthorizationAllowed(outcome);
  return {
    status,
    deviceCode: state.deviceCode,
    summary: outcome?.summary ?? null,
    repo: outcome?.repo ?? null,
    message,
    storedSignIn: state.storedSignIn,
    signInNotice: state.signInNotice,
    // Same window `requirePortAccessAuthorized` enforces; only shown, never trusted back.
    expiresAt: isAllowed && finishedAt !== null ? finishedAt + PORT_ACCESS_WINDOW_MS : null,
  };
}

function githubAppInfo(
  env: Readonly<Record<string, string | undefined>>,
): SessionInfo["githubApp"] {
  const { clientId, source } = resolveGitHubAppClientId(env);
  return { clientId, source };
}

const getSession: ApiHandler = async (context) => {
  // Show whether a keychain sign-in will be reused before the first check (login only).
  context.state.storedSignIn = await readStoredSignInDto(context.deps.credentialStore, context.env);
  const info: SessionInfo = {
    version: PGARD_VERSION,
    projectName: sanitizeDisplayText(path.basename(context.projectRoot), 120),
    presetTargetPort: context.presetTargetPort,
    githubApp: githubAppInfo(context.env),
  };
  return info;
};

/** Starts the authorization check (device flow if needed); the browser polls `GET /api/auth`. */
const startVerify: ApiHandler = async (context) => {
  const { state } = context;
  if (state.auth.status === "running") return authStatus(state);
  const run: SessionState["auth"] = {
    status: "running",
    outcome: null,
    finishedAt: null,
    message: null,
  };
  setAuth(state, run);
  state.signInNotice = null;
  void context.deps
    .verifyProject(context.projectRoot, { getGitHubSession: context.github.getGitHubSession })
    .then((outcome) => {
      if (state.auth !== run) return; // signed out or restarted meanwhile
      state.deviceCode = null;
      setAuth(state, { status: "done", outcome, finishedAt: context.deps.now(), message: null });
    })
    .catch(() => {
      if (state.auth !== run) return;
      state.deviceCode = null;
      setAuth(state, {
        status: "failed",
        outcome: null,
        finishedAt: context.deps.now(),
        message: "The authorization check could not complete.",
      });
    });
  return authStatus(state);
};

const getAuth: ApiHandler = async (context) => authStatus(context.state);

/**
 * Ends this dashboard's GitHub session and stops a pending sign-in (verify or scan). With
 * `{ removeStored: true }` it also deletes the sign-in from the OS keychain; without it the
 * keychain entry is kept and the next check reuses it. The token is never revoked at GitHub
 * (that needs the App's client secret), and the response says so.
 */
const signOut: ApiHandler = async (context, body) => {
  const removeStored = asRecord(body ?? {}).removeStored;
  if (removeStored !== undefined && typeof removeStored !== "boolean") {
    throw new ApiError(400, "bad_request", "removeStored must be true or false.");
  }
  const { state } = context;
  context.github.signOut();
  state.deviceCode = null;
  setAuth(state, { status: "idle", outcome: null, finishedAt: null, message: null });
  if (removeStored !== true) {
    state.signInNotice =
      state.storedSignIn.status === "stored"
        ? `Signed out of this dashboard session only. The sign-in for ${state.storedSignIn.login} is still saved in the OS keychain and the next check reuses it.`
        : "Signed out of this dashboard session.";
    return authStatus(state);
  }
  const { clientId } = resolveGitHubAppClientId(context.env);
  const removed = await removeStoredSignIn(context.deps.credentialStore, clientId);
  if (removed.status === "unavailable") {
    const reason = sanitizeDisplayText(removed.reason, 200);
    state.storedSignIn = { status: "unavailable", reason };
    state.signInNotice = `Signed out of this dashboard session. Nothing was removed from the OS keychain: ${reason}.`;
  } else {
    state.storedSignIn = { status: "none" };
    state.signInNotice =
      removed.status === "removed"
        ? `Signed out and removed the saved GitHub sign-in from the OS keychain. The token stays valid at GitHub until it expires; revoke it at ${GITHUB_APP_AUTHORIZATIONS_URL} if needed.`
        : "Signed out of this dashboard session. No sign-in was saved in the OS keychain.";
  }
  return authStatus(state);
};

/**
 * Port discovery and identity probes touch local services, so they run only after this server
 * session's most recent authorization check for the fixed project root came back "allowed" (the
 * same order the CLI uses). "Allowed" means `isAuthorizationAllowed`: the decision is allowed and all
 * five checks are present, in order, and passed. The outcome is read from server state only;
 * nothing the browser sends can open this gate. A new check, sign-out or a blocked/failed result
 * closes it again, and an allowed result expires after `PORT_ACCESS_WINDOW_MS`. Returns the
 * authorization record that passed, for `requireSameAuthorization`.
 */
export function requirePortAccessAuthorized(
  state: SessionState,
  now: number,
): SessionState["auth"] {
  const auth = state.auth;
  const { status, outcome, finishedAt, message } = auth;
  const isAllowed = status === "done" && outcome !== null && isAuthorizationAllowed(outcome);
  if (isAllowed && isWithinWindow(now, finishedAt, PORT_ACCESS_WINDOW_MS)) return auth;
  let reason: string;
  if (isAllowed && finishedAt !== null && now < finishedAt) {
    reason =
      "The system clock moved back since the authorization check. Check again before PGARD contacts local services.";
  } else if (isAllowed) {
    reason =
      "The authorization check is more than 30 minutes old. Check again before PGARD contacts local services.";
  } else if (status === "running") {
    reason = "The authorization check is still running. Local services are not contacted yet.";
  } else if (status === "done") {
    reason =
      "Authorization was blocked for this project, so PGARD will not discover or probe local services.";
  } else if (status === "failed") {
    reason = `The authorization check did not complete${message ? ` (${message})` : ""}. Local services are not contacted.`;
  } else {
    reason = "Verify project authorization before PGARD discovers or probes local services.";
  }
  throw new ApiError(403, "authorization_required", reason);
}

/**
 * Runs the gate again after an await and requires that the authorization it passes is the same
 * record that opened the request. Signing out or starting a new check while lsof or a probe was
 * running replaces `state.auth`, so the request stops before contacting anything else.
 */
function requireSameAuthorization(context: ApiContext, authAtStart: SessionState["auth"]): void {
  if (requirePortAccessAuthorized(context.state, context.deps.now()) !== authAtStart) {
    throw new ApiError(
      403,
      "authorization_required",
      "Authorization was checked again while this request ran. Local services are not contacted.",
    );
  }
}

const listPorts: ApiHandler = async (context) => {
  const authAtStart = requirePortAccessAuthorized(context.state, context.deps.now());
  // Taken together with `authAtStart`: it aborts as soon as that authorization is replaced.
  const { signal } = context.state.portAccessController;
  const discovery = await context.deps.discoverListeningPorts();
  requireSameAuthorization(context, authAtStart);
  const services = await Promise.all(
    discovery.ports.map(async (entry) => ({
      ...toIdentityDto(await context.deps.probeLocalService(entry.port, { signal })),
      processName: entry.processName,
    })),
  );
  requireSameAuthorization(context, authAtStart);
  const response: PortListResponse = {
    services: services.filter((service) => service.isHttp),
    isDiscoveryAvailable: discovery.isAvailable,
    note: discovery.note,
  };
  return response;
};

/**
 * Probes one port and remembers the identity the user is about to see, tied to the authorization
 * it ran under so a later sign-out or re-check makes it unconfirmable.
 */
const probePort: ApiHandler = async (context, body) => {
  const authAtStart = requirePortAccessAuthorized(context.state, context.deps.now());
  const { signal } = context.state.portAccessController;
  const identity = await context.deps.probeLocalService(readPort(body), { signal });
  requireSameAuthorization(context, authAtStart);
  context.state.lastProbe = { identity, probedAt: context.deps.now(), auth: authAtStart };
  return toIdentityDto(identity);
};

/**
 * Confirms the target. Only the port whose identity was just shown (via probe) can be confirmed,
 * and only if it answered HTTP. The browser never supplies the target object itself.
 */
const confirmTarget: ApiHandler = async (context, body) => {
  const auth = requirePortAccessAuthorized(context.state, context.deps.now());
  const port = readPort(body);
  if (asRecord(body).isConfirmed !== true) {
    throw new ApiError(400, "not_confirmed", "Explicit confirmation is required.");
  }
  const probe = context.state.lastProbe;
  if (
    probe === null ||
    probe.auth !== auth ||
    probe.identity.port !== port ||
    !isWithinWindow(context.deps.now(), probe.probedAt, PROBE_CONFIRM_WINDOW_MS)
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
