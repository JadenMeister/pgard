import {
  buildRuleTextCatalog,
  RULE_LOCALES,
  SCAN_SCOPES,
  scrubAbsolutePaths,
  type RuleLocale,
  type RuleTextCatalog,
  type ScanResult,
  type ScanScope,
} from "@pgard/findings";
import {
  createConfirmedWebTarget,
  isValidPort,
  WEB_RULE_LIST,
  sanitizeDisplayText,
  type ServiceIdentity,
} from "@pgard/http-local";
import { ReportWriteError } from "@pgard/report";
import {
  ADVISORY_STALE_AFTER_DAYS,
  accessNoteFor,
  GITHUB_APP_AUTHORIZATIONS_URL,
  guidedInstallRemedy,
  isAuthorizationAllowed,
  isOpenableGitHubUrl,
  mixedAppOverrideWarning,
  osvDataDir,
  PGARD_VERSION,
  readAdvisoryStatus,
  resolveGitHubAppClientId,
  resolveKeychainClientId,
  removeStoredSignIn,
  ScanCancelledError,
  type AuthorizationDependencies,
  listSupportedRules,
  type OwnerApprovalRemedy,
} from "@pgard/scan-core";
import type {
  AdvisoryStatusDto,
  AuthStatus,
  InstallRemedyDto,
  OwnerApprovalRecheckDto,
  PortListResponse,
  RuleTextsResponse,
  ScanStatus,
  ServiceIdentityDto,
  SessionInfo,
  TargetInfo,
} from "../../shared/api-types.js";
import type { ServerDeps } from "../deps.js";
import { recheckProjectIdentity, requireCurrentEpoch } from "../picker/service.js";
import type { ProjectRecord } from "../picker/session.js";
import { ApiError } from "./api-error.js";
import { PICKER_ROUTES } from "./picker.js";
import { getTrend } from "./trend.js";
import type { GitHubSessionManager } from "../session/github-session.js";
import { readStoredSignInDto, resetAuthIfStoredAccountChanged } from "../session/stored-sign-in.js";
import {
  INSTALL_WAIT_WINDOW_MS,
  isSameAccount,
  isWithinWindow,
  MAX_PROGRESS_EVENTS,
  OWNER_APPROVAL_RECHECK_MIN_INTERVAL_MS,
  PORT_ACCESS_WINDOW_MS,
  PROBE_CONFIRM_WINDOW_MS,
  setAuth,
  type SessionState,
} from "../session/session-state.js";

export { ApiError };

export interface ApiContext {
  /** `fixed`: `pgard dashboard` (one project, no picker). `picker`: `pgard web`. */
  mode: "fixed" | "picker";
  /** PROTOTYPE (#414): `simple` enables `POST /api/code-scan`; always `full` in fixed mode. */
  ui: "full" | "simple";
  presetTargetPort: number | null;
  env: Readonly<Record<string, string | undefined>>;
  state: SessionState;
  deps: ServerDeps;
  github: GitHubSessionManager;
}

/** Per-request facts a handler may need besides the body. */
export interface ApiRequestScope {
  /** Aborts when the client disconnects before the response was sent. */
  signal: AbortSignal;
}

export type ApiHandler = (
  context: ApiContext,
  body: unknown,
  /** Query string of the request (GET routes). */
  query: URLSearchParams,
  request: ApiRequestScope,
) => Promise<unknown>;

/**
 * The project and epoch a handler started with. After every `await`, `assertProjectUnchanged`
 * stops the handler with `project_changed` if either differs, so an in-flight request can never
 * act on, or leave results under, a different project (T12).
 */
interface ProjectCapture {
  project: ProjectRecord;
  epoch: number;
}

/**
 * The selected project, or `409 no_project`. In picker mode a state-changing call passes its
 * body so the epoch it carries is checked; in fixed mode the epoch is always 1 and not required.
 */
function captureProject(context: ApiContext, body?: unknown): ProjectCapture {
  const { state } = context;
  if (state.project === null) {
    throw new ApiError(409, "no_project", "Choose a project first.");
  }
  if (context.mode === "picker" && body !== undefined) {
    requireCurrentEpoch(state, asRecord(body).epoch);
  }
  return { project: state.project, epoch: state.projectEpoch };
}

function isProjectUnchanged(context: ApiContext, capture: ProjectCapture): boolean {
  return context.state.project === capture.project && context.state.projectEpoch === capture.epoch;
}

function assertProjectUnchanged(context: ApiContext, capture: ProjectCapture): void {
  if (context.state.project !== capture.project || context.state.projectEpoch !== capture.epoch) {
    throw new ApiError(
      409,
      "project_changed",
      "The project changed while this was running; the result was discarded.",
    );
  }
}

// Read through functions: TypeScript would otherwise keep the narrowing from before an `await`.
const isAuthRunning = (state: SessionState): boolean => state.auth.status === "running";
const isScanRunning = (state: SessionState): boolean => state.scan.status === "running";

function pickerContextOf(context: ApiContext) {
  return { state: context.state, picker: context.deps.picker, now: context.deps.now };
}

/**
 * Picker mode: repeats the identity chain and ownership checks of the confirmed project before a
 * verify, owner-approval check or scan starts. Fixed mode has nothing to repeat.
 */
async function recheckProject(
  context: ApiContext,
  capture: ProjectCapture,
  /** PROTOTYPE (#414): only the code-only scan accepts a code-only folder. */
  allowFolder = false,
): Promise<void> {
  if (context.mode !== "picker") return;
  await recheckProjectIdentity(
    pickerContextOf(context),
    capture.project,
    capture.epoch,
    allowFolder,
  );
  assertProjectUnchanged(context, capture);
}

/**
 * The repository the user confirmed (picker mode); the gate blocks if the folder now holds
 * another one. Nothing in fixed mode, where the launcher confirmed the folder itself.
 */
function expectedRepoOf(
  project: ProjectRecord,
):
  { expectedRepo: NonNullable<AuthorizationDependencies["expectedRepo"]> } | Record<string, never> {
  return project.repo === null
    ? {}
    : {
        expectedRepo: {
          owner: project.repo.owner,
          name: project.repo.name,
          repositoryId: project.repositoryId,
        },
      };
}

let ruleTextCatalog: RuleTextCatalog | undefined;

function getRuleTextCatalog(): RuleTextCatalog {
  ruleTextCatalog ??= buildRuleTextCatalog([...listSupportedRules(), ...WEB_RULE_LIST]);
  return ruleTextCatalog;
}

/** Every rule's title, impact and fix text in both languages; the client picks by UI language. */
const getRuleTexts: ApiHandler = async () => {
  const texts: RuleTextsResponse = {};
  for (const [id, entry] of getRuleTextCatalog()) texts[id] = entry;
  return texts;
};

/**
 * The state of the downloaded advisory data, from local metadata only. No home directory (no
 * store path) or a missing store reads as "none"; a store that cannot be read reads as "unreadable".
 */
const getAdvisoryStatus: ApiHandler = async (context) => {
  const dir = context.deps.advisoryDataDir ?? null;
  const empty: AdvisoryStatusDto = {
    overall: "none",
    staleAfterDays: ADVISORY_STALE_AFTER_DAYS,
    storePath: null,
    ecosystems: [],
  };
  if (dir === null) return empty;
  // The browser never gets an absolute path: the home directory shows as `~`.
  const storePath = scrubAbsolutePaths(osvDataDir(dir)).slice(0, 300);
  try {
    const status = await (context.deps.readAdvisoryStatus ?? readAdvisoryStatus)(
      dir,
      context.deps.now(),
    );
    return {
      overall: status.overall,
      staleAfterDays: ADVISORY_STALE_AFTER_DAYS,
      storePath,
      ecosystems: status.ecosystems.map((entry) => ({ ...entry })),
    };
  } catch {
    return { ...empty, overall: "unreadable", storePath };
  }
};

function readReportLang(query: URLSearchParams): RuleLocale {
  const value = query.get("lang");
  if (value === null) return "en";
  if (!(RULE_LOCALES as readonly string[]).includes(value)) {
    throw new ApiError(400, "bad_lang", "lang must be en or ko.");
  }
  return value as RuleLocale;
}

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
  return {
    status,
    scopes,
    progress,
    result,
    message,
    deviceCode: state.deviceCode,
    codeOnly: state.scan.codeOnly === true,
  };
}

/** The remedy as the browser may see it; a link is passed only if it is an github.com URL. */
function toRemedyDto(remedy: OwnerApprovalRemedy | null): InstallRemedyDto | null {
  if (remedy === null) return null;
  const url = remedy.url !== null && isOpenableGitHubUrl(remedy.url) ? remedy.url : null;
  return {
    kind: "install_app",
    missing: remedy.missing,
    account: {
      login: sanitizeDisplayText(remedy.account.login, 100),
      type: remedy.account.type,
    },
    url,
    canApprove: url === null ? "no" : remedy.canApprove,
    unavailableReason:
      remedy.unavailableReason === null ? null : sanitizeDisplayText(remedy.unavailableReason, 200),
  };
}

/** The install remedy the latest finished check offers, as the browser may see it, or `null`. */
function pendingInstallRemedy(state: SessionState): InstallRemedyDto | null {
  const { status, outcome } = state.auth;
  return status === "done" && outcome !== null ? toRemedyDto(guidedInstallRemedy(outcome)) : null;
}

function authStatus(state: SessionState): AuthStatus {
  const { status, outcome, finishedAt, message } = state.auth;
  const isAllowed = status === "done" && outcome !== null && isAuthorizationAllowed(outcome);
  const remedy = pendingInstallRemedy(state);
  return {
    status,
    isRechecking: state.ownerApprovalRecheck,
    deviceCode: state.deviceCode,
    summary: outcome?.summary ?? null,
    repo: outcome?.repo ?? null,
    message,
    storedSignIn: state.storedSignIn,
    remedy,
    accessNote: status === "done" && outcome !== null ? accessNoteFor(outcome) : null,
    signInNotice: state.signInNotice,
    // Same window `requirePortAccessAuthorized` enforces; only shown, never trusted back.
    expiresAt: isAllowed && finishedAt !== null ? finishedAt + PORT_ACCESS_WINDOW_MS : null,
    // Same window `recheckOwnerApproval` enforces; only shown, never trusted back.
    installWaitEndsAt:
      remedy !== null && remedy.canApprove !== "no" && finishedAt !== null
        ? finishedAt + INSTALL_WAIT_WINDOW_MS
        : null,
  };
}

function githubAppInfo(
  env: Readonly<Record<string, string | undefined>>,
): SessionInfo["githubApp"] {
  return resolveGitHubAppClientId(env);
}

/** Authorization deps for this dashboard: its session provider and the configured App slug. */
function authorizationDeps(context: ApiContext): AuthorizationDependencies {
  return {
    getGitHubSession: context.github.getGitHubSession,
    appSlug: resolveGitHubAppClientId(context.env).slug,
  };
}

const getSession: ApiHandler = async (context) => {
  // Show whether a keychain sign-in will be reused before the first check (login only).
  context.state.storedSignIn = await readStoredSignInDto(context.deps.credentialStore, context.env);
  const { project } = context.state;
  const info: SessionInfo = {
    version: PGARD_VERSION,
    mode: context.mode,
    ui: context.ui,
    project:
      project === null
        ? null
        : {
            name: project.name,
            repo: project.repo === null ? null : `${project.repo.owner}/${project.repo.name}`,
          },
    projectEpoch: context.state.projectEpoch,
    presetTargetPort: context.presetTargetPort,
    githubApp: githubAppInfo(context.env),
    githubAppWarning: mixedAppOverrideWarning(context.env),
  };
  return info;
};

/** Starts the authorization check (device flow if needed); the browser polls `GET /api/auth`. */
const startVerify: ApiHandler = async (context, body) => {
  const { state } = context;
  const capture = captureProject(context, body);
  if (state.auth.status === "running") return authStatus(state);
  await recheckProject(context, capture);
  // Another request may have started a check while the identity was re-checked.
  if (isAuthRunning(state)) return authStatus(state);
  const run: SessionState["auth"] = {
    status: "running",
    outcome: null,
    finishedAt: null,
    message: null,
  };
  // "Check again" for the same account keeps the confirmed target; the result decides below.
  const previousAccount = state.authAccount;
  setAuth(state, run, { keepConfirmedTarget: previousAccount !== null });
  state.signInNotice = null;
  // Aborted by `POST /api/auth/cancel`, a project change and server shutdown: a git process that
  // blocks (a hostile repository) is killed at once instead of waiting for its time limit.
  const controller = new AbortController();
  state.verifyController = controller;
  const { project } = capture;
  void context.deps
    .verifyProject(project.root, {
      ...authorizationDeps(context),
      signal: controller.signal,
      ...expectedRepoOf(project),
    })
    .then((outcome) => {
      if (state.auth !== run) return; // signed out, cancelled or restarted meanwhile
      if (state.verifyController === controller) state.verifyController = null;
      if (!isProjectUnchanged(context, capture)) {
        // The project changed under the check: its result must not appear under the new one.
        state.deviceCode = null;
        setAuth(state, { status: "idle", outcome: null, finishedAt: null, message: null });
        return;
      }
      state.deviceCode = null;
      setAuth(
        state,
        { status: "done", outcome, finishedAt: context.deps.now(), message: null },
        { keepConfirmedTarget: true },
      );
      // The account the gate itself ran with (not whichever account the provider adopted last,
      // which may have changed meanwhile); a later switch resets it (see resetAuthIfAccountChanged).
      state.authAccount = outcome.account ?? null;
      // Pin GitHub's numeric id once a check returned it: a later run of this project that
      // resolves to another repository is then blocked.
      if (project.repositoryId === null && typeof outcome.repositoryId === "number") {
        project.repositoryId = outcome.repositoryId;
      }
      if (
        state.confirmedTarget !== null &&
        (previousAccount === null ||
          state.authAccount === null ||
          !isAuthorizationAllowed(outcome) ||
          !isSameAccount(previousAccount, state.authAccount))
      ) {
        state.confirmedTarget = null;
      }
    })
    .catch(() => {
      if (state.auth !== run) return;
      if (state.verifyController === controller) state.verifyController = null;
      state.deviceCode = null;
      if (!isProjectUnchanged(context, capture)) {
        setAuth(state, { status: "idle", outcome: null, finishedAt: null, message: null });
        return;
      }
      setAuth(state, {
        status: "failed",
        outcome: null,
        finishedAt: context.deps.now(),
        message: "The authorization check could not complete.",
      });
    });
  return authStatus(state);
};

/**
 * Cancels a running authorization check or owner-approval re-check: kills its blocked git
 * processes, stops a pending GitHub sign-in and resets the authorization to idle (the same pair
 * `cancelScan` uses for a scan). A 200 no-op when nothing runs. It needs no project and no epoch,
 * so a check waiting for the sign-in is never a dead end.
 */
const cancelAuth: ApiHandler = async (context) => {
  const { state } = context;
  if (state.auth.status !== "running" && !state.ownerApprovalRecheck) return authStatus(state);
  state.verifyController?.abort();
  state.verifyController = null;
  state.recheckController?.abort();
  state.recheckController = null;
  context.github.abortPendingSignIn();
  state.deviceCode = null;
  state.ownerApprovalRecheck = false;
  setAuth(state, { status: "idle", outcome: null, finishedAt: null, message: null });
  return authStatus(state);
};

/** Resets the latest check when the keychain now holds another account than it ran with. */
async function syncAccount(context: ApiContext): Promise<void> {
  await resetAuthIfStoredAccountChanged(context.state, context.deps.credentialStore, context.env);
}

const getAuth: ApiHandler = async (context) => {
  await syncAccount(context);
  return authStatus(context.state);
};

/**
 * Checks owner approval alone again while the user installs the PGARD GitHub App, so the panel
 * can start the full check (`POST /api/auth/verify`) as soon as the installation exists. Only
 * available while the latest check offers the guided install to this user, within
 * `INSTALL_WAIT_WINDOW_MS` of that check finishing (409 after), at most once per
 * `OWNER_APPROVAL_RECHECK_MIN_INTERVAL_MS` (429 sooner) and one at a time (409). It uses only the
 * existing sign-in and never starts a device flow. The result is never an authorization and
 * opens nothing: port access still requires a new, allowed full check.
 */
const recheckOwnerApproval: ApiHandler = async (context, body, _query, request) => {
  const { state } = context;
  const capture = captureProject(context, body);
  const remedy = pendingInstallRemedy(state);
  if (remedy === null || remedy.canApprove === "no") {
    throw new ApiError(
      409,
      "no_install_pending",
      "There is no PGARD GitHub App installation to wait for. Check again.",
    );
  }
  const now = context.deps.now();
  // Fail closed on a clock that moved back, like the other windows.
  if (!isWithinWindow(now, state.auth.finishedAt, INSTALL_WAIT_WINDOW_MS)) {
    throw new ApiError(
      409,
      "install_wait_expired",
      "Stopped waiting for the PGARD GitHub App installation after 10 minutes. Install it, then check again.",
    );
  }
  if (state.ownerApprovalRecheck) {
    throw new ApiError(409, "recheck_running", "Owner approval is already being checked.");
  }
  const last = state.ownerApprovalRecheckAt;
  // A clock that moved back since the last re-check gives a negative difference, which is also
  // below the minimum interval, so it counts as too soon without a separate comparison.
  if (last !== null && now - last < OWNER_APPROVAL_RECHECK_MIN_INTERVAL_MS) {
    throw new ApiError(429, "recheck_too_soon", "Wait 5 seconds between owner approval checks.");
  }
  state.ownerApprovalRecheckAt = now;
  state.ownerApprovalRecheck = true;
  // Aborted by `POST /api/auth/cancel`, a client that disconnects and server shutdown.
  const controller = new AbortController();
  state.recheckController = controller;
  const signal = AbortSignal.any([controller.signal, request.signal]);
  try {
    await recheckProject(context, capture);
    const recheck = await context.deps.recheckOwnerApproval(capture.project.root, {
      ...authorizationDeps(context),
      signal,
      ...expectedRepoOf(capture.project),
    });
    assertProjectUnchanged(context, capture);
    const response: OwnerApprovalRecheckDto = {
      status: recheck.status,
      reason: sanitizeDisplayText(recheck.reason, 500),
      remedy: toRemedyDto(recheck.remedy),
    };
    return response;
  } finally {
    if (state.recheckController === controller) {
      state.recheckController = null;
      state.ownerApprovalRecheck = false;
    }
  }
};

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
  // Only the client id names the entry, so a malformed slug override does not block removal.
  const app = resolveKeychainClientId(context.env);
  if (app.clientId === null) {
    // Never remove the built-in App's entry on behalf of a malformed client id override.
    state.signInNotice = `Signed out of this dashboard session. Nothing was removed from the OS keychain: ${app.message}`;
    return authStatus(state);
  }
  const removed = await removeStoredSignIn(context.deps.credentialStore, app.clientId);
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
  const capture = captureProject(context);
  await syncAccount(context);
  assertProjectUnchanged(context, capture);
  const authAtStart = requirePortAccessAuthorized(context.state, context.deps.now());
  // Taken together with `authAtStart`: it aborts as soon as that authorization is replaced.
  const { signal } = context.state.portAccessController;
  const discovery = await context.deps.discoverListeningPorts();
  assertProjectUnchanged(context, capture);
  requireSameAuthorization(context, authAtStart);
  const services = await Promise.all(
    discovery.ports.map(async (entry) => ({
      ...toIdentityDto(await context.deps.probeLocalService(entry.port, { signal })),
      processName: entry.processName,
    })),
  );
  assertProjectUnchanged(context, capture);
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
  const capture = captureProject(context, body);
  await syncAccount(context);
  assertProjectUnchanged(context, capture);
  const authAtStart = requirePortAccessAuthorized(context.state, context.deps.now());
  const { signal } = context.state.portAccessController;
  const identity = await context.deps.probeLocalService(readPort(body), { signal });
  assertProjectUnchanged(context, capture);
  requireSameAuthorization(context, authAtStart);
  context.state.lastProbe = { identity, probedAt: context.deps.now(), auth: authAtStart };
  return toIdentityDto(identity);
};

/**
 * Confirms the target. Only the port whose identity was just shown (via probe) can be confirmed,
 * and only if it answered HTTP. The browser never supplies the target object itself.
 */
const confirmTarget: ApiHandler = async (context, body) => {
  const capture = captureProject(context, body);
  await syncAccount(context);
  assertProjectUnchanged(context, capture);
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
    throw new ApiError(
      400,
      "bad_scopes",
      `Unknown scan scope. Valid scopes: ${SCAN_SCOPES.join(", ")}.`,
    );
  }
  return SCAN_SCOPES.filter((scope) => unique.includes(scope));
}

/** Starts a scan through scan-core; the authorization gate runs inside `runScan` every time. */
const startScan: ApiHandler = async (context, body) => {
  const { state } = context;
  const capture = captureProject(context, body);
  const scopes = readScopes(body);
  if (state.scan.status === "running")
    throw new ApiError(409, "scan_running", "A scan is already running.");
  await recheckProject(context, capture);
  // Another request may have started a scan while the identity was re-checked.
  if (isScanRunning(state)) throw new ApiError(409, "scan_running", "A scan is already running.");
  const controller = new AbortController();
  state.scan = { status: "running", scopes, progress: [], result: null, message: null, controller };
  const webTarget = scopes.includes("web") ? state.confirmedTarget : null;
  void context.deps
    .runScan(
      {
        projectRoot: capture.project.root,
        scopes,
        webTarget,
        ...expectedRepoOf(capture.project),
      },
      {
        authorization: authorizationDeps(context),
        webScanner: context.deps.webScanner,
        webRules: WEB_RULE_LIST,
        signal: controller.signal,
        env: context.env,
        advisoryDataDir: context.deps.advisoryDataDir ?? null,
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
      if (!isProjectUnchanged(context, capture)) {
        // The project changed under the scan: its result must not appear under the new one.
        state.scan = {
          status: "idle",
          scopes: [],
          progress: [],
          result: null,
          message: null,
          controller: null,
        };
        return;
      }
      state.scan = { ...state.scan, status: "done", result, controller: null };
    })
    .catch((error: unknown) => {
      if (state.scan.controller !== controller) return;
      state.deviceCode = null;
      if (!isProjectUnchanged(context, capture)) {
        state.scan = {
          status: "idle",
          scopes: [],
          progress: [],
          result: null,
          message: null,
          controller: null,
        };
        return;
      }
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
 * PROTOTYPE (#414), simple screen only: a code-only scan of the confirmed project's current
 * files. It runs no authorization gate and makes no GitHub or network call; only the `code`
 * scope runs, nothing is stored and the result is marked `codeOnly` for the page to label.
 * Git history, web checks, the trend and export keep the full gate (`POST /api/scan`). The
 * project identity is re-checked first, exactly like an authorized scan. Polled and cancelled
 * through `GET /api/scan` and `POST /api/scan/cancel`.
 */
const startCodeScan: ApiHandler = async (context, body) => {
  const { state } = context;
  if (context.ui !== "simple") throw new ApiError(404, "not_found", "Unknown API route.");
  const capture = captureProject(context, body);
  if (state.scan.status === "running")
    throw new ApiError(409, "scan_running", "A scan is already running.");
  await recheckProject(context, capture, true);
  if (isScanRunning(state)) throw new ApiError(409, "scan_running", "A scan is already running.");
  const controller = new AbortController();
  const idle = (): SessionState["scan"] => ({
    status: "idle",
    scopes: [],
    progress: [],
    result: null,
    message: null,
    controller: null,
  });
  state.scan = {
    status: "running",
    scopes: ["code"],
    progress: [],
    result: null,
    message: null,
    controller,
    codeOnly: true,
  };
  void context.deps
    .runCodeOnlyScan(
      { projectRoot: capture.project.root },
      {
        signal: controller.signal,
        env: context.env,
        advisoryDataDir: context.deps.advisoryDataDir ?? null,
        onProgress: (event) => {
          if (state.scan.controller !== controller) return;
          if (state.scan.progress.length >= MAX_PROGRESS_EVENTS) state.scan.progress.shift();
          state.scan.progress.push({
            stage: event.stage,
            status: event.status,
            message: sanitizeDisplayText(event.message, 300),
          });
        },
      },
    )
    .then((result) => {
      if (state.scan.controller !== controller) return;
      state.scan = isProjectUnchanged(context, capture)
        ? { ...state.scan, status: "done", result, controller: null }
        : idle();
    })
    .catch((error: unknown) => {
      if (state.scan.controller !== controller) return;
      if (!isProjectUnchanged(context, capture)) {
        state.scan = idle();
        return;
      }
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

/** A binary response (a report download) instead of JSON. */
export class ApiDownload {
  readonly contentType: string;
  readonly filename: string;
  readonly body: string | Buffer;
  constructor(contentType: string, filename: string, body: string | Buffer) {
    this.contentType = contentType;
    this.filename = filename;
    this.body = body;
  }
}

const REPORT_CONTENT_TYPES = {
  html: "text/html; charset=utf-8",
  pdf: "application/pdf",
} as const;

/**
 * `pgard-report-<repo>-<timestamp>.<ext>`, ASCII only: "/" in the repo becomes "-" and every
 * other character outside [A-Za-z0-9._-] is dropped, so the name is safe in a header and on disk.
 */
export function reportDownloadName(result: ScanResult, format: "html" | "pdf"): string {
  const repo = (result.target.repo ?? "local")
    .replace(/\//g, "-")
    .replace(/[^A-Za-z0-9._-]/g, "")
    .replace(/^\.+/, "")
    .slice(0, 80);
  const stamp = result.startedAt.replace(/[^0-9]/g, "").slice(0, 14) || "unknown";
  return `pgard-report-${repo === "" ? "local" : repo}-${stamp}.${format}`;
}

/**
 * Renders the current (already redacted) result with the same renderers the CLI file export uses
 * and returns it as a download. Nothing is written to disk.
 */
function downloadReport(format: "html" | "pdf"): ApiHandler {
  return async (context, _body, query) => {
    const capture = captureProject(context);
    const lang = readReportLang(query);
    const result = context.state.scan.result;
    if (result === null || result.overallStatus === "blocked") {
      throw new ApiError(409, "no_result", "There is no scan result to export.");
    }
    // PROTOTYPE (#414): a code-only result is not exported until the report carries the
    // "not authorized" banner on every page (see docs/CODE_ONLY_SCAN_DESIGN.md).
    if (context.state.scan.codeOnly === true) {
      throw new ApiError(
        409,
        "code_only_result",
        "A code-only result cannot be exported in this prototype.",
      );
    }
    try {
      const body = await context.deps.renderReport(result, format, undefined, {
        lang,
        ruleTexts: getRuleTextCatalog(),
      });
      assertProjectUnchanged(context, capture);
      return new ApiDownload(
        REPORT_CONTENT_TYPES[format],
        reportDownloadName(result, format),
        body,
      );
    } catch (error) {
      if (error instanceof ReportWriteError) throw new ApiError(500, error.code, error.message);
      throw error;
    }
  };
}

/** The complete API. Anything not listed here is a 404; there is no file-reading route. */
export const API_ROUTES: Readonly<Record<string, ApiHandler>> = {
  "GET /api/session": getSession,
  "GET /api/auth": getAuth,
  "POST /api/auth/verify": startVerify,
  "POST /api/auth/owner-approval": recheckOwnerApproval,
  "POST /api/auth/sign-out": signOut,
  "POST /api/auth/cancel": cancelAuth,
  "GET /api/ports": listPorts,
  "POST /api/ports/probe": probePort,
  "GET /api/target": getTarget,
  "POST /api/target/confirm": confirmTarget,
  "POST /api/target/clear": clearTarget,
  "GET /api/scan": getScan,
  "POST /api/scan": startScan,
  "POST /api/scan/cancel": cancelScan,
  "POST /api/code-scan": startCodeScan,
  "GET /api/rule-texts": getRuleTexts,
  "GET /api/advisory-status": getAdvisoryStatus,
  "GET /api/trend": getTrend,
  "GET /api/reports/html": downloadReport("html"),
  "GET /api/reports/pdf": downloadReport("pdf"),
  ...PICKER_ROUTES,
};
