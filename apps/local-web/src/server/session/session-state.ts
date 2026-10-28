import type { ConfirmedWebTarget, ScanResult, ScanScope } from "@pgard/findings";
import type { ServiceIdentity } from "@pgard/http-local";
import type { AuthorizationOutcome } from "@pgard/scan-core";
import type {
  DeviceCodeInfo,
  JobStatus,
  ScanProgressDto,
  StoredSignInDto,
} from "../../shared/api-types.js";

/** A probe is only confirmable for a short time after the user saw it. */
export const PROBE_CONFIRM_WINDOW_MS = 10 * 60 * 1000;
export const MAX_PROGRESS_EVENTS = 200;
/**
 * How long an allowed authorization check keeps port discovery and probes open. Scans re-check
 * on every run; this keeps the dashboard from contacting local services hours after a check.
 */
export const PORT_ACCESS_WINDOW_MS = 30 * 60 * 1000;
/**
 * Owner-approval re-checks (waiting for a PGARD GitHub App install) are accepted only this long
 * after the check that offered the install finished, and at most once per
 * `OWNER_APPROVAL_RECHECK_MIN_INTERVAL_MS`. Same timing as the CLI.
 */
export const INSTALL_WAIT_WINDOW_MS = 10 * 60 * 1000;
export const OWNER_APPROVAL_RECHECK_MIN_INTERVAL_MS = 5_000;

/**
 * True while `now` lies in `[since, since + windowMs]`. `deps.now()` is wall-clock time, so a
 * clock that moved back before `since` counts as outside the window (fail closed) instead of
 * stretching it.
 */
export function isWithinWindow(now: number, since: number | null, windowMs: number): boolean {
  return since !== null && now >= since && now - since <= windowMs;
}

/**
 * Everything the dashboard knows, held in memory for the server's lifetime only. Nothing here is
 * written to disk; `clear()` runs on shutdown.
 */
export interface SessionState {
  /**
   * The latest authorization check. A new object is stored whenever the check starts, finishes or
   * is reset, so comparing references tells whether it changed across an await.
   */
  auth: {
    status: JobStatus;
    /** The full outcome (all five checks) once the check finished, otherwise null. */
    outcome: AuthorizationOutcome | null;
    /** When the check finished (`deps.now()`), or null while none has finished. */
    finishedAt: number | null;
    message: string | null;
  };
  /**
   * Aborts the port probes started under the current `auth`. Replace `auth` only through
   * `setAuth`, which aborts this and creates a new one, so sign-out or a new check stops probes
   * that are still in flight (their results would be discarded anyway).
   */
  portAccessController: AbortController;
  /**
   * The GitHub account (login and id) of the latest sign-in this dashboard adopted, from the
   * provider's notices; `null` until one was reused or saved.
   */
  sessionAccount: GitHubAccountRef | null;
  /**
   * The account `auth` was checked with, set when a check finishes. When the signed-in account
   * changes (for example `pgard login` switched accounts), `auth` is reset so the old account's
   * result no longer opens port access. `null` when unknown (no keychain sign-in).
   */
  authAccount: GitHubAccountRef | null;
  /** Device-flow code while a sign-in (from verify or a scan) waits for the user. */
  deviceCode: DeviceCodeInfo | null;
  /** What the keychain holds for this App (login only, never the token). */
  storedSignIn: StoredSignInDto;
  /** Last secret-free sign-in message for the browser. */
  signInNotice: string | null;
  /** The last probe, with the authorization record it ran under. */
  lastProbe: { identity: ServiceIdentity; probedAt: number; auth: SessionState["auth"] } | null;
  confirmedTarget: ConfirmedWebTarget | null;
  /** True while an owner-approval re-check (waiting for an App install) is in flight. */
  ownerApprovalRecheck: boolean;
  /** When the last owner-approval re-check was accepted (`deps.now()`), or null. */
  ownerApprovalRecheckAt: number | null;
  scan: {
    status: JobStatus | "cancelled";
    scopes: ScanScope[];
    progress: ScanProgressDto[];
    result: ScanResult | null;
    message: string | null;
    controller: AbortController | null;
  };
}

/** A GitHub account as the dashboard tracks it: never a token. */
export interface GitHubAccountRef {
  login: string;
  userId: number;
}

/**
 * Same GitHub account means the same user id. The login is not compared: a username rename keeps
 * the account (and would otherwise reset the check on every port route). A missing or invalid id
 * is never "the same": the check is reset (fail closed).
 */
export function isSameAccount(a: GitHubAccountRef, b: GitHubAccountRef): boolean {
  return Number.isSafeInteger(a.userId) && Number.isSafeInteger(b.userId) && a.userId === b.userId;
}

export function createSessionState(): SessionState {
  return {
    auth: { status: "idle", outcome: null, finishedAt: null, message: null },
    portAccessController: new AbortController(),
    sessionAccount: null,
    authAccount: null,
    deviceCode: null,
    storedSignIn: { status: "unknown" },
    signInNotice: null,
    lastProbe: null,
    confirmedTarget: null,
    ownerApprovalRecheck: false,
    ownerApprovalRecheckAt: null,
    scan: {
      status: "idle",
      scopes: [],
      progress: [],
      result: null,
      message: null,
      controller: null,
    },
  };
}

/**
 * Stores a new authorization record and aborts probes started under the previous one. The
 * account the previous record was checked with no longer applies.
 */
export function setAuth(state: SessionState, auth: SessionState["auth"]): void {
  state.portAccessController.abort();
  state.portAccessController = new AbortController();
  state.auth = auth;
  state.authAccount = null;
  // A confirmed web target was approved under the previous authorization; sign-out or any new
  // check must not leave it usable.
  state.confirmedTarget = null;
}

/** Said when the signed-in account changed after the latest check. */
export const ACCOUNT_CHANGED_NOTICE =
  "The GitHub account changed since the last check, so its result no longer applies. Check authorization again.";

/**
 * Resets `auth` (closing port access) when `account` is not the account the latest check ran
 * with. Returns `true` when it reset.
 */
export function resetAuthIfAccountChanged(state: SessionState, account: GitHubAccountRef): boolean {
  const checked = state.authAccount;
  if (checked === null || isSameAccount(checked, account)) return false;
  setAuth(state, { status: "idle", outcome: null, finishedAt: null, message: null });
  state.signInNotice = ACCOUNT_CHANGED_NOTICE;
  return true;
}

export function clearSessionState(state: SessionState): void {
  state.scan.controller?.abort();
  state.portAccessController.abort();
  Object.assign(state, createSessionState());
}
