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
  /** Device-flow code while a sign-in (from verify or a scan) waits for the user. */
  deviceCode: DeviceCodeInfo | null;
  /** What the keychain holds for this App (login only, never the token). */
  storedSignIn: StoredSignInDto;
  /** Last secret-free sign-in message for the browser. */
  signInNotice: string | null;
  /** The last probe, with the authorization record it ran under. */
  lastProbe: { identity: ServiceIdentity; probedAt: number; auth: SessionState["auth"] } | null;
  confirmedTarget: ConfirmedWebTarget | null;
  scan: {
    status: JobStatus | "cancelled";
    scopes: ScanScope[];
    progress: ScanProgressDto[];
    result: ScanResult | null;
    message: string | null;
    controller: AbortController | null;
  };
}

export function createSessionState(): SessionState {
  return {
    auth: { status: "idle", outcome: null, finishedAt: null, message: null },
    deviceCode: null,
    storedSignIn: { status: "unknown" },
    signInNotice: null,
    lastProbe: null,
    confirmedTarget: null,
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

export function clearSessionState(state: SessionState): void {
  state.scan.controller?.abort();
  Object.assign(state, createSessionState());
}
