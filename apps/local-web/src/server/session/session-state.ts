import type { ConfirmedWebTarget, ScanResult, ScanScope } from "@pgard/findings";
import type { ServiceIdentity } from "@pgard/http-local";
import type { AuthorizationOutcome } from "@pgard/scan-core";
import type { DeviceCodeInfo, JobStatus, ScanProgressDto } from "../../shared/api-types.js";

/** A probe is only confirmable for a short time after the user saw it. */
export const PROBE_CONFIRM_WINDOW_MS = 10 * 60 * 1000;
export const MAX_PROGRESS_EVENTS = 200;

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
    message: string | null;
  };
  /** Device-flow code while a sign-in (from verify or a scan) waits for the user. */
  deviceCode: DeviceCodeInfo | null;
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
    auth: { status: "idle", outcome: null, message: null },
    deviceCode: null,
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
