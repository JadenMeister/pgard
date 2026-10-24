import type {
  AuthorizationSummary,
  ConfirmedWebTarget,
  ScanResult,
  ScanScope,
} from "@pgard/findings";
import type { ServiceIdentity } from "@pgard/http-local";
import type { DeviceCodeInfo, JobStatus, ScanProgressDto } from "../../shared/api-types.js";

/** A probe is only confirmable for a short time after the user saw it. */
export const PROBE_CONFIRM_WINDOW_MS = 10 * 60 * 1000;
export const MAX_PROGRESS_EVENTS = 200;

/**
 * Everything the dashboard knows, held in memory for the server's lifetime only. Nothing here is
 * written to disk; `clear()` runs on shutdown.
 */
export interface SessionState {
  auth: {
    status: JobStatus;
    deviceCode: DeviceCodeInfo | null;
    summary: AuthorizationSummary | null;
    repo: string | null;
    message: string | null;
  };
  lastProbe: { identity: ServiceIdentity; probedAt: number } | null;
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
    auth: { status: "idle", deviceCode: null, summary: null, repo: null, message: null },
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
