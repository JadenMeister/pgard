import type { AuthStatus } from "../../../shared/api-types";

/**
 * Port discovery and identity probes contact local services, so the dashboard asks for them only
 * after the authorization check reports "allowed". The server enforces the same rule; this keeps
 * the browser from sending requests that would be refused anyway.
 */
export function isPortAccessAllowed(auth: AuthStatus | null): boolean {
  return auth?.status === "done" && auth.summary?.decision === "allowed";
}

/** Why the service list is not shown yet, or null when port access is allowed. */
export function portAccessMessage(auth: AuthStatus | null): string | null {
  if (isPortAccessAllowed(auth)) return null;
  if (auth?.status === "running") {
    return "Waiting for the authorization check. PGARD does not contact local services until it passes.";
  }
  if (auth?.status === "done") {
    return "Authorization was blocked, so PGARD will not discover or probe local services. See the reasons above.";
  }
  if (auth?.status === "failed") {
    return "The authorization check did not complete, so PGARD will not contact local services. Check again above.";
  }
  return "Verify the project above first. PGARD discovers and probes local services only after authorization passes.";
}

export interface PortRequests {
  listPorts: () => void;
  probe: (port: number) => void;
}

/**
 * The requests the target panel sends when port access opens: the port list, plus a probe of the
 * `--target-port` port if one was given. Sends nothing (and returns false) until authorization
 * reports allowed.
 */
export function startPortRequests(
  auth: AuthStatus | null,
  presetPort: number | null,
  requests: PortRequests,
): boolean {
  if (!isPortAccessAllowed(auth)) return false;
  requests.listPorts();
  if (presetPort !== null) requests.probe(presetPort);
  return true;
}
