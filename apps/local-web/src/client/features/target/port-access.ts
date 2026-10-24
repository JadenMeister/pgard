import type { AuthStatus } from "../../../shared/api-types";

/**
 * Port discovery and identity probes contact local services, so the dashboard asks for them only
 * after the authorization check reports "allowed". The server enforces the same rule; this keeps
 * the browser from sending requests that would be refused anyway.
 */
export function isPortAccessAllowed(auth: AuthStatus | null): boolean {
  return auth?.status === "done" && auth.summary?.decision === "allowed";
}

export const PORT_ACCESS_EXPIRED_MESSAGE =
  "Port access has expired: PGARD contacts local services only within 30 minutes of a passing authorization check. Use Check again above to continue.";

/** True once the allowed check's `expiresAt` has passed (the server refuses from then on). */
export function isPortAccessExpired(auth: AuthStatus | null, now: number): boolean {
  return typeof auth?.expiresAt === "number" && now > auth.expiresAt;
}

/** Milliseconds until port access expires, or null when there is no allowed check to expire. */
export function msUntilPortAccessExpires(auth: AuthStatus | null, now: number): number | null {
  if (!isPortAccessAllowed(auth) || typeof auth?.expiresAt !== "number") return null;
  return Math.max(0, auth.expiresAt - now);
}

/**
 * True for the server's 403 `authorization_required`: the check expired or changed while the
 * panel still showed it as allowed. The panel then asks the user to check again instead of
 * showing the raw error.
 */
export function isAuthorizationRequiredError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    (error as { status?: unknown }).status === 403 &&
    (error as { code?: unknown }).code === "authorization_required"
  );
}

/** Why the service list is not shown yet, or null when port access is allowed. */
export function portAccessMessage(
  auth: AuthStatus | null,
  now: number = Date.now(),
): string | null {
  if (isPortAccessAllowed(auth)) {
    return isPortAccessExpired(auth, now) ? PORT_ACCESS_EXPIRED_MESSAGE : null;
  }
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

export interface PortAccessHandlers extends PortRequests {
  /** Forget the services, identity and error shown for an earlier access period. */
  reset: () => void;
}

/**
 * Decides when the target panel contacts local services. Feed it every new authorization status
 * with `update`. It starts the port requests once when access opens, resets the panel once when
 * it closes, and ignores repeated statuses in between (polling, re-renders, React StrictMode's
 * double effects). Each open period gets a new token; a response is shown only if the token it
 * started with is still current, so a reply that arrives after sign-out or a new check is dropped
 * even when access has opened again since.
 */
export class PortAccessController {
  private token: number | null = null;
  private nextToken = 1;
  private readonly presetPort: number | null;
  private readonly handlers: PortAccessHandlers;

  constructor(presetPort: number | null, handlers: PortAccessHandlers) {
    this.presetPort = presetPort;
    this.handlers = handlers;
  }

  update(auth: AuthStatus | null): void {
    const isAllowed = isPortAccessAllowed(auth);
    if (isAllowed === (this.token !== null)) return;
    if (!isAllowed) {
      this.token = null;
      this.handlers.reset();
      return;
    }
    this.token = this.nextToken;
    this.nextToken += 1;
    startPortRequests(auth, this.presetPort, this.handlers);
  }

  /** Token of the current access period, or null while access is closed. */
  currentToken(): number | null {
    return this.token;
  }

  /** True while the access period that `token` came from is still open. */
  isCurrent(token: number | null): boolean {
    return token !== null && token === this.token;
  }
}
