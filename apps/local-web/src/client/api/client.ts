import {
  SESSION_HEADER,
  type ApiError,
  type SessionExchangeResponse,
} from "../../shared/api-types";

/**
 * The only boundary between the browser and the local server (#419, design doc section 12).
 *
 * The URL token the launcher printed is only an invitation: it is read once from the fragment,
 * removed from the address bar, and spent by `POST /api/session/exchange`, which returns this
 * tab's session secret. The secret is kept in `sessionStorage` (this exact origin, port
 * included, and this tab only; gone when the tab closes), so a reload of the same tab keeps
 * working while the same link opened anywhere else is refused as already used. Never a cookie,
 * never `localStorage`, never the URL.
 */
let inviteToken: string | null = null;
let sessionSecret: string | null = null;

/** The `sessionStorage` key of this tab's session secret. */
export const SESSION_STORAGE_KEY = "pgard.session";

export function takeTokenFromLocation(location: Location, history: History): string | null {
  const match = /(?:^#|&)token=([A-Za-z0-9_-]{20,200})(?:&|$)/.exec(location.hash);
  // Remove the token from the address bar and history entry right away.
  history.replaceState(null, "", `${location.pathname}${location.search}`);
  inviteToken = match?.[1] ?? null;
  return inviteToken;
}

/** True while a link's one-time token waits to be exchanged. */
export function hasInviteToken(): boolean {
  return inviteToken !== null;
}

/** True once this tab holds a session secret (after the exchange, or restored on reload). */
export function hasSessionToken(): boolean {
  return sessionSecret !== null;
}

/** Sets the secret directly; for tests and for `connectSession`. */
export function setSessionSecret(secret: string | null): void {
  sessionSecret = secret;
}

/**
 * - `connected`: this tab holds a working session secret.
 * - `used`: the link was already exchanged (another tab, a copied link, the history).
 * - `expired`: the link was never used and is older than 10 minutes.
 * - `ended`: this tab's session ended (30 minutes idle, or the server was restarted).
 * - `no_link`: the page was opened without a link and has no session.
 * - `invalid`: the link does not belong to this server.
 * - `unreachable`: the server did not answer.
 */
export type ConnectOutcome =
  "connected" | "used" | "expired" | "ended" | "no_link" | "invalid" | "unreachable";

type SessionStore = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function tabStorage(): SessionStore | null {
  try {
    return typeof sessionStorage === "undefined" ? null : sessionStorage;
  } catch {
    return null;
  }
}

function readStored(store: SessionStore | null): string | null {
  try {
    const value = store?.getItem(SESSION_STORAGE_KEY) ?? null;
    return value !== null && /^[A-Za-z0-9_-]{20,200}$/.test(value) ? value : null;
  } catch {
    return null;
  }
}

function writeStored(store: SessionStore | null, value: string | null): void {
  try {
    if (value === null) store?.removeItem(SESSION_STORAGE_KEY);
    else store?.setItem(SESSION_STORAGE_KEY, value);
  } catch {
    // Without storage the session still works in memory; a reload then needs a new link.
  }
}

async function errorCode(response: Response): Promise<string> {
  const payload = (await response.json().catch(() => null)) as ApiError | null;
  return payload?.error?.code ?? "error";
}

/** Is the stored secret still accepted? `GET /api/session` is the cheapest authenticated read. */
async function isSecretAlive(secret: string): Promise<boolean | null> {
  try {
    const response = await fetch("/api/session", {
      method: "GET",
      headers: { [SESSION_HEADER]: secret },
      credentials: "omit",
      cache: "no-store",
    });
    return response.ok;
  } catch {
    return null;
  }
}

async function connect(store: SessionStore | null): Promise<ConnectOutcome> {
  const stored = readStored(store);
  // A reload (or the same tab opening the link again) reuses this tab's secret first.
  if (stored !== null) {
    const isAlive = await isSecretAlive(stored);
    if (isAlive === null) return "unreachable";
    if (isAlive) {
      sessionSecret = stored;
      inviteToken = null;
      return "connected";
    }
    writeStored(store, null);
    if (inviteToken === null) return "ended";
  }
  if (inviteToken === null) return "no_link";
  const token = inviteToken;
  // The invitation is spent whatever the answer is; it is never sent twice.
  inviteToken = null;
  let response: Response;
  try {
    response = await fetch("/api/session/exchange", {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "omit",
      cache: "no-store",
      body: JSON.stringify({ token }),
    });
  } catch {
    return "unreachable";
  }
  if (response.ok) {
    const payload = (await response.json().catch(() => null)) as SessionExchangeResponse | null;
    const secret = payload?.session;
    if (typeof secret !== "string" || secret.length === 0) return "unreachable";
    sessionSecret = secret;
    writeStored(store, secret);
    return "connected";
  }
  const code = await errorCode(response);
  if (code === "token_used") return "used";
  if (code === "token_expired") return "expired";
  if (response.status === 401) return "invalid";
  return "unreachable";
}

let connecting: Promise<ConnectOutcome> | null = null;

/**
 * Connects this tab once (React strict mode runs effects twice; a second exchange would be
 * refused as `token_used`, so every caller shares the first attempt).
 */
export function connectSession(store: SessionStore | null = tabStorage()): Promise<ConnectOutcome> {
  connecting ??= connect(store);
  return connecting;
}

/** Test hook: forget the shared attempt, the invitation and the secret. */
export function resetSessionForTests(): void {
  connecting = null;
  inviteToken = null;
  sessionSecret = null;
}

/** Called when the server says this tab's session is over (idle timeout, server restarted). */
let onSessionEnded: (() => void) | null = null;

export function setSessionEndedListener(listener: (() => void) | null): void {
  onSessionEnded = listener;
}

const SESSION_ENDED_CODES: ReadonlySet<string> = new Set(["session_expired", "bad_session"]);

/**
 * The project epoch of the view the page shows (from `GET /api/session`). State-changing project
 * calls carry it, so a second window with an older view fails with `project_changed` instead of
 * acting on the wrong project.
 */
let projectEpoch: number | null = null;
const EPOCH_PATHS: ReadonlySet<string> = new Set([
  "/api/auth/verify",
  "/api/auth/owner-approval",
  "/api/ports/probe",
  "/api/target/confirm",
  "/api/scan",
]);

export function setProjectEpoch(epoch: number | null): void {
  projectEpoch = epoch;
}

export function getProjectEpoch(): number | null {
  return projectEpoch;
}

/** Called when the server says this view's project is out of date (`409 project_changed`). */
let onProjectChanged: (() => void) | null = null;

export function setProjectChangedListener(listener: (() => void) | null): void {
  onProjectChanged = listener;
}

export class ApiRequestError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
    this.code = code;
  }
}

function withEpoch(path: string, body: unknown): unknown {
  if (projectEpoch === null || !EPOCH_PATHS.has(path)) return body ?? {};
  return { ...(body as Record<string, unknown> | undefined), epoch: projectEpoch };
}

async function request<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
  if (sessionSecret === null) {
    throw new ApiRequestError(401, "missing_session", "This page is not connected.");
  }
  const headers: Record<string, string> = { [SESSION_HEADER]: sessionSecret };
  if (method === "POST") headers["content-type"] = "application/json";
  const response = await fetch(path, {
    method,
    headers,
    credentials: "omit",
    cache: "no-store",
    ...(method === "POST" ? { body: JSON.stringify(withEpoch(path, body)) } : {}),
  });
  const payload = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    const error = (payload as ApiError | null)?.error;
    if (error?.code === "project_changed") onProjectChanged?.();
    if (error !== undefined && SESSION_ENDED_CODES.has(error.code)) {
      sessionSecret = null;
      writeStored(tabStorage(), null);
      onSessionEnded?.();
    }
    throw new ApiRequestError(
      response.status,
      error?.code ?? "error",
      error?.message ?? "Request failed.",
    );
  }
  return payload as T;
}

/** `filename="..."` from a Content-Disposition header, or null. */
export function filenameFromDisposition(header: string | null): string | null {
  const match = /filename="([A-Za-z0-9._-]{1,200})"/.exec(header ?? "");
  return match?.[1] ?? null;
}

/** GET with the session secret, returning the body as a Blob (used for report downloads). */
export async function apiDownload(
  path: string,
  fallbackName: string,
): Promise<{ blob: Blob; filename: string }> {
  if (sessionSecret === null) {
    throw new ApiRequestError(401, "missing_session", "This page is not connected.");
  }
  const response = await fetch(path, {
    method: "GET",
    headers: { [SESSION_HEADER]: sessionSecret },
    credentials: "omit",
    cache: "no-store",
  });
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as ApiError | null;
    throw new ApiRequestError(
      response.status,
      payload?.error?.code ?? "error",
      payload?.error?.message ?? "Request failed.",
    );
  }
  return {
    // Never keep the response's own type: a report must not be renderable in this origin.
    blob: new Blob([await response.arrayBuffer()], { type: "application/octet-stream" }),
    filename: filenameFromDisposition(response.headers.get("content-disposition")) ?? fallbackName,
  };
}

export const apiGet = <T>(path: string): Promise<T> => request<T>("GET", path);
export const apiPost = <T>(path: string, body?: unknown): Promise<T> =>
  request<T>("POST", path, body);
