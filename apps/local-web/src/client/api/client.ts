import { SESSION_TOKEN_HEADER, type ApiError } from "../../shared/api-types";

/**
 * The only boundary between the browser and the local server. The session token lives in this
 * module's memory: it is read once from the URL fragment and never stored in localStorage,
 * cookies or the URL afterwards.
 */
let sessionToken: string | null = null;

export function takeTokenFromLocation(location: Location, history: History): string | null {
  const match = /(?:^#|&)token=([A-Za-z0-9_-]{20,200})(?:&|$)/.exec(location.hash);
  // Remove the token from the address bar and history entry right away.
  history.replaceState(null, "", `${location.pathname}${location.search}`);
  sessionToken = match?.[1] ?? null;
  return sessionToken;
}

export function hasSessionToken(): boolean {
  return sessionToken !== null;
}

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
  if (sessionToken === null) throw new ApiRequestError(401, "missing_token", "No session token.");
  const headers: Record<string, string> = { [SESSION_TOKEN_HEADER]: sessionToken };
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

/** GET with the session token, returning the body as a Blob (used for report downloads). */
export async function apiDownload(
  path: string,
  fallbackName: string,
): Promise<{ blob: Blob; filename: string }> {
  if (sessionToken === null) throw new ApiRequestError(401, "missing_token", "No session token.");
  const response = await fetch(path, {
    method: "GET",
    headers: { [SESSION_TOKEN_HEADER]: sessionToken },
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
