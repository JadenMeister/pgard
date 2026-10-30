/** Minimal subset of `fetch` used by this package so tests can inject a mock. */
export interface FetchRequestInit {
  method: "GET" | "POST";
  headers: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
  redirect?: "follow" | "error" | "manual";
}

export interface FetchResponseLike {
  readonly status: number;
  readonly ok: boolean;
  /** Response headers; optional so minimal test doubles need not provide them. */
  readonly headers?: { get(name: string): string | null };
  /** Optional so minimal test doubles need not provide it; cancelled for unread redirect bodies. */
  readonly body?: { cancel(): Promise<unknown> } | null;
  json(): Promise<unknown>;
}

export type FetchLike = (url: string, init: FetchRequestInit) => Promise<FetchResponseLike>;

export const defaultFetch: FetchLike = (url, init) => fetch(url, init);

/**
 * Each GitHub request gets at most this long to answer (headers), so a stalled network ends the
 * authorization with a clear failure instead of hanging for minutes.
 */
export const GITHUB_REQUEST_TIMEOUT_MS = 10_000;

/** A request that got no answer within its time limit. */
export class RequestTimeoutError extends Error {
  constructor(readonly timeoutMs: number) {
    super(`No answer within ${Math.ceil(timeoutMs / 1000)} s.`);
    this.name = "RequestTimeoutError";
  }
}

/**
 * Calls `fetchImpl` with a signal that aborts after `timeoutMs` (or when `init.signal` aborts),
 * and rejects with `RequestTimeoutError` at the limit even if `fetchImpl` ignores the signal.
 */
export async function fetchWithTimeout(
  fetchImpl: FetchLike,
  url: string,
  init: FetchRequestInit,
  timeoutMs: number,
): Promise<FetchResponseLike> {
  const controller = new AbortController();
  const outer = init.signal;
  const onOuterAbort = (): void => controller.abort(outer?.reason);
  if (outer?.aborted === true) controller.abort(outer.reason);
  else outer?.addEventListener("abort", onOuterAbort, { once: true });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const error = new RequestTimeoutError(timeoutMs);
      controller.abort(error);
      reject(error);
    }, timeoutMs);
  });
  try {
    return await Promise.race([fetchImpl(url, { ...init, signal: controller.signal }), timedOut]);
  } finally {
    clearTimeout(timer);
    outer?.removeEventListener("abort", onOuterAbort);
  }
}

export function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

export function asInteger(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}
