import http from "node:http";
import {
  LOOPBACK_IPV4,
  MAX_BODY_BYTES,
  MAX_REDIRECTS,
  REQUEST_TIMEOUT_MS,
  USER_AGENT,
} from "./constants.js";
import { isUnsafeLinkPath } from "./html.js";
import { buildLoopbackOrigin, InvalidTargetError, parseAllowedLoopbackUrl } from "./target.js";

/** Only read-only methods exist in this module. There is deliberately no way to send a body. */
export type ReadOnlyMethod = "GET" | "HEAD";

export interface LoopbackResponse {
  /**
   * Origin + path of the request that produced this response (loopback, same port). The query
   * string is never included, so tokens in URLs cannot reach findings, fingerprints or progress.
   */
  url: string;
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  isBodyTruncated: boolean;
}

export type RedirectStopReason =
  "off_target" | "unsafe_path" | "too_many_redirects" | "invalid_location";

export interface RedirectStop {
  reason: RedirectStopReason;
  /** The URL whose response asked for the redirect. */
  fromUrl: string;
}

export interface LoopbackFetchResult {
  response: LoopbackResponse;
  /** Set when a redirect was not followed; `response` is then the 3xx response itself. */
  redirectStop: RedirectStop | null;
}

export interface LoopbackRequestOptions {
  method?: ReadOnlyMethod;
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Extra request headers (e.g. `origin` for the CORS check). Never credentials. */
  headers?: Record<string, string>;
  maxBodyBytes?: number;
}

export class LoopbackRequestError extends Error {
  readonly code: "timeout" | "aborted" | "network";
  constructor(code: "timeout" | "aborted" | "network", message: string) {
    super(message);
    this.name = "LoopbackRequestError";
    this.code = code;
  }
}

/**
 * Performs exactly one GET/HEAD request to `127.0.0.1:<port><path>`. The socket address is
 * always the numeric loopback IP; no DNS lookup and no connection reuse take place.
 */
export function requestLoopbackOnce(
  port: number,
  pathWithQuery: string,
  options: LoopbackRequestOptions = {},
): Promise<LoopbackResponse> {
  const origin = buildLoopbackOrigin(port);
  if (!pathWithQuery.startsWith("/")) {
    throw new InvalidTargetError("Request path must start with '/'.");
  }
  const method = options.method ?? "GET";
  if (method !== "GET" && method !== "HEAD") {
    throw new InvalidTargetError("Only GET and HEAD requests are allowed.");
  }
  const timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;
  const maxBodyBytes = options.maxBodyBytes ?? MAX_BODY_BYTES;
  const url = `${origin}${pathWithQuery.split(/[?#]/, 1)[0] ?? "/"}`;

  return new Promise<LoopbackResponse>((resolve, reject) => {
    if (options.signal?.aborted === true) {
      reject(new LoopbackRequestError("aborted", "Request was cancelled."));
      return;
    }
    let isSettled = false;
    const settle = (action: () => void): void => {
      if (isSettled) return;
      isSettled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      action();
    };

    const request = http.request({
      host: LOOPBACK_IPV4,
      family: 4,
      port,
      path: pathWithQuery,
      method,
      agent: false,
      headers: {
        "user-agent": USER_AGENT,
        accept: "text/html,application/xhtml+xml,*/*;q=0.8",
        ...options.headers,
      },
    });

    const timer = setTimeout(() => {
      settle(() => reject(new LoopbackRequestError("timeout", `Timed out after ${timeoutMs} ms.`)));
      request.destroy();
    }, timeoutMs);
    const onAbort = (): void => {
      settle(() => reject(new LoopbackRequestError("aborted", "Request was cancelled.")));
      request.destroy();
    };
    options.signal?.addEventListener("abort", onAbort, { once: true });

    request.on("error", (error: Error) => {
      settle(() => reject(new LoopbackRequestError("network", error.message)));
    });
    request.on("response", (response) => {
      const chunks: Buffer[] = [];
      let receivedBytes = 0;
      let isBodyTruncated = false;
      const finish = (): void => {
        settle(() =>
          resolve({
            url,
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks),
            isBodyTruncated,
          }),
        );
      };
      response.on("data", (chunk: Buffer) => {
        if (isBodyTruncated) return;
        const remaining = maxBodyBytes - receivedBytes;
        if (chunk.length >= remaining) {
          chunks.push(chunk.subarray(0, Math.max(remaining, 0)));
          receivedBytes = maxBodyBytes;
          isBodyTruncated = chunk.length > remaining;
          if (isBodyTruncated) {
            finish();
            response.destroy();
          }
          return;
        }
        chunks.push(chunk);
        receivedBytes += chunk.length;
      });
      response.on("end", finish);
      response.on("error", (error: Error) => {
        settle(() => reject(new LoopbackRequestError("network", error.message)));
      });
    });
    request.end();
  });
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * GET/HEAD with manual redirect handling. `timeoutMs` bounds the whole redirect chain. Every `Location` is re-validated: it must stay on
 * `http://127.0.0.1:<same port>`. Anything else stops the chain without contacting the new host.
 */
export async function fetchLoopback(
  port: number,
  pathWithQuery: string,
  options: LoopbackRequestOptions = {},
): Promise<LoopbackFetchResult> {
  let currentPath = pathWithQuery;
  const origin = buildLoopbackOrigin(port);
  // One deadline for the whole chain: every hop only gets the time that is left.
  const timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;
  const deadline = Date.now() + timeoutMs;
  for (let hop = 0; ; hop += 1) {
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) {
      throw new LoopbackRequestError("timeout", `Timed out after ${timeoutMs} ms.`);
    }
    const response = await requestLoopbackOnce(port, currentPath, {
      ...options,
      timeoutMs: remainingMs,
    });
    const location = response.headers.location;
    if (!REDIRECT_STATUSES.has(response.status) || location === undefined) {
      return { response, redirectStop: null };
    }
    if (hop >= MAX_REDIRECTS) {
      return { response, redirectStop: { reason: "too_many_redirects", fromUrl: response.url } };
    }
    if (typeof location !== "string" || location.trim() === "") {
      return { response, redirectStop: { reason: "invalid_location", fromUrl: response.url } };
    }
    // Resolve against the full current URL (with query) but never report it.
    const next = parseAllowedLoopbackUrl(location, `${origin}${currentPath}`, { port });
    if (next === null) {
      return { response, redirectStop: { reason: "off_target", fromUrl: response.url } };
    }
    if (isUnsafeLinkPath(next.pathname)) {
      return { response, redirectStop: { reason: "unsafe_path", fromUrl: response.url } };
    }
    currentPath = `${next.pathname}${next.search}`;
  }
}
