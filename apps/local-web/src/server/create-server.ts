import { randomBytes } from "node:crypto";
import http from "node:http";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { sanitizeDisplayText } from "@pgard/http-local";
import { isOpenableGitHubUrl } from "@pgard/scan-core";
import { createDefaultServerDeps, type ServerDeps } from "./deps.js";
import {
  applySecurityHeaders,
  checkHost,
  checkOrigin,
  checkSession,
  type RequestCheck,
} from "./middleware/security.js";
import { createUrlSession } from "./session/url-session.js";
import { API_ROUTES, ApiDownload, ApiError, type ApiContext } from "./routes/api.js";
import { createGitHubSessionManager } from "./session/github-session.js";
import { applySignInNotice } from "./session/stored-sign-in.js";
import {
  clearSessionState,
  createSessionState,
  type SessionState,
} from "./session/session-state.js";
import type { StaticAsset } from "./static-files.js";

export { createDefaultServerDeps, type ServerDeps } from "./deps.js";

export const MAX_BODY_BYTES = 16 * 1024;
export const LOOPBACK_HOST = "127.0.0.1";

/**
 * Connection limits for the loopback server. Every route answers quickly: a scan is started with
 * one short POST and read by polling `GET /api/scan`, so no route needs a long request (there is
 * no streaming route). Scans of any length are therefore unaffected by `REQUEST_TIMEOUT_MS`.
 */
export const HEADERS_TIMEOUT_MS = 10_000;
export const REQUEST_TIMEOUT_MS = 30_000;
export const KEEP_ALIVE_TIMEOUT_MS = 5_000;
export const MAX_CONNECTIONS = 64;

export interface LocalWebServerOptions {
  /**
   * Git root confirmed by the launcher in the terminal (`pgard dashboard`): fixed for the
   * server's lifetime, and every picker route is refused. `null` is picker mode (`pgard web`):
   * the project is chosen after start through `deps.picker`.
   */
  projectRoot: string | null;
  presetTargetPort: number | null;
  env: Readonly<Record<string, string | undefined>>;
  assets: Map<string, StaticAsset>;
  deps?: ServerDeps;
  /**
   * Opens a GitHub page (the device sign-in page) in the system browser. Omitted: nothing is
   * opened automatically. Only `https://github.com/` URLs are ever passed.
   */
  openGitHubPage?: (url: string) => void;
  /** Test hook; production uses 32 random bytes. */
  token?: string;
  /**
   * Test hook: a session secret that is already connected, as if the URL token had been
   * exchanged. Production never passes it: the page must exchange the URL token.
   */
  sessionSecretForTests?: string;
  /**
   * The clock of the URL token expiry and the session idle timeout (test hook; `Date.now`). Kept
   * apart from `deps.now`, which tests move by days to age authorization checks.
   */
  sessionClock?: () => number;
  /** Called on every successful exchange (the launcher prints "Browser connected at ..."). */
  onBrowserConnected?: (at: Date) => void;
  /** Dev preview hook; production always takes a free port. */
  port?: number;
  /**
   * The first screen in picker mode: `simple` (the default; choose a folder, scan, read the
   * findings) or `full` (the dashboard with the search picker). Fixed mode (`pgard dashboard`) is
   * always `full`.
   */
  ui?: "full" | "simple";
}

export interface LocalWebServer {
  url: string;
  port: number;
  token: string;
  state: SessionState;
  /** The underlying HTTP server (exposed for limit checks in tests). */
  server: http.Server;
  close: () => Promise<void>;
}

function sendJson(response: http.ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload ?? null);
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.end(body);
}

function sendError(
  response: http.ServerResponse,
  status: number,
  code: string,
  message: string,
): void {
  sendJson(response, status, { error: { code, message } });
}

function reject(response: http.ServerResponse, check: RequestCheck): void {
  sendError(response, check.status, check.code, check.message);
}

async function readJsonBody(request: http.IncomingMessage): Promise<unknown> {
  const contentType = request.headers["content-type"] ?? "";
  if (!/^application\/json\b/i.test(contentType)) {
    throw new ApiError(415, "bad_content_type", "Expected application/json.");
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES)
      throw new ApiError(413, "body_too_large", "Request body is too large.");
    chunks.push(chunk as Buffer);
  }
  if (size === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new ApiError(400, "bad_json", "Request body is not valid JSON.");
  }
}

/**
 * Starts the dashboard server on 127.0.0.1 with a free port. Every API call needs the session
 * secret header (traded once for the URL token, #419), our exact Host and (for writes) our
 * Origin; there is no CORS and no route that
 * reads arbitrary files. The browser only ever receives redacted results.
 */
export async function startLocalWebServer(options: LocalWebServerOptions): Promise<LocalWebServer> {
  const deps = options.deps ?? createDefaultServerDeps();
  const token = options.token ?? randomBytes(32).toString("base64url");
  const sessionClock = options.sessionClock ?? Date.now;
  const urlSession = createUrlSession(
    token,
    sessionClock(),
    options.sessionSecretForTests === undefined
      ? {}
      : { presetSecret: options.sessionSecretForTests },
  );
  const state = createSessionState(
    options.projectRoot === null
      ? null
      : {
          root: options.projectRoot,
          name: sanitizeDisplayText(path.basename(options.projectRoot), 120),
          repo: null,
          repositoryId: null,
          identity: null,
          candidateId: null,
        },
  );
  const github = createGitHubSessionManager(
    deps,
    options.env,
    (code) => {
      state.deviceCode = {
        userCode: sanitizeDisplayText(code.userCode, 40),
        verificationUri: sanitizeDisplayText(code.verificationUri, 200),
        expiresIn: code.expiresIn,
      };
      if (isOpenableGitHubUrl(code.verificationUri)) {
        try {
          options.openGitHubPage?.(code.verificationUri);
        } catch {
          // Failing to open a browser is never an error; the page is linked in the dashboard.
        }
      }
    },
    (notice) => applySignInNotice(state, notice),
  );
  let port = 0;
  const context: ApiContext = {
    mode: options.projectRoot === null ? "picker" : "fixed",
    ui: options.projectRoot === null && options.ui !== "full" ? "simple" : "full",
    presetTargetPort: options.presetTargetPort,
    env: options.env,
    state,
    deps,
    github,
  };

  // `connectionsCheckingInterval` makes `headersTimeout` fire close to 10 s (the default checks
  // only every 30 s).
  const server = http.createServer({ connectionsCheckingInterval: 1000 }, (request, response) => {
    applySecurityHeaders(response);
    const hostCheck = checkHost(request, port);
    if (!hostCheck.isAllowed) return reject(response, hostCheck);
    const method = request.method ?? "GET";
    const [pathname = "/", queryString = ""] = (request.url ?? "/").split("?", 2);
    const query = new URLSearchParams(queryString);

    if (pathname.startsWith("/api/")) {
      const isStateChanging = method !== "GET";
      const originCheck = checkOrigin(request, port, isStateChanging);
      if (!originCheck.isAllowed) return reject(response, originCheck);
      if (pathname === "/api/session/exchange") {
        if (method !== "POST") return sendError(response, 404, "not_found", "Unknown API route.");
        void (async () => {
          try {
            const body = (await readJsonBody(request)) as { token?: unknown } | null;
            const outcome = urlSession.exchange(body?.token, sessionClock());
            if (outcome.kind === "ok") {
              try {
                options.onBrowserConnected?.(new Date());
              } catch {
                // The terminal line is informational only.
              }
              return sendJson(response, 200, { session: outcome.secret });
            }
            if (outcome.kind === "token_used") {
              return sendError(
                response,
                409,
                "token_used",
                "This link was already used. Run the command again to get a new one.",
              );
            }
            if (outcome.kind === "token_expired") {
              return sendError(
                response,
                410,
                "token_expired",
                "This link expired. Run the command again to get a new one.",
              );
            }
            return sendError(response, 401, "bad_token", "This link is not valid for this server.");
          } catch (error) {
            if (error instanceof ApiError)
              return sendError(response, error.status, error.code, error.message);
            sendError(response, 500, "internal", "Internal error.");
          }
        })();
        return;
      }
      const sessionCheck = checkSession(request, urlSession, sessionClock());
      if (!sessionCheck.isAllowed) return reject(response, sessionCheck);
      // Fixed mode (`pgard dashboard`): the picker is hard-disabled. Every picker request, any
      // method, any body, is refused before the body is read and before the route is looked up.
      if (context.mode === "fixed" && pathname.startsWith("/api/picker")) {
        return sendError(
          response,
          409,
          "fixed_project",
          "This dashboard was started for one project. To pick another, start `pgard web`.",
        );
      }
      const handler = API_ROUTES[`${method} ${pathname}`];
      if (handler === undefined) return sendError(response, 404, "not_found", "Unknown API route.");
      // Aborts when the client goes away before the answer was sent, so work only that request
      // waits for (an owner-approval re-check and its git processes) stops with it.
      const requestAbort = new AbortController();
      response.on("close", () => {
        if (!response.writableFinished) requestAbort.abort();
      });
      void (async () => {
        try {
          const body = isStateChanging ? await readJsonBody(request) : undefined;
          const payload = await handler(context, body, query, { signal: requestAbort.signal });
          if (payload instanceof ApiDownload) {
            const content = Buffer.from(payload.body);
            response.statusCode = 200;
            response.setHeader("Content-Type", payload.contentType);
            response.setHeader("Content-Disposition", `attachment; filename="${payload.filename}"`);
            response.setHeader("Content-Length", content.length);
            response.end(content);
            return;
          }
          sendJson(response, 200, payload);
        } catch (error) {
          if (error instanceof ApiError)
            return sendError(response, error.status, error.code, error.message);
          sendError(response, 500, "internal", "Internal error.");
        }
      })();
      return;
    }

    if (method !== "GET" && method !== "HEAD") {
      return sendError(response, 405, "method_not_allowed", "Method not allowed.");
    }
    const originCheck = checkOrigin(request, port, false);
    if (!originCheck.isAllowed) return reject(response, originCheck);
    const asset = options.assets.get(pathname);
    if (asset === undefined) return sendError(response, 404, "not_found", "Not found.");
    response.statusCode = 200;
    response.setHeader("Content-Type", asset.contentType);
    response.end(method === "HEAD" ? undefined : asset.body);
  });

  server.headersTimeout = HEADERS_TIMEOUT_MS;
  server.requestTimeout = REQUEST_TIMEOUT_MS;
  server.keepAliveTimeout = KEEP_ALIVE_TIMEOUT_MS;
  server.maxConnections = MAX_CONNECTIONS;

  await new Promise<void>((resolve, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(options.port ?? 0, LOOPBACK_HOST, () => resolve());
  });
  port = (server.address() as AddressInfo).port;

  return {
    url: `http://${LOOPBACK_HOST}:${port}/#token=${token}`,
    port,
    token,
    state,
    server,
    close: async () => {
      // Stops a pending device flow too, so the process can exit right away.
      github.dispose();
      // Aborts a running check (killing its git children) and ends the inspector processes.
      clearSessionState(state);
      deps.picker?.inspector.stopAll();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
