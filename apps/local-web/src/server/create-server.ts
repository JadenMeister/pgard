import { randomBytes } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { sanitizeDisplayText } from "@pgard/http-local";
import { isOpenableGitHubUrl } from "@pgard/scan-core";
import { createDefaultServerDeps, type ServerDeps } from "./deps.js";
import {
  applySecurityHeaders,
  checkHost,
  checkOrigin,
  checkSessionToken,
  type RequestCheck,
} from "./middleware/security.js";
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

export interface LocalWebServerOptions {
  /** Git root confirmed by the launcher in the terminal. Fixed for the server's lifetime. */
  projectRoot: string;
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
}

export interface LocalWebServer {
  url: string;
  port: number;
  token: string;
  state: SessionState;
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
 * token header, our exact Host and (for writes) our Origin; there is no CORS and no route that
 * reads arbitrary files. The browser only ever receives redacted results.
 */
export async function startLocalWebServer(options: LocalWebServerOptions): Promise<LocalWebServer> {
  const deps = options.deps ?? createDefaultServerDeps();
  const token = options.token ?? randomBytes(32).toString("base64url");
  const state = createSessionState();
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
    projectRoot: options.projectRoot,
    presetTargetPort: options.presetTargetPort,
    env: options.env,
    state,
    deps,
    github,
  };

  const server = http.createServer((request, response) => {
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
      const tokenCheck = checkSessionToken(request, token);
      if (!tokenCheck.isAllowed) return reject(response, tokenCheck);
      const handler = API_ROUTES[`${method} ${pathname}`];
      if (handler === undefined) return sendError(response, 404, "not_found", "Unknown API route.");
      void (async () => {
        try {
          const body = isStateChanging ? await readJsonBody(request) : undefined;
          const payload = await handler(context, body, query);
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

  await new Promise<void>((resolve, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, LOOPBACK_HOST, () => resolve());
  });
  port = (server.address() as AddressInfo).port;

  return {
    url: `http://${LOOPBACK_HOST}:${port}/#token=${token}`,
    port,
    token,
    state,
    close: async () => {
      // Stops a pending device flow too, so the process can exit right away.
      github.dispose();
      clearSessionState(state);
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
