import { GitHubAuthError } from "./errors.js";
import { asInteger, asRecord, asString, defaultFetch, type FetchLike } from "./fetch.js";
import { createGitHubClient, type GitHubClient } from "./github-client.js";

export const GITHUB_OAUTH_BASE_URL = "https://github.com";
const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
const DEFAULT_INTERVAL_SECONDS = 5;
const SLOW_DOWN_INCREMENT_SECONDS = 5;

/** What the CLI/web must show the user. Contains no secret; the device code stays internal. */
export interface DeviceUserCode {
  userCode: string;
  verificationUri: string;
  /** Seconds until the code expires. */
  expiresIn: number;
}

export interface DeviceFlowOptions {
  clientId: string;
  onUserCode: (code: DeviceUserCode) => void | Promise<void>;
  fetch?: FetchLike;
  signal?: AbortSignal;
  oauthBaseUrl?: string;
  apiBaseUrl?: string;
  /** Injectable for tests. */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  now?: () => number;
}

/**
 * An authenticated GitHub user session. The access token is held only inside `client`'s closure
 * and is not reachable from this object, its JSON form, or its string form.
 */
export interface GitHubSession {
  readonly client: GitHubClient;
  /** Epoch ms when the access token expires, from the token response's `expires_in`; `null` if unknown. */
  readonly expiresAt: number | null;
}

interface DeviceCodeGrant {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  expiresIn: number;
  interval: number;
}

function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new GitHubAuthError("cancelled", "GitHub sign-in was cancelled."));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new GitHubAuthError("cancelled", "GitHub sign-in was cancelled."));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

async function postForm(
  fetchImpl: FetchLike,
  url: string,
  form: Record<string, string>,
  signal: AbortSignal | undefined,
): Promise<Record<string, unknown>> {
  let response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "pgard",
      },
      body: new URLSearchParams(form).toString(),
      redirect: "error",
      ...(signal ? { signal } : {}),
    });
  } catch {
    if (signal?.aborted) {
      throw new GitHubAuthError("cancelled", "GitHub sign-in was cancelled.");
    }
    throw new GitHubAuthError("network_error", "Could not reach GitHub for sign-in.");
  }
  let body: Record<string, unknown> | null = null;
  try {
    body = asRecord(await response.json());
  } catch {
    body = null;
  }
  if (!body) {
    throw new GitHubAuthError(
      "unexpected_response",
      `GitHub sign-in returned an unexpected response (status ${response.status}).`,
      response.status,
    );
  }
  if (!response.ok && asString(body.error) === null) {
    throw new GitHubAuthError(
      "http_error",
      `GitHub sign-in failed with status ${response.status}.`,
      response.status,
    );
  }
  return body;
}

function mapDeviceFlowError(error: string): GitHubAuthError {
  switch (error) {
    case "access_denied":
      return new GitHubAuthError("access_denied", "GitHub sign-in was denied by the user.");
    case "expired_token":
      return new GitHubAuthError("expired_token", "The GitHub sign-in code expired.");
    case "device_flow_disabled":
      return new GitHubAuthError(
        "device_flow_disabled",
        "Device flow is not enabled for the configured GitHub App.",
      );
    case "incorrect_client_credentials":
      return new GitHubAuthError(
        "incorrect_client_credentials",
        "The configured GitHub App client id was rejected by GitHub.",
      );
    default:
      return new GitHubAuthError("unexpected_response", "GitHub sign-in failed.");
  }
}

async function requestDeviceCode(
  fetchImpl: FetchLike,
  options: DeviceFlowOptions,
): Promise<DeviceCodeGrant> {
  const base = options.oauthBaseUrl ?? GITHUB_OAUTH_BASE_URL;
  const body = await postForm(
    fetchImpl,
    `${base}/login/device/code`,
    { client_id: options.clientId },
    options.signal,
  );
  const error = asString(body.error);
  if (error !== null) {
    throw mapDeviceFlowError(error);
  }
  const deviceCode = asString(body.device_code);
  const userCode = asString(body.user_code);
  const verificationUri = asString(body.verification_uri);
  const expiresIn = asInteger(body.expires_in);
  const interval = asInteger(body.interval) ?? DEFAULT_INTERVAL_SECONDS;
  if (!deviceCode || !userCode || !verificationUri || expiresIn === null) {
    throw new GitHubAuthError("unexpected_response", "GitHub returned an invalid device code.");
  }
  if (!verificationUri.startsWith("https://github.com/")) {
    throw new GitHubAuthError("unexpected_response", "GitHub returned an unexpected sign-in URL.");
  }
  return { deviceCode, userCode, verificationUri, expiresIn, interval: Math.max(interval, 1) };
}

/**
 * Tokens from GitHub's token endpoint. Held only by this package: never logged, never part of an
 * error, never sent anywhere but GitHub.
 */
export interface UserTokenSet {
  accessToken: string;
  /** Epoch ms when the access token expires; `null` when the App does not expire tokens. */
  expiresAt: number | null;
  /** Present only when the App expires user tokens. */
  refreshToken: string | null;
  /** Epoch ms when the refresh token expires; `null` if unknown. */
  refreshTokenExpiresAt: number | null;
}

function parseTokenResponse(body: Record<string, unknown>, now: number): UserTokenSet {
  const accessToken = asString(body.access_token);
  if (!accessToken) {
    throw new GitHubAuthError("unexpected_response", "GitHub did not return an access token.");
  }
  const expiresIn = asInteger(body.expires_in);
  const refreshToken = asString(body.refresh_token);
  const refreshExpiresIn = asInteger(body.refresh_token_expires_in);
  return {
    accessToken,
    expiresAt: expiresIn !== null && expiresIn > 0 ? now + expiresIn * 1000 : null,
    refreshToken: refreshToken || null,
    refreshTokenExpiresAt:
      refreshToken && refreshExpiresIn !== null && refreshExpiresIn > 0
        ? now + refreshExpiresIn * 1000
        : null,
  };
}

export interface RefreshTokenOptions {
  clientId: string;
  refreshToken: string;
  fetch?: FetchLike;
  signal?: AbortSignal;
  oauthBaseUrl?: string;
  now?: () => number;
}

/**
 * Exchanges a refresh token for a new token set. GitHub documents `client_secret` as required
 * "unless the user access token was generated using the device flow", so PGARD refreshes with the
 * client id alone. GitHub rotates the refresh token: the old one stops working once this returns.
 * Rejects with `refresh_failed` when GitHub rejects the refresh token.
 */
export async function refreshUserToken(options: RefreshTokenOptions): Promise<UserTokenSet> {
  const fetchImpl = options.fetch ?? defaultFetch;
  const now = options.now ?? Date.now;
  const base = options.oauthBaseUrl ?? GITHUB_OAUTH_BASE_URL;
  const body = await postForm(
    fetchImpl,
    `${base}/login/oauth/access_token`,
    {
      client_id: options.clientId,
      grant_type: "refresh_token",
      refresh_token: options.refreshToken,
    },
    options.signal,
  );
  const error = asString(body.error);
  if (error === "incorrect_client_credentials") {
    throw mapDeviceFlowError(error);
  }
  if (error !== null) {
    throw new GitHubAuthError("refresh_failed", "GitHub did not accept the stored refresh token.");
  }
  return parseTokenResponse(body, now());
}

/** Runs the device flow (see `requestDeviceFlowTokens`) and resolves with an in-memory session. */
export async function authenticateWithDeviceFlow(
  options: DeviceFlowOptions,
): Promise<GitHubSession> {
  const tokens = await requestDeviceFlowTokens(options);
  return createSessionFromToken(tokens.accessToken, tokens.expiresAt, options);
}

/**
 * Runs the GitHub App device flow: requests a user code, reports it through `onUserCode`, and
 * polls until the user approves, denies, or the code expires. Resolves with the token set.
 */
export async function requestDeviceFlowTokens(options: DeviceFlowOptions): Promise<UserTokenSet> {
  const fetchImpl = options.fetch ?? defaultFetch;
  const sleep = options.sleep ?? defaultSleep;
  const now = options.now ?? Date.now;
  const base = options.oauthBaseUrl ?? GITHUB_OAUTH_BASE_URL;

  const grant = await requestDeviceCode(fetchImpl, options);
  await options.onUserCode({
    userCode: grant.userCode,
    verificationUri: grant.verificationUri,
    expiresIn: grant.expiresIn,
  });

  const deadline = now() + grant.expiresIn * 1000;
  let intervalSeconds = grant.interval;
  while (now() < deadline) {
    await sleep(intervalSeconds * 1000, options.signal);
    const body = await postForm(
      fetchImpl,
      `${base}/login/oauth/access_token`,
      {
        client_id: options.clientId,
        device_code: grant.deviceCode,
        grant_type: DEVICE_GRANT_TYPE,
      },
      options.signal,
    );
    const error = asString(body.error);
    if (error === "authorization_pending") {
      continue;
    }
    if (error === "slow_down") {
      // GitHub returns the new interval with slow_down; only fall back to +5 when it is absent.
      const suggested = asInteger(body.interval);
      intervalSeconds =
        suggested !== null && suggested > 0
          ? suggested
          : intervalSeconds + SLOW_DOWN_INCREMENT_SECONDS;
      continue;
    }
    if (error !== null) {
      throw mapDeviceFlowError(error);
    }
    return parseTokenResponse(body, now());
  }
  throw new GitHubAuthError("expired_token", "The GitHub sign-in code expired.");
}

/** Builds a session around an access token; the token stays inside the client's closure. */
export function createSessionFromToken(
  token: string,
  expiresAt: number | null,
  options: { fetch?: FetchLike; apiBaseUrl?: string; signal?: AbortSignal },
): GitHubSession {
  const client = createGitHubClient({
    token,
    fetch: options.fetch ?? defaultFetch,
    ...(options.apiBaseUrl ? { baseUrl: options.apiBaseUrl } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
  });
  return createGitHubSession(client, expiresAt);
}

/** Wraps a client as a session whose JSON/string forms reveal nothing. */
export function createGitHubSession(
  client: GitHubClient,
  expiresAt: number | null = null,
): GitHubSession {
  const session: GitHubSession = { client, expiresAt };
  Object.defineProperty(session, "toJSON", { value: () => ({ type: "github-session" }) });
  Object.defineProperty(session, "toString", { value: () => "[GitHubSession]" });
  return Object.freeze(session);
}
