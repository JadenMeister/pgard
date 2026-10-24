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
 * Runs the GitHub App device flow: requests a user code, reports it through `onUserCode`, and
 * polls until the user approves, denies, or the code expires. Resolves with an in-memory session.
 */
export async function authenticateWithDeviceFlow(
  options: DeviceFlowOptions,
): Promise<GitHubSession> {
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
      intervalSeconds = (asInteger(body.interval) ?? intervalSeconds) + SLOW_DOWN_INCREMENT_SECONDS;
      continue;
    }
    if (error !== null) {
      throw mapDeviceFlowError(error);
    }
    const accessToken = asString(body.access_token);
    if (!accessToken) {
      throw new GitHubAuthError("unexpected_response", "GitHub did not return an access token.");
    }
    return createSession(accessToken, fetchImpl, options);
  }
  throw new GitHubAuthError("expired_token", "The GitHub sign-in code expired.");
}

function createSession(
  token: string,
  fetchImpl: FetchLike,
  options: DeviceFlowOptions,
): GitHubSession {
  const client = createGitHubClient({
    token,
    fetch: fetchImpl,
    ...(options.apiBaseUrl ? { baseUrl: options.apiBaseUrl } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
  });
  return createGitHubSession(client);
}

/** Wraps a client as a session whose JSON/string forms reveal nothing. */
export function createGitHubSession(client: GitHubClient): GitHubSession {
  const session: GitHubSession = { client };
  Object.defineProperty(session, "toJSON", { value: () => ({ type: "github-session" }) });
  Object.defineProperty(session, "toString", { value: () => "[GitHubSession]" });
  return Object.freeze(session);
}
