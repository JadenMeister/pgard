import { describe, expect, it } from "vitest";
import { authenticateWithDeviceFlow } from "./device-flow.js";
import type { FetchLike } from "./fetch.js";
import { createGitHubClient } from "./github-client.js";
import {
  CONNECTION_CAUSE_CODES,
  TLS_CAUSE_CODES,
  networkCauseCode,
  networkHintEnglish,
  networkHintKind,
} from "./network-cause.js";

/** What Node's `fetch` throws: `TypeError: fetch failed` with the reason in `cause.code`. */
function fetchFailed(code: string, secretText = "connect to proxy.corp:3128"): Error {
  const cause = Object.assign(new Error(secretText), { code });
  return new TypeError("fetch failed", { cause });
}

const failingWith =
  (error: unknown): FetchLike =>
  async () => {
    throw error;
  };

const ALL_CODES = [...TLS_CAUSE_CODES, ...CONNECTION_CAUSE_CODES];

describe("networkCauseCode", () => {
  it.each(ALL_CODES)("keeps %s from the cause chain", (code) => {
    expect(networkCauseCode(fetchFailed(code))).toBe(code);
  });

  it("finds a code inside an AggregateError and a deeper cause", () => {
    const aggregate = new AggregateError([fetchFailed("ECONNREFUSED")], "all failed");
    expect(networkCauseCode(new TypeError("fetch failed", { cause: aggregate }))).toBe(
      "ECONNREFUSED",
    );
  });

  it("ignores codes outside the whitelist, text and non-errors", () => {
    expect(networkCauseCode(fetchFailed("ESOMETHINGELSE"))).toBeNull();
    expect(networkCauseCode(new TypeError("fetch failed ENOTFOUND"))).toBeNull();
    expect(networkCauseCode("ENOTFOUND")).toBeNull();
    expect(networkCauseCode(null)).toBeNull();
    const loop: { cause?: unknown } = {};
    loop.cause = loop;
    expect(networkCauseCode(loop)).toBeNull();
  });
});

describe("network hints", () => {
  it.each(TLS_CAUSE_CODES)("sends %s to the TLS remedy", (code) => {
    expect(networkHintKind(code)).toBe("tls");
    expect(networkHintEnglish(code, { codeOnly: false })).toContain("NODE_EXTRA_CA_CERTS");
  });

  it.each(CONNECTION_CAUSE_CODES)("sends %s to the proxy and offline remedy", (code) => {
    expect(networkHintKind(code)).toBe("network");
    const hint = networkHintEnglish(code, { codeOnly: false });
    expect(hint).toContain("HTTPS_PROXY");
    expect(hint).toContain("NODE_USE_ENV_PROXY=1");
    expect(hint).not.toContain("--code-only");
  });

  it("points to --code-only only when asked, and treats an unknown cause as offline", () => {
    expect(networkHintEnglish(null, { codeOnly: true })).toContain("`pgard scan code --code-only`");
    expect(networkHintKind(null)).toBe("network");
  });
});

describe("network failures keep the cause code and never echo raw text", () => {
  const SECRET = "http://user:hunter2@proxy.corp:3128";

  it.each(ALL_CODES)("sign-in reports %s", async (code) => {
    const failure = await authenticateWithDeviceFlow({
      clientId: "Iv1.test",
      onUserCode: () => {},
      fetch: failingWith(fetchFailed(code, SECRET)),
      sleep: async () => {},
    }).then(
      () => null,
      (error: unknown) => error,
    );
    expect(failure).toMatchObject({
      code: "network_error",
      causeCode: code,
      message: `Could not reach GitHub for sign-in (${code}).`,
    });
    expect(String((failure as Error).message)).not.toContain("hunter2");
  });

  it.each(ALL_CODES)("the API client reports %s", async (code) => {
    const client = createGitHubClient({
      token: "t",
      fetch: failingWith(fetchFailed(code, SECRET)),
    });
    await expect(client.getAuthenticatedUser()).rejects.toMatchObject({
      code: "network_error",
      causeCode: code,
      message: `Could not reach the GitHub API (${code}).`,
    });
  });

  it("keeps the plain message and a null cause when the reason is unknown", async () => {
    const client = createGitHubClient({ token: "t", fetch: failingWith(new Error(SECRET)) });
    const failure = await client.getAuthenticatedUser().then(
      () => null,
      (error: unknown) => error,
    );
    expect(failure).toMatchObject({
      code: "network_error",
      causeCode: null,
      message: "Could not reach the GitHub API.",
    });
  });
});
