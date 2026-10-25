import { describe, expect, it, vi } from "vitest";
import { authenticateWithDeviceFlow } from "./device-flow.js";
import { DEFAULT_GITHUB_APP_CLIENT_ID, resolveGitHubAppClientId } from "./env.js";
import { GitHubAuthError } from "./errors.js";
import type { FetchLike, FetchRequestInit } from "./fetch.js";
import { createDeviceFlowSessionProvider } from "./session-provider.js";

const FAKE_TOKEN = ["ghu", "fakeTokenForTestsOnly000000000000000"].join("_");

function jsonResponse(status: number, body: unknown) {
  return { status, ok: status >= 200 && status < 300, json: async () => body };
}

interface Call {
  url: string;
  init: FetchRequestInit;
}

function createFetch(tokenResponses: unknown[]): { fetch: FetchLike; calls: Call[] } {
  const calls: Call[] = [];
  const queue = [...tokenResponses];
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith("/login/device/code")) {
      return jsonResponse(200, {
        device_code: "device-code-secret",
        user_code: "ABCD-1234",
        verification_uri: "https://github.com/login/device",
        expires_in: 900,
        interval: 5,
      });
    }
    if (url.endsWith("/login/oauth/access_token")) {
      return jsonResponse(200, queue.shift() ?? { error: "expired_token" });
    }
    if (url.endsWith("/user")) {
      return init.headers.Authorization?.endsWith("revoked")
        ? jsonResponse(401, { message: "Bad credentials" })
        : jsonResponse(200, { id: 7, login: "octo", name: null, email: null });
    }
    return jsonResponse(404, {});
  };
  return { fetch, calls };
}

const noSleep = async () => {};

describe("authenticateWithDeviceFlow", () => {
  it("reports the user code, polls through pending/slow_down and returns a session", async () => {
    const { fetch, calls } = createFetch([
      { error: "authorization_pending" },
      { error: "slow_down", interval: 10 },
      { access_token: FAKE_TOKEN, token_type: "bearer" },
    ]);
    const sleeps: number[] = [];
    const onUserCode = vi.fn();
    const session = await authenticateWithDeviceFlow({
      clientId: "Iv1.test",
      onUserCode,
      fetch,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
    });
    expect(onUserCode).toHaveBeenCalledWith({
      userCode: "ABCD-1234",
      verificationUri: "https://github.com/login/device",
      expiresIn: 900,
    });
    expect(sleeps).toEqual([5000, 5000, 10000]);
    const user = await session.client.getAuthenticatedUser();
    expect(user.id).toBe(7);
    const userCall = calls.find((call) => call.url.endsWith("/user"));
    expect(userCall?.init.headers.Authorization).toBe(`Bearer ${FAKE_TOKEN}`);
  });

  it("never exposes the token through the session object", async () => {
    const { fetch } = createFetch([{ access_token: FAKE_TOKEN }]);
    const session = await authenticateWithDeviceFlow({
      clientId: "Iv1.test",
      onUserCode: () => {},
      fetch,
      sleep: noSleep,
    });
    expect(JSON.stringify(session)).not.toContain(FAKE_TOKEN);
    expect(String(session)).not.toContain(FAKE_TOKEN);
    expect(JSON.stringify(session.client)).not.toContain(FAKE_TOKEN);
    expect(Object.values(session.client).join(" ")).not.toContain(FAKE_TOKEN);
  });

  it.each([
    ["access_denied", "access_denied"],
    ["expired_token", "expired_token"],
    ["device_flow_disabled", "device_flow_disabled"],
  ])("maps %s to a typed error", async (githubError, code) => {
    const { fetch } = createFetch([{ error: githubError }]);
    const promise = authenticateWithDeviceFlow({
      clientId: "Iv1.test",
      onUserCode: () => {},
      fetch,
      sleep: noSleep,
    });
    await expect(promise).rejects.toMatchObject({ code });
  });

  it("does not leak the device code in error messages", async () => {
    const { fetch } = createFetch([{ error: "access_denied" }]);
    const error = await authenticateWithDeviceFlow({
      clientId: "Iv1.test",
      onUserCode: () => {},
      fetch,
      sleep: noSleep,
    }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(GitHubAuthError);
    expect((error as Error).message).not.toContain("device-code-secret");
  });

  it("rejects a verification URL outside github.com", async () => {
    const fetch: FetchLike = async () =>
      jsonResponse(200, {
        device_code: "x",
        user_code: "ABCD-1234",
        verification_uri: "https://evil.example/login",
        expires_in: 900,
        interval: 5,
      });
    await expect(
      authenticateWithDeviceFlow({ clientId: "Iv1.test", onUserCode: () => {}, fetch }),
    ).rejects.toMatchObject({ code: "unexpected_response" });
  });

  it("stops polling once the code expires", async () => {
    let clock = 0;
    const { fetch } = createFetch(Array(1000).fill({ error: "authorization_pending" }));
    await expect(
      authenticateWithDeviceFlow({
        clientId: "Iv1.test",
        onUserCode: () => {},
        fetch,
        now: () => clock,
        sleep: async (ms) => {
          clock += ms;
        },
      }),
    ).rejects.toMatchObject({ code: "expired_token" });
  });
});

describe("createDeviceFlowSessionProvider", () => {
  it("signs in with the built-in PGARD App when no override is set", async () => {
    const { fetch, calls } = createFetch([{ access_token: FAKE_TOKEN }]);
    const provider = createDeviceFlowSessionProvider({
      clientId: resolveGitHubAppClientId({}).clientId,
      onUserCode: () => {},
      fetch,
      sleep: noSleep,
    });
    await provider();
    const codeRequest = calls.find((call) => call.url.endsWith("/login/device/code"));
    expect(new URLSearchParams(codeRequest?.init.body ?? "").get("client_id")).toBe(
      DEFAULT_GITHUB_APP_CLIENT_ID,
    );
  });

  it("reuses the in-memory session within one provider", async () => {
    const { fetch, calls } = createFetch([{ access_token: FAKE_TOKEN }]);
    const provider = createDeviceFlowSessionProvider({
      clientId: "Iv1.test",
      onUserCode: () => {},
      fetch,
      sleep: noSleep,
    });
    const first = await provider();
    const second = await provider();
    expect(first).toBe(second);
    expect(calls.filter((call) => call.url.endsWith("/login/device/code"))).toHaveLength(1);
  });

  const deviceCodeRequests = (calls: Call[]) =>
    calls.filter((call) => call.url.endsWith("/login/device/code")).length;

  it("drops the session after a 401 so the next call signs in again", async () => {
    const revoked = ["ghu", "revoked"].join("_");
    const { fetch, calls } = createFetch([{ access_token: revoked }, { access_token: FAKE_TOKEN }]);
    const provider = createDeviceFlowSessionProvider({
      clientId: "Iv1.test",
      onUserCode: () => {},
      fetch,
      sleep: noSleep,
    });
    const first = await provider();
    await expect(first.client.getAuthenticatedUser()).rejects.toMatchObject({
      code: "unauthorized",
    });
    const second = await provider();
    expect(second).not.toBe(first);
    expect((await second.client.getAuthenticatedUser()).id).toBe(7);
    expect(deviceCodeRequests(calls)).toBe(2);
  });

  it("renews the session before the token's expires_in elapses", async () => {
    let clock = 1_000_000;
    const { fetch, calls } = createFetch([
      { access_token: FAKE_TOKEN, expires_in: 28800 },
      { access_token: FAKE_TOKEN, expires_in: 28800 },
    ]);
    const provider = createDeviceFlowSessionProvider({
      clientId: "Iv1.test",
      onUserCode: () => {},
      fetch,
      sleep: noSleep,
      now: () => clock,
    });
    const first = await provider();
    expect(first.expiresAt).toBe(1_000_000 + 28800 * 1000);
    clock += 1000;
    expect(await provider()).toBe(first);
    clock += 28800 * 1000;
    expect(await provider()).not.toBe(first);
    expect(deviceCodeRequests(calls)).toBe(2);
  });

  it("signOut forgets the session", async () => {
    const { fetch, calls } = createFetch([
      { access_token: FAKE_TOKEN },
      { access_token: FAKE_TOKEN },
    ]);
    const provider = createDeviceFlowSessionProvider({
      clientId: "Iv1.test",
      onUserCode: () => {},
      fetch,
      sleep: noSleep,
    });
    const first = await provider();
    provider.signOut();
    await expect(first.client.getAuthenticatedUser()).rejects.toMatchObject({
      code: "unauthorized",
    });
    const userCallsAfterSignOut = calls.filter((call) => call.url.endsWith("/user")).length;
    expect(userCallsAfterSignOut).toBe(0);
    const second = await provider();
    expect(second).not.toBe(first);
    expect((await second.client.getAuthenticatedUser()).id).toBe(7);
    expect(deviceCodeRequests(calls)).toBe(2);
  });

  it("invalidate() also revokes sessions already handed out", async () => {
    const { fetch } = createFetch([{ access_token: FAKE_TOKEN }]);
    const provider = createDeviceFlowSessionProvider({
      clientId: "Iv1.test",
      onUserCode: () => {},
      fetch,
      sleep: noSleep,
    });
    const first = await provider();
    expect((await first.client.getAuthenticatedUser()).id).toBe(7);
    provider.invalidate();
    await expect(first.client.getAuthenticatedUser()).rejects.toMatchObject({
      code: "unauthorized",
    });
  });

  it("does not remember a failed sign-in", async () => {
    const { fetch, calls } = createFetch([
      { error: "access_denied" },
      { access_token: FAKE_TOKEN },
    ]);
    const provider = createDeviceFlowSessionProvider({
      clientId: "Iv1.test",
      onUserCode: () => {},
      fetch,
      sleep: noSleep,
    });
    await expect(provider()).rejects.toMatchObject({ code: "access_denied" });
    await expect(provider()).resolves.toBeDefined();
    expect(deviceCodeRequests(calls)).toBe(2);
  });
});

describe("slow_down handling", () => {
  it("falls back to +5 seconds only when GitHub sends no interval", async () => {
    const { fetch } = createFetch([{ error: "slow_down" }, { access_token: FAKE_TOKEN }]);
    const sleeps: number[] = [];
    await authenticateWithDeviceFlow({
      clientId: "Iv1.test",
      onUserCode: () => {},
      fetch,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
    });
    expect(sleeps).toEqual([5000, 10000]);
  });
});
