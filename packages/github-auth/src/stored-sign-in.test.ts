import { describe, expect, it } from "vitest";
import {
  createInMemoryCredentialStore,
  createUnavailableCredentialStore,
  CredentialStoreError,
  isCredentialStoreError,
  type CredentialStore,
} from "./credential-store.js";
import { DEFAULT_GITHUB_APP_CLIENT_ID, resolveGitHubAppClientId } from "./env.js";
import type { FetchLike, FetchRequestInit } from "./fetch.js";

import {
  createDeviceFlowSessionProvider,
  signInAndStore,
  type SignInNotice,
} from "./session-provider.js";
import {
  readStoredSignInStatus,
  removeStoredSignIn,
  signInKey,
  withKeychainLock,
} from "./stored-sign-in.js";

const CLIENT_ID = "Iv23.testClient";
const OTHER_CLIENT_ID = "Iv23.otherClient";
const token = (name: string) => ["ghu", `${name}SecretTokenForTests0000`].join("_");
const refresh = (name: string) => ["ghr", `${name}SecretRefreshForTests000`].join("_");
const NEW_TOKEN = token("new");
const NEW_REFRESH = refresh("new");
const STORED_TOKEN = token("stored");
const STORED_REFRESH = refresh("stored");
const REFRESHED_TOKEN = token("refreshed");
const REFRESHED_REFRESH = refresh("refreshed");
const REVOKED_TOKEN = token("revoked");
const ALL_SECRETS = [
  NEW_TOKEN,
  NEW_REFRESH,
  STORED_TOKEN,
  STORED_REFRESH,
  REFRESHED_TOKEN,
  REFRESHED_REFRESH,
  REVOKED_TOKEN,
];

const HOUR = 3600 * 1000;
const START = 1_800_000_000_000;

interface Call {
  url: string;
  init: FetchRequestInit;
  form: URLSearchParams;
}

function jsonResponse(status: number, body: unknown) {
  return { status, ok: status >= 200 && status < 300, json: async () => body };
}

/**
 * Fake GitHub. Device flow returns `deviceTokens` in order; the refresh grant answers with
 * `refreshResponse`; `GET /user` returns 401 for `REVOKED_TOKEN`.
 */
function fakeGitHub(
  options: {
    deviceTokens?: unknown[];
    refreshResponse?: unknown;
  } = {},
) {
  const calls: Call[] = [];
  const deviceTokens = [...(options.deviceTokens ?? [])];
  const fetch: FetchLike = async (url, init) => {
    const form = new URLSearchParams(init.body ?? "");
    calls.push({ url, init, form });
    if (url.endsWith("/login/device/code")) {
      return jsonResponse(200, {
        device_code: "device-code-internal",
        user_code: "ABCD-1234",
        verification_uri: "https://github.com/login/device",
        expires_in: 900,
        interval: 5,
      });
    }
    if (url.endsWith("/login/oauth/access_token")) {
      if (form.get("grant_type") === "refresh_token") {
        return jsonResponse(200, options.refreshResponse ?? { error: "bad_refresh_token" });
      }
      return jsonResponse(200, deviceTokens.shift() ?? { error: "expired_token" });
    }
    if (url.endsWith("/user")) {
      return init.headers.Authorization === `Bearer ${REVOKED_TOKEN}`
        ? jsonResponse(401, { message: "Bad credentials" })
        : jsonResponse(200, { id: 7, login: "octo", name: null, email: null });
    }
    return jsonResponse(404, {});
  };
  const count = (kind: "device" | "refresh" | "user") =>
    calls.filter((call) =>
      kind === "device"
        ? call.url.endsWith("/login/device/code")
        : kind === "refresh"
          ? call.form.get("grant_type") === "refresh_token"
          : call.url.endsWith("/user"),
    ).length;
  return { fetch, calls, count };
}

function storedRecord(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    version: 1,
    host: "github.com",
    clientId: CLIENT_ID,
    accessToken: STORED_TOKEN,
    expiresAt: START + 8 * HOUR,
    refreshToken: STORED_REFRESH,
    refreshTokenExpiresAt: START + 180 * 24 * HOUR,
    login: "octo",
    userId: 7,
    savedAt: START,
    ...overrides,
  });
}

const KEY = signInKey("github.com", CLIENT_ID);

async function storeWith(
  record: string | null,
): Promise<ReturnType<typeof createInMemoryCredentialStore>> {
  const store = createInMemoryCredentialStore();
  if (record !== null) await store.set(KEY, record);
  return store;
}

function makeProvider(
  github: ReturnType<typeof fakeGitHub>,
  store: CredentialStore | null,
  extra: { clientId?: string; now?: () => number; sleep?: (ms: number) => Promise<void> } = {},
) {
  const notices: SignInNotice[] = [];
  const userCodes: string[] = [];
  const provider = createDeviceFlowSessionProvider({
    clientId: extra.clientId ?? CLIENT_ID,
    onUserCode: (code) => {
      userCodes.push(code.userCode);
    },
    credentialStore: store,
    onNotice: (notice) => notices.push(notice),
    fetch: github.fetch,
    sleep: extra.sleep ?? (async () => {}),
    now: extra.now ?? (() => START),
  });
  return { provider, notices, userCodes };
}

function expectNoSecret(text: string): void {
  for (const secret of ALL_SECRETS) expect(text).not.toContain(secret);
}

describe("stored sign-in reuse", () => {
  it("saves a device-flow sign-in and reuses it in the next run without a device code", async () => {
    const store = await storeWith(null);
    const github = fakeGitHub({
      deviceTokens: [
        {
          access_token: NEW_TOKEN,
          expires_in: 28800,
          refresh_token: NEW_REFRESH,
          refresh_token_expires_in: 15897600,
        },
      ],
    });
    const first = makeProvider(github, store);
    await first.provider();
    expect(first.userCodes).toEqual(["ABCD-1234"]);
    expect(first.notices).toEqual([{ kind: "saved", login: "octo", userId: 7 }]);
    expect(JSON.parse((await store.get(KEY)) ?? "{}")).toMatchObject({
      accessToken: NEW_TOKEN,
      refreshToken: NEW_REFRESH,
      expiresAt: START + 28800 * 1000,
      login: "octo",
    });

    // A second CLI run: a fresh provider, same keychain.
    const second = makeProvider(github, store);
    const session = await second.provider();
    expect(second.userCodes).toEqual([]);
    expect(second.notices).toEqual([
      { kind: "reused", login: "octo", userId: 7, isRefreshed: false },
    ]);
    expect((await session.client.getAuthenticatedUser()).login).toBe("octo");
    expect(github.count("device")).toBe(1);
  });

  it("refreshes an expired access token without a client secret and stores the rotated tokens", async () => {
    const store = await storeWith(storedRecord({ expiresAt: START - HOUR }));
    const github = fakeGitHub({
      refreshResponse: {
        access_token: REFRESHED_TOKEN,
        expires_in: 28800,
        refresh_token: REFRESHED_REFRESH,
        refresh_token_expires_in: 15897600,
      },
    });
    const { provider, notices, userCodes } = makeProvider(github, store);
    await provider();
    expect(userCodes).toEqual([]);
    expect(notices).toEqual([{ kind: "reused", login: "octo", userId: 7, isRefreshed: true }]);
    const refreshCall = github.calls.find(
      (call) => call.form.get("grant_type") === "refresh_token",
    );
    expect(refreshCall?.form.get("client_id")).toBe(CLIENT_ID);
    expect(refreshCall?.form.has("client_secret")).toBe(false);
    expect(JSON.parse((await store.get(KEY)) ?? "{}")).toMatchObject({
      accessToken: REFRESHED_TOKEN,
      refreshToken: REFRESHED_REFRESH,
    });
  });

  it("deletes an expired entry without a refresh token and signs in again", async () => {
    const store = await storeWith(storedRecord({ expiresAt: START - HOUR, refreshToken: null }));
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const { provider, notices, userCodes } = makeProvider(github, store);
    await provider();
    expect(userCodes).toEqual(["ABCD-1234"]);
    expect(notices).toEqual([
      { kind: "removed", reason: "expired" },
      { kind: "saved", login: "octo", userId: 7 },
    ]);
    expect(JSON.parse((await store.get(KEY)) ?? "{}").accessToken).toBe(NEW_TOKEN);
  });

  it("deletes the entry when GitHub rejects the refresh token and signs in again", async () => {
    const store = await storeWith(storedRecord({ expiresAt: START - HOUR }));
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const { provider, notices, userCodes } = makeProvider(github, store);
    await provider();
    expect(github.count("refresh")).toBe(1);
    expect(userCodes).toEqual(["ABCD-1234"]);
    expect(notices[0]).toEqual({ kind: "removed", reason: "refresh_failed" });
  });

  it("uses a refresh another process stored meanwhile instead of deleting it", async () => {
    const store = await storeWith(storedRecord({ expiresAt: START - HOUR }));
    const racing: CredentialStore = {
      ...store,
      get: async (key) => {
        const value = await store.get(key);
        // After our first read, the "other process" wins the refresh and writes new tokens.
        await store.set(
          key,
          storedRecord({ accessToken: REFRESHED_TOKEN, refreshToken: REFRESHED_REFRESH }),
        );
        return value;
      },
    };
    const github = fakeGitHub();
    const { provider, notices, userCodes } = makeProvider(github, racing);
    await provider();
    expect(userCodes).toEqual([]);
    expect(notices).toEqual([{ kind: "reused", login: "octo", userId: 7, isRefreshed: false }]);
  });

  it("waits briefly for a racing refresh to be saved before deleting the entry", async () => {
    const store = await storeWith(storedRecord({ expiresAt: START - HOUR }));
    const waits: number[] = [];
    // The other process refreshed first but saves its rotated tokens only a moment later.
    const sleep = async (ms: number) => {
      waits.push(ms);
      await store.set(
        KEY,
        storedRecord({ accessToken: REFRESHED_TOKEN, refreshToken: REFRESHED_REFRESH }),
      );
    };
    const github = fakeGitHub();
    const { provider, notices, userCodes } = makeProvider(github, store, { sleep });
    await provider();
    expect(waits).toHaveLength(1);
    expect(waits[0]).toBeGreaterThan(0);
    expect(userCodes).toEqual([]);
    expect(notices).toEqual([{ kind: "reused", login: "octo", userId: 7, isRefreshed: false }]);
    expect(JSON.parse((await store.get(KEY)) ?? "{}").accessToken).toBe(REFRESHED_TOKEN);
  });

  it("deletes a revoked (401) entry and runs the device flow in the same call", async () => {
    const store = await storeWith(storedRecord({ accessToken: REVOKED_TOKEN }));
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const { provider, notices, userCodes } = makeProvider(github, store);
    const session = await provider();
    expect((await session.client.getAuthenticatedUser()).login).toBe("octo");
    expect(userCodes).toEqual(["ABCD-1234"]);
    expect(notices).toEqual([
      { kind: "removed", reason: "revoked" },
      { kind: "saved", login: "octo", userId: 7 },
    ]);
    expect(JSON.parse((await store.get(KEY)) ?? "{}").accessToken).toBe(NEW_TOKEN);
  });

  it("deletes the entry when GitHub answers 401 during a scan", async () => {
    const store = await storeWith(null);
    let isRevoked = false;
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const fetch: FetchLike = (url, init) =>
      isRevoked && url.endsWith("/user")
        ? Promise.resolve(jsonResponse(401, {}))
        : github.fetch(url, init);
    const notices: SignInNotice[] = [];
    const provider = createDeviceFlowSessionProvider({
      clientId: CLIENT_ID,
      onUserCode: () => {},
      credentialStore: store,
      onNotice: (notice) => notices.push(notice),
      fetch,
      sleep: async () => {},
    });
    const session = await provider();
    expect(store.size()).toBe(1);
    isRevoked = true;
    await expect(session.client.getAuthenticatedUser()).rejects.toMatchObject({
      code: "unauthorized",
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(store.size()).toBe(0);
    expect(notices).toContainEqual({ kind: "removed", reason: "revoked" });
  });

  it("keeps a newer sign-in when the old session's token gets a 401", async () => {
    // The dashboard holds the stored token; `pgard login` elsewhere then saves a new one.
    const store = await storeWith(storedRecord());
    let isRevoked = false;
    const github = fakeGitHub();
    const fetch: FetchLike = (url, init) =>
      isRevoked && init.headers.Authorization === `Bearer ${STORED_TOKEN}`
        ? Promise.resolve(jsonResponse(401, {}))
        : github.fetch(url, init);
    const notices: SignInNotice[] = [];
    const provider = createDeviceFlowSessionProvider({
      clientId: CLIENT_ID,
      onUserCode: () => {},
      credentialStore: store,
      onNotice: (notice) => notices.push(notice),
      fetch,
      sleep: async () => {},
      now: () => START,
    });
    const session = await provider();
    await store.set(KEY, storedRecord({ accessToken: NEW_TOKEN, refreshToken: NEW_REFRESH }));
    isRevoked = true;
    await expect(session.client.getAuthenticatedUser()).rejects.toMatchObject({
      code: "unauthorized",
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(JSON.parse((await store.get(KEY)) ?? "{}").accessToken).toBe(NEW_TOKEN);
    expect(notices).not.toContainEqual({ kind: "removed", reason: "revoked" });
  });

  it("keeps a sign-in saved meanwhile when the token it read was revoked", async () => {
    const store = await storeWith(storedRecord({ accessToken: REVOKED_TOKEN }));
    const github = fakeGitHub();
    const fetch: FetchLike = async (url, init) => {
      const response = await github.fetch(url, init);
      if (url.endsWith("/user") && response.status === 401) {
        // `pgard login` in another process saved a new sign-in while we checked the old one.
        await store.set(KEY, storedRecord({ accessToken: NEW_TOKEN }));
      }
      return response;
    };
    const { provider, notices, userCodes } = makeProvider({ ...github, fetch }, store);
    await provider();
    expect(userCodes).toEqual([]);
    expect(notices).not.toContainEqual({ kind: "removed", reason: "revoked" });
    expect(JSON.parse((await store.get(KEY)) ?? "{}").accessToken).toBe(NEW_TOKEN);
  });

  it("keeps a sign-in saved between the reload and the delete of a revoked entry (#162)", async () => {
    const { store, inner } = controllableStore();
    await inner.set(KEY, storedRecord({ accessToken: REVOKED_TOKEN }));
    const github = fakeGitHub();
    let reads = 0;
    // The reload (second read) returns the revoked entry; `pgard login` then saves a new one
    // before the delete's own re-check (third read).
    const racing: CredentialStore = {
      ...store,
      get: async (key) => {
        reads += 1;
        const value = await store.get(key);
        if (reads === 2) await inner.set(KEY, storedRecord({ accessToken: NEW_TOKEN }));
        return value;
      },
    };
    const { provider, notices } = makeProvider(github, racing);
    // No device token is queued, so the device flow after the rejected entry ends in an error and
    // cannot write anything itself: whatever the keychain holds afterwards was left by the race.
    await expect(provider()).rejects.toBeDefined();
    expect(JSON.parse((await inner.get(KEY)) ?? "{}").accessToken).toBe(NEW_TOKEN);
    expect(notices).not.toContainEqual({ kind: "removed", reason: "revoked" });
  });

  /**
   * A keychain where `pgard login` saves `replacement` right after the `afterRead`-th read
   * returned (the reads are numbered across the whole test).
   */
  function replacedAfterRead(
    inner: ReturnType<typeof createInMemoryCredentialStore>,
    afterRead: number,
    replacement: string,
  ): CredentialStore {
    let reads = 0;
    return {
      get: async (key) => {
        reads += 1;
        const value = await inner.get(key);
        if (reads === afterRead) await inner.set(KEY, replacement);
        return value;
      },
      set: (key, secret) => inner.set(key, secret),
      delete: (key) => inner.delete(key),
    };
  }

  it("keeps a sign-in saved while an expired entry was about to be deleted (#162)", async () => {
    const inner = await storeWith(storedRecord({ expiresAt: START - HOUR, refreshToken: null }));
    const store = replacedAfterRead(inner, 1, storedRecord({ accessToken: NEW_TOKEN }));
    const { provider, notices } = makeProvider(fakeGitHub(), store);
    await expect(provider()).rejects.toBeDefined(); // no device token queued
    expect(JSON.parse((await inner.get(KEY)) ?? "{}").accessToken).toBe(NEW_TOKEN);
    expect(notices).not.toContainEqual({ kind: "removed", reason: "expired" });
  });

  it("keeps a sign-in saved while a rejected refresh was about to delete its entry (#162)", async () => {
    const inner = await storeWith(storedRecord({ expiresAt: START - HOUR }));
    // Reads: 1 load, 2 and 3 the race reloads (the same refresh token), 4 the delete's re-check.
    const store = replacedAfterRead(inner, 3, storedRecord({ accessToken: NEW_TOKEN }));
    const { provider, notices } = makeProvider(fakeGitHub(), store);
    await expect(provider()).rejects.toBeDefined();
    expect(JSON.parse((await inner.get(KEY)) ?? "{}").accessToken).toBe(NEW_TOKEN);
    expect(notices).not.toContainEqual({ kind: "removed", reason: "refresh_failed" });
  });

  it("keeps a sign-in saved while a malformed entry was about to be deleted (#162)", async () => {
    const inner = await storeWith("{not json");
    const store = replacedAfterRead(inner, 1, storedRecord({ accessToken: NEW_TOKEN }));
    const { provider } = makeProvider(fakeGitHub(), store);
    await expect(provider()).rejects.toBeDefined();
    expect(JSON.parse((await inner.get(KEY)) ?? "{}").accessToken).toBe(NEW_TOKEN);
  });

  it("deletes a malformed entry that is still unchanged (#162)", async () => {
    const inner = await storeWith("{not json");
    const { provider, notices } = makeProvider(
      fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] }),
      inner,
    );
    await provider();
    expect(notices[0]).toEqual({ kind: "removed", reason: "malformed" });
    expect(JSON.parse((await inner.get(KEY)) ?? "{}").accessToken).toBe(NEW_TOKEN);
  });

  it("stops reusing a cached keychain session after pgard logout in another process", async () => {
    const store = await storeWith(storedRecord());
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const { provider, userCodes } = makeProvider(github, store);
    const first = await provider();
    expect(await provider()).toBe(first);
    expect(userCodes).toEqual([]);

    await store.delete(KEY); // `pgard logout` elsewhere
    const second = await provider();
    expect(second).not.toBe(first);
    expect(userCodes).toEqual(["ABCD-1234"]);
    await expect(first.client.getAuthenticatedUser()).rejects.toMatchObject({
      code: "unauthorized",
    });
  });

  it("switches to the sign-in that pgard login saved in another process", async () => {
    const store = await storeWith(storedRecord());
    const github = fakeGitHub();
    const { provider, notices, userCodes } = makeProvider(github, store);
    const first = await provider();
    await store.set(KEY, storedRecord({ accessToken: NEW_TOKEN, refreshToken: NEW_REFRESH }));
    const second = await provider();
    expect(second).not.toBe(first);
    expect(userCodes).toEqual([]);
    expect(notices).toEqual([
      { kind: "reused", login: "octo", userId: 7, isRefreshed: false },
      { kind: "reused", login: "octo", userId: 7, isRefreshed: false },
    ]);
    const lastUserCall = github.calls.filter((call) => call.url.endsWith("/user")).at(-1);
    expect(lastUserCall?.init.headers.Authorization).toBe(`Bearer ${NEW_TOKEN}`);
  });

  it("does not save a device-flow sign-in that finished after sign-out and removal", async () => {
    const store = await storeWith(null);
    const controller = new AbortController();
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    let signOutAndRemove = async () => {};
    const fetch: FetchLike = async (url, init) => {
      // The user clicks "Sign out and remove from OS keychain" while GET /user is in flight.
      if (url.endsWith("/user")) await signOutAndRemove();
      return github.fetch(url, init);
    };
    const notices: SignInNotice[] = [];
    const provider = createDeviceFlowSessionProvider({
      clientId: CLIENT_ID,
      onUserCode: () => {},
      credentialStore: store,
      onNotice: (notice) => notices.push(notice),
      fetch,
      signal: controller.signal,
      sleep: async () => {},
      now: () => START,
    });
    signOutAndRemove = async () => {
      controller.abort();
      provider.signOut();
      await removeStoredSignIn(store, CLIENT_ID);
    };
    await provider().catch(() => null);
    expect(store.size()).toBe(0);
    expect(notices).not.toContainEqual({ kind: "saved", login: "octo", userId: 7 });
  });

  it("does not write refreshed tokens back after the entry was removed by sign-out", async () => {
    const store = await storeWith(storedRecord({ expiresAt: START - HOUR }));
    const github = fakeGitHub({
      refreshResponse: { access_token: REFRESHED_TOKEN, refresh_token: REFRESHED_REFRESH },
    });
    let signOutAndRemove = async () => {};
    const fetch: FetchLike = async (url, init) => {
      if (url.endsWith("/user")) await signOutAndRemove();
      return github.fetch(url, init);
    };
    const { provider } = makeProvider({ ...github, fetch }, store);
    signOutAndRemove = async () => {
      provider.signOut();
      await removeStoredSignIn(store, CLIENT_ID);
    };
    await provider().catch(() => null);
    expect(store.size()).toBe(0);
  });

  it("still saves refreshed tokens over the spent entry after a session-only sign-out", async () => {
    const store = await storeWith(storedRecord({ expiresAt: START - HOUR }));
    const github = fakeGitHub({
      refreshResponse: { access_token: REFRESHED_TOKEN, refresh_token: REFRESHED_REFRESH },
    });
    let signOut = () => {};
    const fetch: FetchLike = async (url, init) => {
      if (url.endsWith("/user")) signOut();
      return github.fetch(url, init);
    };
    const { provider } = makeProvider({ ...github, fetch }, store);
    signOut = () => provider.signOut();
    await provider().catch(() => null);
    expect(JSON.parse((await store.get(KEY)) ?? "{}").refreshToken).toBe(REFRESHED_REFRESH);
  });

  it("never reuses a sign-in stored for another App client id", async () => {
    const store = await storeWith(storedRecord());
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const { provider, userCodes } = makeProvider(github, store, { clientId: OTHER_CLIENT_ID });
    await provider();
    expect(userCodes).toEqual(["ABCD-1234"]);
    // The other App's entry is untouched; the new sign-in has its own entry.
    expect(JSON.parse((await store.get(KEY)) ?? "{}").accessToken).toBe(STORED_TOKEN);
    const other = await store.get(signInKey("github.com", OTHER_CLIENT_ID));
    expect(JSON.parse(other ?? "{}")).toMatchObject({
      clientId: OTHER_CLIENT_ID,
      accessToken: NEW_TOKEN,
    });
  });

  it("refuses an invalid override without touching GitHub or the built-in App's entry", async () => {
    const builtInKey = signInKey("github.com", DEFAULT_GITHUB_APP_CLIENT_ID);
    const store = createInMemoryCredentialStore();
    await store.set(builtInKey, storedRecord({ clientId: DEFAULT_GITHUB_APP_CLIENT_ID }));
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const app = resolveGitHubAppClientId({ PGARD_GITHUB_APP_CLIENT_ID: '"bad id"' });
    expect(app).toMatchObject({ clientId: null, slug: null, source: "invalid" });
    const notices: SignInNotice[] = [];
    const provider = createDeviceFlowSessionProvider({
      clientId: app.clientId,
      onUserCode: () => {},
      credentialStore: store,
      onNotice: (notice) => notices.push(notice),
      fetch: github.fetch,
    });
    await expect(provider()).rejects.toMatchObject({
      code: "invalid_client_id_override",
      message:
        "PGARD_GITHUB_APP_CLIENT_ID is set but is not a valid client id; unset it to use the built-in PGARD App.",
    });
    expect(github.calls).toEqual([]);
    expect(notices).toEqual([]);
    expect(store.size()).toBe(1);
    expect(await store.get(builtInKey)).not.toBeNull();
  });

  it("keys the built-in App and a same-id env override to one entry, other overrides apart", async () => {
    const valid = (env: Record<string, string>) => {
      const app = resolveGitHubAppClientId(env);
      if (app.source === "invalid") throw new Error("expected a valid client id");
      return app;
    };
    const builtIn = valid({});
    const sameOverride = valid({ PGARD_GITHUB_APP_CLIENT_ID: ` ${DEFAULT_GITHUB_APP_CLIENT_ID} ` });
    const otherOverride = valid({ PGARD_GITHUB_APP_CLIENT_ID: OTHER_CLIENT_ID });
    expect([builtIn.source, sameOverride.source, otherOverride.source]).toEqual([
      "default",
      "env",
      "env",
    ]);
    expect(signInKey("github.com", builtIn.clientId)).toEqual({
      service: "pgard",
      account: `github:github.com:${DEFAULT_GITHUB_APP_CLIENT_ID}`,
    });
    expect(signInKey("github.com", sameOverride.clientId)).toEqual(
      signInKey("github.com", builtIn.clientId),
    );
    expect(signInKey("github.com", otherOverride.clientId)).not.toEqual(
      signInKey("github.com", builtIn.clientId),
    );

    const store = createInMemoryCredentialStore();
    await store.set(
      signInKey("github.com", builtIn.clientId),
      storedRecord({ clientId: builtIn.clientId }),
    );
    // Saved under the built-in App, reused by the same id given as an override: no device code.
    const same = makeProvider(fakeGitHub(), store, { clientId: sameOverride.clientId });
    await same.provider();
    expect(same.userCodes).toEqual([]);
    expect(same.notices).toEqual([
      { kind: "reused", login: "octo", userId: 7, isRefreshed: false },
    ]);

    // A different override never sees that entry and signs in on its own.
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const other = makeProvider(github, store, { clientId: otherOverride.clientId });
    await other.provider();
    expect(other.userCodes).toEqual(["ABCD-1234"]);
    expect(github.calls[0]?.form.get("client_id")).toBe(OTHER_CLIENT_ID);
    expect(
      JSON.parse((await store.get(signInKey("github.com", builtIn.clientId))) ?? "{}").accessToken,
    ).toBe(STORED_TOKEN);
  });

  it("treats an entry whose payload names another client id as malformed and deletes it", async () => {
    const store = await storeWith(storedRecord({ clientId: OTHER_CLIENT_ID }));
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const { provider, notices, userCodes } = makeProvider(github, store);
    await provider();
    expect(userCodes).toEqual(["ABCD-1234"]);
    expect(notices[0]).toEqual({ kind: "removed", reason: "malformed" });
    expect(JSON.parse((await store.get(KEY)) ?? "{}").accessToken).toBe(NEW_TOKEN);
  });

  it("falls back to memory only when no keychain is available, and says why once", async () => {
    const store = createUnavailableCredentialStore("no keychain here");
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const { provider, notices, userCodes } = makeProvider(github, store);
    const first = await provider();
    expect(await provider()).toBe(first);
    expect(userCodes).toEqual(["ABCD-1234"]);
    expect(notices).toEqual([{ kind: "memory_only", reason: "no keychain here" }]);
  });

  it("keeps working in memory when saving to the keychain fails", async () => {
    const store = createInMemoryCredentialStore();
    const failingSet: CredentialStore = {
      ...store,
      set: async () => {
        throw new (await import("./credential-store.js")).CredentialStoreError("locked");
      },
    };
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const { provider, notices } = makeProvider(github, failingSet);
    await provider();
    expect(notices).toEqual([{ kind: "memory_only", reason: "locked" }]);
  });

  it("never puts a token into notices, errors or the session's printable forms", async () => {
    const store = await storeWith(storedRecord({ expiresAt: START - HOUR }));
    const github = fakeGitHub({ deviceTokens: [{ error: "access_denied" }] });
    const { provider, notices } = makeProvider(github, store);
    const error = await provider().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expectNoSecret(`${String(error)} ${(error as Error).stack ?? ""} ${JSON.stringify(error)}`);
    expectNoSecret(JSON.stringify(notices));

    const reused = makeProvider(fakeGitHub(), await storeWith(storedRecord()));
    const session = await reused.provider();
    expectNoSecret(`${String(session)} ${JSON.stringify(session)}`);
    expectNoSecret(
      JSON.stringify(await readStoredSignInStatus(await storeWith(storedRecord()), CLIENT_ID)),
    );
  });
});

describe("login, logout and status helpers", () => {
  it("signInAndStore always runs the device flow and replaces the entry", async () => {
    const store = await storeWith(storedRecord());
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const codes: string[] = [];
    const result = await signInAndStore({
      clientId: CLIENT_ID,
      onUserCode: (code) => {
        codes.push(code.userCode);
      },
      credentialStore: store,
      fetch: github.fetch,
      sleep: async () => {},
    });
    expect(result).toEqual({ login: "octo", savedError: null });
    expect(codes).toEqual(["ABCD-1234"]);
    expect(JSON.parse((await store.get(KEY)) ?? "{}").accessToken).toBe(NEW_TOKEN);
  });

  it("reads a secret-free status and removes the entry", async () => {
    const store = await storeWith(storedRecord());
    expect(await readStoredSignInStatus(store, CLIENT_ID)).toEqual({
      status: "stored",
      login: "octo",
      userId: 7,
      expiresAt: START + 8 * HOUR,
      refreshExpiresAt: START + 180 * 24 * HOUR,
    });
    expect(await readStoredSignInStatus(store, OTHER_CLIENT_ID)).toEqual({ status: "none" });
    expect(await removeStoredSignIn(store, CLIENT_ID)).toEqual({
      status: "removed",
      login: "octo",
    });
    expect(await removeStoredSignIn(store, CLIENT_ID)).toEqual({ status: "none" });
    expect(store.size()).toBe(0);
  });

  it("reads the status of a malformed entry without deleting it", async () => {
    const store = await storeWith("not json");
    expect(await readStoredSignInStatus(store, CLIENT_ID)).toEqual({ status: "none" });
    expect(await store.get(KEY)).toBe("not json");
  });

  it("reports an unavailable keychain without throwing", async () => {
    const store = createUnavailableCredentialStore("no keychain here");
    expect(await readStoredSignInStatus(store, CLIENT_ID)).toEqual({
      status: "unavailable",
      reason: "no keychain here",
    });
    expect(await removeStoredSignIn(store, CLIENT_ID)).toEqual({
      status: "unavailable",
      reason: "no keychain here",
    });
  });
});

describe("existing() (non-interactive session for background re-checks)", () => {
  it("resolves null without a device flow when nothing is cached or stored", async () => {
    const store = await storeWith(null);
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const { provider, userCodes } = makeProvider(github, store);
    expect(await provider.existing()).toBeNull();
    expect(userCodes).toEqual([]);
    expect(github.count("device")).toBe(0);
    // Memory only: still no device flow.
    const memory = makeProvider(github, null);
    expect(await memory.provider.existing()).toBeNull();
    expect(github.count("device")).toBe(0);
  });

  it("reuses the keychain sign-in and caches it for the next interactive call", async () => {
    const store = await storeWith(storedRecord());
    const github = fakeGitHub();
    const { provider, userCodes, notices } = makeProvider(github, store);
    const session = await provider.existing();
    expect(session).not.toBeNull();
    expect(await provider()).toBe(session);
    expect(await provider.existing()).toBe(session);
    expect(userCodes).toEqual([]);
    expect(notices).toEqual([{ kind: "reused", login: "octo", userId: 7, isRefreshed: false }]);
    expect(github.count("device")).toBe(0);
  });

  it("returns the cached session, and null once the entry was removed elsewhere", async () => {
    const store = await storeWith(storedRecord());
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const { provider, userCodes } = makeProvider(github, store);
    const first = await provider();
    expect(await provider.existing()).toBe(first);
    await store.delete(KEY);
    expect(await provider.existing()).toBeNull();
    expect(userCodes).toEqual([]);
    expect(github.count("device")).toBe(0);
  });

  it("does not wait for a sign-in that is still running", async () => {
    const store = await storeWith(null);
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    let release = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    const { provider } = makeProvider(github, store, { sleep: () => gate });
    const interactive = provider();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(await provider.existing()).toBeNull();
    release();
    await interactive;
    expect(github.count("device")).toBe(1);
  });

  it("refuses a malformed override like the interactive call", async () => {
    const provider = createDeviceFlowSessionProvider({
      clientId: null,
      onUserCode: () => {},
      credentialStore: await storeWith(storedRecord()),
    });
    await expect(provider.existing()).rejects.toMatchObject({
      code: "invalid_client_id_override",
    });
  });
});

/** A manually opened gate for the fake keychain below. */
function gate(): { promise: Promise<void>; open: () => void } {
  let open = (): void => {};
  const promise = new Promise<void>((resolve) => (open = resolve));
  return { promise, open };
}

/** Lets every pending promise and timer-0 callback run (the fake keychain is in memory). */
async function settle(): Promise<void> {
  for (let i = 0; i < 20; i += 1) await new Promise((resolve) => setTimeout(resolve, 0));
}

/**
 * A fake keychain whose writes and removals the test holds open: while `setGate` / `deleteGate`
 * is set, `set` / `delete` wait for it before taking effect. `failGet` makes reads throw.
 */
function controllableStore(): {
  store: CredentialStore;
  inner: ReturnType<typeof createInMemoryCredentialStore>;
  control: {
    setGate: Promise<void> | null;
    deleteGate: Promise<void> | null;
    failGet: boolean;
    setCalls: number;
    deleteCalls: number;
  };
} {
  const inner = createInMemoryCredentialStore();
  const control = {
    setGate: null as Promise<void> | null,
    deleteGate: null as Promise<void> | null,
    failGet: false,
    setCalls: 0,
    deleteCalls: 0,
  };
  const store: CredentialStore = {
    get: async (key) => {
      if (control.failGet) throw new CredentialStoreError("the OS keychain is locked");
      return inner.get(key);
    },
    set: async (key, secret) => {
      control.setCalls += 1;
      if (control.setGate) await control.setGate;
      await inner.set(key, secret);
    },
    delete: async (key) => {
      control.deleteCalls += 1;
      if (control.deleteGate) await control.deleteGate;
      return inner.delete(key);
    },
  };
  return { store, inner, control };
}

describe("keychain writes and removals are serialized (#143)", () => {
  it("keeps the cached session when the keychain cannot be read right now", async () => {
    const { store, inner, control } = controllableStore();
    await inner.set(KEY, storedRecord());
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const { provider, userCodes } = makeProvider(github, store);
    const first = await provider();
    control.failGet = true;
    // An unreadable keychain says nothing about a sign-out: the session is kept.
    expect(await provider()).toBe(first);
    expect(await provider.existing()).toBe(first);
    expect(userCodes).toEqual([]);
    expect(github.count("device")).toBe(0);
    expect(github.count("user")).toBe(1);
  });

  it.each([
    ["a malformed entry", "{not json"],
    ["an expired entry", storedRecord({ expiresAt: START - HOUR, refreshToken: null })],
  ])("deletes %s only under the keychain lock (#162)", async (_name, text) => {
    const { store, inner, control } = controllableStore();
    await inner.set(KEY, text);
    const lock = gate();
    const holding = withKeychainLock(store, () => lock.promise);
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const { provider } = makeProvider(github, store);
    const signingIn = provider();
    await settle();
    // Someone else holds the lock (a save or removal in flight): the delete must wait.
    expect(control.deleteCalls).toBe(0);
    lock.open();
    await holding;
    await signingIn;
    expect(control.deleteCalls).toBeGreaterThan(0);
  });

  it("removes a device-flow sign-in whose save was in flight when removal started", async () => {
    const { store, inner, control } = controllableStore();
    const save = gate();
    control.setGate = save.promise;
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    const { provider } = makeProvider(github, store);
    const signingIn = provider();
    await settle();
    expect(control.setCalls).toBe(1); // the save is in flight

    provider.signOut();
    let isRemoved = false;
    const removing = removeStoredSignIn(store, CLIENT_ID).then((result) => {
      isRemoved = true;
      return result;
    });
    await settle();
    // The removal waits for the save instead of running before it.
    expect(isRemoved).toBe(false);
    save.open();
    await signingIn;
    expect(await removing).toEqual({ status: "removed", login: "octo" });
    expect(inner.size()).toBe(0);
  });

  it("does not recreate an entry whose removal was in flight when a refresh was saved", async () => {
    const { store, inner, control } = controllableStore();
    await inner.set(KEY, storedRecord({ expiresAt: START - HOUR }));
    const removal = gate();
    const github = fakeGitHub({
      refreshResponse: { access_token: REFRESHED_TOKEN, refresh_token: REFRESHED_REFRESH },
    });
    let removing: Promise<unknown> = Promise.resolve();
    let provider: ReturnType<typeof makeProvider>["provider"] | null = null;
    const fetch: FetchLike = async (url, init) => {
      if (new URLSearchParams(init.body ?? "").get("grant_type") === "refresh_token") {
        // "Sign out and remove from OS keychain" starts while GitHub rotates the token; its
        // delete is still in flight (and the entry still readable) when the provider saves.
        control.deleteGate = removal.promise;
        provider?.signOut();
        removing = removeStoredSignIn(store, CLIENT_ID);
      }
      return github.fetch(url, init);
    };
    provider = makeProvider({ ...github, fetch }, store).provider;
    const reusing = provider().catch(() => null);
    await settle();
    expect(control.deleteCalls).toBe(1);
    removal.open();
    await reusing;
    await removing;
    // The provider re-checked inside the lock, after the removal, and saved nothing.
    expect(inner.size()).toBe(0);
  });

  it("never overwrites a sign-in that pgard login saved during a refresh", async () => {
    const store = await storeWith(storedRecord({ expiresAt: START - HOUR }));
    const github = fakeGitHub({
      refreshResponse: { access_token: REFRESHED_TOKEN, refresh_token: REFRESHED_REFRESH },
    });
    const fetch: FetchLike = async (url, init) => {
      if (new URLSearchParams(init.body ?? "").get("grant_type") === "refresh_token") {
        await store.set(KEY, storedRecord({ accessToken: NEW_TOKEN, refreshToken: NEW_REFRESH }));
      }
      return github.fetch(url, init);
    };
    const { provider } = makeProvider({ ...github, fetch }, store);
    await provider();
    expect(JSON.parse((await store.get(KEY)) ?? "{}").refreshToken).toBe(NEW_REFRESH);
  });

  it("follows the keychain when pgard login replaced the entry during a refresh (#162)", async () => {
    const store = await storeWith(storedRecord({ expiresAt: START - HOUR }));
    const github = fakeGitHub({
      refreshResponse: { access_token: REFRESHED_TOKEN, refresh_token: REFRESHED_REFRESH },
    });
    const fetch: FetchLike = async (url, init) => {
      if (new URLSearchParams(init.body ?? "").get("grant_type") === "refresh_token") {
        // `pgard login` saves another sign-in while GitHub rotates the old one.
        await store.set(KEY, storedRecord({ accessToken: NEW_TOKEN, refreshToken: NEW_REFRESH }));
      }
      return github.fetch(url, init);
    };
    const { provider, userCodes } = makeProvider({ ...github, fetch }, store);
    const first = await provider();
    // The refreshed session is not what the keychain holds: the next call must not serve it.
    const second = await provider();
    expect(second).not.toBe(first);
    expect(userCodes).toEqual([]);
    const lastUserCall = github.calls.filter((call) => call.url.endsWith("/user")).at(-1);
    expect(lastUserCall?.init.headers.Authorization).toBe(`Bearer ${NEW_TOKEN}`);
    await expect(first.client.getAuthenticatedUser()).rejects.toMatchObject({
      code: "unauthorized",
    });
    expect(JSON.parse((await store.get(KEY)) ?? "{}").accessToken).toBe(NEW_TOKEN);
  });

  it("signs in again when pgard logout removed the entry during a refresh (#162)", async () => {
    const store = await storeWith(storedRecord({ expiresAt: START - HOUR }));
    const github = fakeGitHub({
      refreshResponse: { access_token: REFRESHED_TOKEN, refresh_token: REFRESHED_REFRESH },
      deviceTokens: [{ access_token: NEW_TOKEN }],
    });
    const fetch: FetchLike = async (url, init) => {
      if (new URLSearchParams(init.body ?? "").get("grant_type") === "refresh_token") {
        await store.delete(KEY); // `pgard logout` in another process
      }
      return github.fetch(url, init);
    };
    const { provider, userCodes } = makeProvider({ ...github, fetch }, store);
    const first = await provider();
    expect(store.size()).toBe(0);
    const second = await provider();
    expect(second).not.toBe(first);
    expect(userCodes).toEqual(["ABCD-1234"]);
  });

  it("saves rotated tokens even when a session-only sign-out aborts the /user check", async () => {
    const store = await storeWith(storedRecord({ expiresAt: START - HOUR }));
    const controller = new AbortController();
    const github = fakeGitHub({
      refreshResponse: {
        access_token: REFRESHED_TOKEN,
        expires_in: 28800,
        refresh_token: REFRESHED_REFRESH,
        refresh_token_expires_in: 15897600,
      },
    });
    let signOut = () => {};
    const fetch: FetchLike = async (url, init) => {
      if (url.endsWith("/user")) {
        // "End dashboard session (keep keychain sign-in)" aborts the in-flight request.
        signOut();
        throw new DOMException("The operation was aborted.", "AbortError");
      }
      return github.fetch(url, init);
    };
    const provider = createDeviceFlowSessionProvider({
      clientId: CLIENT_ID,
      onUserCode: () => {},
      credentialStore: store,
      fetch,
      signal: controller.signal,
      sleep: async () => {},
      now: () => START,
    });
    signOut = () => {
      controller.abort();
      provider.signOut();
    };
    await expect(provider()).rejects.toBeDefined();
    // GitHub already rotated the refresh token: the keychain holds the new pair, never the spent one.
    expect(JSON.parse((await store.get(KEY)) ?? "{}")).toMatchObject({
      accessToken: REFRESHED_TOKEN,
      refreshToken: REFRESHED_REFRESH,
      login: "octo",
      userId: 7,
    });
  });
});

describe("keychain lock: re-check right before the device-flow save", () => {
  it("skips the save when a sign-out lands while the save waits for the lock", async () => {
    const { store, inner, control } = controllableStore();
    // Another keychain removal holds the lock (its delete is in flight).
    const removal = gate();
    control.deleteGate = removal.promise;
    const github = fakeGitHub({ deviceTokens: [{ access_token: NEW_TOKEN }] });
    let provider: ReturnType<typeof makeProvider>["provider"] | null = null;
    let removing: Promise<unknown> = Promise.resolve();
    const fetch: FetchLike = async (url, init) => {
      if (url.endsWith("/user")) removing = removeStoredSignIn(store, CLIENT_ID);
      return github.fetch(url, init);
    };
    provider = makeProvider({ ...github, fetch }, store).provider;
    const signingIn = provider();
    await settle();
    expect(control.deleteCalls).toBe(1);
    expect(control.setCalls).toBe(0); // the save waits for the lock
    provider.signOut();
    removal.open();
    await signingIn;
    await removing;
    expect(control.setCalls).toBe(0);
    expect(inner.size()).toBe(0);
  });
});
