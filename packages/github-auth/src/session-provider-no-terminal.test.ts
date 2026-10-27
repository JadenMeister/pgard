import { describe, expect, it } from "vitest";
import {
  createInMemoryCredentialStore,
  createUnavailableCredentialStore,
  type CredentialStore,
} from "./credential-store.js";
import { isGitHubAuthError, NOT_SIGNED_IN_NO_TERMINAL_MESSAGE } from "./errors.js";
import type { FetchLike } from "./fetch.js";
import { createDeviceFlowSessionProvider } from "./session-provider.js";
import { signInKey } from "./stored-sign-in.js";

const CLIENT_ID = "Iv23.noTerminalClient";
const START = 1_800_000_000_000;
const TOKEN = ["ghu", "noTerminalStoredTokenForTests"].join("_");

/** A fetch that records the URL and refuses to answer: no device code may ever be requested. */
function recordingFetch() {
  const urls: string[] = [];
  const fetch: FetchLike = async (url) => {
    urls.push(url);
    throw new Error("network access is not allowed in this test");
  };
  return { fetch, urls };
}

function provider(store: CredentialStore | null, fetch: FetchLike, canSignInInteractively = false) {
  const userCodes: string[] = [];
  const instance = createDeviceFlowSessionProvider({
    clientId: CLIENT_ID,
    onUserCode: (code) => {
      userCodes.push(code.userCode);
    },
    credentialStore: store,
    canSignInInteractively,
    fetch,
    sleep: async () => {},
    now: () => START,
  });
  return { instance, userCodes };
}

describe("session provider without a terminal", () => {
  const stores: Array<[string, () => CredentialStore | null]> = [
    ["an empty keychain", () => createInMemoryCredentialStore()],
    ["an unavailable keychain", () => createUnavailableCredentialStore("locked")],
    ["no keychain at all", () => null],
  ];

  it.each(stores)(
    "fails with not_signed_in and never requests a device code (%s)",
    async (_name, makeStore) => {
      const github = recordingFetch();
      const { instance, userCodes } = provider(makeStore(), github.fetch);
      const failure = await instance().then(
        () => null,
        (error: unknown) => error,
      );
      expect(isGitHubAuthError(failure)).toBe(true);
      expect(failure).toMatchObject({
        code: "not_signed_in",
        message: NOT_SIGNED_IN_NO_TERMINAL_MESSAGE,
      });
      expect(NOT_SIGNED_IN_NO_TERMINAL_MESSAGE).toContain("Run `pgard login` in a terminal first");
      expect(github.urls).toEqual([]);
      expect(userCodes).toEqual([]);
    },
  );

  it("treats a malformed stored entry as no sign-in, still without a device code", async () => {
    const store = createInMemoryCredentialStore();
    await store.set(signInKey("github.com", CLIENT_ID), "{not json");
    const github = recordingFetch();
    const { instance } = provider(store, github.fetch);
    await expect(instance()).rejects.toMatchObject({ code: "not_signed_in" });
    expect(github.urls.filter((url) => url.includes("/login/"))).toEqual([]);
  });

  it("still reuses a usable stored sign-in", async () => {
    const store = createInMemoryCredentialStore();
    await store.set(
      signInKey("github.com", CLIENT_ID),
      JSON.stringify({
        version: 1,
        host: "github.com",
        clientId: CLIENT_ID,
        accessToken: TOKEN,
        expiresAt: START + 8 * 3600_000,
        refreshToken: null,
        refreshTokenExpiresAt: null,
        login: "octo",
        userId: 7,
        savedAt: START,
      }),
    );
    const urls: string[] = [];
    const fetch: FetchLike = async (url) => {
      urls.push(url);
      return {
        status: 200,
        ok: true,
        json: async () => ({ id: 7, login: "octo", name: null, email: null }),
      };
    };
    const { instance, userCodes } = provider(store, fetch);
    const session = await instance();
    expect((await session.client.getAuthenticatedUser()).login).toBe("octo");
    expect(userCodes).toEqual([]);
    expect(urls.some((url) => url.includes("/login/device/code"))).toBe(false);
  });

  it("keeps the interactive default: a terminal still starts the device flow", async () => {
    const github = recordingFetch();
    const { instance } = provider(createInMemoryCredentialStore(), github.fetch, true);
    await expect(instance()).rejects.not.toMatchObject({ code: "not_signed_in" });
    expect(github.urls.some((url) => url.endsWith("/login/device/code"))).toBe(true);
  });
});
