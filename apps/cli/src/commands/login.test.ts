import {
  createDeviceFlowSessionProvider,
  createInMemoryCredentialStore,
  createUnavailableCredentialStore,
  GitHubAuthError,
  signInAndStore,
  type CredentialStore,
} from "@pgard/scan-core";
import { describe, expect, it, vi } from "vitest";
import { main } from "../app.js";
import { createSessionProvider } from "../flows/authenticate.js";
import { parseCommandLine } from "../options.js";
import {
  createTestContext,
  createTestDeps,
  createTestIo,
  noInterrupts,
  type CapturedIo,
} from "../test-support.js";
import { runDoctor } from "./doctor.js";
import { runLogin, runLogout } from "./login.js";

const CLIENT_ID = "Iv23liTestClient";
const ENV = { PGARD_GITHUB_APP_CLIENT_ID: CLIENT_ID };
const ACCESS_TOKEN = ["ghu", "cliSecretAccessTokenForTests000"].join("_");
const REFRESH_TOKEN = ["ghr", "cliSecretRefreshTokenForTests00"].join("_");
const KEY = { service: "pgard", account: `github:github.com:${CLIENT_ID}` };
const FAR_FUTURE = Date.UTC(2099, 0, 1);

/** Minimal fake of GitHub's device flow, token endpoint and `GET /user`. */
function fakeFetch() {
  const calls: string[] = [];
  const fetch = async (url: string) => {
    calls.push(url);
    const json = (body: unknown) => ({ status: 200, ok: true, json: async () => body });
    if (url.endsWith("/login/device/code")) {
      return json({
        device_code: "device-code-internal",
        user_code: "WXYZ-1234",
        verification_uri: "https://github.com/login/device",
        expires_in: 900,
        interval: 5,
      });
    }
    if (url.endsWith("/login/oauth/access_token")) {
      return json({
        access_token: ACCESS_TOKEN,
        expires_in: 28800,
        refresh_token: REFRESH_TOKEN,
        refresh_token_expires_in: 15897600,
      });
    }
    return json({ id: 7, login: "octo", name: null, email: null });
  };
  return { fetch, deviceCodes: () => calls.filter((url) => url.endsWith("/device/code")).length };
}

function storedEntry(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    version: 1,
    host: "github.com",
    clientId: CLIENT_ID,
    accessToken: ACCESS_TOKEN,
    expiresAt: FAR_FUTURE,
    refreshToken: REFRESH_TOKEN,
    refreshTokenExpiresAt: FAR_FUTURE,
    login: "octo",
    userId: 7,
    savedAt: 0,
    ...overrides,
  });
}

async function storeWith(entry: string | null) {
  const store = createInMemoryCredentialStore();
  if (entry !== null) await store.set(KEY, entry);
  return store;
}

function expectNoSecret(captured: CapturedIo): void {
  const output = captured.stdout() + captured.stderr();
  expect(output).not.toContain(ACCESS_TOKEN);
  expect(output).not.toContain(REFRESH_TOKEN);
  expect(output).not.toContain("device-code-internal");
}

describe("pgard login", () => {
  it("parses login and logout without arguments only", () => {
    expect(parseCommandLine(["login"])).toEqual({ kind: "login" });
    expect(parseCommandLine(["logout"])).toEqual({ kind: "logout" });
    expect(parseCommandLine(["login", "--help"])).toEqual({ kind: "help", topic: "login" });
    expect(() => parseCommandLine(["logout", "now"])).toThrow("Unexpected argument");
    expect(() => parseCommandLine(["login", "--port", "1"])).toThrow("not available");
  });

  it("signs in with the device flow, saves to the keychain and never prints a token", async () => {
    const store = await storeWith(null);
    const github = fakeFetch();
    const captured = createTestIo({ env: ENV });
    const deps = createTestDeps({
      credentialStore: store,
      signInAndStore: (options) =>
        signInAndStore({ ...options, fetch: github.fetch, sleep: async () => {} }),
    });
    expect(await runLogin(createTestContext(captured, deps))).toBe(0);
    expect(captured.stderr()).toContain("Enter the code WXYZ-1234");
    expect(captured.stdout()).toContain("Signed in to GitHub as octo.");
    expect(captured.stdout()).toContain("saved in the OS keychain");
    expect(captured.stdout()).toContain("still checked on every scan");
    expect(JSON.parse((await store.get(KEY)) ?? "{}")).toMatchObject({
      accessToken: ACCESS_TOKEN,
      login: "octo",
    });
    expectNoSecret(captured);
  });

  it("stops before the device flow when no keychain is available (exit 4)", async () => {
    const signIn = vi.fn();
    const captured = createTestIo({ env: ENV });
    const deps = createTestDeps({
      credentialStore: createUnavailableCredentialStore("no keychain service is running"),
      signInAndStore: signIn,
    });
    expect(await runLogin(createTestContext(captured, deps))).toBe(4);
    expect(signIn).not.toHaveBeenCalled();
    expect(captured.stderr()).toContain(
      "No OS keychain is available: no keychain service is running. Nothing was saved",
    );
  });

  it("reports a failed sign-in with exit 3 and a missing client id with exit 3", async () => {
    const denied = createTestIo({ env: ENV });
    const deps = createTestDeps({
      signInAndStore: async () => {
        throw new GitHubAuthError("access_denied", "GitHub sign-in was denied by the user.");
      },
    });
    expect(await runLogin(createTestContext(denied, deps))).toBe(3);
    expect(denied.stderr()).toContain("GitHub sign-in failed: GitHub sign-in was denied");

    const missing = createTestIo();
    expect(await runLogin(createTestContext(missing, createTestDeps()))).toBe(3);
    expect(missing.stderr()).toContain("PGARD_GITHUB_APP_CLIENT_ID is not set");
  });

  it("reports a keychain that refused to save with exit 4", async () => {
    const captured = createTestIo({ env: ENV });
    const deps = createTestDeps({
      signInAndStore: async () => ({ login: "octo", savedError: "the keychain is locked" }),
    });
    expect(await runLogin(createTestContext(captured, deps))).toBe(4);
    expect(captured.stderr()).toContain("Signed in to GitHub as octo, but the OS keychain did not");
  });

  it("is reachable through main with its own help text", async () => {
    const captured = createTestIo();
    expect(
      await main(["login", "--help"], captured.io, {
        deps: createTestDeps(),
        interrupts: noInterrupts,
      }),
    ).toBe(0);
    expect(captured.stdout()).toContain("never written to a file");
    const mainHelp = createTestIo();
    await main(["--help"], mainHelp.io, { deps: createTestDeps(), interrupts: noInterrupts });
    expect(mainHelp.stdout()).toContain("pgard login");
    expect(mainHelp.stdout()).toContain("pgard logout");
  });
});

describe("pgard logout", () => {
  it("removes the entry, names the account and explains how to revoke at GitHub", async () => {
    const store = await storeWith(storedEntry());
    const captured = createTestIo({ env: ENV });
    expect(
      await runLogout(createTestContext(captured, createTestDeps({ credentialStore: store }))),
    ).toBe(0);
    expect(captured.stdout()).toContain(
      "Removed the GitHub sign-in for octo from the OS keychain.",
    );
    expect(captured.stdout()).toContain("https://github.com/settings/apps/authorizations");
    expect(store.size()).toBe(0);
    expectNoSecret(captured);
  });

  it("says when nothing is saved and exits 0", async () => {
    const captured = createTestIo({ env: ENV });
    expect(await runLogout(createTestContext(captured, createTestDeps()))).toBe(0);
    expect(captured.stdout()).toContain("No GitHub sign-in is saved in the OS keychain");
  });

  it("exits 4 when no keychain is available", async () => {
    const captured = createTestIo({ env: ENV });
    const deps = createTestDeps({ credentialStore: createUnavailableCredentialStore("locked") });
    expect(await runLogout(createTestContext(captured, deps))).toBe(4);
    expect(captured.stderr()).toContain("Nothing was removed.");
  });
});

describe("doctor: saved GitHub sign-in", () => {
  const doctor = async (store: CredentialStore, env: Record<string, string> = ENV) => {
    const captured = createTestIo({ env });
    expect(
      await runDoctor(createTestContext(captured, createTestDeps({ credentialStore: store }))),
    ).toBe(0);
    expectNoSecret(captured);
    return captured.stdout();
  };

  it("shows the account and refresh window, never the token", async () => {
    expect(await doctor(await storeWith(storedEntry()))).toContain(
      "[ok]   Saved GitHub sign-in: octo (OS keychain; refreshed automatically until 2099-01-01T00:00:00Z)",
    );
    expect(
      await doctor(await storeWith(storedEntry({ expiresAt: null, refreshToken: null }))),
    ).toContain("[ok]   Saved GitHub sign-in: octo (OS keychain; the token does not expire)");
  });

  it("warns when nothing is saved, the keychain is unavailable or no client id is set", async () => {
    expect(await doctor(await storeWith(null))).toContain(
      "[warn] Saved GitHub sign-in: none - run `pgard login` once",
    );
    expect(await doctor(createUnavailableCredentialStore("no keychain service"))).toContain(
      "[warn] Saved GitHub sign-in: OS keychain unavailable (no keychain service)",
    );
    expect(await doctor(await storeWith(storedEntry()), {})).toContain(
      "[warn] Saved GitHub sign-in: not checked (PGARD_GITHUB_APP_CLIENT_ID is not set)",
    );
  });

  it("shows an expired entry without a refresh token as [warn]", async () => {
    expect(
      await doctor(await storeWith(storedEntry({ expiresAt: 1000, refreshToken: null }))),
    ).toContain("[warn] Saved GitHub sign-in: octo (OS keychain; expired");
  });
});

describe("scan sign-in reuse", () => {
  it("reuses the keychain sign-in in a second run without showing a device code", async () => {
    const store = await storeWith(null);
    const github = fakeFetch();
    const deps = createTestDeps({
      credentialStore: store,
      createSessionProvider: (options) =>
        createDeviceFlowSessionProvider({
          ...options,
          clientId: CLIENT_ID,
          credentialStore: store,
          fetch: github.fetch,
          sleep: async () => {},
        }),
    });
    const firstRun = createTestIo({ env: ENV });
    await createSessionProvider(createTestContext(firstRun, deps))();
    expect(firstRun.stderr()).toContain("Enter the code WXYZ-1234");
    expect(firstRun.stderr()).toContain("Saved the GitHub sign-in for octo in the OS keychain");

    const secondRun = createTestIo({ env: ENV });
    await createSessionProvider(createTestContext(secondRun, deps))();
    expect(secondRun.stderr()).not.toContain("Enter the code");
    expect(secondRun.stderr()).toContain(
      "Using the GitHub sign-in for octo saved in the OS keychain.",
    );
    expect(github.deviceCodes()).toBe(1);
    expectNoSecret(firstRun);
    expectNoSecret(secondRun);
  });

  it("explains a memory-only fallback when no keychain is available", async () => {
    const github = fakeFetch();
    const store = createUnavailableCredentialStore("no keychain service is running");
    const deps = createTestDeps({
      createSessionProvider: (options) =>
        createDeviceFlowSessionProvider({
          ...options,
          clientId: CLIENT_ID,
          credentialStore: store,
          fetch: github.fetch,
          sleep: async () => {},
        }),
    });
    const run = createTestIo({ env: ENV });
    await createSessionProvider(createTestContext(run, deps))();
    expect(run.stderr()).toContain(
      "The GitHub sign-in is kept in memory for this run only: no keychain service is running.",
    );
  });

  it("tells the user when a saved sign-in was removed and a new one is needed", async () => {
    const store = await storeWith(storedEntry({ expiresAt: 1000, refreshToken: null }));
    const github = fakeFetch();
    const deps = createTestDeps({
      createSessionProvider: (options) =>
        createDeviceFlowSessionProvider({
          ...options,
          clientId: CLIENT_ID,
          credentialStore: store,
          fetch: github.fetch,
          sleep: async () => {},
        }),
    });
    const run = createTestIo({ env: ENV });
    await createSessionProvider(createTestContext(run, deps))();
    expect(run.stderr()).toContain(
      "The saved GitHub sign-in has expired and was removed from the OS keychain.",
    );
    expect(run.stderr()).toContain("Enter the code WXYZ-1234");
  });
});
