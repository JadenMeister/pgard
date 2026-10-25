import {
  createDeviceFlowSessionProvider,
  createInMemoryCredentialStore,
  createUnavailableCredentialStore,
  DEFAULT_GITHUB_APP_CLIENT_ID,
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

  it("reports a failed sign-in with exit 3", async () => {
    const denied = createTestIo({ env: ENV });
    const deps = createTestDeps({
      signInAndStore: async () => {
        throw new GitHubAuthError("access_denied", "GitHub sign-in was denied by the user.");
      },
    });
    expect(await runLogin(createTestContext(denied, deps))).toBe(3);
    expect(denied.stderr()).toContain("GitHub sign-in failed: GitHub sign-in was denied");
  });

  it("signs in with the built-in PGARD App when no override is set, or the override when set", async () => {
    const clientIdFor = async (env: Record<string, string>): Promise<string | undefined> => {
      const signIn = vi.fn(async () => ({ login: "octo", savedError: null }));
      const captured = createTestIo({ env });
      expect(
        await runLogin(createTestContext(captured, createTestDeps({ signInAndStore: signIn }))),
      ).toBe(0);
      expect(captured.stderr()).not.toContain("PGARD_GITHUB_APP_CLIENT_ID");
      return (signIn.mock.calls[0] as unknown as [{ clientId: string }] | undefined)?.[0].clientId;
    };
    expect(await clientIdFor({})).toBe(DEFAULT_GITHUB_APP_CLIENT_ID);
    expect(await clientIdFor({ PGARD_GITHUB_APP_CLIENT_ID: "   " })).toBe(
      DEFAULT_GITHUB_APP_CLIENT_ID,
    );
    expect(await clientIdFor(ENV)).toBe(CLIENT_ID);
  });

  it("says on stdout when the override is in use, and not for the built-in App", async () => {
    const run = async (env: Record<string, string>) => {
      const captured = createTestIo({ env });
      const signIn = async () => ({ login: "octo", savedError: null });
      await runLogin(createTestContext(captured, createTestDeps({ signInAndStore: signIn })));
      return captured;
    };
    const override = await run(ENV);
    expect(override.stdout()).toContain(
      `Using GitHub App ${CLIENT_ID} from PGARD_GITHUB_APP_CLIENT_ID (override).`,
    );
    expect((await run({})).stdout()).not.toContain("Using GitHub App");
  });

  it("exits 3 for a malformed override before any sign-in, without printing the value", async () => {
    const signIn = vi.fn();
    const captured = createTestIo({ env: { PGARD_GITHUB_APP_CLIENT_ID: '"bad id"' } });
    expect(
      await runLogin(createTestContext(captured, createTestDeps({ signInAndStore: signIn }))),
    ).toBe(3);
    expect(signIn).not.toHaveBeenCalled();
    expect(captured.stderr()).toContain(
      "PGARD_GITHUB_APP_CLIENT_ID is set but is not a valid client id; unset it to use the built-in PGARD App.",
    );
    expect(captured.stdout() + captured.stderr()).not.toContain("bad id");
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

  it("documents the built-in App and the override, and no 'not set' exit code", async () => {
    const help = async (args: string[]): Promise<string> => {
      const captured = createTestIo();
      expect(
        await main(args, captured.io, { deps: createTestDeps(), interrupts: noInterrupts }),
      ).toBe(0);
      return captured.stdout();
    };
    const login = await help(["login", "--help"]);
    expect(login).toContain("PGARD signs in as the built-in PGARD GitHub App");
    expect(login).toContain("set PGARD_GITHUB_APP_CLIENT_ID\nonly to use another App");
    expect(login).toContain("A value that is not\na valid client id blocks sign-in (exit 3)");
    expect(login).toContain(
      "  3    GitHub sign-in failed, or PGARD_GITHUB_APP_CLIENT_ID is not a valid\n       client id\n",
    );
    const logout = await help(["logout", "--help"]);
    expect(logout).toContain(
      "  0    removed, or nothing was saved\n  3    PGARD_GITHUB_APP_CLIENT_ID is not a valid client id; nothing was removed\n  4    no OS keychain",
    );
    const doctor = await help(["doctor", "--help"]);
    expect(doctor).toContain(
      "(the built-in PGARD App, or PGARD_GITHUB_APP_CLIENT_ID\nas an override)",
    );
    for (const text of [login, logout, doctor]) {
      expect(text).not.toContain("is not set");
      for (const line of text.split("\n")) expect(line.length).toBeLessThanOrEqual(82);
    }
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

  it("removes the built-in App's entry when no override is set, never an override's", async () => {
    const builtInKey = {
      service: "pgard",
      account: `github:github.com:${DEFAULT_GITHUB_APP_CLIENT_ID}`,
    };
    const store = await storeWith(storedEntry());
    await store.set(builtInKey, storedEntry({ clientId: DEFAULT_GITHUB_APP_CLIENT_ID }));
    const captured = createTestIo();
    expect(
      await runLogout(createTestContext(captured, createTestDeps({ credentialStore: store }))),
    ).toBe(0);
    expect(captured.stdout()).toContain("Removed the GitHub sign-in for octo");
    expect(await store.get(builtInKey)).toBeNull();
    expect(await store.get(KEY)).not.toBeNull();
  });

  it("exits 3 for a malformed override and keeps the built-in App's entry", async () => {
    const builtInKey = {
      service: "pgard",
      account: `github:github.com:${DEFAULT_GITHUB_APP_CLIENT_ID}`,
    };
    const store = await storeWith(null);
    await store.set(builtInKey, storedEntry({ clientId: DEFAULT_GITHUB_APP_CLIENT_ID }));
    const captured = createTestIo({ env: { PGARD_GITHUB_APP_CLIENT_ID: '"bad id"' } });
    expect(
      await runLogout(createTestContext(captured, createTestDeps({ credentialStore: store }))),
    ).toBe(3);
    expect(captured.stderr()).toContain(
      "PGARD_GITHUB_APP_CLIENT_ID is set but is not a valid client id; unset it to use the built-in PGARD App.",
    );
    expect(await store.get(builtInKey)).not.toBeNull();
    expect(captured.stdout()).not.toContain("Removed");
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

  it("warns when nothing is saved for this App or the keychain is unavailable", async () => {
    expect(await doctor(await storeWith(null))).toContain(
      "[warn] Saved GitHub sign-in: none - run `pgard login` once",
    );
    expect(await doctor(createUnavailableCredentialStore("no keychain service"))).toContain(
      "[warn] Saved GitHub sign-in: OS keychain unavailable (no keychain service)",
    );
    // Without the override, doctor looks up the built-in App's entry, not the override's.
    expect(await doctor(await storeWith(storedEntry()), {})).toContain(
      "[warn] Saved GitHub sign-in: none - run `pgard login` once",
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
