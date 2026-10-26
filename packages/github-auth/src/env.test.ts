import { describe, expect, it } from "vitest";
import {
  DEFAULT_GITHUB_APP_CLIENT_ID,
  INVALID_CLIENT_ID_OVERRIDE_MESSAGE,
  MIXED_APP_OVERRIDE_MESSAGE,
  mixedAppOverrideWarning,
  resolveGitHubAppClientId,
  resolveKeychainClientId,
} from "./env.js";

describe("resolveKeychainClientId", () => {
  it("ignores a malformed slug override: only the client id names the keychain entry", () => {
    const env = { PGARD_GITHUB_APP_SLUG: "Not A Slug!" };
    // Sign-in still blocks on the malformed slug...
    expect(resolveGitHubAppClientId(env).source).toBe("invalid");
    // ...but removing the stored sign-in does not.
    expect(resolveKeychainClientId(env)).toEqual({
      clientId: DEFAULT_GITHUB_APP_CLIENT_ID,
      message: null,
    });
    expect(
      resolveKeychainClientId({ ...env, PGARD_GITHUB_APP_CLIENT_ID: "Iv23.forkClient" }),
    ).toEqual({ clientId: "Iv23.forkClient", message: null });
  });

  it("still refuses a malformed client id override (never the built-in App's entry)", () => {
    expect(resolveKeychainClientId({ PGARD_GITHUB_APP_CLIENT_ID: "bad id!" })).toEqual({
      clientId: null,
      message: INVALID_CLIENT_ID_OVERRIDE_MESSAGE,
    });
  });
});

describe("mixedAppOverrideWarning", () => {
  it("warns when an overridden slug is used with the built-in client id", () => {
    expect(mixedAppOverrideWarning({ PGARD_GITHUB_APP_SLUG: "my-fork" })).toBe(
      MIXED_APP_OVERRIDE_MESSAGE,
    );
  });

  it("stays quiet for consistent or no overrides", () => {
    expect(mixedAppOverrideWarning({})).toBeNull();
    expect(mixedAppOverrideWarning({ PGARD_GITHUB_APP_SLUG: "pgard-jadenmeister" })).toBeNull();
    expect(
      mixedAppOverrideWarning({
        PGARD_GITHUB_APP_SLUG: "my-fork",
        PGARD_GITHUB_APP_CLIENT_ID: "Iv23.forkClient",
      }),
    ).toBeNull();
    // A malformed slug already blocks with its own reason.
    expect(mixedAppOverrideWarning({ PGARD_GITHUB_APP_SLUG: "Bad Slug" })).toBeNull();
  });
});
