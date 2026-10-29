import { describe, expect, it } from "vitest";
import type { AuthStatus } from "../../../shared/api-types";
import { targetRefreshKey } from "./target-refresh";

const allowed: AuthStatus = {
  status: "done",
  deviceCode: null,
  summary: { decision: "allowed", checks: [] },
  repo: "acme/shop",
  message: null,
  storedSignIn: { status: "stored", login: "octo-dev" },
  remedy: null,
  accessNote: null,
  signInNotice: null,
  expiresAt: 1_000,
  installWaitEndsAt: null,
};

describe("targetRefreshKey", () => {
  it("stays the same while nothing about the authorization changed", () => {
    expect(targetRefreshKey({ ...allowed })).toBe(targetRefreshKey(allowed));
    expect(targetRefreshKey({ ...allowed, signInNotice: "Reused the saved sign-in." })).toBe(
      targetRefreshKey(allowed),
    );
  });

  it("waits while a check runs, then changes once it finished again", () => {
    expect(targetRefreshKey(null)).toBeNull();
    expect(targetRefreshKey({ ...allowed, status: "running" })).toBeNull();
    expect(targetRefreshKey({ ...allowed, expiresAt: 2_000 })).not.toBe(targetRefreshKey(allowed));
  });

  it("changes on a blocked check, on either sign-out and on another account", () => {
    const before = targetRefreshKey(allowed);
    const blocked = { ...allowed, summary: { decision: "blocked" as const, checks: [] } };
    const sessionOnly = {
      ...allowed,
      status: "idle" as const,
      summary: null,
      repo: null,
      expiresAt: null,
    };
    const removed = { ...sessionOnly, storedSignIn: { status: "none" as const } };
    const otherAccount = {
      ...allowed,
      storedSignIn: { status: "stored" as const, login: "other" },
    };
    const keys = [blocked, sessionOnly, removed, otherAccount].map(targetRefreshKey);
    for (const key of keys) {
      expect(key).not.toBeNull();
      expect(key).not.toBe(before);
    }
    expect(new Set(keys).size).toBe(keys.length);
  });
});
