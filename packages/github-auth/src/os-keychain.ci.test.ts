import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createOsCredentialStore } from "./os-keychain.js";

/**
 * Real OS keychain round trip (Windows Credential Manager, macOS Keychain, Linux Secret
 * Service). Runs only when PGARD_KEYCHAIN_CI=1, which the CI workflow sets on Windows. It uses
 * a random throwaway service name and deletes the entry; it never touches the `pgard` service.
 */
describe.skipIf(process.env.PGARD_KEYCHAIN_CI !== "1")("OS keychain (CI only)", () => {
  it("stores, reads and deletes a throwaway credential", async () => {
    const store = createOsCredentialStore();
    const key = { service: `pgard-ci-test-${randomUUID()}`, account: "throwaway" };
    const secret = `ci-${randomUUID()}`;
    try {
      await store.set(key, secret);
      expect(await store.get(key)).toBe(secret);
    } finally {
      await store.delete(key).catch(() => false);
    }
    expect(await store.get(key)).toBeNull();
    expect(await store.delete(key)).toBe(false);
  });
});
