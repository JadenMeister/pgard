import { describe, expect, it } from "vitest";
import { isCredentialStoreError } from "./credential-store.js";
import { createOsCredentialStore } from "./os-keychain.js";

const KEY = { service: "pgard", account: "github:github.com:Iv23.testClient" };
const SECRET = ["ghu", "storedSecretTokenForTests0000"].join("_");

describe("createOsCredentialStore", () => {
  it("round-trips through the native binding's AsyncEntry", async () => {
    const backing = new Map<string, string>();
    const options: unknown[] = [];
    class AsyncEntry {
      private readonly id: string;
      constructor(service: string, account: string, entryOptions: unknown) {
        this.id = `${service}/${account}`;
        options.push(entryOptions);
      }
      async getPassword() {
        return backing.get(this.id) ?? null;
      }
      async setPassword(value: string) {
        backing.set(this.id, value);
      }
      async deleteCredential() {
        return backing.delete(this.id);
      }
    }
    const store = createOsCredentialStore(async () => ({ AsyncEntry }));
    await store.set(KEY, "value");
    expect(backing.get("pgard/github:github.com:Iv23.testClient")).toBe("value");
    expect(await store.get(KEY)).toBe("value");
    expect(await store.delete(KEY)).toBe(true);
    expect(await store.get(KEY)).toBeNull();
    expect(options[0]).toEqual({ linux: { store: "secret-service" } });
  });

  it("reports a missing binding as unavailable", async () => {
    const store = createOsCredentialStore(async () => {
      throw new Error("Cannot find module");
    });
    const error = await store.get(KEY).catch((caught: unknown) => caught);
    expect(isCredentialStoreError(error)).toBe(true);
    expect((error as Error).message).toMatch(/not available/);
  });

  it("never forwards the native error text, which could echo the secret", async () => {
    class AsyncEntry {
      async getPassword() {
        return null;
      }
      async setPassword(value: string) {
        throw new Error(`keychain refused ${value}`);
      }
      async deleteCredential() {
        return false;
      }
    }
    const store = createOsCredentialStore(async () => ({ AsyncEntry }));
    const error = await store.set(KEY, SECRET).catch((caught: unknown) => caught);
    expect(isCredentialStoreError(error)).toBe(true);
    expect(`${String(error)} ${(error as Error).stack ?? ""}`).not.toContain(SECRET);
  });
});
