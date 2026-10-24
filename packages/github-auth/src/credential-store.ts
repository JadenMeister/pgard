/**
 * Where a GitHub sign-in is kept between runs. The only production implementation is the OS
 * keychain (`createOsCredentialStore`); there is deliberately no file-based store. Tests use
 * `createInMemoryCredentialStore`.
 */

/** Identifies one keychain entry. Neither part is secret. */
export interface CredentialKey {
  service: string;
  account: string;
}

/**
 * Minimal keychain interface. Implementations must never put the secret in process arguments,
 * child-process environments, logs or error messages. Every method rejects with
 * `CredentialStoreError` when the store cannot be used.
 */
export interface CredentialStore {
  get(key: CredentialKey): Promise<string | null>;
  set(key: CredentialKey, secret: string): Promise<void>;
  /** Resolves `true` if an entry was deleted, `false` if there was none. */
  delete(key: CredentialKey): Promise<boolean>;
}

/** Thrown by a `CredentialStore`. The message is fixed text, safe to show; it never holds a secret. */
export class CredentialStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CredentialStoreError";
  }
}

export function isCredentialStoreError(error: unknown): error is CredentialStoreError {
  return error instanceof CredentialStoreError;
}

function keyId(key: CredentialKey): string {
  return `${key.service}\u0000${key.account}`;
}

/** In-memory store for tests and for callers that want the old memory-only behavior. */
export function createInMemoryCredentialStore(): CredentialStore & { size(): number } {
  const entries = new Map<string, string>();
  return {
    get: async (key) => entries.get(keyId(key)) ?? null,
    set: async (key, secret) => {
      entries.set(keyId(key), secret);
    },
    delete: async (key) => entries.delete(keyId(key)),
    size: () => entries.size,
  };
}

/** A store that is never available, e.g. when the OS keychain cannot be loaded. */
export function createUnavailableCredentialStore(reason: string): CredentialStore {
  const fail = async (): Promise<never> => {
    throw new CredentialStoreError(reason);
  };
  return { get: fail, set: fail, delete: fail };
}
