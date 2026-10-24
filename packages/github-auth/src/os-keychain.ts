import {
  CredentialStoreError,
  type CredentialKey,
  type CredentialStore,
} from "./credential-store.js";

/** The part of `@napi-rs/keyring` that PGARD uses. */
interface KeyringEntry {
  getPassword(): Promise<string | null>;
  setPassword(password: string): Promise<void>;
  deleteCredential(): Promise<boolean>;
}
interface KeyringModule {
  AsyncEntry: new (
    service: string,
    account: string,
    options?: { linux?: { store?: "secret-service" | "keyutils" } },
  ) => KeyringEntry;
}

const NOT_LOADED = "the OS keychain module is not available on this platform";
const NOT_ACCESSIBLE =
  "the OS keychain could not be used (it may be locked, or no keychain service is running)";

/**
 * The OS keychain: macOS Keychain, Windows Credential Manager or the Linux Secret Service,
 * through the `@napi-rs/keyring` native binding. The secret is passed to the OS API in memory;
 * no child process is started, so it never appears in argv or a child environment.
 *
 * `loadModule` is a test hook. When the binding cannot be loaded, or the keychain rejects a
 * call, methods reject with a `CredentialStoreError` whose message is fixed text; the native
 * error is never forwarded because its wording is outside our control.
 */
export function createOsCredentialStore(
  loadModule: () => Promise<unknown> = () => import("@napi-rs/keyring"),
): CredentialStore {
  let loaded: Promise<KeyringModule> | null = null;
  const load = (): Promise<KeyringModule> => {
    loaded ??= loadModule().then(
      (module) => {
        const candidate = module as Partial<KeyringModule> | null;
        if (typeof candidate?.AsyncEntry !== "function") throw new Error("missing AsyncEntry");
        return candidate as KeyringModule;
      },
      () => {
        throw new Error("not loadable");
      },
    );
    return loaded;
  };

  const withEntry = async <T>(
    key: CredentialKey,
    action: (entry: KeyringEntry) => Promise<T>,
  ): Promise<T> => {
    let module: KeyringModule;
    try {
      module = await load();
    } catch {
      throw new CredentialStoreError(NOT_LOADED);
    }
    try {
      // Pin Linux to the Secret Service so the entry survives a reboot; ignored elsewhere.
      const entry = new module.AsyncEntry(key.service, key.account, {
        linux: { store: "secret-service" },
      });
      return await action(entry);
    } catch {
      throw new CredentialStoreError(NOT_ACCESSIBLE);
    }
  };

  return {
    get: (key) => withEntry(key, (entry) => entry.getPassword()),
    set: (key, secret) => withEntry(key, (entry) => entry.setPassword(secret)),
    delete: (key) => withEntry(key, (entry) => entry.deleteCredential()),
  };
}
