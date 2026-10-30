import type { PickerDeps } from "./picker/session.js";
import {
  discoverListeningPorts,
  probeLocalService,
  scanLocalWeb,
  type PortDiscoveryResult,
  type ServiceIdentity,
} from "@pgard/http-local";
import { renderReport } from "@pgard/report";
import { createResultStore, resolveStoreDirectory, type ResultStore } from "@pgard/result-store";
import {
  createDeviceFlowSessionProvider,
  createOsCredentialStore,
  recheckOwnerApproval,
  resolveGitHubAppClientId,
  runCodeOnlyScan,
  runScan,
  verifyProject,
  type CredentialStore,
  type DeviceUserCode,
  type GitHubSessionProvider,
  readAdvisoryStatus,
  type SignInNotice,
  type WebScanner,
} from "@pgard/scan-core";

/** Side effects of the dashboard server, injectable for tests. */
export interface ServerDeps {
  verifyProject: typeof verifyProject;
  runScan: typeof runScan;
  /** #414: the code-only scan of the simple screen (no gate, code scope only). */
  runCodeOnlyScan: typeof runCodeOnlyScan;
  /** Owner approval alone, while waiting for an App install; never an authorization. */
  recheckOwnerApproval: typeof recheckOwnerApproval;
  createSessionProvider: (options: {
    env: Readonly<Record<string, string | undefined>>;
    onUserCode: (code: DeviceUserCode) => void;
    onNotice: (notice: SignInNotice) => void;
    /** Aborts a pending device flow (scan cancel, sign-out, shutdown). */
    signal: AbortSignal;
  }) => GitHubSessionProvider;
  /**
   * The OS keychain the sign-in is reused from (server side only; the token never reaches the
   * browser). An unavailable keychain means memory only for this dashboard.
   */
  credentialStore: CredentialStore;
  webScanner: WebScanner;
  /** `signal` aborts when sign-out or a new check replaces the authorization it ran under. */
  probeLocalService: (port: number, options: { signal: AbortSignal }) => Promise<ServiceIdentity>;
  discoverListeningPorts: () => Promise<PortDiscoveryResult>;
  /** Renders the same HTML or PDF the CLI file export writes; the dashboard never writes files. */
  renderReport: typeof renderReport;
  now: () => number;
  /**
   * The per-user data folder whose `advisories/osv` holds the downloaded OSV data, read (never
   * written) by the dependency check of a scan. `null`/absent: no advisory data can be read.
   */
  advisoryDataDir?: string | null;
  /** Reads the status of that data (local files only). Defaults to the real reader. */
  readAdvisoryStatus?: typeof readAdvisoryStatus;
  /**
   * Opens the local result store the Trend view reads (read only; the dashboard never saves).
   * Absent or `null`: there is no store folder. Tests inject a store on a temporary directory.
   */
  openResultStore?: (env: Readonly<Record<string, string | undefined>>) => ResultStore | null;
  /** `pgard web --no-store`: the Trend view says the store is off and reads nothing. */
  isStoreDisabled?: boolean;
  /** Picker mode (`pgard web`) only: inspector, recent-list storage and search scope. */
  picker?: PickerDeps;
}

/** Client id (or the fixed reason a malformed override blocks) for the session provider. */
function deviceFlowApp(env: Readonly<Record<string, string | undefined>>): {
  clientId: string | null;
  invalidClientIdMessage?: string;
} {
  const app = resolveGitHubAppClientId(env);
  return app.source === "invalid"
    ? { clientId: null, invalidClientIdMessage: app.message }
    : { clientId: app.clientId };
}

export function createDefaultServerDeps(): ServerDeps {
  // Lazy: the native keychain binding is loaded on first use, not here.
  const credentialStore = createOsCredentialStore();
  return {
    verifyProject,
    runScan,
    runCodeOnlyScan,
    recheckOwnerApproval,
    createSessionProvider: ({ env, onUserCode, onNotice, signal }) =>
      createDeviceFlowSessionProvider({
        ...deviceFlowApp(env),
        onUserCode,
        onNotice,
        credentialStore,
        signal,
      }),
    credentialStore,
    webScanner: scanLocalWeb,
    probeLocalService: (port, { signal }) => probeLocalService(port, { signal }),
    discoverListeningPorts: () => discoverListeningPorts(),
    renderReport,
    now: Date.now,
    openResultStore: (env) => {
      const dir = resolveStoreDirectory({ env, homeDir: env.HOME ?? env.USERPROFILE ?? "" });
      return dir === null ? null : createResultStore({ dir });
    },
    advisoryDataDir: resolveStoreDirectory({
      env: process.env,
      homeDir: process.env.HOME ?? process.env.USERPROFILE ?? "",
    }),
  };
}
