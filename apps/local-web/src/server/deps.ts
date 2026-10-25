import {
  discoverListeningPorts,
  probeLocalService,
  scanLocalWeb,
  type PortDiscoveryResult,
  type ServiceIdentity,
} from "@pgard/http-local";
import { isPathInsideDirectory, writeReports } from "@pgard/report";
import {
  createDeviceFlowSessionProvider,
  createOsCredentialStore,
  recheckOwnerApproval,
  resolveGitHubAppClientId,
  runScan,
  verifyProject,
  type CredentialStore,
  type DeviceUserCode,
  type GitHubSessionProvider,
  type SignInNotice,
  type WebScanner,
} from "@pgard/scan-core";

/** Side effects of the dashboard server, injectable for tests. */
export interface ServerDeps {
  verifyProject: typeof verifyProject;
  runScan: typeof runScan;
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
  writeReports: typeof writeReports;
  isPathInsideDirectory: typeof isPathInsideDirectory;
  now: () => number;
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
    writeReports,
    isPathInsideDirectory,
    now: Date.now,
  };
}
