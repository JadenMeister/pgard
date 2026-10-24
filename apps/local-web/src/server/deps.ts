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
  readGitHubAppClientId,
  runScan,
  verifyProject,
  type DeviceUserCode,
  type GitHubSessionProvider,
  type WebScanner,
} from "@pgard/scan-core";

/** Side effects of the dashboard server, injectable for tests. */
export interface ServerDeps {
  verifyProject: typeof verifyProject;
  runScan: typeof runScan;
  createSessionProvider: (options: {
    env: Readonly<Record<string, string | undefined>>;
    onUserCode: (code: DeviceUserCode) => void;
  }) => GitHubSessionProvider;
  webScanner: WebScanner;
  probeLocalService: (port: number) => Promise<ServiceIdentity>;
  discoverListeningPorts: () => Promise<PortDiscoveryResult>;
  writeReports: typeof writeReports;
  isPathInsideDirectory: typeof isPathInsideDirectory;
  now: () => number;
}

export function createDefaultServerDeps(): ServerDeps {
  return {
    verifyProject,
    runScan,
    createSessionProvider: ({ env, onUserCode }) =>
      createDeviceFlowSessionProvider({ clientId: readGitHubAppClientId(env), onUserCode }),
    webScanner: scanLocalWeb,
    probeLocalService: (port) => probeLocalService(port),
    discoverListeningPorts: () => discoverListeningPorts(),
    writeReports,
    isPathInsideDirectory,
    now: Date.now,
  };
}
