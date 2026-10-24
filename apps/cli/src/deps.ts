import { execFile, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
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
  findGitRoot,
  peekAdvisoryDb,
  readGitHubAppClientId,
  runScan,
  verifyProject,
  type AdvisoryDbStatus,
  type DeviceUserCode,
  type GitHubSessionProvider,
  type WebScanner,
} from "@pgard/scan-core";

/**
 * Everything the CLI does outside pure formatting goes through these functions, so commands can
 * be tested without GitHub, Git or real ports. The defaults are the real implementations.
 */
export interface CliDeps {
  findGitRoot: (cwd: string) => Promise<string | null>;
  verifyProject: typeof verifyProject;
  runScan: typeof runScan;
  createSessionProvider: (options: {
    env: Readonly<Record<string, string | undefined>>;
    onUserCode: (code: DeviceUserCode) => void;
    signal?: AbortSignal;
  }) => GitHubSessionProvider;
  webScanner: WebScanner;
  probeLocalService: (port: number) => Promise<ServiceIdentity>;
  discoverListeningPorts: () => Promise<PortDiscoveryResult>;
  writeReports: typeof writeReports;
  isPathInsideDirectory: typeof isPathInsideDirectory;
  /** Absolute path of the installed local-web launcher, or `null` if it is not installed. */
  resolveDashboardEntry: () => string | null;
  /** Starts the dashboard process (no shell) and resolves with its exit code. */
  startDashboardProcess: (entry: string, args: readonly string[]) => Promise<number>;
  readGitVersion: () => Promise<string | null>;
  checkGitHubReachable: () => Promise<boolean>;
  /**
   * Local advisory DB status (ok/missing/invalid/stale); its note never contains the DB path.
   * The default is a cheap peek: large files and directories are not fully loaded and come back
   * with `validated: false`.
   */
  readAdvisoryDbStatus: (
    env: Readonly<Record<string, string | undefined>>,
  ) => Promise<AdvisoryDbStatus>;
  nodeVersion: string;
}

/** Package specifier of the dashboard launcher. Only its file path is resolved, never imported. */
export const DASHBOARD_LAUNCHER_SPECIFIER = "@pgard/local-web/launcher";
const DOCTOR_TIMEOUT_MS = 5000;

function resolveDashboardEntryDefault(): string | null {
  try {
    const url = import.meta.resolve(DASHBOARD_LAUNCHER_SPECIFIER);
    // fileURLToPath decodes percent-escapes (spaces, non-ASCII) that URL.pathname keeps.
    return url.startsWith("file:") ? fileURLToPath(url) : null;
  } catch {
    return null;
  }
}

function startDashboardProcessDefault(entry: string, args: readonly string[]): Promise<number> {
  return new Promise((resolve, reject) => {
    // Fixed executable (this Node binary) and argument vector; no shell string.
    const child = spawn(process.execPath, [entry, ...args], { stdio: "inherit", shell: false });
    const forwardInterrupt = (): void => {
      child.kill("SIGINT");
    };
    process.on("SIGINT", forwardInterrupt);
    child.on("error", (error) => {
      process.off("SIGINT", forwardInterrupt);
      reject(error);
    });
    child.on("exit", (code, signal) => {
      process.off("SIGINT", forwardInterrupt);
      resolve(code ?? (signal === "SIGINT" ? 130 : 5));
    });
  });
}

function readGitVersionDefault(): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(
      "git",
      ["--version"],
      { timeout: DOCTOR_TIMEOUT_MS, shell: false },
      (error, stdout) => {
        resolve(error === null ? stdout.trim().slice(0, 80) : null);
      },
    );
  });
}

async function checkGitHubReachableDefault(): Promise<boolean> {
  try {
    // Unauthenticated HEAD request: no token, no repository data.
    const response = await fetch("https://api.github.com/", {
      method: "HEAD",
      signal: AbortSignal.timeout(DOCTOR_TIMEOUT_MS),
    });
    return response.status < 500;
  } catch {
    return false;
  }
}

export function createDefaultDeps(): CliDeps {
  return {
    findGitRoot,
    verifyProject,
    runScan,
    createSessionProvider: ({ env, onUserCode, signal }) =>
      createDeviceFlowSessionProvider({
        clientId: readGitHubAppClientId(env),
        onUserCode,
        ...(signal === undefined ? {} : { signal }),
      }),
    webScanner: scanLocalWeb,
    probeLocalService: (port) => probeLocalService(port),
    discoverListeningPorts: () => discoverListeningPorts(),
    writeReports,
    isPathInsideDirectory,
    resolveDashboardEntry: resolveDashboardEntryDefault,
    startDashboardProcess: startDashboardProcessDefault,
    readGitVersion: readGitVersionDefault,
    checkGitHubReachable: checkGitHubReachableDefault,
    readAdvisoryDbStatus: (env) => peekAdvisoryDb(env),
    nodeVersion: process.versions.node,
  };
}
