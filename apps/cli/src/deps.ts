import { execFile, spawn } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { openLocalFile } from "./adapters/open-file.js";
import { readAdvisoryStatus, updateOsvData } from "@pgard/dependencies";
import {
  discoverListeningPorts,
  probeLocalService,
  scanLocalWeb,
  type PortDiscoveryResult,
  type ServiceIdentity,
} from "@pgard/http-local";
import { isPathInsideDirectory, writeReports } from "@pgard/report";
import { createResultStore, resolveStoreDirectory, type ResultStore } from "@pgard/result-store";
import {
  createDeviceFlowSessionProvider,
  createOsCredentialStore,
  findGitRoot,
  openGitHubUrl,
  recheckOwnerApproval,
  resolveGitExecutable,
  resolveGitHubAppClientId,
  runScan,
  signInAndStore,
  verifyProject,
  type CredentialStore,
  type DeviceUserCode,
  type GitHubSessionProvider,
  type SignInNotice,
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
  /** Owner approval alone, for noticing an App install; never an authorization by itself. */
  recheckOwnerApproval: typeof recheckOwnerApproval;
  /**
   * Opens an `https://github.com/` URL in the system browser (fixed argv, no shell). Resolves
   * `false` when nothing was opened; never rejects.
   */
  openBrowser: (url: string) => Promise<boolean>;
  /** Waits `ms`; rejects when `signal` aborts. */
  sleep: (ms: number, signal: AbortSignal) => Promise<void>;
  now: () => number;
  createSessionProvider: (options: {
    env: Readonly<Record<string, string | undefined>>;
    onUserCode: (code: DeviceUserCode) => void;
    onNotice: (notice: SignInNotice) => void;
    /**
     * False without a terminal (stdin or stderr is not a TTY): a stored sign-in is still used,
     * but no device flow is ever started; the gate blocks with "not signed in" instead.
     */
    canSignInInteractively?: boolean;
    signal?: AbortSignal;
  }) => GitHubSessionProvider;
  /**
   * Where the GitHub sign-in is kept between runs: the OS keychain by default. There is no
   * file-based fallback; an unavailable keychain means memory only.
   */
  credentialStore: CredentialStore;
  /** `pgard login`: device flow, then save to `credentialStore`. */
  signInAndStore: typeof signInAndStore;
  /**
   * Opens the local result store for this invocation's environment, or `null` when no
   * app-data directory can be determined (no home in `env`). Derived from `env`, never from the
   * process, so a test with a bare environment can never reach the real store.
   */
  openResultStore: (env: Readonly<Record<string, string | undefined>>) => ResultStore | null;
  webScanner: WebScanner;
  probeLocalService: (port: number) => Promise<ServiceIdentity>;
  discoverListeningPorts: () => Promise<PortDiscoveryResult>;
  writeReports: typeof writeReports;
  /**
   * Opens a report file (an absolute `.html` or `.pdf` path) with the system's default program
   * (fixed argv, no shell). Resolves `false` when nothing was opened; never rejects.
   */
  openLocalFile: (filePath: string) => Promise<boolean>;
  /**
   * Creates a fresh private directory (`mkdtemp`, mode 0700) for one `pgard report` run that has
   * no `--output-dir`. Rejects when it cannot be created.
   */
  makeReportDir: () => Promise<string>;
  isPathInsideDirectory: typeof isPathInsideDirectory;
  /** Absolute path of the installed local-web launcher, or `null` if it is not installed. */
  resolveDashboardEntry: () => string | null;
  /** Starts the dashboard process (no shell) and resolves with its exit code. */
  startDashboardProcess: (entry: string, args: readonly string[]) => Promise<number>;
  readGitVersion: () => Promise<string | null>;
  checkGitHubReachable: () => Promise<boolean>;
  nodeVersion: string;
  /** Per-user data directory (downloaded advisory data lives under it). */
  appDataDir: string | null;
  /** `pgard advisories update`: the only place advisory data is downloaded. */
  updateAdvisories: typeof updateOsvData;
  /** Age of the downloaded data, from local metadata only. */
  readAdvisoryStatus: typeof readAdvisoryStatus;
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

function sleepDefault(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new Error("aborted"));
      return;
    }
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new Error("aborted"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

export function readGitVersionDefault(
  options: { env?: NodeJS.ProcessEnv } = {},
): Promise<string | null> {
  // An absolute path on Windows: a bare "git" would be searched in the current directory first.
  const gitProgram = resolveGitExecutable(options.env === undefined ? {} : { env: options.env });
  if (gitProgram === null) return Promise.resolve(null);
  return new Promise((resolve) => {
    execFile(
      gitProgram,
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

/**
 * The per-user data directory, shared by the result store and the advisory data (one resolver).
 * An empty home (not absolute) means "unknown": no fallback to the real home directory.
 */
function resolveDataDirectory(env: Readonly<Record<string, string | undefined>>): string | null {
  return resolveStoreDirectory({ env, homeDir: env.HOME ?? env.USERPROFILE ?? "" });
}

function openResultStoreDefault(
  env: Readonly<Record<string, string | undefined>>,
): ResultStore | null {
  const dir = resolveDataDirectory(env);
  return dir === null ? null : createResultStore({ dir });
}

/** A new private directory (mode 0700 on POSIX) under the system temporary directory. */
export function makeReportDirDefault(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), "pgard-report-"));
}

export function createDefaultDeps(): CliDeps {
  // Lazy: the native keychain binding is loaded on first use, not here.
  const credentialStore = createOsCredentialStore();
  return {
    findGitRoot,
    verifyProject,
    runScan,
    recheckOwnerApproval,
    openBrowser: (url) => openGitHubUrl(url),
    sleep: sleepDefault,
    now: Date.now,
    createSessionProvider: ({ env, onUserCode, onNotice, canSignInInteractively, signal }) =>
      createDeviceFlowSessionProvider({
        ...deviceFlowApp(env),
        onUserCode,
        onNotice,
        ...(canSignInInteractively === undefined ? {} : { canSignInInteractively }),
        credentialStore,
        ...(signal === undefined ? {} : { signal }),
      }),
    credentialStore,
    signInAndStore,
    openResultStore: openResultStoreDefault,
    webScanner: scanLocalWeb,
    probeLocalService: (port) => probeLocalService(port),
    discoverListeningPorts: () => discoverListeningPorts(),
    writeReports,
    openLocalFile: (filePath) => openLocalFile(filePath),
    makeReportDir: makeReportDirDefault,
    isPathInsideDirectory,
    resolveDashboardEntry: resolveDashboardEntryDefault,
    startDashboardProcess: startDashboardProcessDefault,
    readGitVersion: readGitVersionDefault,
    checkGitHubReachable: checkGitHubReachableDefault,
    nodeVersion: process.versions.node,
    appDataDir: resolveDataDirectory(process.env),
    updateAdvisories: updateOsvData,
    readAdvisoryStatus,
  };
}
