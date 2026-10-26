import { PassThrough } from "node:stream";
import { readAdvisoryStatus } from "@pgard/dependencies";
import type { AuthorizationSummary, Finding, ScanResult } from "@pgard/findings";
import type { ServiceIdentity } from "@pgard/http-local";
import { createInMemoryCredentialStore } from "@pgard/scan-core";
import type { InterruptSource } from "./adapters/cancel.js";
import type { CliIo, Key, KeyReader } from "./adapters/terminal.js";
import type { CommandContext } from "./context.js";
import type { CliDeps } from "./deps.js";
import { createStyle } from "./ui/formatters/style.js";

/** The test stdin: writable, so a test can type keys, and with an optional raw-mode switch. */
export type TestStdin = PassThrough & {
  isTTY?: boolean;
  setRawMode?: (mode: boolean) => void;
};

export interface CapturedIo {
  io: CliIo;
  /** The same stream as `io.stdin`, with its writable side typed. */
  stdin: TestStdin;
  stdout: () => string;
  stderr: () => string;
}

function capture(isTTY: boolean): {
  stream: PassThrough & { isTTY?: boolean };
  read: () => string;
} {
  const stream = new PassThrough() as PassThrough & { isTTY?: boolean };
  stream.isTTY = isTTY;
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString();
  });
  return { stream, read: () => text };
}

export function createTestIo(
  options: { isTTY?: boolean; env?: Record<string, string>; cwd?: string } = {},
): CapturedIo {
  const isTTY = options.isTTY ?? false;
  const stdout = capture(isTTY);
  const stderr = capture(isTTY);
  const stdin: TestStdin = new PassThrough();
  stdin.isTTY = isTTY;
  return {
    io: {
      stdin,
      stdout: stdout.stream,
      stderr: stderr.stream,
      env: options.env ?? {},
      cwd: options.cwd ?? "/work/repo",
    },
    stdin,
    stdout: stdout.read,
    stderr: stderr.read,
  };
}

export const noInterrupts: InterruptSource = { on: () => undefined, off: () => undefined };

export function scriptedKeys(sequence: readonly (string | Key)[]): KeyReader {
  const queue = sequence.map((entry) =>
    typeof entry === "string"
      ? {
          name: entry.length === 1 ? entry : entry,
          sequence: entry.length === 1 ? entry : undefined,
          ctrl: false,
        }
      : entry,
  );
  return {
    readKey: async () => {
      const next = queue.shift();
      if (next === undefined) throw new Error("scriptedKeys: no more keys");
      return next;
    },
    suspend: () => undefined,
    close: () => undefined,
  };
}

export const ALLOWED: AuthorizationSummary = {
  decision: "allowed",
  checks: [
    { id: "repository", status: "passed", reason: "GitHub remote owner/name" },
    { id: "github_identity", status: "passed", reason: "Signed in as user" },
    { id: "owner_approval", status: "passed", reason: "Owner approved" },
    { id: "current_access", status: "passed", reason: "Write access" },
    { id: "contribution", status: "passed", reason: "Merged commit found" },
  ],
};

export const BLOCKED: AuthorizationSummary = {
  decision: "blocked",
  checks: [
    { id: "repository", status: "passed", reason: "GitHub remote owner/name" },
    {
      id: "github_identity",
      status: "unverifiable",
      reason: "GitHub sign-in was denied.",
    },
    { id: "owner_approval", status: "unverifiable", reason: "Not evaluated." },
    { id: "current_access", status: "unverifiable", reason: "Not evaluated." },
    { id: "contribution", status: "unverifiable", reason: "Not evaluated." },
  ],
};

export function testFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    ruleId: "PG-SQL-001",
    title: "User input concatenated into SQL",
    category: "injection",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    location: { kind: "file", path: "src/api/users.ts", line: 42, url: null, commit: null },
    evidence: "req.query -> concat -> query()",
    impact: "Query structure may change",
    recommendation: "Use parameters",
    references: { cwe: ["CWE-89"], owasp: [], cve: [] },
    sources: ["code"],
    ...overrides,
  };
}

export function testResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    schemaVersion: "1.0",
    scanId: "scan-1234abcd",
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code", "history"],
    overallStatus: "completed",
    target: { repo: "owner/name", revision: "abcdef1234567890", webOrigin: null },
    authorization: ALLOWED,
    coverage: [
      { area: "source:typescript", scope: "code", status: "completed", ruleIds: [], note: null },
      { area: "history:secrets", scope: "history", status: "completed", ruleIds: [], note: null },
    ],
    findings: [testFinding()],
    advisoryDb: { version: null, updatedAt: null },
    ...overrides,
  };
}

export const HTTP_IDENTITY: ServiceIdentity = {
  port: 3000,
  url: "http://127.0.0.1:3000/",
  status: 200,
  title: "Shop dev",
  inferredTechnologies: ["Express"],
  isHttp: true,
  redirectStop: null,
  error: null,
};

/** Deps whose every call fails loudly unless a test overrides it. */
export function createTestDeps(overrides: Partial<CliDeps> = {}): CliDeps {
  const unexpected = (name: string) => () => {
    throw new Error(`unexpected call: ${name}`);
  };
  return {
    findGitRoot: async () => "/work/repo",
    verifyProject: async () => ({ summary: ALLOWED, repo: "owner/name", revision: "abc" }),
    runScan: async () => testResult(),
    recheckOwnerApproval: unexpected("recheckOwnerApproval") as never,
    // Never opens a real browser; a test that expects a call overrides it.
    openBrowser: unexpected("openBrowser") as never,
    sleep: async () => undefined,
    now: () => 0,
    createSessionProvider: () =>
      Object.assign(async () => unexpected("getGitHubSession")(), {
        existing: async () => unexpected("existing")(),
      }) as never,
    // A fake keychain: tests never touch the real OS keychain.
    credentialStore: createInMemoryCredentialStore(),
    signInAndStore: unexpected("signInAndStore") as never,
    webScanner: unexpected("webScanner") as never,
    probeLocalService: async () => HTTP_IDENTITY,
    discoverListeningPorts: async () => ({
      ports: [{ port: 3000, processName: "node" }],
      method: "lsof",
      isComplete: false,
      isAvailable: true,
      note: null,
    }),
    writeReports: unexpected("writeReports") as never,
    isPathInsideDirectory: async () => false,
    resolveDashboardEntry: () => null,
    startDashboardProcess: unexpected("startDashboardProcess") as never,
    readGitVersion: async () => "git version 2.50.0",
    checkGitHubReachable: async () => true,
    nodeVersion: "22.23.4",
    // No data directory: doctor reports "none"; a test that needs data overrides these.
    appDataDir: "/nonexistent/pgard-test-appdata",
    updateAdvisories: unexpected("updateAdvisories") as never,
    readAdvisoryStatus,
    ...overrides,
  };
}

export function createTestContext(
  captured: CapturedIo,
  deps: CliDeps,
  keys: KeyReader | null = null,
  isMenu = false,
): CommandContext {
  return {
    io: captured.io,
    deps,
    style: createStyle(false),
    errStyle: createStyle(false),
    keys,
    canOpenBrowser: false,
    signal: new AbortController().signal,
    isMenu,
    releaseInterrupts: () => undefined,
  };
}
