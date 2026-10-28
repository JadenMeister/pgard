import { PassThrough } from "node:stream";
import { readAdvisoryStatus } from "@pgard/dependencies";
import {
  SCHEMA_VERSION,
  type AuthorizationSummary,
  type Finding,
  type ScanResult,
} from "@pgard/findings";
import type { ServiceIdentity } from "@pgard/http-local";
import {
  createInMemoryCredentialStore,
  DEFAULT_GITHUB_APP_CLIENT_ID,
  type CredentialStore,
} from "@pgard/scan-core";
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
    schemaVersion: SCHEMA_VERSION,
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

/**
 * A fake keychain that already holds a valid sign-in for any App, so the menu does not start its
 * guided first run (which only applies when nothing is stored). Never touches the real keychain.
 */
export function createSignedInCredentialStore(): CredentialStore {
  const entry = JSON.stringify({
    version: 1,
    host: "github.com",
    clientId: DEFAULT_GITHUB_APP_CLIENT_ID,
    accessToken: "stored-access-token-for-tests",
    expiresAt: Date.UTC(2099, 0, 1),
    refreshToken: null,
    refreshTokenExpiresAt: null,
    login: "octo",
    userId: 7,
    savedAt: 0,
  });
  return {
    get: async () => entry,
    set: async () => undefined,
    delete: async () => true,
  };
}

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
    // No store by default: tests never write to the real app-data directory.
    openResultStore: () => null,
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
    openLocalFile: unexpected("openLocalFile") as never,
    reportDefaultDir: () => "/work/reports",
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

/** A mixed result for the panel view: every severity, three scopes, a Korean title, a long note. */
export function panelsFixtureResult(): ScanResult {
  const at = (
    n: number,
    severity: Finding["severity"],
    overrides: Partial<Finding> = {},
  ): Finding =>
    testFinding({
      id: `f${n}`,
      severity,
      ruleId: `PG-FIX-${String(n).padStart(3, "0")}`,
      title: `Fixture finding ${n}`,
      location: {
        kind: "file",
        path: `src/module${n}/handler.ts`,
        line: 10 + n,
        url: null,
        commit: null,
      },
      references: {
        cwe: [],
        owasp: n % 3 === 0 ? [] : [n % 2 === 0 ? "A05:2025" : "A01:2025"],
        cve: [],
      },
      ...overrides,
    });
  const findings: Finding[] = [
    at(1, "critical", { status: "confirmed", title: "Hardcoded production secret" }),
    at(2, "high", { title: "비밀번호가 코드에 그대로 들어 있습니다" }),
    at(3, "high", {
      sources: ["history"],
      location: {
        kind: "commit",
        path: "config/.env",
        line: null,
        url: null,
        commit: "0123456789abcdef0123",
      },
    }),
    at(4, "high", {
      suppression: { reason: "accepted", expires: "2027-01-01", source: "pgard.config.json" },
    }),
    at(5, "medium"),
    at(6, "medium", {
      sources: ["code", "web"],
      location: {
        kind: "url",
        path: null,
        line: null,
        url: "http://127.0.0.1:3000/admin",
        commit: null,
      },
    }),
    at(7, "medium", { inBaseline: true }),
    at(8, "low", { status: "informational" }),
    at(9, "low"),
    at(10, "info", { status: "informational" }),
    at(11, "high"),
    at(12, "medium"),
  ];
  return testResult({
    requestedScopes: ["code", "history", "web"],
    overallStatus: "partial",
    ruleStats: [
      {
        ruleId: "PG-FIX-001",
        area: "source:typescript",
        scope: "code",
        status: "completed",
        targets: [{ unit: "files", examined: 152, reason: null }],
        findings: 3,
      },
      {
        ruleId: "PG-FIX-002",
        area: "history:secrets",
        scope: "history",
        status: "partial",
        targets: [{ unit: "commits", examined: 500, reason: null }],
        findings: 1,
      },
    ],
    coverage: [
      {
        area: "source:typescript",
        scope: "code",
        status: "completed",
        ruleIds: ["PG-FIX-001"],
        note: null,
      },
      {
        area: "history:secrets",
        scope: "history",
        status: "partial",
        ruleIds: [],
        note: "Only the last 500 commits were read because the repository history is very long.",
      },
      {
        area: "web:anonymous",
        scope: "web",
        status: "not_tested",
        ruleIds: [],
        note: "No confirmed local web target.",
      },
      {
        area: "dependencies:npm",
        scope: "code",
        status: "not_selected",
        ruleIds: [],
        note: null,
      },
    ],
    findings,
  });
}
