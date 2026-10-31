/**
 * Integration: the guided first run of the menu (#305) and the fail-fast without a terminal
 * (#296), against the real authorization gate (scan-core + policy), a throwaway Git repository
 * and the policy package's in-memory GitHub. The keychain, the browser, the device flow and the
 * clock are fakes: nothing here reaches GitHub, signs in, or touches the OS keychain.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createResultStore } from "@pgard/result-store";
import {
  createDeviceFlowSessionProvider,
  createInMemoryCredentialStore,
  createUnavailableCredentialStore,
  DEFAULT_GITHUB_APP_CLIENT_ID,
  runCodeOnlyScan as realRunCodeOnlyScan,
  runScan as realRunScan,
  verifyProject as realVerify,
  type AuthorizationOutcome,
  type CredentialStore,
} from "@pgard/scan-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Key, KeyReader } from "../../apps/cli/src/adapters/terminal.js";
import { main, type CliDeps } from "../../apps/cli/src/app.js";
import { resolveLanguage } from "../../apps/cli/src/language.js";
import { runGuidedFirstRun, MAX_INSTALL_RETRIES } from "../../apps/cli/src/flows/first-run.js";
import {
  createSignedInCredentialStore,
  createTestContext,
  createTestDeps,
  createTestIo,
  noInterrupts,
  scriptedKeys,
  type CapturedIo,
} from "../../apps/cli/src/test-support.js";
import { UserCancelledError } from "../../apps/cli/src/ui/components/prompts.js";
import {
  createGitFixture,
  type GitFixture,
} from "../../packages/git-history/src/test-support/git-fixture.js";
import {
  ME,
  createMockGitHub,
  orgInstallation,
  orgMembership,
  orgRepository,
  ownerInstallation,
  userRepository,
  type MockGitHubState,
} from "../../packages/policy/src/test-support/mock-github.js";
import { TIME_FACTOR } from "../support/timing.js";

const INSTALL_URL =
  "https://github.com/apps/pgard-jadenmeister/installations/new/permissions?suggested_target_id=1001&repository_ids%5B%5D=555";
const FIVE_CHECKS = [
  "repository",
  "github_identity",
  "owner_approval",
  "current_access",
  "contribution",
];
const ENTER_ALTERNATE_SCREEN = "\u001b[?1049h";
const CTRL_C: Key = { name: "c", sequence: "\u0003", ctrl: true };
const ENTER_KEY = "return";

let fixture: GitFixture | null = null;
let tempDirs: string[] = [];
let networkCalls: string[] = [];

beforeEach(() => {
  networkCalls = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      networkCalls.push(String(url));
      throw new Error("network access is not allowed in this test");
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  fixture?.cleanup();
  fixture = null;
  for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true });
  tempDirs = [];
});

function project(remote = "git@github.com:me/app.git"): { root: string; head: string } {
  fixture = createGitFixture({ remotes: { origin: remote } });
  const head = fixture.commit({
    authorName: "Me Person",
    authorEmail: "me@example.com",
    files: { "src/index.ts": "export const x = 1;\n" },
  });
  return { root: fixture.root, head };
}

/** Identity, access and a verified contribution are fine; the App is not installed. */
function notInstalled(head: string, overrides: Partial<MockGitHubState> = {}): MockGitHubState {
  return {
    user: ME,
    repository: userRepository(),
    installations: [],
    installationRepositories: {},
    pulls: {},
    commits: { [head]: { sha: head, authorId: ME.id, committerId: ME.id, isVerified: true } },
    compare: { [head]: "identical" },
    ...overrides,
  };
}

function installForOwner(state: MockGitHubState): void {
  state.installations = [ownerInstallation()];
  state.installationRepositories = { 77: [555] };
}

/** Keys for the prompts, with a hook that runs when the n-th key (1-based) is asked for. */
function keysWithHook(
  sequence: ReadonlyArray<string | Key>,
  onKey: (count: number) => void = () => {},
): KeyReader & { asked: () => number } {
  const inner = scriptedKeys(sequence);
  let asked = 0;
  return {
    readKey: async () => {
      asked += 1;
      onKey(asked);
      return inner.readKey();
    },
    suspend: () => undefined,
    close: () => undefined,
    asked: () => asked,
  };
}

interface Harness {
  deps: CliDeps;
  captured: CapturedIo;
  signIn: ReturnType<typeof vi.fn>;
  openBrowser: ReturnType<typeof vi.fn>;
  /** Every complete gate run: its check ids and the GitHub calls it made. */
  gates: Array<{ checks: string[]; calls: string[]; outcome: AuthorizationOutcome }>;
  scans: string[];
}

function harness(state: MockGitHubState, store: CredentialStore | null = null): Harness {
  const { session, calls } = createMockGitHub(state);
  const provider = Object.assign(async () => session, {
    invalidate: () => undefined,
    signOut: () => undefined,
    existing: async () => session,
  });
  const gates: Harness["gates"] = [];
  const scans: string[] = [];
  const signIn = vi.fn(async () => ({ login: "me", savedError: null }));
  const openBrowser = vi.fn(async () => true);
  const deps = createTestDeps({
    findGitRoot: async () => fixture?.root ?? null,
    credentialStore: store ?? createInMemoryCredentialStore(),
    createSessionProvider: () => provider,
    signInAndStore: signIn as never,
    verifyProject: async (root, authorization) => {
      const before = calls.length;
      const outcome = await realVerify(root, authorization);
      gates.push({
        checks: outcome.summary.checks.map((check) => check.id),
        calls: calls.slice(before),
        outcome,
      });
      return outcome;
    },
    runScan: async (request, scanDeps) => {
      const result = await realRunScan(request, scanDeps);
      scans.push(result.overallStatus);
      return result;
    },
    openBrowser,
  });
  const captured = createTestIo({ isTTY: true, cwd: fixture?.root ?? "/", env: {} });
  (captured.io.stdout as unknown as { columns: number; rows: number }).columns = 80;
  (captured.io.stdout as unknown as { columns: number; rows: number }).rows = 24;
  return { deps, captured, signIn, openBrowser, gates, scans };
}

function contextOf(h: Harness, keys: KeyReader, options: { browser?: boolean } = {}) {
  const context = createTestContext(h.captured, h.deps, keys, true);
  context.canOpenBrowser = options.browser ?? false;
  return context;
}

const countOf = (text: string, needle: string): number => text.split(needle).length - 1;

describe("guided first run: sign in, install the App, re-verify, scan", () => {
  it("walks no sign-in -> sign in -> App missing -> retry -> success -> scan -> panels", async () => {
    const { head } = project();
    const state = notInstalled(head);
    const h = harness(state);
    // Y (sign in), Enter (open the page), Enter (after installing; the App is installed while
    // the user is "on GitHub"), Esc (leave the panels), Esc (no report).
    const keys = keysWithHook([ENTER_KEY, ENTER_KEY, ENTER_KEY, "escape", "escape"], (count) => {
      if (count === 3) installForOwner(state);
    });
    await runGuidedFirstRun(contextOf(h, keys, { browser: true }));
    const stdout = h.captured.stdout();
    const stderr = h.captured.stderr();
    expect(stderr).toContain("You are not signed in to GitHub yet.");
    expect(stdout).toContain("Sign in now? [Y/n]");
    expect(h.signIn).toHaveBeenCalledTimes(1);
    // The exact install URL for this account and repository, shown and opened after Enter.
    expect(stderr).toContain(`1. Open ${INSTALL_URL}`);
    expect(h.openBrowser).toHaveBeenCalledExactlyOnceWith(INSTALL_URL);
    expect(stdout).toContain("Press Enter to open the page in your browser (or s to skip)");
    expect(stdout).toContain("Press Enter after installing (or q to quit)");
    expect(stderr).toContain(
      "Checking again from scratch, all five authorization checks (try 1 of 3)",
    );
    // Blocked once (App missing), then a complete fresh gate that passes.
    expect(h.gates.map((gate) => gate.outcome.summary.decision)).toEqual(["blocked", "allowed"]);
    expect(h.scans).toEqual(["completed"]);
    expect(stdout).toContain(ENTER_ALTERNATE_SCREEN);
  });

  it("runs the complete five-check gate every time, with no cache between runs", async () => {
    const { head } = project();
    const state = notInstalled(head);
    const h = harness(state);
    const keys = keysWithHook([ENTER_KEY, ENTER_KEY, "escape"], (count) => {
      if (count === 2) installForOwner(state);
    });
    h.captured.io.env = { PGARD_PANELS: "off" };
    await runGuidedFirstRun(contextOf(h, keys));
    // The retry gate is not a shortcut: same five checks, same order, and it asked GitHub for
    // the user and the repository again before anything else.
    expect(h.gates.length).toBeGreaterThanOrEqual(2);
    for (const gate of h.gates) {
      expect(gate.checks).toEqual(FIVE_CHECKS);
      expect(gate.calls.slice(0, 2)).toEqual(["user", "repo"]);
      expect(gate.calls).toContain("installations");
    }
    const [blocked, retried] = h.gates;
    expect(blocked?.outcome.summary.decision).toBe("blocked");
    expect(retried?.outcome.summary.checks.every((check) => check.status === "passed")).toBe(true);
    expect(
      retried?.calls.some((call) => call.startsWith("commit:") || call.startsWith("compare:")),
    ).toBe(true);
  });

  it(`stops with the blocked result when the App is still missing after ${MAX_INSTALL_RETRIES} retries`, async () => {
    const { head } = project();
    const h = harness(notInstalled(head));
    h.captured.io.env = { PGARD_PANELS: "off" };
    const keys = keysWithHook([
      ENTER_KEY,
      ...Array.from({ length: MAX_INSTALL_RETRIES }, () => ENTER_KEY),
    ]);
    await runGuidedFirstRun(contextOf(h, keys));
    expect(h.gates).toHaveLength(1 + MAX_INSTALL_RETRIES);
    for (const gate of h.gates) expect(gate.checks).toEqual(FIVE_CHECKS);
    expect(countOf(h.captured.stdout(), "Press Enter after installing")).toBe(MAX_INSTALL_RETRIES);
    expect(h.captured.stderr()).toContain("Still blocked after 3 tries");
    expect(h.captured.stdout()).toContain("No PGARD GitHub App installation");
    expect(h.scans).toEqual([]);
    expect(h.gates.at(-1)?.outcome.summary.decision).toBe("blocked");
  });

  it("q at the install prompt quits without another check", async () => {
    const { head } = project();
    const h = harness(notInstalled(head));
    await runGuidedFirstRun(contextOf(h, keysWithHook([ENTER_KEY, "q"])));
    expect(h.gates).toHaveLength(1);
    expect(h.captured.stderr()).toContain("Run `pgard` again after the App is installed.");
    expect(h.scans).toEqual([]);
  });

  it("a reason the App cannot fix (no contribution evidence) shows the result and no retry loop", async () => {
    const { head } = project();
    const state = notInstalled(head, { commits: {}, compare: {} });
    installForOwner(state);
    const h = harness(state);
    await runGuidedFirstRun(contextOf(h, keysWithHook([ENTER_KEY])));
    expect(h.gates).toHaveLength(1);
    expect(h.gates[0]?.outcome.summary.decision).toBe("blocked");
    expect(h.captured.stdout()).not.toContain("Press Enter after installing");
    expect(h.captured.stderr()).toContain("cannot be fixed by installing the App");
    expect(h.scans).toEqual([]);
  });

  it("no read access shows the result without a retry loop", async () => {
    const { head } = project();
    const state = notInstalled(head, {
      repository: userRepository({
        permissions: { admin: false, maintain: false, push: false, triage: false, pull: false },
      }),
    });
    installForOwner(state);
    const h = harness(state);
    await runGuidedFirstRun(contextOf(h, keysWithHook([ENTER_KEY])));
    expect(h.gates).toHaveLength(1);
    expect(h.captured.stdout()).toContain("no read access");
    expect(h.captured.stdout()).not.toContain("Press Enter after installing");
  });

  it("not a GitHub remote shows the result without a retry loop", async () => {
    const { head } = project("git@example.com:me/app.git");
    const h = harness(notInstalled(head));
    await runGuidedFirstRun(contextOf(h, keysWithHook([ENTER_KEY])));
    expect(h.gates).toHaveLength(1);
    expect(h.captured.stdout()).not.toContain("Press Enter after installing");
    expect(h.captured.stderr()).toContain("cannot be fixed by installing the App");
  });

  it("an organization non-owner is told to ask an owner, with no retry loop", async () => {
    const { head } = project("git@github.com:acme/app.git");
    const state = notInstalled(head, {
      repository: orgRepository(),
      memberships: { acme: orgMembership({ role: "member" }) },
    });
    const h = harness(state);
    await runGuidedFirstRun(contextOf(h, keysWithHook([ENTER_KEY])));
    expect(h.gates).toHaveLength(1);
    expect(h.captured.stderr()).toContain("Ask an owner of acme");
    expect(h.captured.stdout()).not.toContain("Press Enter after installing");
    expect(h.scans).toEqual([]);
  });

  it("an organization owner is guided like a personal owner", async () => {
    const { head } = project("git@github.com:acme/app.git");
    const state = notInstalled(head, {
      repository: orgRepository(),
      memberships: { acme: orgMembership() },
    });
    const h = harness(state);
    h.captured.io.env = { PGARD_PANELS: "off" };
    const keys = keysWithHook([ENTER_KEY, ENTER_KEY, "escape"], (count) => {
      if (count === 2) {
        state.installations = [orgInstallation()];
        state.installationRepositories = { 88: [555] };
      }
    });
    await runGuidedFirstRun(contextOf(h, keys));
    expect(h.captured.stderr()).toContain("suggested_target_id=42");
    expect(h.gates.map((gate) => gate.outcome.summary.decision)).toEqual(["blocked", "allowed"]);
  });

  it("declining the sign-in does nothing else", async () => {
    const { head } = project();
    const h = harness(notInstalled(head));
    await runGuidedFirstRun(contextOf(h, keysWithHook(["n"])));
    expect(h.signIn).not.toHaveBeenCalled();
    expect(h.gates).toHaveLength(0);
    expect(h.captured.stderr()).toContain("Run `pgard login` whenever you are ready");
  });

  it("is not a first run when a sign-in is stored, or outside a Git repository", async () => {
    const { head } = project();
    const signedIn = harness(notInstalled(head), createSignedInCredentialStore());
    await runGuidedFirstRun(contextOf(signedIn, keysWithHook([])));
    expect(signedIn.gates).toHaveLength(0);
    expect(signedIn.captured.stdout()).toBe("");

    const outside = harness(notInstalled(head));
    outside.deps.findGitRoot = async () => null;
    await runGuidedFirstRun(contextOf(outside, keysWithHook([])));
    expect(outside.captured.stdout()).toBe("");

    const noKeychain = harness(notInstalled(head), createUnavailableCredentialStore("locked"));
    await runGuidedFirstRun(contextOf(noKeychain, keysWithHook([])));
    expect(noKeychain.captured.stdout()).toBe("");
  });

  it("speaks Korean with PGARD_LANG=ko, including the authorization block", async () => {
    const { head } = project();
    const h = harness(notInstalled(head));
    const env = { PGARD_LANG: "ko" };
    h.captured.io.env = env;
    const context = contextOf(h, keysWithHook([ENTER_KEY, "q"]));
    // The same resolution the menu performs for PGARD_LANG.
    context.ruleLocale = resolveLanguage({ flag: null, env });
    expect(context.ruleLocale).toBe("ko");
    await runGuidedFirstRun(context);
    const stdout = h.captured.stdout();
    expect(h.captured.stderr()).toContain("아직 GitHub에 로그인하지 않았습니다.");
    expect(stdout).toContain("지금 로그인할까요? [Y/n]");
    expect(stdout).toContain("설치한 뒤 Enter를 누르세요 (종료하려면 q)");
    const block = stdout.slice(stdout.indexOf("Repository "), stdout.indexOf("설치한 뒤 Enter"));
    expect(block).toContain("GitHub");
    // Check names and status words come from the Korean catalog, not English.
    expect(block).not.toMatch(/\b(passed|failed|unverifiable)\b/);
    expect(block).not.toMatch(/\[(passed|failed)\]/);
  });

  it("asks nothing when stdin or stderr is not a terminal", async () => {
    const { head } = project();
    const h = harness(notInstalled(head));
    (h.captured.io.stderr as { isTTY?: boolean }).isTTY = false;
    await runGuidedFirstRun(contextOf(h, keysWithHook([])));
    expect(h.captured.stdout()).toBe("");
    expect(h.gates).toHaveLength(0);
    expect(h.signIn).not.toHaveBeenCalled();
  });

  it("App missing AND another check failed: no install prompt, one gate (remedy alone is not enough)", async () => {
    const { head } = project();
    // Not installed (remedy is set) and no contribution evidence (another check fails).
    const h = harness(notInstalled(head, { commits: {}, compare: {} }));
    await runGuidedFirstRun(contextOf(h, keysWithHook([ENTER_KEY])));
    expect(h.gates).toHaveLength(1);
    expect(h.gates[0]?.outcome.remedy ?? null).not.toBeNull();
    expect(h.captured.stdout()).not.toContain("Press Enter after installing");
    expect(h.captured.stderr()).toContain("cannot be fixed by installing the App");
    expect(h.scans).toEqual([]);
  });
});

describe("guided first run: Ctrl+C at each prompt exits through the cancel path", () => {
  async function cancelledAt(promptNumber: number): Promise<Harness> {
    const { head } = project();
    const h = harness(notInstalled(head));
    // Enter answers the earlier prompts; Ctrl+C then y at the chosen one.
    const keys = [...Array.from({ length: promptNumber - 1 }, () => ENTER_KEY), CTRL_C, "y"];
    await expect(
      runGuidedFirstRun(contextOf(h, keysWithHook(keys), { browser: true })),
    ).rejects.toBeInstanceOf(UserCancelledError);
    return h;
  }

  it("at 'Sign in now?'", async () => {
    const h = await cancelledAt(1);
    expect(h.signIn).not.toHaveBeenCalled();
  });

  it("at 'Press Enter to open the page'", async () => {
    const h = await cancelledAt(2);
    expect(h.openBrowser).not.toHaveBeenCalled();
  });

  it("at 'Press Enter after installing'", async () => {
    const h = await cancelledAt(3);
    expect(h.gates).toHaveLength(1);
  });

  it("any other key after Ctrl+C resumes the same prompt", async () => {
    const { head } = project();
    const h = harness(notInstalled(head));
    await runGuidedFirstRun(contextOf(h, keysWithHook([CTRL_C, "n", "n"])));
    expect(h.captured.stdout().match(/Sign in now\? \[Y\/n\]/g)?.length).toBe(2);
    expect(h.signIn).not.toHaveBeenCalled();
  });

  it("through the menu, a confirmed Ctrl+C at the first question exits 130", async () => {
    const { head } = project();
    const h = harness(notInstalled(head));
    h.captured.stdin.setRawMode = () => undefined;
    const running = main([], h.captured.io, { deps: h.deps, interrupts: noInterrupts });
    const press = async (sequence: string): Promise<void> => {
      await new Promise((resolve) => setTimeout(resolve, 150));
      h.captured.stdin.write(sequence);
    };
    await press("\u0003");
    await press("y");
    expect(await running).toBe(130);
    expect(h.signIn).not.toHaveBeenCalled();
  });

  it("through the menu, declining the sign-in still opens the menu", async () => {
    const { head } = project();
    const h = harness(notInstalled(head));
    h.captured.stdin.setRawMode = () => undefined;
    const running = main([], h.captured.io, { deps: h.deps, interrupts: noInterrupts });
    const press = async (sequence: string): Promise<void> => {
      await new Promise((resolve) => setTimeout(resolve, 150));
      h.captured.stdin.write(sequence);
    };
    await press("n");
    await press("\u001b"); // Esc on the menu = quit
    expect(await running).toBe(0);
    expect(h.captured.stdout()).toContain("Sign in now? [Y/n]");
    expect(h.captured.stdout()).toContain("Verify project");
  });
});

describe("no terminal: fail fast instead of starting the device flow (#296)", () => {
  function noTerminal(
    store: CredentialStore,
    options: { dir?: string } = {},
  ): { deps: CliDeps; fetchCalls: string[]; deviceCodeRequests: () => number } {
    const fetchCalls: string[] = [];
    const deps = createTestDeps({
      findGitRoot: async () => fixture?.root ?? null,
      credentialStore: store,
      verifyProject: realVerify,
      runScan: realRunScan,
      openResultStore: () =>
        options.dir === undefined ? null : createResultStore({ dir: options.dir }),
      createSessionProvider: (providerOptions) =>
        createDeviceFlowSessionProvider({
          ...providerOptions,
          clientId: DEFAULT_GITHUB_APP_CLIENT_ID,
          credentialStore: store,
          fetch: async (url) => {
            fetchCalls.push(url);
            throw new Error("network access is not allowed in this test");
          },
          sleep: async () => {},
        }),
    });
    return {
      deps,
      fetchCalls,
      deviceCodeRequests: () => fetchCalls.filter((url) => url.includes("/login/")).length,
    };
  }

  /** stdin from /dev/null, stdout and stderr redirected: nothing is a terminal. */
  function redirected(cwd: string): CapturedIo {
    const captured = createTestIo({ isTTY: false, cwd, env: {} });
    captured.io.stdin = fs.createReadStream(os.devNull);
    return captured;
  }

  const stores: Array<[string, () => CredentialStore]> = [
    ["an empty keychain", () => createInMemoryCredentialStore()],
    ["a locked or missing keychain", () => createUnavailableCredentialStore("locked")],
  ];
  const REASON = "Run `pgard login` in a terminal first";

  describe.each(stores)("with %s", (_name, makeStore) => {
    const formats: Array<[string, string[]]> = [
      ["scan (text)", ["scan", "code"]],
      ["scan history (text)", ["scan", "history"]],
      ["scan all with a port (text)", ["scan", "all", "--port", "3000"]],
      ["scan --format json", ["scan", "code", "--format", "json"]],
      ["scan all --format json", ["scan", "all", "--port", "3000", "--format", "json"]],
      ["scan --format sarif", ["scan", "code", "--format", "sarif"]],
      ["project verify", ["project", "verify"]],
      ["baseline show", ["baseline", "show"]],
    ];

    it.each(formats)("%s exits 3 quickly with a blocked result", async (name, argv) => {
      const { head } = project();
      void head;
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pgard-first-run-"));
      tempDirs.push(dir);
      const run = noTerminal(makeStore(), { dir });
      const captured = redirected(fixture?.root ?? "/");
      const started = Date.now();
      const exitCode = await main(argv, captured.io, { deps: run.deps, interrupts: noInterrupts });
      expect(Date.now() - started).toBeLessThan(1000 * TIME_FACTOR);
      expect(exitCode).toBe(3);
      // The device flow was never requested, and GitHub was not contacted at all.
      expect(run.deviceCodeRequests()).toBe(0);
      expect(run.fetchCalls).toEqual([]);
      expect(captured.stderr()).not.toContain("Enter the code");
      expect(captured.stderr()).not.toContain("Waiting for approval");

      if (name.includes("json")) {
        const result = JSON.parse(captured.stdout()) as {
          overallStatus: string;
          authorization: {
            decision: string;
            checks: Array<{ id: string; status: string; reason: string }>;
          };
        };
        expect(result.overallStatus).toBe("blocked");
        expect(result.authorization.decision).toBe("blocked");
        expect(result.authorization.checks.map((check) => check.id)).toEqual(FIVE_CHECKS);
        const identity = result.authorization.checks.find(
          (check) => check.id === "github_identity",
        );
        expect(identity?.status).toBe("unverifiable");
        expect(identity?.reason).toContain("Not signed in");
        expect(identity?.reason).toContain(REASON);
      } else if (name.includes("sarif")) {
        const sarif = JSON.parse(captured.stdout()) as { version: string; runs: unknown[] };
        expect(sarif.version).toBe("2.1.0");
        expect(sarif.runs).toHaveLength(1);
        expect(captured.stderr()).toContain("Do not upload this SARIF: the scan did not run.");
      } else {
        expect(captured.stdout()).toContain("Not signed in");
        expect(captured.stdout()).toContain(REASON);
      }
    });
  });

  it("only stderr redirected (stdin is a terminal) also fails fast with valid JSON", async () => {
    project();
    const run = noTerminal(createInMemoryCredentialStore());
    const captured = createTestIo({ isTTY: true, cwd: fixture?.root ?? "/", env: {} });
    (captured.io.stdout as { isTTY?: boolean }).isTTY = false;
    (captured.io.stderr as { isTTY?: boolean }).isTTY = false;
    const exitCode = await main(["scan", "code", "--format", "json"], captured.io, {
      deps: run.deps,
      interrupts: noInterrupts,
    });
    expect(exitCode).toBe(3);
    expect(run.fetchCalls).toEqual([]);
    expect(run.deviceCodeRequests()).toBe(0);
    expect((JSON.parse(captured.stdout()) as { overallStatus: string }).overallStatus).toBe(
      "blocked",
    );
  });

  it.each([
    ["text", [] as string[]],
    ["json", ["--format", "json"]],
    ["sarif", ["--format", "sarif"]],
  ])(
    "pgard scan code --code-only (%s): no fetch, no device code, no credential read",
    async (format, extra) => {
      project();
      const store = createInMemoryCredentialStore();
      const credentialReads: string[] = [];
      const spyStore: CredentialStore = {
        get: async (key) => {
          credentialReads.push(`get ${key.service}`);
          return store.get(key);
        },
        set: async (key, secret) => {
          credentialReads.push(`set ${key.service}`);
          return store.set(key, secret);
        },
        delete: async (key) => {
          credentialReads.push(`delete ${key.service}`);
          return store.delete(key);
        },
      };
      const run = noTerminal(spyStore);
      const verifyProject = vi.fn(realVerify);
      const deps = { ...run.deps, verifyProject, runCodeOnlyScan: realRunCodeOnlyScan };
      const captured = redirected(fixture?.root ?? "/");
      const exitCode = await main(["scan", "code", "--code-only", ...extra], captured.io, {
        deps,
        interrupts: noInterrupts,
      });
      expect(exitCode).toBe(0);
      expect(run.fetchCalls).toEqual([]);
      expect(run.deviceCodeRequests()).toBe(0);
      expect(networkCalls).toEqual([]);
      expect(credentialReads).toEqual([]);
      expect(verifyProject).not.toHaveBeenCalled();
      expect(captured.stderr()).not.toContain("Enter the code");
      if (format === "json") {
        const result = JSON.parse(captured.stdout()) as { scanBasis?: { mode: string } };
        expect(result.scanBasis?.mode).toBe("code_only");
      } else if (format === "sarif") {
        const sarif = JSON.parse(captured.stdout()) as {
          runs: Array<{ automationDetails?: { id?: string } }>;
        };
        expect(sarif.runs[0]?.automationDetails?.id).toBe("pgard/code-only/");
      } else {
        expect(captured.stdout()).toContain("Code-only scan: authorization not verified");
      }
    },
  );

  it("the default pgard precommit runs code-only: no fetch, no device code, no credential read", async () => {
    project();
    const root = fixture?.root ?? "/";
    fixture?.writeFile("src/config.ts", `export const token = "${"ghp_"}${"a".repeat(36)}";\n`);
    fixture?.writeFile("README.md", "notes\n");
    fixture?.git("add", "src/config.ts", "README.md");
    const store = createInMemoryCredentialStore();
    const credentialCalls: string[] = [];
    const spyStore: CredentialStore = {
      get: async (key) => {
        credentialCalls.push(`get ${key.service}`);
        return store.get(key);
      },
      set: async (key, secret) => {
        credentialCalls.push(`set ${key.service}`);
        return store.set(key, secret);
      },
      delete: async (key) => {
        credentialCalls.push(`delete ${key.service}`);
        return store.delete(key);
      },
    };
    const run = noTerminal(spyStore);
    const verifyProject = vi.fn(realVerify);
    const runScan = vi.fn(realRunScan);
    const deps = {
      ...run.deps,
      verifyProject,
      runScan,
      runCodeOnlyScan: realRunCodeOnlyScan,
    };
    const captured = createTestIo({ isTTY: false, cwd: root, env: { PGARD_NO_STORE: "1" } });
    captured.io.stdin = fs.createReadStream(os.devNull);
    const exitCode = await main(["precommit"], captured.io, { deps, interrupts: noInterrupts });
    // The staged secret is found and blocks the commit; nothing about GitHub was touched.
    expect(exitCode).toBe(1);
    expect(captured.stdout()).toContain("PG-SECRET-002 src/config.ts:1");
    expect(captured.stderr()).toContain("code-only, authorization not verified");
    expect(run.fetchCalls).toEqual([]);
    expect(run.deviceCodeRequests()).toBe(0);
    expect(networkCalls).toEqual([]);
    expect(credentialCalls).toEqual([]);
    expect(verifyProject).not.toHaveBeenCalled();
    expect(runScan).not.toHaveBeenCalled();
  });

  it.each([["scan"], ["scan", "code"]])(
    "pgard %s without a terminal stays blocked: exit 3, the --code-only hint, never code-only",
    async (...argv) => {
      project();
      const run = noTerminal(createInMemoryCredentialStore());
      const runCodeOnlyScan = vi.fn(realRunCodeOnlyScan);
      const captured = redirected(fixture?.root ?? "/");
      const exitCode = await main(argv, captured.io, {
        deps: { ...run.deps, runCodeOnlyScan },
        interrupts: noInterrupts,
      });
      expect(exitCode).toBe(3);
      expect(runCodeOnlyScan).not.toHaveBeenCalled();
      expect(captured.stdout() + captured.stderr()).toContain(
        "For a code-only scan, add --code-only.",
      );
      expect(captured.stdout() + captured.stderr()).not.toContain("[y/N]");
    },
  );

  it("pgard login refuses without a terminal (usage error, exit 2) and requests nothing", async () => {
    project();
    const run = noTerminal(createInMemoryCredentialStore());
    run.deps.signInAndStore = vi.fn() as never;
    const captured = redirected(fixture?.root ?? "/");
    const exitCode = await main(["login"], captured.io, {
      deps: run.deps,
      interrupts: noInterrupts,
    });
    expect(exitCode).toBe(2);
    expect(run.deps.signInAndStore).not.toHaveBeenCalled();
    expect(run.fetchCalls).toEqual([]);
    expect(captured.stderr()).toContain("`pgard login` needs a terminal");
  });

  it("a terminal on stdin and stderr behaves as before: the device flow is requested", async () => {
    project();
    const run = noTerminal(createInMemoryCredentialStore());
    const captured = createTestIo({ isTTY: true, cwd: fixture?.root ?? "/", env: {} });
    // stdout redirected, stdin and stderr are terminals.
    (captured.io.stdout as { isTTY?: boolean }).isTTY = false;
    const exitCode = await main(["scan", "code", "--format", "json"], captured.io, {
      deps: run.deps,
      interrupts: noInterrupts,
    });
    expect(exitCode).toBe(3);
    expect(run.deviceCodeRequests()).toBe(1);
    expect(run.fetchCalls[0]).toContain("/login/device/code");
  });
});
