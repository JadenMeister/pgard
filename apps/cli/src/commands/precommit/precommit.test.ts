import { execFileSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AuthorizationOutcome } from "@pgard/policy";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { scriptedKeys, testResult, type CapturedIo } from "../../test-support.js";

const authorizeProject =
  vi.fn<(root: string, deps: { signal?: AbortSignal }) => Promise<AuthorizationOutcome>>();

vi.mock("@pgard/policy", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@pgard/policy")>();
  return {
    ...actual,
    authorizeProject: (root: string, deps: { signal?: AbortSignal }) =>
      authorizeProject(root, deps),
  };
});

const { findGitRoot, runScan } = await import("@pgard/scan-core");
const { createTestContext, createTestDeps, createTestIo } = await import("../../test-support.js");
const { main } = await import("../../app.js");
const { EXIT_CODES } = await import("../../exit-codes.js");
const { HOOK_SCRIPT } = await import("./hook.js");
const precommit = await import("./index.js");

// Assembled at run time so this file holds no literal token.
const GITHUB_TOKEN = `ghp_${"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"}`;

const CHECKS = [
  "repository",
  "github_identity",
  "owner_approval",
  "current_access",
  "contribution",
] as const;
const ALLOWED: AuthorizationOutcome = {
  summary: {
    decision: "allowed",
    checks: CHECKS.map((id) => ({ id, status: "passed" as const, reason: "ok" })),
  },
  repo: "octo/app",
  repositoryId: 7,
  revision: "a".repeat(40),
};
const BLOCKED: AuthorizationOutcome = {
  summary: {
    decision: "blocked",
    checks: CHECKS.map((id) =>
      id === "owner_approval"
        ? { id, status: "unverifiable" as const, reason: "the App is not installed" }
        : { id, status: "passed" as const, reason: "ok" },
    ),
  },
  repo: "octo/app",
  revision: null,
};

const temps: string[] = [];
afterEach(() => {
  for (const dir of temps.splice(0)) {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  }
});
beforeEach(() => {
  authorizeProject.mockReset();
  authorizeProject.mockResolvedValue(ALLOWED);
});

function git(root: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH ?? "",
      HOME: root,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_TERMINAL_PROMPT: "0",
    },
  });
}

function makeRepo(files: Record<string, string> = { "README.md": "hello\n" }): string {
  const root = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-precommit-")));
  temps.push(root);
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "commit.gpgsign", "false");
  write(root, files);
  git(root, "add", "-A");
  git(root, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "init");
  return root;
}

function write(root: string, files: Record<string, string>): void {
  for (const [name, content] of Object.entries(files)) {
    const target = path.join(root, name);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
}

function setup(
  root: string,
  options: { env?: Record<string, string>; isTTY?: boolean; keys?: string[]; lang?: "ko" } = {},
) {
  const captured: CapturedIo = createTestIo({
    cwd: root,
    env: { PGARD_NO_STORE: "1", ...options.env },
    isTTY: options.isTTY ?? false,
  });
  const createSessionProvider = vi.fn(() =>
    Object.assign(async () => Promise.reject(new Error("no sign-in in tests")), {
      existing: async () => null,
      invalidate: () => undefined,
      signOut: async () => undefined,
    }),
  );
  const deps = createTestDeps({
    findGitRoot,
    runScan,
    createSessionProvider: createSessionProvider as never,
  });
  const context = {
    ...createTestContext(
      captured,
      deps,
      options.keys === undefined ? null : scriptedKeys(options.keys),
    ),
    ...(options.lang === undefined ? {} : { ruleLocale: options.lang }),
  };
  return { captured, context, createSessionProvider };
}

const SECRET_LINE = `const token = "${GITHUB_TOKEN}";\n`;

function stageSecret(root: string): void {
  write(root, { "src/secret.ts": SECRET_LINE });
  git(root, "add", "src/secret.ts");
}

describe("pgard precommit", () => {
  it("blocks a commit with a staged secret in block mode (the default), and never prints the value", async () => {
    const root = makeRepo();
    stageSecret(root);
    const { captured, context } = setup(root);
    const code = await precommit.runPrecommit(context);
    expect(code).toBe(EXIT_CODES.findings);
    const text = captured.stdout();
    expect(text).toContain("PG-SECRET-002");
    expect(text).toContain("src/secret.ts:1");
    expect(text).toContain("Commit BLOCKED");
    expect(text + captured.stderr()).not.toContain(GITHUB_TOKEN);
  });

  it("prints the findings and exits 0 in warn mode", async () => {
    const root = makeRepo();
    write(root, { "pgard.config.json": '{"version":1,"precommit":{"mode":"warn"}}' });
    stageSecret(root);
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.ok);
    expect(captured.stdout()).toContain("PG-SECRET-002");
    expect(captured.stdout()).toContain("Commit allowed (mode: warn)");
  });

  it("allows a clean commit and says it scanned", async () => {
    const root = makeRepo();
    write(root, { "docs.md": "no secrets here\n" });
    git(root, "add", "docs.md");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.ok);
    expect(captured.stdout()).toContain("Scanned 1 staged file(s)");
    expect(captured.stdout()).toContain("nothing found");
  });

  it("reads the staged content, not the working tree", async () => {
    const root = makeRepo();
    stageSecret(root);
    write(root, { "src/secret.ts": "const token = process.env.TOKEN;\n" });
    const staged = setup(root);
    expect(await precommit.runPrecommit(staged.context)).toBe(EXIT_CODES.findings);

    const other = makeRepo();
    write(other, { "src/secret.ts": SECRET_LINE });
    const unstaged = setup(other);
    expect(await precommit.runPrecommit(unstaged.context)).toBe(EXIT_CODES.ok);
    expect(unstaged.captured.stdout()).toContain("Scanned 0 staged file(s)");
  });

  it("scans the index git is committing when GIT_INDEX_FILE names a temporary one", async () => {
    const root = makeRepo();
    stageSecret(root);
    const lock = path.join(root, ".git", "next-index-1.lock");
    copyFileSync(path.join(root, ".git", "index"), lock);
    // The regular index changes afterwards: only the file git points at is the commit.
    git(root, "reset", "-q", "--", "src/secret.ts");
    const { context } = setup(root, { env: { GIT_INDEX_FILE: lock } });
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.findings);
    const regular = setup(root);
    expect(await precommit.runPrecommit(regular.context)).toBe(EXIT_CODES.ok);
  });

  it("refuses an index outside .git and says nothing was scanned", async () => {
    const root = makeRepo();
    stageSecret(root);
    const elsewhere = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-idx-")));
    temps.push(elsewhere);
    copyFileSync(path.join(root, ".git", "index"), path.join(elsewhere, "index"));
    const { captured, context } = setup(root, {
      env: { GIT_INDEX_FILE: path.join(elsewhere, "index") },
    });
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.partial);
    expect(captured.stderr()).toContain("NOT scanned");
    expect(authorizeProject).not.toHaveBeenCalled();
  });

  it("applies suppressions and ignores findings it must not count", async () => {
    const root = makeRepo();
    write(root, {
      "pgard.config.json": JSON.stringify({
        version: 1,
        suppressions: [{ ruleId: "PG-SECRET-002", path: "src/**", reason: "test fixture" }],
      }),
    });
    stageSecret(root);
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.ok);
    expect(captured.stdout()).toContain("1 suppressed");
    expect(captured.stdout()).not.toContain("PG-SECRET-002 ");
  });

  it("does not count findings that are in the baseline", async () => {
    const root = makeRepo();
    stageSecret(root);
    // First look at what the staged scan finds, then store exactly that as the baseline.
    const first = setup(root, { env: { PGARD_NO_STORE: "1" } });
    let captured: unknown = null;
    await runScan(
      { projectRoot: root, scopes: ["code"], webTarget: null },
      {
        authorization: { getGitHubSession: first.context.deps.createSessionProvider as never },
        analyzers: {
          code: async (analyzerContext) => {
            const { createStagedAnalyzer } = await import("@pgard/scan-core");
            const output = await createStagedAnalyzer()(analyzerContext);
            captured = output.findings;
            return output;
          },
        },
      },
    );
    const baselineResult = testResult({ findings: captured as never, requestedScopes: ["code"] });
    const run = setup(root, { env: { PGARD_NO_STORE: "0" } });
    const withStore = {
      ...run.context,
      deps: {
        ...run.context.deps,
        openResultStore: () =>
          ({
            getBaseline: async () => ({
              ok: true,
              baseline: {
                sourceVersion: baselineResult.schemaVersion,
                result: baselineResult,
                setAt: new Date("2026-10-01T00:00:00Z"),
              },
            }),
          }) as never,
      },
    };
    expect(await precommit.runPrecommit(withStore)).toBe(EXIT_CODES.ok);
    expect(run.captured.stdout()).toContain("1 in the baseline");
  });

  describe("when nothing could be scanned", () => {
    it("blocks in block mode, with the five checks shown", async () => {
      authorizeProject.mockResolvedValue(BLOCKED);
      const root = makeRepo();
      stageSecret(root);
      const { captured, context } = setup(root);
      expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.blocked);
      const all = captured.stdout() + captured.stderr();
      expect(all).toContain("NOT scanned");
      expect(all).toContain("not authorized");
      expect(all).toContain("the App is not installed");
      expect(all).toContain("Commit BLOCKED");
      expect(all).not.toContain("PG-SECRET-002");
    });

    it("exits 0 in warn mode, but plainly says nothing was scanned", async () => {
      authorizeProject.mockResolvedValue(BLOCKED);
      const root = makeRepo();
      write(root, { "pgard.config.json": '{"version":1,"precommit":{"mode":"warn"}}' });
      stageSecret(root);
      const { captured, context } = setup(root);
      expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.ok);
      const all = captured.stdout() + captured.stderr();
      expect(all).toContain("NOT scanned");
      expect(all).toContain("WARNING: commit allowed");
      expect(all).not.toContain("nothing found");
    });

    it("follows whenNotScanned when it is configured explicitly", async () => {
      authorizeProject.mockResolvedValue(BLOCKED);
      const root = makeRepo();
      write(root, {
        "pgard.config.json": '{"version":1,"precommit":{"mode":"block","whenNotScanned":"warn"}}',
      });
      stageSecret(root);
      const lenient = setup(root);
      expect(await precommit.runPrecommit(lenient.context)).toBe(EXIT_CODES.ok);
      expect(lenient.captured.stdout()).toContain("WARNING");

      write(root, {
        "pgard.config.json": '{"version":1,"precommit":{"mode":"warn","whenNotScanned":"block"}}',
      });
      const strict = setup(root);
      expect(await precommit.runPrecommit(strict.context)).toBe(EXIT_CODES.blocked);
    });

    it("never starts a sign-in from a hook", async () => {
      const root = makeRepo();
      const { context, createSessionProvider } = setup(root, { isTTY: true, keys: [] });
      await precommit.runPrecommit(context);
      expect(createSessionProvider).toHaveBeenCalledWith(
        expect.objectContaining({ canSignInInteractively: false }),
      );
    });

    it("treats a timed-out authorization as not scanned", async () => {
      authorizeProject.mockImplementation(
        (_root, deps) =>
          new Promise((_resolve, reject) => {
            deps.signal?.addEventListener("abort", () => reject(new Error("aborted")), {
              once: true,
            });
          }),
      );
      const root = makeRepo();
      stageSecret(root);
      const { captured, context } = setup(root);
      const code = await precommit.runPrecommit(context, { authTimeoutMs: 50 });
      expect(code).toBe(EXIT_CODES.blocked);
      expect(captured.stderr()).toContain("did not finish within");
      expect(captured.stderr()).toContain("NOT scanned");
    });

    it("treats an authorization error as not scanned", async () => {
      authorizeProject.mockRejectedValue(new Error("boom"));
      const root = makeRepo();
      stageSecret(root);
      const { captured, context } = setup(root);
      expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.partial);
      expect(captured.stderr()).toContain("NOT scanned");
    });

    it("an invalid config means block, and says why", async () => {
      const root = makeRepo();
      write(root, { "pgard.config.json": '{"version":1,"precommit":{"mode":"off"}}' });
      stageSecret(root);
      const { captured, context } = setup(root);
      expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.findings);
      expect(captured.stderr()).toContain("pgard.config.json is invalid");
    });

    it("is not a pass outside a Git repository", async () => {
      const dir = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-norepo-")));
      temps.push(dir);
      const { captured, context } = setup(dir);
      expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.blocked);
      expect(captured.stderr()).toContain("not inside a Git repository");
    });
  });

  it("says a file over the size limit was not scanned, and blocks on it in block mode", async () => {
    const root = makeRepo();
    write(root, { "big.txt": "x".repeat(2 * 1024 * 1024) });
    git(root, "add", "big.txt");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.partial);
    const text = captured.stdout();
    expect(text).toContain("Not everything was scanned");
    expect(text).toContain("big.txt");
    expect(text).toContain("size limit");
  });

  it("handles renames and deletions without scanning old content again", async () => {
    const root = makeRepo({ "old.ts": SECRET_LINE, "gone.ts": SECRET_LINE });
    git(root, "mv", "old.ts", "new.ts");
    git(root, "rm", "-q", "gone.ts");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.ok);
    expect(captured.stdout()).toContain("Scanned 1 staged file(s)");
  });

  it("skips binary files by design and does not call that unscanned", async () => {
    const root = makeRepo();
    writeFileSync(path.join(root, "pic.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 1]));
    git(root, "add", "pic.png");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.ok);
    expect(captured.stdout()).not.toContain("Not everything was scanned");
  });

  it("speaks Korean with --lang ko / ruleLocale ko", async () => {
    authorizeProject.mockResolvedValue(BLOCKED);
    const root = makeRepo();
    const { captured, context } = setup(root, { lang: "ko" });
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.blocked);
    expect(captured.stderr() + captured.stdout()).toMatch(/검사하지 못했습니다/);
  });

  it("runs through main() as pgard precommit (language, exit code)", async () => {
    const root = makeRepo();
    stageSecret(root);
    const captured = createTestIo({ cwd: root, env: { PGARD_NO_STORE: "1", PGARD_LANG: "en" } });
    const deps = createTestDeps({ findGitRoot, runScan });
    expect(await main(["precommit"], captured.io, { deps })).toBe(EXIT_CODES.findings);
    expect(captured.stdout()).toContain("PG-SECRET-002");
  });
});

describe("pgard precommit install / uninstall", () => {
  const hookPath = (root: string) => path.join(root, ".git", "hooks", "pre-commit");

  it("installs an executable hook that only runs pgard precommit, and is idempotent", async () => {
    const root = makeRepo();
    const first = setup(root);
    expect(await precommit.runPrecommitInstall(first.context)).toBe(EXIT_CODES.ok);
    expect(readFileSync(hookPath(root), "utf8")).toBe(HOOK_SCRIPT);
    if (process.platform !== "win32") {
      expect(statSync(hookPath(root)).mode & 0o777).toBe(0o755);
    }
    expect(first.captured.stdout()).toContain("Installed the pre-commit hook");
    const again = setup(root);
    expect(await precommit.runPrecommitInstall(again.context)).toBe(EXIT_CODES.ok);
    expect(again.captured.stdout()).toContain("already installed");
  });

  it("refuses to replace a hook PGARD did not write without a terminal", async () => {
    const root = makeRepo();
    mkdirSync(path.join(root, ".git", "hooks"), { recursive: true });
    writeFileSync(hookPath(root), "#!/bin/sh\necho mine\n");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommitInstall(context)).toBe(EXIT_CODES.usage);
    expect(readFileSync(hookPath(root), "utf8")).toBe("#!/bin/sh\necho mine\n");
    expect(captured.stderr()).toContain("Without a terminal");
    expect(
      readdirSync(path.join(root, ".git", "hooks")).filter((name) => name.includes("backup")),
    ).toEqual([]);
  });

  it("asks before replacing, keeps the old hook as a backup, and 'n' changes nothing", async () => {
    const root = makeRepo();
    mkdirSync(path.join(root, ".git", "hooks"), { recursive: true });
    writeFileSync(hookPath(root), "#!/bin/sh\necho mine\n");
    const declined = setup(root, { isTTY: true, keys: ["n"] });
    expect(await precommit.runPrecommitInstall(declined.context)).toBe(EXIT_CODES.ok);
    expect(readFileSync(hookPath(root), "utf8")).toBe("#!/bin/sh\necho mine\n");
    expect(declined.captured.stdout()).toContain("unchanged");

    const accepted = setup(root, { isTTY: true, keys: ["y"] });
    expect(await precommit.runPrecommitInstall(accepted.context)).toBe(EXIT_CODES.ok);
    expect(readFileSync(hookPath(root), "utf8")).toBe(HOOK_SCRIPT);
    expect(readFileSync(`${hookPath(root)}.pgard-backup`, "utf8")).toBe("#!/bin/sh\necho mine\n");
    expect(accepted.captured.stdout()).toContain("kept as");
  });

  it("treats a PGARD hook that was edited afterwards as somebody else's", async () => {
    const root = makeRepo();
    mkdirSync(path.join(root, ".git", "hooks"), { recursive: true });
    const edited = `${HOOK_SCRIPT}echo extra\n`;
    writeFileSync(hookPath(root), edited);
    const { context } = setup(root);
    expect(await precommit.runPrecommitInstall(context)).toBe(EXIT_CODES.usage);
    expect(readFileSync(hookPath(root), "utf8")).toBe(edited);
  });

  it.skipIf(process.platform === "win32")(
    "never writes through a symlinked hook: the link is moved aside, its target untouched",
    async () => {
      const root = makeRepo();
      const elsewhere = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-target-")));
      temps.push(elsewhere);
      writeFileSync(path.join(elsewhere, "real-hook"), "#!/bin/sh\necho other\n");
      mkdirSync(path.join(root, ".git", "hooks"), { recursive: true });
      symlinkSync(path.join(elsewhere, "real-hook"), hookPath(root));
      const refused = setup(root);
      expect(await precommit.runPrecommitInstall(refused.context)).toBe(EXIT_CODES.usage);
      const accepted = setup(root, { isTTY: true, keys: ["y"] });
      expect(await precommit.runPrecommitInstall(accepted.context)).toBe(EXIT_CODES.ok);
      expect(readFileSync(path.join(elsewhere, "real-hook"), "utf8")).toBe(
        "#!/bin/sh\necho other\n",
      );
      expect(readFileSync(hookPath(root), "utf8")).toBe(HOOK_SCRIPT);
    },
  );

  it("refuses core.hooksPath outside the repository and writes nothing there", async () => {
    const root = makeRepo();
    const elsewhere = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-hooks-")));
    temps.push(elsewhere);
    git(root, "config", "core.hooksPath", elsewhere);
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommitInstall(context)).toBe(EXIT_CODES.usage);
    expect(readdirSync(elsewhere)).toEqual([]);
    expect(existsSync(hookPath(root))).toBe(false);
    expect(captured.stderr()).toContain("outside the repository");
  });

  it("refuses core.hooksPath inside the repository too, and points to the snippet", async () => {
    const root = makeRepo();
    mkdirSync(path.join(root, ".husky"));
    git(root, "config", "core.hooksPath", ".husky");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommitInstall(context)).toBe(EXIT_CODES.usage);
    expect(readdirSync(path.join(root, ".husky"))).toEqual([]);
    expect(captured.stderr()).toContain("pgard precommit snippet");
  });

  it.skipIf(process.platform === "win32")(
    "refuses a hooks directory that is a symlink out of the repository",
    async () => {
      const root = makeRepo();
      const elsewhere = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-hooks-")));
      temps.push(elsewhere);
      rmSync(path.join(root, ".git", "hooks"), { recursive: true, force: true });
      symlinkSync(elsewhere, path.join(root, ".git", "hooks"));
      const { captured, context } = setup(root);
      expect(await precommit.runPrecommitInstall(context)).toBe(EXIT_CODES.usage);
      expect(readdirSync(elsewhere)).toEqual([]);
      expect(captured.stderr()).toContain("symbolic link");
    },
  );

  it("uninstall removes only a hook PGARD wrote", async () => {
    const root = makeRepo();
    const install = setup(root);
    await precommit.runPrecommitInstall(install.context);
    const removed = setup(root);
    expect(await precommit.runPrecommitUninstall(removed.context)).toBe(EXIT_CODES.ok);
    expect(existsSync(hookPath(root))).toBe(false);
    expect(removed.captured.stdout()).toContain("Removed");

    const none = setup(root);
    expect(await precommit.runPrecommitUninstall(none.context)).toBe(EXIT_CODES.ok);
    expect(none.captured.stdout()).toContain("No pre-commit hook is installed");

    writeFileSync(hookPath(root), "#!/bin/sh\necho mine\n");
    const foreign = setup(root);
    expect(await precommit.runPrecommitUninstall(foreign.context)).toBe(EXIT_CODES.ok);
    expect(readFileSync(hookPath(root), "utf8")).toBe("#!/bin/sh\necho mine\n");
    expect(foreign.captured.stdout()).toContain("not written by PGARD");

    // A PGARD hook that was edited afterwards is left alone too.
    writeFileSync(hookPath(root), `${HOOK_SCRIPT}echo extra\n`);
    const edited = setup(root);
    await precommit.runPrecommitUninstall(edited.context);
    expect(existsSync(hookPath(root))).toBe(true);
  });

  it.skipIf(process.platform === "win32")(
    "uninstall leaves a symlink named pre-commit alone",
    async () => {
      const root = makeRepo();
      const elsewhere = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-target-")));
      temps.push(elsewhere);
      writeFileSync(path.join(elsewhere, "hook"), HOOK_SCRIPT);
      mkdirSync(path.join(root, ".git", "hooks"), { recursive: true });
      symlinkSync(path.join(elsewhere, "hook"), hookPath(root));
      const { context } = setup(root);
      await precommit.runPrecommitUninstall(context);
      expect(existsSync(path.join(elsewhere, "hook"))).toBe(true);
      expect(existsSync(hookPath(root))).toBe(true);
    },
  );

  it("uninstall mentions a kept backup", async () => {
    const root = makeRepo();
    mkdirSync(path.join(root, ".git", "hooks"), { recursive: true });
    writeFileSync(hookPath(root), "#!/bin/sh\necho mine\n");
    await precommit.runPrecommitInstall(setup(root, { isTTY: true, keys: ["y"] }).context);
    const { captured, context } = setup(root);
    await precommit.runPrecommitUninstall(context);
    expect(captured.stdout()).toContain("pre-commit.pgard-backup");
  });

  it("snippet prints framework and husky lines and writes nothing", () => {
    const root = makeRepo();
    const { captured, context } = setup(root);
    expect(precommit.runPrecommitSnippet(context)).toBe(EXIT_CODES.ok);
    expect(captured.stdout()).toContain("entry: pgard precommit");
    expect(captured.stdout()).toContain(".husky/pre-commit");
    expect(existsSync(hookPath(root))).toBe(false);
  });
});

describe.skipIf(process.platform === "win32")("the installed hook inside git", () => {
  /** A `pgard` on PATH that records its arguments and exits with `exitCode`. */
  function fakePgard(exitCode: number): { bin: string; log: string } {
    const bin = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-bin-")));
    temps.push(bin);
    const log = path.join(bin, "log");
    writeFileSync(
      path.join(bin, "pgard"),
      `#!/bin/sh\necho "$@ idx=$GIT_INDEX_FILE" >> "${log}"\nexit ${exitCode}\n`,
    );
    chmodSync(path.join(bin, "pgard"), 0o755);
    return { bin, log };
  }

  function commit(root: string, pathEnv: string): { ok: boolean } {
    try {
      execFileSync(
        "git",
        ["-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qam", "change"],
        {
          cwd: root,
          env: {
            PATH: pathEnv,
            HOME: root,
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_CONFIG_GLOBAL: "/dev/null",
          },
          stdio: "pipe",
        },
      );
      return { ok: true };
    } catch {
      return { ok: false };
    }
  }

  it("blocks the commit when pgard precommit fails, and lets it through when it passes", async () => {
    const root = makeRepo({ "a.txt": "one\n" });
    await precommit.runPrecommitInstall(setup(root).context);
    write(root, { "a.txt": "two\n" });
    const failing = fakePgard(1);
    expect(commit(root, `${failing.bin}:/usr/bin:/bin`).ok).toBe(false);
    expect(readFileSync(failing.log, "utf8")).toContain("precommit");
    const passing = fakePgard(0);
    expect(commit(root, `${passing.bin}:/usr/bin:/bin`).ok).toBe(true);
    // `git commit -a` hands the hook a temporary index; the real hook sees it in its environment.
    expect(readFileSync(passing.log, "utf8")).toContain("index.lock");
  });

  it("fails closed when pgard is not on PATH", async () => {
    const root = makeRepo({ "a.txt": "one\n" });
    await precommit.runPrecommitInstall(setup(root).context);
    write(root, { "a.txt": "two\n" });
    expect(commit(root, "/usr/bin:/bin").ok).toBe(false);
  });
});

describe("hook helpers", () => {
  it("moves a leftover temporary file out of the way only by exclusive creation", async () => {
    const { installHook } = await import("./hook.js");
    const dir = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-hookdir-")));
    temps.push(dir);
    const result = await installHook(path.join(dir, "hooks"), { confirmReplace: null });
    expect(result.kind).toBe("installed");
    expect(readdirSync(path.join(dir, "hooks"))).toEqual(["pre-commit"]);
  });
});
