import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { readScanResult, type ScanResult } from "@pgard/findings";
import { runCodeOnlyScan } from "@pgard/scan-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { main } from "../../app.js";
import { EXIT_CODES } from "../../exit-codes.js";
import { parseCommandLine, UsageError } from "../../options.js";
import {
  BLOCKED,
  codeOnlyTestResult,
  createTestContext,
  createTestDeps,
  createTestIo,
  noInterrupts,
  scriptedKeys,
  testResult,
} from "../../test-support.js";
import { codeOnlyFolderRefusal, codeOnlyHome } from "./code-only.js";
import { runScanCommand } from "./index.js";

/** `pgard scan code` without approval (#414 phase 2: D1, D2, D4). */

const CODE = { variant: "code", port: null, report: null, codeOnly: true } as const;
const BLOCKED_RESULT = (reasonOverrides: Partial<ScanResult> = {}): ScanResult =>
  testResult({
    overallStatus: "blocked",
    authorization: BLOCKED,
    findings: [],
    coverage: [],
    scanBasis: { mode: "authorized", authorization: "not_verified", reason: "no_approval" },
    ...reasonOverrides,
  });
// The AWS documentation key with its last letter changed (EXAMPLE itself reads as a placeholder).
const FAKE_KEY = `${"AKIA"}IOSFODNN7EXAMPLQ`;

const unexpected = (name: string) =>
  vi.fn(() => {
    throw new Error(`unexpected call: ${name}`);
  });

let dir: string | null = null;
/** One temporary folder per test, removed afterwards. */
async function temp(): Promise<string> {
  dir = await mkdtemp(path.join(os.tmpdir(), "pgard-cli-codeonly-folder-"));
  return dir;
}

afterEach(async () => {
  if (dir !== null) await rm(dir, { recursive: true, force: true });
  dir = null;
});

describe("pgard scan code --code-only is a code-only scan (D1)", () => {
  it("never runs the gate, signs in or stores, and says so first", async () => {
    const runScan = unexpected("runScan");
    const verifyProject = unexpected("verifyProject");
    const openResultStore = unexpected("openResultStore");
    const runCode = vi.fn(async () => codeOnlyTestResult());
    const captured = createTestIo();
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          runScan: runScan as never,
          verifyProject: verifyProject as never,
          openResultStore: openResultStore as never,
          runCodeOnlyScan: runCode,
        }),
      ),
      CODE,
    );
    expect(code).toBe(EXIT_CODES.ok);
    expect(runScan).not.toHaveBeenCalled();
    expect(verifyProject).not.toHaveBeenCalled();
    expect(openResultStore).not.toHaveBeenCalled();
    expect(runCode).toHaveBeenCalledWith(
      { projectRoot: "/work/repo", reason: "not_checked" },
      expect.anything(),
    );
    const text = captured.stdout();
    expect(text.split("\n")[1]).toBe(
      "! Code-only scan: authorization not verified (current files only; no Git history, no web checks, not saved).",
    );
    expect(text).toContain("run `pgard scan` (GitHub sign-in and owner approval)");
    expect(text).not.toContain("Authorization: blocked");
  });

  it("exits 4 for partial code coverage and never 3", async () => {
    const captured = createTestIo();
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          runCodeOnlyScan: async () => codeOnlyTestResult({ overallStatus: "partial" }),
        }),
      ),
      CODE,
    );
    expect(code).toBe(EXIT_CODES.partial);
  });

  it("speaks Korean with --lang ko", async () => {
    const captured = createTestIo();
    await runScanCommand(
      { ...createTestContext(captured, createTestDeps()), ruleLocale: "ko" },
      CODE,
    );
    expect(captured.stdout()).toContain("! 코드 전용 검사: 권한 미확인");
  });

  it("parses --code-only for scan and scan code only; scan --code-only is scan code", () => {
    expect(parseCommandLine(["scan", "code", "--code-only"])).toMatchObject({
      kind: "scan",
      variant: "code",
      codeOnly: true,
    });
    expect(parseCommandLine(["scan", "--code-only"])).toMatchObject({
      variant: "code",
      codeOnly: true,
    });
    expect(parseCommandLine(["scan", "code"])).not.toHaveProperty("codeOnly");
    for (const argv of [
      ["scan", "history", "--code-only"],
      ["scan", "all", "--code-only"],
      ["scan", "web", "--port", "3000", "--code-only"],
      ["project", "verify", "--code-only"],
      ["scan", "code", "--require-authorization"],
    ]) {
      expect(() => parseCommandLine(argv)).toThrow(UsageError);
    }
  });
});

describe("authorization first, then a y/N question (D1)", () => {
  const blockedDeps = (runCode: ReturnType<typeof vi.fn>, result = BLOCKED_RESULT()) =>
    createTestDeps({
      runCodeOnlyScan: runCode as never,
      runScan: async () => result,
    });

  it("a terminal and N (the default) exits 3 with the approval guidance", async () => {
    const runCode = unexpected("runCodeOnlyScan");
    const captured = createTestIo({ isTTY: true });
    const code = await runScanCommand(
      createTestContext(captured, blockedDeps(runCode), scriptedKeys(["return"])),
      { variant: "code", port: null, report: null },
    );
    expect(code).toBe(EXIT_CODES.blocked);
    expect(runCode).not.toHaveBeenCalled();
    const text = captured.stdout();
    expect(text).toContain(
      "Skip Git history and scan only the current code? (marked as not authorized) [y/N] N",
    );
    expect(text).toContain("GitHub sign-in was denied.");
    expect(text).not.toContain("--code-only");
  });

  it("a terminal and y runs the code-only scan with the gate's reason", async () => {
    const runCode = vi.fn(async () => codeOnlyTestResult());
    const captured = createTestIo({ isTTY: true });
    const code = await runScanCommand(
      createTestContext(captured, blockedDeps(runCode), scriptedKeys(["y"])),
      { variant: "default", port: null, report: null },
    );
    expect(code).toBe(EXIT_CODES.ok);
    expect(runCode).toHaveBeenCalledWith(
      { projectRoot: "/work/repo", reason: "no_approval" },
      expect.anything(),
    );
    expect(captured.stdout()).toContain("! Code-only scan: authorization not verified");
  });

  it("asks in Korean", async () => {
    const captured = createTestIo({ isTTY: true });
    await runScanCommand(
      {
        ...createTestContext(
          captured,
          blockedDeps(unexpected("runCodeOnlyScan")),
          scriptedKeys(["n"]),
        ),
        ruleLocale: "ko",
      },
      { variant: "code", port: null, report: null },
    );
    expect(captured.stdout()).toContain(
      "Git 기록은 빼고 현재 코드만 검사할까요? (권한 미확인으로 표시됩니다) [y/N]",
    );
  });

  it("names no_github_remote and check_failed as the reason", async () => {
    const noRemote = BLOCKED_RESULT({
      authorization: {
        decision: "blocked",
        checks: [
          {
            id: "repository",
            status: "failed",
            reason: "No GitHub remote: add a github.com remote.",
          },
        ],
      } as never,
    });
    const runCode = vi.fn(async () => codeOnlyTestResult());
    await runScanCommand(
      createTestContext(
        createTestIo({ isTTY: true }),
        blockedDeps(runCode, noRemote),
        scriptedKeys(["y"]),
      ),
      { variant: "code", port: null, report: null },
    );
    expect(runCode).toHaveBeenCalledWith(
      { projectRoot: "/work/repo", reason: "no_github_remote" },
      expect.anything(),
    );
    const failed = BLOCKED_RESULT({
      overallStatus: "failed",
      scanBasis: { mode: "authorized", authorization: "not_verified", reason: "check_failed" },
    });
    const runCodeAfterFailure = vi.fn(async () => codeOnlyTestResult());
    await runScanCommand(
      createTestContext(
        createTestIo({ isTTY: true }),
        blockedDeps(runCodeAfterFailure, failed),
        scriptedKeys(["y"]),
      ),
      { variant: "code", port: null, report: null },
    );
    expect(runCodeAfterFailure).toHaveBeenCalledWith(
      { projectRoot: "/work/repo", reason: "check_failed" },
      expect.anything(),
    );
  });

  it("outside a Git repository asks too, and y scans the folder as it is", async () => {
    const folder = await temp();
    const runCode = vi.fn(async () => codeOnlyTestResult());
    const captured = createTestIo({ isTTY: true, cwd: folder });
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({ findGitRoot: async () => null, runCodeOnlyScan: runCode }),
        scriptedKeys(["y"]),
      ),
      { variant: "code", port: null, report: null },
    );
    expect(code).toBe(EXIT_CODES.ok);
    expect(runCode).toHaveBeenCalledWith(
      { projectRoot: path.resolve(folder), reason: "not_a_git_repository" },
      expect.anything(),
    );
  });

  it.each([
    ["text to a pipe", "text"],
    ["--format json to a pipe", "json"],
    ["--format sarif to a pipe", "sarif"],
  ] as const)(
    "without a terminal (%s) it never asks, exits 3 and hints --code-only",
    async (_name, format) => {
      const runCode = unexpected("runCodeOnlyScan");
      // Keys exist (stdin is a terminal) but stdout is a pipe: still no question.
      const captured = createTestIo({ isTTY: true });
      (captured.io.stdout as { isTTY?: boolean }).isTTY = false;
      const code = await runScanCommand(
        createTestContext(captured, blockedDeps(runCode), scriptedKeys(["y"])),
        { variant: "code", port: null, report: null, format },
      );
      expect(code).toBe(EXIT_CODES.blocked);
      expect(runCode).not.toHaveBeenCalled();
      const all = captured.stdout() + captured.stderr();
      expect(all).toContain("For a code-only scan, add --code-only.");
      expect(all).not.toContain("[y/N]");
    },
  );

  it("a failed authorization with no terminal never turns into a code-only scan by itself", async () => {
    for (const variant of ["default", "code"] as const) {
      const runCode = unexpected("runCodeOnlyScan");
      const captured = createTestIo();
      const code = await runScanCommand(createTestContext(captured, blockedDeps(runCode)), {
        variant,
        port: null,
        report: null,
      });
      expect(code).toBe(EXIT_CODES.blocked);
      expect(runCode).not.toHaveBeenCalled();
    }
    const outside = createTestIo();
    const runCode = unexpected("runCodeOnlyScan");
    expect(
      await runScanCommand(
        createTestContext(
          outside,
          createTestDeps({ findGitRoot: async () => null, runCodeOnlyScan: runCode as never }),
        ),
        { variant: "code", port: null, report: null },
      ),
    ).toBe(EXIT_CODES.blocked);
    expect(runCode).not.toHaveBeenCalled();
    expect(outside.stdout()).toContain("For a code-only scan, add --code-only.");
  });

  it("baseline set --from-current never offers a code-only scan", async () => {
    const runCode = unexpected("runCodeOnlyScan");
    const captured = createTestIo({ isTTY: true });
    const code = await runScanCommand(
      createTestContext(captured, blockedDeps(runCode), scriptedKeys(["y"])),
      { variant: "default", port: null, report: null, setBaseline: true },
    );
    expect(code).toBe(EXIT_CODES.blocked);
    expect(captured.stdout()).not.toContain("[y/N]");
  });
});

describe("the other scopes stay strict (D2)", () => {
  it.each(["history", "all"] as const)(
    "scan %s still runs the gate, exits 3 when blocked and adds the hint, without asking",
    async (variant) => {
      const runCode = unexpected("runCodeOnlyScan");
      const captured = createTestIo();
      const code = await runScanCommand(
        createTestContext(
          captured,
          createTestDeps({
            runCodeOnlyScan: runCode as never,
            verifyProject: async () => ({ summary: BLOCKED, repo: "owner/name", revision: "abc" }),
            runScan: async () => BLOCKED_RESULT(),
          }),
        ),
        { variant, port: variant === "all" ? 3000 : null, report: null, format: "json" },
      );
      expect(code).toBe(EXIT_CODES.blocked);
      expect(runCode).not.toHaveBeenCalled();
      expect(captured.stderr()).toContain("`pgard scan code --code-only` checks the current files");
    },
  );
});

describe("any folder (D4)", () => {
  it("scans a folder without Git as it is, with reason not_a_git_repository", async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), "pgard-cli-codeonly-"));
    const runCode = vi.fn(async () => codeOnlyTestResult());
    const captured = createTestIo({ cwd: dir });
    await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({ findGitRoot: async () => null, runCodeOnlyScan: runCode }),
      ),
      CODE,
    );
    expect(runCode).toHaveBeenCalledWith(
      { projectRoot: path.resolve(dir), reason: "not_a_git_repository" },
      expect.anything(),
    );
  });

  it("refuses the home folder and the file-system root outside a Git repository", async () => {
    expect(await codeOnlyFolderRefusal("/", "/home/u", "linux")).toBe("root");
    // The home folder is given explicitly (HOME), so a redirected HOME in the test process or an
    // account home that differs from os.homedir() cannot change the outcome.
    const home = await temp();
    expect(await codeOnlyFolderRefusal(home, home)).toBe("home");
    const runCode = unexpected("runCodeOnlyScan");
    const captured = createTestIo({ cwd: home, env: { HOME: home } });
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({ findGitRoot: async () => null, runCodeOnlyScan: runCode as never }),
      ),
      CODE,
    );
    expect(code).toBe(EXIT_CODES.usage);
    expect(runCode).not.toHaveBeenCalled();
    expect(captured.stderr()).toContain("not a project");
  });

  it("compares real paths: a symlinked home folder and another spelling are still home", async () => {
    const base = await temp();
    const home = path.join(base, "RealHome");
    await mkdir(home);
    const link = path.join(base, "home-link");
    // A junction on Windows (no admin rights needed); the type is ignored elsewhere.
    await symlink(home, link, "junction");
    expect(await codeOnlyFolderRefusal(home, link, "linux")).toBe("home");
    expect(await codeOnlyFolderRefusal(link, home, "linux")).toBe("home");
    expect(await codeOnlyFolderRefusal(base, link, "linux")).toBe("above_home");
    expect(await codeOnlyFolderRefusal(path.join(base, "realhome"), home, "darwin")).toBe("home");
    await mkdir(path.join(home, "code", "app"), { recursive: true });
    expect(await codeOnlyFolderRefusal(path.join(home, "code", "app"), link, "linux")).toBeNull();
  });

  it("refuses when either the given path or its real path is too broad (macOS /tmp -> /private/tmp)", async () => {
    expect(await codeOnlyFolderRefusal("/tmp", "/home/u", "linux")).toBe("top_level");
    expect(await codeOnlyFolderRefusal("/etc", "/home/u", "darwin")).toBe("top_level");
    // A deep-looking path whose real path is the file-system root.
    const base = await temp();
    const toRoot = path.join(base, "deep", "looking");
    await mkdir(path.dirname(toRoot), { recursive: true });
    await symlink(path.parse(base).root, toRoot, "junction");
    expect(await codeOnlyFolderRefusal(toRoot, "/home/u", "linux")).toBe("root");
  });

  it("falls back to the account's home folder when HOME is empty, and refuses with none", async () => {
    expect(codeOnlyHome({ HOME: "/home/u" }, () => "/home/acct")).toBe("/home/u");
    expect(codeOnlyHome({ HOME: "" }, () => "/home/acct")).toBe("/home/acct");
    expect(codeOnlyHome({ HOME: "  ", USERPROFILE: "" }, () => "/home/acct")).toBe("/home/acct");
    expect(codeOnlyHome({ HOME: "" }, () => "")).toBeNull();
    expect(
      codeOnlyHome({}, () => {
        throw new Error("no account");
      }),
    ).toBeNull();
    // HOME="" no longer skips the check: the account's home folder is still refused.
    const accountHome = os.userInfo().homedir;
    const runCode = unexpected("runCodeOnlyScan");
    const captured = createTestIo({ cwd: accountHome, env: { HOME: "" } });
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({ findGitRoot: async () => null, runCodeOnlyScan: runCode as never }),
      ),
      CODE,
    );
    expect(code).toBe(EXIT_CODES.usage);
    expect(runCode).not.toHaveBeenCalled();
    expect(captured.stderr()).toContain("not a project");
  });

  it("refuses a Git repository whose top folder is the home folder (a dotfiles repository)", async () => {
    const home = await temp();
    const notes = path.join(home, "notes");
    await mkdir(notes);
    const runCode = unexpected("runCodeOnlyScan");
    const captured = createTestIo({ cwd: notes, env: { HOME: home } });
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({ findGitRoot: async () => home, runCodeOnlyScan: runCode as never }),
      ),
      CODE,
    );
    expect(code).toBe(EXIT_CODES.usage);
    expect(runCode).not.toHaveBeenCalled();
    expect(captured.stderr()).toContain("inside a Git repository at your home folder");
    expect(captured.stderr()).toContain("has its own Git repository");
  });

  it("refuses a Git repository at a folder above home or at a top-level folder", async () => {
    const base = await temp();
    const home = path.join(base, "u");
    await mkdir(home);
    for (const root of [base, "/"]) {
      const runCode = unexpected("runCodeOnlyScan");
      const captured = createTestIo({ cwd: home, env: { HOME: home } });
      const code = await runScanCommand(
        createTestContext(
          captured,
          createTestDeps({ findGitRoot: async () => root, runCodeOnlyScan: runCode as never }),
        ),
        CODE,
      );
      expect(code).toBe(EXIT_CODES.usage);
      expect(runCode).not.toHaveBeenCalled();
    }
  });

  it("refuses a .git folder and a bare repository instead of scanning Git's own files", async () => {
    const base = await temp();
    const dotGit = path.join(base, "repo", ".git", "objects");
    await mkdir(dotGit, { recursive: true });
    const bare = path.join(base, "bare.git-like");
    await mkdir(path.join(bare, "objects"), { recursive: true });
    await mkdir(path.join(bare, "refs"));
    await writeFile(path.join(bare, "HEAD"), "ref: refs/heads/main\n");
    await writeFile(path.join(bare, "config"), "[core]\n\tbare = true\n");
    for (const cwd of [path.join(base, "repo", ".git"), dotGit, bare, path.join(bare, "refs")]) {
      const runCode = unexpected("runCodeOnlyScan");
      const captured = createTestIo({ cwd });
      const code = await runScanCommand(
        createTestContext(
          captured,
          createTestDeps({ findGitRoot: async () => null, runCodeOnlyScan: runCode as never }),
        ),
        CODE,
      );
      expect(code).toBe(EXIT_CODES.usage);
      expect(runCode).not.toHaveBeenCalled();
      expect(captured.stderr()).toContain("This is a Git directory");
    }
  });
});

describe("--format json and sarif carry scanBasis", () => {
  async function machine(format: "json" | "sarif"): Promise<{ code: number; doc: unknown }> {
    const captured = createTestIo();
    const code = await runScanCommand(createTestContext(captured, createTestDeps()), {
      ...CODE,
      format,
    });
    return { code, doc: JSON.parse(captured.stdout()) };
  }

  it("prints one JSON document with the code-only scanBasis, the notes on stderr", async () => {
    const { code, doc } = await machine("json");
    expect(code).toBe(EXIT_CODES.ok);
    const read = readScanResult(doc);
    expect(read.ok && read.result.scanBasis).toEqual({
      mode: "code_only",
      authorization: "not_verified",
      reason: "not_checked",
    });
  });

  it("prints a SARIF run in the code-only category with the notice", async () => {
    const { doc } = await machine("sarif");
    const run = (doc as { runs: Array<Record<string, unknown>> }).runs[0] as {
      automationDetails: { id: string };
      properties: { pgard: { scanBasis: { mode: string } } };
    };
    expect(run.automationDetails.id).toBe("pgard/code-only/");
    expect(run.properties.pgard.scanBasis.mode).toBe("code_only");
  });
});

describe("end to end through main() on a real folder without Git", () => {
  it("finds a secret, exits 0 and stores nothing", async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), "pgard-cli-codeonly-e2e-"));
    await mkdir(path.join(dir, "src"), { recursive: true });
    await writeFile(
      path.join(dir, "src", "config.js"),
      `export const aws = { accessKeyId: "${FAKE_KEY}" };\n`,
    );
    const captured = createTestIo({ cwd: dir, env: { PGARD_LANG: "en" } });
    const deps = createTestDeps({
      findGitRoot: async () => null,
      appDataDir: null,
      runCodeOnlyScan,
      openResultStore: unexpected("openResultStore") as never,
    });
    const code = await main(["scan", "code", "--code-only", "--format", "json"], captured.io, {
      deps,
      interrupts: noInterrupts,
    });
    expect(code).toBe(EXIT_CODES.ok);
    const result = JSON.parse(captured.stdout()) as ScanResult;
    expect(result.scanBasis?.reason).toBe("not_a_git_repository");
    expect(result.findings.some((finding) => finding.ruleId === "PG-SECRET-002")).toBe(true);
    expect(captured.stdout()).not.toContain(FAKE_KEY);
    expect(captured.stdout()).not.toContain(dir);
  });
});
