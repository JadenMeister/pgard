import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
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
  testResult,
} from "../../test-support.js";
import { isTooBroadForCodeOnly } from "./code-only.js";
import { runScanCommand } from "./index.js";

/** `pgard scan code` without approval (#414 phase 2: D1, D2, D4). */

const CODE = { variant: "code", port: null, report: null } as const;
// The AWS documentation key with its last letter changed (EXAMPLE itself reads as a placeholder).
const FAKE_KEY = `${"AKIA"}IOSFODNN7EXAMPLQ`;

const unexpected = (name: string) =>
  vi.fn(() => {
    throw new Error(`unexpected call: ${name}`);
  });

let dir: string | null = null;
afterEach(async () => {
  if (dir !== null) await rm(dir, { recursive: true, force: true });
  dir = null;
});

describe("pgard scan code is a code-only scan (D1)", () => {
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
    expect(text).toContain("pgard scan code --require-authorization");
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

  it("--require-authorization restores the gate: blocked exits 3 with the hint", async () => {
    const runCode = unexpected("runCodeOnlyScan");
    const captured = createTestIo();
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          runCodeOnlyScan: runCode as never,
          runScan: async () =>
            testResult({
              overallStatus: "blocked",
              authorization: BLOCKED,
              findings: [],
              coverage: [],
              scanBasis: {
                mode: "authorized",
                authorization: "not_verified",
                reason: "no_approval",
              },
            }),
        }),
      ),
      { ...CODE, requireAuthorization: true },
    );
    expect(code).toBe(EXIT_CODES.blocked);
    expect(runCode).not.toHaveBeenCalled();
    expect(captured.stdout()).toContain(
      "`pgard scan code` checks the current files without approval.",
    );
  });

  it("parses --require-authorization for scan code only", () => {
    expect(parseCommandLine(["scan", "code", "--require-authorization"])).toMatchObject({
      kind: "scan",
      variant: "code",
      requireAuthorization: true,
    });
    expect(parseCommandLine(["scan", "code"])).not.toHaveProperty("requireAuthorization");
    for (const argv of [
      ["scan", "--require-authorization"],
      ["scan", "all", "--require-authorization"],
      ["project", "verify", "--require-authorization"],
    ]) {
      expect(() => parseCommandLine(argv)).toThrow(UsageError);
    }
  });
});

describe("the other scopes stay strict (D2)", () => {
  it.each(["default", "history", "all"] as const)(
    "scan %s still runs the gate, exits 3 when blocked and adds the hint",
    async (variant) => {
      const runCode = unexpected("runCodeOnlyScan");
      const captured = createTestIo();
      const code = await runScanCommand(
        createTestContext(
          captured,
          createTestDeps({
            runCodeOnlyScan: runCode as never,
            verifyProject: async () => ({ summary: BLOCKED, repo: "owner/name", revision: "abc" }),
            runScan: async () =>
              testResult({
                overallStatus: "blocked",
                authorization: BLOCKED,
                findings: [],
                coverage: [],
                scanBasis: {
                  mode: "authorized",
                  authorization: "not_verified",
                  reason: "no_approval",
                },
              }),
          }),
        ),
        { variant, port: variant === "all" ? 3000 : null, report: null, format: "json" },
      );
      expect(code).toBe(EXIT_CODES.blocked);
      expect(runCode).not.toHaveBeenCalled();
      expect(captured.stderr()).toContain("`pgard scan code` checks the current files");
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
    expect(isTooBroadForCodeOnly("/", "/home/u")).toBe(true);
    expect(isTooBroadForCodeOnly("/home/u", "/home/u")).toBe(true);
    expect(isTooBroadForCodeOnly("/home/u/code/app", "/home/u")).toBe(false);
    const runCode = unexpected("runCodeOnlyScan");
    const captured = createTestIo({ cwd: os.homedir() });
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
    const code = await main(["scan", "code", "--format", "json"], captured.io, {
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
