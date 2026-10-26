import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { readScanResult, type ScanRequest } from "@pgard/findings";
import { ScanCancelledError } from "@pgard/scan-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { UserCancelledError } from "../../ui/components/prompts.js";
import {
  BLOCKED,
  createTestContext,
  createTestDeps,
  createTestIo,
  scriptedKeys,
  testFinding,
  testResult,
} from "../../test-support.js";
import { runScanCommand } from "./index.js";

const DEFAULT_SCAN = { variant: "default", port: null, report: null } as const;

describe("runScanCommand", () => {
  it("exits 0 for a full scan whose selected areas all completed, with no advisory text", async () => {
    const captured = createTestIo();
    const code = await runScanCommand(
      createTestContext(captured, createTestDeps({ runScan: async () => testResult() })),
      DEFAULT_SCAN,
    );
    expect(code).toBe(0);
    expect(captured.stdout()).toContain("PGARD does not ship or query a vulnerability database.");
    expect(captured.stdout()).toContain(
      "Dependency versions are not checked against known vulnerabilities.",
    );
    expect(captured.stdout()).not.toMatch(/advisory/i);
  });

  it("keeps exit 4 for genuine partial coverage (history time budget)", async () => {
    const captured = createTestIo();
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          runScan: async () =>
            testResult({
              overallStatus: "partial",
              coverage: [
                {
                  area: "source:typescript",
                  scope: "code",
                  status: "completed",
                  ruleIds: [],
                  note: null,
                },
                {
                  area: "history:commits",
                  scope: "history",
                  status: "partial",
                  ruleIds: [],
                  note: "Stopped at the time budget.",
                },
              ],
            }),
        }),
      ),
      DEFAULT_SCAN,
    );
    expect(code).toBe(4);
    expect(captured.stdout()).toContain("history:commits");
  });

  it("exits 3 outside a Git repository without scanning", async () => {
    const captured = createTestIo();
    const runScan = vi.fn();
    const code = await runScanCommand(
      createTestContext(captured, createTestDeps({ findGitRoot: async () => null, runScan })),
      DEFAULT_SCAN,
    );
    expect(code).toBe(3);
    expect(runScan).not.toHaveBeenCalled();
    expect(captured.stderr()).toContain("not inside a Git repository");
  });

  it("shows per-check reasons and exits 3 when blocked, without a client-id hint", async () => {
    const captured = createTestIo();
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          runScan: async () =>
            testResult({
              overallStatus: "blocked",
              authorization: BLOCKED,
              findings: [],
              coverage: [],
            }),
        }),
      ),
      DEFAULT_SCAN,
    );
    expect(code).toBe(3);
    expect(captured.stdout()).toContain(
      "[unverifiable] github identity: GitHub sign-in was denied.",
    );
    expect(captured.stdout()).toContain("[unverifiable] owner approval: Not evaluated.");
    // The client id always resolves (built-in PGARD App), so there is no "not set" hint.
    expect(captured.stdout() + captured.stderr()).not.toContain("PGARD_GITHUB_APP_CLIENT_ID");
  });

  it("passes code+history scopes with the Git root and exits 0 for a completed scan with findings", async () => {
    const captured = createTestIo();
    let request: ScanRequest | null = null;
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          runScan: async (scanRequest) => {
            request = scanRequest;
            return testResult();
          },
        }),
      ),
      DEFAULT_SCAN,
    );
    expect(code).toBe(0);
    expect(request).toEqual({
      projectRoot: "/work/repo",
      scopes: ["code", "history"],
      webTarget: null,
    });
    const stdout = captured.stdout();
    expect(stdout).toContain("Findings by severity (1 total)");
    expect(stdout).toContain("src/api/users.ts:42");
    expect(stdout).toContain("Findings (1)");
    expect(stdout).toContain("Coverage");
  });

  it("names an override App once on stderr, and nothing for the built-in App", async () => {
    const run = async (env: Record<string, string>) => {
      const captured = createTestIo({ env });
      await runScanCommand(
        createTestContext(captured, createTestDeps({ runScan: async () => testResult() })),
        DEFAULT_SCAN,
      );
      return captured;
    };
    const override = await run({ PGARD_GITHUB_APP_CLIENT_ID: "Iv23liForkApp" });
    expect(
      override
        .stderr()
        .split("\n")
        .filter((line) => line.startsWith("Using GitHub App")),
    ).toEqual(["Using GitHub App Iv23liForkApp from PGARD_GITHUB_APP_CLIENT_ID (override)."]);
    expect(override.stdout()).not.toContain("Using GitHub App");
    expect((await run({})).stderr()).not.toContain("Using GitHub App");
  });

  it("lists test or fixture findings in their own group after the headline counts", async () => {
    const captured = createTestIo();
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          runScan: async () =>
            testResult({
              findings: [
                testFinding({
                  id: "t1",
                  ruleId: "PG-SECRET-002",
                  title: "Secret in a tracked file",
                  severity: "critical",
                  confidence: "low",
                  context: "test",
                  location: {
                    kind: "file",
                    path: "src/redact.test.ts",
                    line: 7,
                    url: null,
                    commit: null,
                  },
                }),
                testFinding(),
              ],
            }),
        }),
      ),
      DEFAULT_SCAN,
    );
    expect(code).toBe(0);
    const stdout = captured.stdout();
    expect(stdout).toContain("Findings by severity (1 total) - plus 1 in test or fixture code");
    expect(stdout).toMatch(/Critical\s+0\n/);
    expect(stdout).toContain("Findings (1)");
    const testGroup = stdout.indexOf("In test or fixture code (1)");
    expect(testGroup).toBeGreaterThan(stdout.indexOf("src/api/users.ts:42"));
    expect(stdout.indexOf("src/redact.test.ts:7")).toBeGreaterThan(testGroup);
    expect(stdout.indexOf("Coverage")).toBeGreaterThan(testGroup);
  });

  it("does not call a scan with only test findings empty", async () => {
    const captured = createTestIo();
    await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          runScan: async () =>
            testResult({
              findings: [
                testFinding({
                  context: "test",
                  confidence: "low",
                  location: {
                    kind: "file",
                    path: "test/db.js",
                    line: 1,
                    url: null,
                    commit: null,
                  },
                }),
              ],
            }),
        }),
      ),
      DEFAULT_SCAN,
    );
    const stdout = captured.stdout();
    expect(stdout).toContain("No findings outside test or fixture code");
    expect(stdout).toContain("In test or fixture code (1)");
    expect(stdout).toContain("test/db.js:1");
  });

  it("lists vendored findings last as suggestions, outside the headline counts", async () => {
    const captured = createTestIo();
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          runScan: async () =>
            testResult({
              findings: [
                testFinding({
                  id: "v1",
                  ruleId: "PG-SECRET-002",
                  title: "Secret in a tracked file",
                  severity: "high",
                  confidence: "low",
                  context: "vendored",
                  location: {
                    kind: "file",
                    path: "node_modules/@babel/parser/lib/index.js",
                    line: 11694,
                    url: null,
                    commit: null,
                  },
                }),
                testFinding({
                  id: "t1",
                  confidence: "low",
                  context: "test",
                  location: {
                    kind: "file",
                    path: "test/db.js",
                    line: 1,
                    url: null,
                    commit: null,
                  },
                }),
                testFinding(),
              ],
            }),
        }),
      ),
      DEFAULT_SCAN,
    );
    expect(code).toBe(0);
    const stdout = captured.stdout();
    expect(stdout).toContain(
      "Findings by severity (1 total) - plus 1 in test or fixture code, 1 suggestion in vendored code (1 high)",
    );
    expect(stdout).toMatch(/High\s+#+ 1\n/);
    const testGroup = stdout.indexOf("In test or fixture code (1)");
    const suggestions = stdout.indexOf("Suggestions: in third-party/vendored code (1)");
    expect(suggestions).toBeGreaterThan(testGroup);
    expect(stdout).toContain("This code is a committed dependency, not your code.");
    const vendoredLine = stdout.indexOf("node_modules/@babel/parser/lib/index.js:11694");
    expect(vendoredLine).toBeGreaterThan(suggestions);
    expect(stdout.slice(vendoredLine)).toContain("PG-SECRET-002 - confidence low");
    expect(stdout.indexOf("Coverage")).toBeGreaterThan(suggestions);
  });

  it("does not call a scan with only vendored findings empty and keeps its exit code", async () => {
    const captured = createTestIo();
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          runScan: async () =>
            testResult({
              findings: [
                testFinding({
                  context: "vendored",
                  confidence: "low",
                  location: {
                    kind: "file",
                    path: "vendor/acme/lib.php",
                    line: 2,
                    url: null,
                    commit: null,
                  },
                }),
              ],
            }),
        }),
      ),
      DEFAULT_SCAN,
    );
    expect(code).toBe(0);
    const stdout = captured.stdout();
    expect(stdout).toContain(
      "Findings by severity (0 total) - plus 1 suggestion in vendored code (1 high)",
    );
    // The severity bars count regular code only: the vendored high finding is not a bar.
    expect(stdout).toMatch(/High\s+0\n/);
    expect(stdout).toContain("No findings outside vendored code");
    expect(stdout).toContain("Suggestions: in third-party/vendored code (1)");
    expect(stdout).toContain("vendor/acme/lib.php:2");
  });

  it("exits 4 for a partial scan and records web as not tested without a terminal", async () => {
    const captured = createTestIo();
    let request: ScanRequest | null = null;
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          runScan: async (scanRequest) => {
            request = scanRequest;
            return testResult({
              overallStatus: "partial",
              requestedScopes: ["code", "history", "web"],
              coverage: [
                {
                  area: "web:anonymous",
                  scope: "web",
                  status: "not_tested",
                  ruleIds: [],
                  note: "no target",
                },
              ],
            });
          },
        }),
      ),
      { variant: "all", port: 3000, report: null },
    );
    expect(code).toBe(4);
    expect(request).toMatchObject({ scopes: ["code", "history", "web"], webTarget: null });
    expect(captured.stderr()).toContain("cannot be confirmed without an interactive terminal");
    expect(captured.stdout()).toContain("[not tested] web:anonymous");
  });

  it("does not probe ports when authorization is blocked for a web scan", async () => {
    const captured = createTestIo();
    const probeLocalService = vi.fn();
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          verifyProject: async () => ({ summary: BLOCKED, repo: null, revision: null }),
          probeLocalService,
        }),
        scriptedKeys([]),
      ),
      { variant: "web", port: 3000, report: null },
    );
    expect(code).toBe(3);
    expect(probeLocalService).not.toHaveBeenCalled();
  });

  it("builds a confirmed target only after an explicit y", async () => {
    const captured = createTestIo();
    let request: ScanRequest | null = null;
    await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          runScan: async (scanRequest) => {
            request = scanRequest;
            return testResult({ requestedScopes: ["web"] });
          },
        }),
        scriptedKeys(["y"]),
      ),
      { variant: "web", port: 3000, report: null },
    );
    expect(captured.stdout()).toContain("Title:  Shop dev");
    expect(captured.stdout()).toContain("Technology (inferred, not verified): Express");
    expect(request).toMatchObject({
      webTarget: { port: 3000, origin: "http://127.0.0.1:3000", confirmedByUser: true },
    });
  });

  it("treats Enter (default N) as no and lets the user continue without web checks", async () => {
    const captured = createTestIo();
    let request: ScanRequest | null = null;
    await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          runScan: async (scanRequest) => {
            request = scanRequest;
            return testResult({ overallStatus: "partial" });
          },
        }),
        // Enter = N on the preset port; then pick "Continue without web checks" (3rd item).
        scriptedKeys(["return", "down", "down", "return"]),
      ),
      { variant: "web", port: 3000, report: null },
    );
    expect(request).toMatchObject({ webTarget: null });
  });

  it("maps a cancelled scan to UserCancelledError (exit 130)", async () => {
    const captured = createTestIo();
    await expect(
      runScanCommand(
        createTestContext(
          captured,
          createTestDeps({
            runScan: async () => {
              throw new ScanCancelledError();
            },
          }),
        ),
        DEFAULT_SCAN,
      ),
    ).rejects.toBeInstanceOf(UserCancelledError);
  });

  it("never prints raw control sequences from findings", async () => {
    const captured = createTestIo();
    await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          runScan: async () =>
            testResult({ findings: [testFinding({ title: "bad\u001b]0;pwned\u0007title" })] }),
        }),
      ),
      DEFAULT_SCAN,
    );
    expect(captured.stdout()).not.toContain("\u001b]0;");
  });
});

describe("runScanCommand cancellation during the web pre-check", () => {
  it("ends as a cancellation, not a blocked gate", async () => {
    const captured = createTestIo();
    const controller = new AbortController();
    const context = {
      ...createTestContext(
        captured,
        createTestDeps({
          verifyProject: async () => {
            controller.abort();
            return { summary: BLOCKED, repo: null, revision: null };
          },
        }),
        scriptedKeys([]),
      ),
      signal: controller.signal,
    };
    await expect(
      runScanCommand(context, { variant: "web", port: 3000, report: null }),
    ).rejects.toBeInstanceOf(UserCancelledError);
  });
});

describe("runScanCommand Esc on the port list", () => {
  it("returns to the menu instead of exiting", async () => {
    const captured = createTestIo();
    const runScan = vi.fn();
    const code = await runScanCommand(
      createTestContext(captured, createTestDeps({ runScan }), scriptedKeys(["escape"]), true),
      { variant: "web", port: null, report: null },
    );
    expect(code).toBe(130);
    expect(runScan).not.toHaveBeenCalled();
  });

  it("cancels a direct subcommand", async () => {
    const captured = createTestIo();
    await expect(
      runScanCommand(createTestContext(captured, createTestDeps(), scriptedKeys(["escape"])), {
        variant: "web",
        port: null,
        report: null,
      }),
    ).rejects.toBeInstanceOf(UserCancelledError);
  });
});

describe("runScanCommand reports", () => {
  let directory: string;
  beforeEach(async () => {
    directory = await mkdtemp(path.join(os.tmpdir(), "pgard-cli-report-"));
  });
  afterEach(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it("rejects a missing output directory with exit 2 before scanning", async () => {
    const captured = createTestIo();
    const runScan = vi.fn();
    const code = await runScanCommand(createTestContext(captured, createTestDeps({ runScan })), {
      variant: "default",
      port: null,
      report: { format: "html", outputDir: path.join(directory, "missing") },
    });
    expect(code).toBe(2);
    expect(runScan).not.toHaveBeenCalled();
  });

  it("refuses an output directory inside the repository without a terminal", async () => {
    const captured = createTestIo();
    const runScan = vi.fn();
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({ runScan, isPathInsideDirectory: async () => true }),
      ),
      { variant: "default", port: null, report: { format: "html", outputDir: directory } },
    );
    expect(code).toBe(2);
    expect(runScan).not.toHaveBeenCalled();
    expect(captured.stderr()).toContain("inside the Git repository");
  });

  it("writes the report and exits 4 when writing fails", async () => {
    const captured = createTestIo();
    const writeReports = vi.fn(async () => [
      { format: "html" as const, filePath: path.join(directory, "r.html") },
    ]);
    expect(
      await runScanCommand(createTestContext(captured, createTestDeps({ writeReports })), {
        variant: "default",
        port: null,
        report: { format: "html", outputDir: directory },
      }),
    ).toBe(0);
    expect(writeReports).toHaveBeenCalledOnce();
    expect(captured.stdout()).toContain("Saved HTML report");

    const failing = createTestIo();
    const code = await runScanCommand(
      createTestContext(
        failing,
        createTestDeps({
          writeReports: async () => {
            throw new Error("disk full");
          },
        }),
      ),
      { variant: "default", port: null, report: { format: "pdf", outputDir: directory } },
    );
    expect(code).toBe(4);
  });

  it("prints a warning on stderr when the PDF fell back to the Latin-1 font", async () => {
    const captured = createTestIo();
    const writeReports = vi.fn(async () => [
      {
        format: "pdf" as const,
        filePath: path.join(directory, "r.pdf"),
        warning: "The Korean-capable PDF font could not be loaded (font file unreadable: ENOENT).",
      },
    ]);
    const code = await runScanCommand(
      createTestContext(captured, createTestDeps({ writeReports })),
      { variant: "default", port: null, report: { format: "pdf", outputDir: directory } },
    );
    expect(code).toBe(0);
    expect(captured.stdout()).toContain("Saved PDF report");
    expect(captured.stderr()).toContain("Warning: The Korean-capable PDF font could not be loaded");
  });

  it("does not write a report for a blocked scan", async () => {
    const captured = createTestIo();
    const writeReports = vi.fn();
    const code = await runScanCommand(
      createTestContext(
        captured,
        createTestDeps({
          writeReports,
          runScan: async () => testResult({ overallStatus: "blocked", authorization: BLOCKED }),
        }),
      ),
      { variant: "default", port: null, report: { format: "html", outputDir: directory } },
    );
    expect(code).toBe(3);
    expect(writeReports).not.toHaveBeenCalled();
  });

  describe("--format json", () => {
    const JSON_SCAN = { variant: "code", port: null, report: null, format: "json" } as const;

    it("prints only the ScanResult on stdout, which readScanResult accepts, and the rest on stderr", async () => {
      const captured = createTestIo();
      const result = testResult({
        findings: [testFinding(), testFinding({ id: "f2", severity: "low" })],
      });
      const code = await runScanCommand(
        createTestContext(captured, createTestDeps({ runScan: async () => result })),
        JSON_SCAN,
      );
      expect(code).toBe(0);
      const parsed: unknown = JSON.parse(captured.stdout());
      const read = readScanResult(parsed);
      expect(read.ok).toBe(true);
      if (read.ok) expect(read.result).toEqual(result);
      expect(captured.stdout()).not.toContain("PGARD scan result");
      expect(captured.stderr()).toContain("Scanning (code)");
    });

    it("keeps the exit code of the scan status and prints a blocked result too", async () => {
      const captured = createTestIo();
      const code = await runScanCommand(
        createTestContext(
          captured,
          createTestDeps({
            runScan: async () => testResult({ overallStatus: "blocked", authorization: BLOCKED }),
          }),
        ),
        JSON_SCAN,
      );
      expect(code).toBe(3);
      expect(JSON.parse(captured.stdout()).overallStatus).toBe("blocked");
    });

    it("is a usage error, before any scan, when web checks would need a port prompt", async () => {
      const captured = createTestIo();
      const runScan = vi.fn();
      const code = await runScanCommand(
        createTestContext(captured, createTestDeps({ runScan }), scriptedKeys([])),
        { variant: "web", port: null, report: null, format: "json" },
      );
      expect(code).toBe(2);
      expect(runScan).not.toHaveBeenCalled();
      expect(captured.stdout()).toBe("");
      expect(captured.stderr()).toContain("--port");
    });

    it("sends the port confirmation prompt to stderr, never stdout", async () => {
      const captured = createTestIo();
      const code = await runScanCommand(
        createTestContext(
          captured,
          createTestDeps({ runScan: async () => testResult() }),
          scriptedKeys(["y"]),
        ),
        { variant: "web", port: 3000, report: null, format: "json" },
      );
      expect(code).toBe(0);
      expect(() => JSON.parse(captured.stdout())).not.toThrow();
      expect(captured.stderr()).toContain("Is this the current project's service?");
    });
  });
});
