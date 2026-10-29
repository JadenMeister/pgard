import { readScanResult, type AnalyzerOutput } from "@pgard/findings";
import type { AuthorizationOutcome } from "@pgard/policy";
import { describe, expect, it, vi } from "vitest";

const authorizeProject = vi.fn<(root: string) => Promise<AuthorizationOutcome>>();

vi.mock("@pgard/policy", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@pgard/policy")>();
  return { ...actual, authorizeProject: (root: string) => authorizeProject(root) };
});

const { CODE_ONLY_CHECK_REASON, runCodeOnlyScan } = await import("./index.js");

const ROOT = "/home/user/projects/app";

const codeOutput: AnalyzerOutput = {
  findings: [
    {
      id: "f1",
      ruleId: "PG-SECRET-001",
      title: "t",
      category: "secret_exposure",
      severity: "high",
      status: "suspected",
      confidence: "medium",
      location: { kind: "file", path: `${ROOT}/src/config.ts`, line: 3, url: null, commit: null },
      evidence: `key in ${ROOT}/src/config.ts`,
      impact: "i",
      recommendation: "r",
      references: { cwe: [], owasp: [], cve: [] },
      sources: ["code"],
    },
  ],
  coverage: [
    {
      area: "source:typescript",
      scope: "code",
      status: "completed",
      ruleIds: ["PG-SECRET-001"],
      note: null,
    },
  ],
};

describe("runCodeOnlyScan (prototype, #414)", () => {
  it("runs only the code analyzer, never the gate, and never claims authorization", async () => {
    const code = vi.fn(async () => codeOutput);
    const history = vi.fn(async () => codeOutput);
    const stages: string[] = [];
    const result = await runCodeOnlyScan(
      { projectRoot: ROOT },
      {
        analyzers: { code, history },
        onProgress: (event) => stages.push(`${event.stage}:${event.status}`),
      },
    );
    expect(authorizeProject).not.toHaveBeenCalled();
    expect(history).not.toHaveBeenCalled();
    expect(code).toHaveBeenCalledOnce();
    expect(result.authorization.decision).toBe("blocked");
    expect(result.authorization.checks).toHaveLength(5);
    for (const check of result.authorization.checks) {
      expect(check).toMatchObject({ status: "unverifiable", reason: CODE_ONLY_CHECK_REASON });
    }
    expect(result.requestedScopes).toEqual(["code"]);
    expect(result.overallStatus).toBe("completed");
    expect(result.target).toEqual({ repo: null, revision: null, webOrigin: null });
    expect(result.incremental).toBeUndefined();
    expect(result.findings).toHaveLength(1);
    // Paths are repository-relative, exactly as in an authorized scan.
    expect(result.findings[0]?.location.path).toBe("src/config.ts");
    expect(JSON.stringify(result)).not.toContain(ROOT);
    expect(stages[0]).toBe("authorization:skipped");
    expect(readScanResult(JSON.parse(JSON.stringify(result))).ok).toBe(true);
  });

  it("reports partial when the code coverage is partial", async () => {
    const result = await runCodeOnlyScan(
      { projectRoot: ROOT },
      {
        analyzers: {
          code: async () => ({
            findings: [],
            coverage: [
              { area: "deps:npm", scope: "code", status: "not_tested", ruleIds: [], note: "x" },
            ],
          }),
        },
      },
    );
    expect(result.overallStatus).toBe("partial");
  });

  it("refuses a relative project root", async () => {
    await expect(runCodeOnlyScan({ projectRoot: "app" }, {})).rejects.toThrow(/absolute/);
  });
});
