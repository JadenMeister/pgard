import type { AnalyzerOutput, Finding, ScanRequest } from "@pgard/findings";
import type { AuthorizationOutcome } from "@pgard/policy";
import { beforeEach, describe, expect, it, vi } from "vitest";

const authorizeProject = vi.fn<(root: string) => Promise<AuthorizationOutcome>>();

vi.mock("@pgard/policy", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@pgard/policy")>();
  return { ...actual, authorizeProject: (root: string) => authorizeProject(root) };
});

const { runScan, ScanCancelledError } = await import("./index.js");

const ROOT = "/home/user/projects/app";

const ALLOWED: AuthorizationOutcome = {
  summary: {
    decision: "allowed",
    checks: (
      ["repository", "github_identity", "owner_approval", "current_access", "contribution"] as const
    ).map((id) => ({ id, status: "passed" as const, reason: "ok" })),
  },
  repo: "octo/app",
  revision: "a".repeat(40),
};

const BLOCKED: AuthorizationOutcome = {
  summary: {
    decision: "blocked",
    checks: ALLOWED.summary.checks.map((check) =>
      check.id === "owner_approval"
        ? { ...check, status: "unverifiable", reason: "org repo" }
        : check,
    ),
  },
  repo: "octo/app",
  revision: null,
};

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    ruleId: "PG-SQL-001",
    title: "t",
    category: "injection",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    location: { kind: "file", path: `${ROOT}/src/db.ts`, line: 3, url: null, commit: null },
    evidence: `query built in ${ROOT}/src/db.ts`,
    impact: "i",
    recommendation: "r",
    references: { cwe: [], owasp: [], cve: [] },
    sources: ["code"],
    ...overrides,
  };
}

const codeOutput: AnalyzerOutput = {
  findings: [finding()],
  coverage: [
    {
      area: "source:typescript",
      scope: "code",
      status: "completed",
      ruleIds: ["PG-SQL-001"],
      note: null,
    },
  ],
};
const historyOutput: AnalyzerOutput = {
  findings: [],
  coverage: [
    { area: "history:secrets", scope: "history", status: "completed", ruleIds: [], note: null },
  ],
};

const deps = (overrides: Record<string, unknown> = {}) => ({
  authorization: { getGitHubSession: async () => Promise.reject(new Error("unused")) },
  analyzers: { code: async () => codeOutput, history: async () => historyOutput },
  createScanId: () => "scan-1",
  now: () => new Date("2026-10-24T00:00:00Z"),
  ...overrides,
});

const request = (overrides: Partial<ScanRequest> = {}): ScanRequest => ({
  projectRoot: ROOT,
  scopes: ["code", "history"],
  webTarget: null,
  ...overrides,
});

beforeEach(() => {
  authorizeProject.mockReset();
});

describe("runScan", () => {
  it("does not run any analyzer when authorization is blocked", async () => {
    authorizeProject.mockResolvedValue(BLOCKED);
    const code = vi.fn(async () => codeOutput);
    const webScanner = vi.fn(async () => codeOutput);
    const result = await runScan(
      request({ scopes: ["code", "history", "web"] }),
      deps({ analyzers: { code, history: code }, webScanner }),
    );
    expect(result.overallStatus).toBe("blocked");
    expect(result.authorization.decision).toBe("blocked");
    expect(result.findings).toEqual([]);
    expect(code).not.toHaveBeenCalled();
    expect(webScanner).not.toHaveBeenCalled();
    expect(result.coverage.every((entry) => entry.status === "not_tested")).toBe(true);
  });

  it("treats a forged 'allowed' decision with failing checks as blocked", async () => {
    authorizeProject.mockResolvedValue({
      ...BLOCKED,
      summary: { ...BLOCKED.summary, decision: "allowed" },
    });
    const code = vi.fn(async () => codeOutput);
    const result = await runScan(request(), deps({ analyzers: { code, history: code } }));
    expect(result.overallStatus).toBe("blocked");
    expect(result.authorization.decision).toBe("blocked");
    expect(code).not.toHaveBeenCalled();
  });

  it("re-runs authorization on every scan", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    await runScan(request(), deps());
    await runScan(request(), deps());
    expect(authorizeProject).toHaveBeenCalledTimes(2);
  });

  it("records not-requested scopes as not_selected and completes", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    const result = await runScan(request(), deps());
    expect(result.overallStatus).toBe("completed");
    expect(result.coverage.find((entry) => entry.scope === "web")).toMatchObject({
      status: "not_selected",
    });
    expect(result.target).toEqual({
      repo: "octo/app",
      revision: "a".repeat(40),
      webOrigin: null,
    });
  });

  it("marks web not_tested and the scan partial when no target was confirmed", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    const webScanner = vi.fn(async () => codeOutput);
    const result = await runScan(
      request({ scopes: ["web", "code", "history"] }),
      deps({ webScanner }),
    );
    expect(result.overallStatus).toBe("partial");
    expect(result.requestedScopes).toEqual(["code", "history", "web"]);
    expect(result.coverage.find((entry) => entry.scope === "web")?.status).toBe("not_tested");
    expect(webScanner).not.toHaveBeenCalled();
  });

  it("refuses unconfirmed or non-loopback web targets", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    const webScanner = vi.fn(async () => codeOutput);
    const result = await runScan(
      request({
        scopes: ["web"],
        webTarget: {
          port: 3000,
          origin: "http://example.com:3000",
          title: null,
          confirmedByUser: true,
        },
      }),
      deps({ webScanner }),
    );
    expect(webScanner).not.toHaveBeenCalled();
    expect(result.overallStatus).toBe("partial");
    expect(result.target.webOrigin).toBeNull();
  });

  it("passes a confirmed loopback target to the injected web scanner", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    const webOutput: AnalyzerOutput = {
      findings: [
        finding({
          id: "w1",
          ruleId: "PG-WEB-001",
          location: {
            kind: "url",
            path: null,
            line: null,
            url: "http://127.0.0.1:3000/",
            commit: null,
          },
          sources: [],
        }),
      ],
      coverage: [
        { area: "web:anonymous", scope: "code", status: "completed", ruleIds: [], note: null },
      ],
    };
    const webScanner = vi.fn(async () => webOutput);
    const target = {
      port: 3000,
      origin: "http://127.0.0.1:3000",
      title: "App",
      confirmedByUser: true as const,
    };
    const result = await runScan(
      request({ scopes: ["web"], webTarget: target }),
      deps({ webScanner }),
    );
    expect(webScanner).toHaveBeenCalledWith(target, expect.any(Object));
    expect(result.overallStatus).toBe("completed");
    expect(result.target.webOrigin).toBe("http://127.0.0.1:3000");
    const webFinding = result.findings.find((entry) => entry.ruleId === "PG-WEB-001");
    expect(webFinding?.sources).toEqual(["web"]);
    expect(result.coverage.find((entry) => entry.area === "web:anonymous")?.scope).toBe("web");
  });

  it("keeps other results when one analyzer fails", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    const result = await runScan(
      request(),
      deps({
        analyzers: {
          code: async () => codeOutput,
          history: async () => {
            throw new Error(`boom at ${ROOT}`);
          },
        },
      }),
    );
    expect(result.overallStatus).toBe("partial");
    expect(result.findings).toHaveLength(1);
    const history = result.coverage.find((entry) => entry.scope === "history");
    expect(history?.status).toBe("not_tested");
    expect(JSON.stringify(result)).not.toContain(ROOT);
  });

  it("converts absolute paths to repository-relative paths", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    const result = await runScan(request(), deps());
    expect(result.findings[0]?.location.path).toBe("src/db.ts");
    expect(result.findings[0]?.evidence).toBe("query built in ./src/db.ts");
    expect(JSON.stringify(result)).not.toContain(ROOT);
  });

  it("drops paths that escape the project root", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    const outside = finding({
      location: { kind: "file", path: "/etc/passwd", line: 1, url: null, commit: null },
    });
    const result = await runScan(
      request({ scopes: ["code"] }),
      deps({ analyzers: { code: async () => ({ ...codeOutput, findings: [outside] }) } }),
    );
    expect(result.findings[0]?.location.path).toBeNull();
  });

  it("returns failed when the authorization gate throws", async () => {
    authorizeProject.mockRejectedValue(new Error("internal"));
    const result = await runScan(request(), deps());
    expect(result.overallStatus).toBe("failed");
    expect(result.authorization.decision).toBe("blocked");
  });

  it("rejects with ScanCancelledError when aborted", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    const controller = new AbortController();
    const promise = runScan(
      request(),
      deps({
        signal: controller.signal,
        analyzers: {
          code: async () => {
            controller.abort();
            return codeOutput;
          },
          history: async () => historyOutput,
        },
      }),
    );
    await expect(promise).rejects.toBeInstanceOf(ScanCancelledError);
  });

  it("rejects invalid requests before authorization", async () => {
    await expect(runScan(request({ projectRoot: "relative/path" }), deps())).rejects.toThrow(
      /absolute/,
    );
    await expect(runScan(request({ scopes: [] }), deps())).rejects.toThrow(/scope/);
    expect(authorizeProject).not.toHaveBeenCalled();
  });
});
