import {
  readScanResult,
  SCHEMA_VERSION,
  type AnalyzerOutput,
  type Finding,
  type ScanRequest,
} from "@pgard/findings";
import type { AuthorizationOutcome } from "@pgard/policy";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { sessionProvider } from "../../policy/src/test-support/mock-github.js";

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
  authorization: {
    getGitHubSession: sessionProvider(async () => Promise.reject(new Error("unused"))),
  },
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
  it("produces a result that the reader accepts unchanged, also after a JSON round trip", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    const result = await runScan(request(), deps());
    expect(result.findings.length).toBeGreaterThan(0);
    expect(readScanResult(result)).toEqual({ ok: true, result, sourceVersion: SCHEMA_VERSION });
    expect(readScanResult(JSON.parse(JSON.stringify(result)))).toEqual({
      ok: true,
      result,
      sourceVersion: SCHEMA_VERSION,
    });
    authorizeProject.mockResolvedValue(BLOCKED);
    const blocked = await runScan(request(), deps());
    expect(readScanResult(blocked)).toEqual({
      ok: true,
      result: blocked,
      sourceVersion: SCHEMA_VERSION,
    });
  });

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

  it("hands the authorization outcome to onAuthorization, which cannot change the result", async () => {
    authorizeProject.mockResolvedValue(BLOCKED);
    const seen: AuthorizationOutcome[] = [];
    const blocked = await runScan(
      request(),
      deps({ onAuthorization: (outcome: AuthorizationOutcome) => seen.push(outcome) }),
    );
    expect(seen).toEqual([BLOCKED]);
    expect(blocked.overallStatus).toBe("blocked");

    authorizeProject.mockResolvedValue(ALLOWED);
    const allowed = await runScan(
      request(),
      deps({
        onAuthorization: () => {
          throw new Error("display failure");
        },
      }),
    );
    expect(allowed.overallStatus).toBe("completed");
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

  it("marks code and history findings in test or fixture code", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    const file = (path: string) => ({
      kind: "file" as const,
      path,
      line: 1,
      url: null,
      commit: null,
    });
    const code: AnalyzerOutput = {
      ...codeOutput,
      findings: [
        finding({ id: "c1", location: file(`${ROOT}/src/db.ts`) }),
        finding({ id: "c2", confidence: "high", location: file(`${ROOT}/src/db.test.ts`) }),
        finding({
          id: "d1",
          ruleId: "PG-SQL-003",
          location: file("testdata/seed.go"),
        }),
      ],
    };
    const history: AnalyzerOutput = {
      ...historyOutput,
      findings: [
        finding({
          id: "h1",
          ruleId: "PG-SECRET-003",
          severity: "critical",
          confidence: "high",
          location: { ...file("fixtures/key.pem"), kind: "commit", commit: "b".repeat(40) },
          sources: ["history"],
        }),
      ],
    };
    const result = await runScan(
      request(),
      deps({ analyzers: { code: async () => code, history: async () => history } }),
    );
    const byId = new Map(result.findings.map((entry) => [entry.id, entry]));
    expect(result.findings).toHaveLength(4);
    expect(byId.get("c1")?.context).toBeUndefined();
    expect(byId.get("c1")?.confidence).toBe("medium");
    for (const id of ["c2", "d1", "h1"]) {
      expect(byId.get(id)).toMatchObject({ context: "test", confidence: "low" });
    }
    // Rule, severity and evidence are kept.
    expect(byId.get("h1")).toMatchObject({ ruleId: "PG-SECRET-003", severity: "critical" });
  });

  it("marks findings in committed vendored code as suggestions without changing status", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    const history: AnalyzerOutput = {
      ...historyOutput,
      findings: [
        finding({
          id: "v1",
          ruleId: "PG-SECRET-002",
          severity: "high",
          confidence: "medium",
          location: {
            kind: "file",
            path: "node_modules/pkg/test/index.js",
            line: 3,
            url: null,
            commit: null,
          },
          sources: ["history"],
        }),
      ],
    };
    const result = await runScan(
      request(),
      deps({ analyzers: { code: async () => codeOutput, history: async () => history } }),
    );
    const vendored = result.findings.find((entry) => entry.id === "v1");
    // Kept (rule, severity unchanged), vendored wins over the test path, confidence capped.
    expect(vendored).toMatchObject({
      ruleId: "PG-SECRET-002",
      severity: "high",
      context: "vendored",
      confidence: "low",
    });
    const withoutVendored = await runScan(
      request(),
      deps({
        analyzers: {
          code: async () => codeOutput,
          history: async () => ({ ...history, findings: [] }),
        },
      }),
    );
    // The grouping never changes coverage or the overall status.
    expect(result.overallStatus).toBe(withoutVendored.overallStatus);
    expect(result.coverage).toEqual(withoutVendored.coverage);
  });

  it("classifies vendored code after making paths repository-relative", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    // The project itself lives under a directory named vendor/: only the path inside the
    // repository may decide the context.
    const projectRoot = "/x/vendor/proj";
    const code: AnalyzerOutput = {
      ...codeOutput,
      findings: [
        finding({
          id: "p1",
          location: {
            kind: "file",
            path: `${projectRoot}/server/db.ts`,
            line: 1,
            url: null,
            commit: null,
          },
        }),
      ],
    };
    const result = await runScan(
      request({ projectRoot }),
      deps({
        analyzers: {
          code: async () => code,
          history: async () => ({ ...historyOutput, findings: [] }),
        },
      }),
    );
    const own = result.findings.find((entry) => entry.id === "p1");
    expect(own?.location.path).toBe("server/db.ts");
    expect(own?.context).toBeUndefined();
    expect(own?.confidence).toBe("medium");
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

  it("redacts secrets in analyzer and web scanner output", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    const fakeToken = ["ghp", "_", "z".repeat(36)].join("");
    const leaky = finding({ evidence: `found ${fakeToken}`, title: `token ${fakeToken}` });
    const webScanner = vi.fn(async () => ({
      findings: [finding({ id: "w", evidence: `Set-Cookie: sid=${fakeToken}`, sources: ["web"] })],
      coverage: [
        {
          area: "web:anonymous",
          scope: "web" as const,
          status: "completed" as const,
          ruleIds: [],
          note: null,
        },
      ],
    }));
    const result = await runScan(
      request({
        scopes: ["code", "web"],
        webTarget: {
          port: 3000,
          origin: "http://127.0.0.1:3000",
          title: null,
          confirmedByUser: true,
        },
      }),
      deps({ analyzers: { code: async () => ({ ...codeOutput, findings: [leaky] }) }, webScanner }),
    );
    expect(JSON.stringify(result)).not.toContain(fakeToken);
    expect(result.findings[0]?.evidence).toContain("[REDACTED:");
  });

  it("merges the same finding from code and web, preserving both sources", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    const webScanner = vi.fn(async () => ({
      findings: [finding({ sources: ["web"], evidence: "header missing" })],
      coverage: [
        {
          area: "web:anonymous",
          scope: "web" as const,
          status: "completed" as const,
          ruleIds: [],
          note: null,
        },
      ],
    }));
    const result = await runScan(
      request({
        scopes: ["code", "web"],
        webTarget: {
          port: 3000,
          origin: "http://127.0.0.1:3000",
          title: null,
          confirmedByUser: true,
        },
      }),
      deps({ webScanner }),
    );
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.sources).toEqual(["code", "web"]);
  });

  it("redacts coverage notes (#53)", async () => {
    authorizeProject.mockResolvedValue(ALLOWED);
    const fakeToken = ["ghp", "_", "n".repeat(36)].join("");
    const result = await runScan(
      request({ scopes: ["code"] }),
      deps({
        analyzers: {
          code: async () => ({
            findings: [],
            coverage: [
              {
                area: "source:typescript",
                scope: "code" as const,
                status: "partial" as const,
                ruleIds: [],
                note: `failed on ${ROOT}/src/x.ts with ${fakeToken} under /opt/cache/y`,
              },
            ],
          }),
        },
      }),
    );
    const json = JSON.stringify(result.coverage);
    expect(json).not.toContain(fakeToken);
    expect(json).not.toContain(ROOT);
    expect(json).not.toContain("/opt/cache");
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
