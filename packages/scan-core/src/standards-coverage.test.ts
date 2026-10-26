import type { AnalyzerOutput, Coverage, RuleStat, ScanRequest, ScanResult } from "@pgard/findings";
import type { AuthorizationOutcome } from "@pgard/policy";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { sessionProvider } from "../../policy/src/test-support/mock-github.js";

const authorizeProject = vi.fn<(root: string) => Promise<AuthorizationOutcome>>();

vi.mock("@pgard/policy", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@pgard/policy")>();
  return { ...actual, authorizeProject: (root: string) => authorizeProject(root) };
});

const { runScan, listSupportedRules } = await import("./index.js");

const ROOT = "/home/user/projects/app";
const checks = (
  ["repository", "github_identity", "owner_approval", "current_access", "contribution"] as const
).map((id) => ({ id, status: "passed" as const, reason: "ok" }));
const ALLOWED: AuthorizationOutcome = {
  summary: { decision: "allowed", checks },
  repo: "octo/app",
  revision: "a".repeat(40),
};
const BLOCKED: AuthorizationOutcome = {
  summary: { decision: "blocked", checks },
  repo: "octo/app",
  revision: null,
};

const cov = (
  area: string,
  scope: Coverage["scope"],
  status: Coverage["status"],
  ruleIds: string[] = [],
): Coverage => ({ area, scope, status, ruleIds, note: null });

const row = (
  ruleId: string,
  area: string,
  status: RuleStat["status"],
  scope: RuleStat["scope"] = "code",
): RuleStat => ({
  ruleId,
  area,
  scope,
  status,
  targets: [{ unit: "files", examined: 4, reason: null }],
  findings: 0,
});

const run = (
  code: AnalyzerOutput,
  history: AnalyzerOutput = {
    findings: [],
    coverage: [cov("history:commits", "history", "not_tested")],
  },
  extra: Record<string, unknown> = {},
  scopes: ScanRequest["scopes"] = ["code", "history"],
): Promise<ScanResult> =>
  runScan(
    { projectRoot: ROOT, scopes, webTarget: null },
    {
      authorization: {
        getGitHubSession: sessionProvider(async () => Promise.reject(new Error("unused"))),
      },
      analyzers: { code: async () => code, history: async () => history },
      createScanId: () => "scan-1",
      now: () => new Date("2026-10-24T00:00:00Z"),
      ...extra,
    },
  );

beforeEach(() => {
  authorizeProject.mockReset();
  authorizeProject.mockResolvedValue(ALLOWED);
});

describe("runScan: ruleStats", () => {
  it("keeps what the analyzer measured and takes the status from the area's coverage", async () => {
    const result = await run({
      findings: [],
      coverage: [cov("source:typescript", "code", "partial", ["PG-SQL-001"])],
      // The analyzer claimed `completed`; the area says `partial`. Coverage wins.
      ruleStats: [row("PG-SQL-001", "source:typescript", "completed")],
    });
    expect(result.ruleStats).toEqual([row("PG-SQL-001", "source:typescript", "partial")]);
  });

  it("marks the count unknown, with a reason, when the analyzer reported none", async () => {
    const result = await run({
      findings: [],
      coverage: [cov("source:typescript", "code", "completed", ["PG-SQL-001", "PG-XSS-001"])],
    });
    expect(result.ruleStats).toHaveLength(2);
    for (const stat of result.ruleStats ?? []) {
      expect(stat.targets).toEqual([
        { unit: "unknown", examined: null, reason: expect.stringContaining("did not report") },
      ]);
    }
  });

  it("has no row for a rule of an area that did not run, or that coverage does not list", async () => {
    const result = await run({
      findings: [],
      coverage: [
        cov("source:go", "code", "not_tested", ["PG-SQL-003"]),
        cov("source:typescript", "code", "completed", ["PG-SQL-001"]),
      ],
      ruleStats: [
        row("PG-SQL-003", "source:go", "completed"),
        row("PG-SQL-001", "source:typescript", "completed"),
        row("PG-NOT-LISTED", "source:typescript", "completed"),
      ],
    });
    expect(result.ruleStats?.map((stat) => `${stat.area}|${stat.ruleId}`)).toEqual([
      "source:typescript|PG-SQL-001",
    ]);
  });

  it("forces the stat's scope to the stage's scope", async () => {
    const result = await run({
      findings: [],
      coverage: [cov("source:typescript", "code", "completed", ["PG-SQL-001"])],
      ruleStats: [row("PG-SQL-001", "source:typescript", "completed", "web")],
    });
    expect(result.ruleStats?.[0]?.scope).toBe("code");
  });

  it("is empty for a blocked scan, and nothing is checked", async () => {
    authorizeProject.mockResolvedValue(BLOCKED);
    const result = await run({ findings: [], coverage: [] });
    expect(result.overallStatus).toBe("blocked");
    expect(result.ruleStats).toEqual([]);
    expect(
      result.standardsCoverage?.owasp.every(
        (entry) => entry.state === "not_run" || entry.state === "no_rules",
      ),
    ).toBe(true);
  });
});

describe("runScan: standardsCoverage with the real rule catalog", () => {
  const tsCompleted: AnalyzerOutput = {
    findings: [],
    coverage: [cov("source:typescript", "code", "completed", ["PG-SQL-001"])],
    ruleStats: [row("PG-SQL-001", "source:typescript", "completed")],
  };

  it("derives A05 and CWE-89 from the rules' own mappings", async () => {
    const result = await run(tsCompleted);
    const a05 = result.standardsCoverage?.owasp.find((entry) => entry.id === "A05:2025");
    expect(a05).toMatchObject({ state: "rules_ran", ruleIds: ["PG-SQL-001"] });
    expect(a05?.mappedRuleIds).toContain("PG-SQL-003");
    expect(result.standardsCoverage?.cweTop25.find((entry) => entry.id === "CWE-89")?.state).toBe(
      "rules_ran",
    );
  });

  it("downgrades to rules_partial when a Java project sits next to the TypeScript one", async () => {
    const result = await run({
      ...tsCompleted,
      coverage: [...tsCompleted.coverage, cov("source:java", "code", "not_tested")],
    });
    expect(result.standardsCoverage?.owasp.find((e) => e.id === "A05:2025")?.state).toBe(
      "rules_partial",
    );
  });

  it("downgrades to rules_partial when the TypeScript area was partial", async () => {
    const result = await run({
      findings: [],
      coverage: [cov("source:typescript", "code", "partial", ["PG-SQL-001"])],
      ruleStats: [row("PG-SQL-001", "source:typescript", "partial")],
    });
    expect(result.standardsCoverage?.owasp.find((e) => e.id === "A05:2025")?.state).toBe(
      "rules_partial",
    );
  });

  it("is not_run when the code scope was not requested", async () => {
    const result = await run(tsCompleted, undefined, {}, ["history"]);
    const a05 = result.standardsCoverage?.owasp.find((entry) => entry.id === "A05:2025");
    expect(a05?.state).toBe("not_run");
    expect(a05?.reason).toContain("code scope not selected");
  });

  it("counts committed dependency directories (PG-HYGIENE-001) for A03, and nothing else", async () => {
    // Decision: OSV advisories are not part of a scan (PGARD ships no vulnerability database), so
    // they never count. A03 maps only to PG-HYGIENE-001 today.
    const result = await run(tsCompleted);
    const a03 = result.standardsCoverage?.owasp.find((entry) => entry.id === "A03:2025");
    expect(a03?.mappedRuleIds).toEqual(["PG-HYGIENE-001"]);
    expect(a03?.state).toBe("not_run");
    const withHistory = await run(tsCompleted, {
      findings: [],
      coverage: [cov("history:tracked-files", "history", "completed", ["PG-HYGIENE-001"])],
      ruleStats: [row("PG-HYGIENE-001", "history:tracked-files", "completed", "history")],
    });
    expect(
      withHistory.standardsCoverage?.owasp.find((entry) => entry.id === "A03:2025")?.state,
    ).toBe("rules_ran");
  });

  it("includes web rules only when the launcher passes them", async () => {
    const web: AnalyzerOutput = {
      findings: [],
      coverage: [cov("web:anonymous", "web", "completed", ["PG-WEB-X"])],
      ruleStats: [row("PG-WEB-X", "web:anonymous", "completed", "web")],
    };
    const webRule = {
      id: "PG-WEB-X",
      metadata: {
        standards: { owasp: ["A02:2025"], cwe: ["CWE-693"], cert: [] },
        rationale: { en: "", ko: "" },
        remediation: { en: "", ko: "" },
      },
    };
    const target = {
      port: 3000,
      origin: "http://127.0.0.1:3000",
      title: null,
      confirmedByUser: true as const,
    };
    const call = (extra: Record<string, unknown>) =>
      runScan(
        { projectRoot: ROOT, scopes: ["web"], webTarget: target },
        {
          authorization: {
            getGitHubSession: sessionProvider(async () => Promise.reject(new Error("unused"))),
          },
          webScanner: async () => web,
          createScanId: () => "scan-1",
          now: () => new Date("2026-10-24T00:00:00Z"),
          ...extra,
        },
      );
    // Without the catalog the map would claim more than it can support, so the scan refuses.
    await expect(call({})).rejects.toThrow("webRules");
    const withRules = await call({ webRules: [webRule] });
    expect(withRules.standardsCoverage?.owasp.find((e) => e.id === "A02:2025")).toMatchObject({
      // The code rules that map to A02 (PG-COOKIE-001) were not selected in this web-only scan.
      state: "rules_partial",
      ruleIds: ["PG-WEB-X"],
    });
    expect(withRules.standardsCoverage?.owasp.find((e) => e.id === "A02:2025")?.reason).toContain(
      "code rules not run: scope not selected",
    );
  });

  it("invariant: no entry is `rules_ran` unless every contributing row is completed", async () => {
    const statuses = ["completed", "partial"] as const;
    for (const ts of statuses) {
      for (const go of statuses) {
        const result = await run({
          findings: [],
          coverage: [
            cov("source:typescript", "code", ts, ["PG-SQL-001", "PG-XSS-001", "PG-CMD-001"]),
            cov("source:go", "code", go, ["PG-SQL-003", "PG-CMD-002"]),
          ],
          ruleStats: [
            ...["PG-SQL-001", "PG-XSS-001", "PG-CMD-001"].map((id) =>
              row(id, "source:typescript", ts),
            ),
            ...["PG-SQL-003", "PG-CMD-002"].map((id) => row(id, "source:go", go)),
          ],
        });
        const partialIds = new Set(
          (result.ruleStats ?? []).filter((s) => s.status === "partial").map((s) => s.ruleId),
        );
        for (const entry of [
          ...(result.standardsCoverage?.owasp ?? []),
          ...(result.standardsCoverage?.cweTop25 ?? []),
        ]) {
          if (entry.state === "rules_ran") {
            expect(entry.ruleIds.length).toBeGreaterThan(0);
            expect(entry.ruleIds.some((id) => partialIds.has(id))).toBe(false);
          }
        }
      }
    }
  });

  it("every rule id a state lists exists in the catalog", async () => {
    const result = await run(tsCompleted);
    const known = new Set(listSupportedRules().map((rule) => rule.id));
    for (const entry of result.standardsCoverage?.owasp ?? []) {
      for (const id of entry.mappedRuleIds) expect(known.has(id)).toBe(true);
    }
  });
});
