import { describe, expect, it } from "vitest";
import type { Coverage, Finding } from "./contract.js";
import { deriveOverallStatus, summarizeBySeverity } from "./summary.js";

const coverage = (scope: Coverage["scope"], status: Coverage["status"]): Coverage => ({
  area: scope,
  scope,
  status,
  ruleIds: [],
  note: null,
});

describe("summarizeBySeverity", () => {
  it("counts every severity, including zeros", () => {
    const findings = [{ severity: "high" }, { severity: "high" }, { severity: "low" }] as Finding[];
    expect(summarizeBySeverity(findings)).toEqual({
      critical: 0,
      high: 2,
      medium: 0,
      low: 1,
      info: 0,
    });
  });
});

describe("deriveOverallStatus", () => {
  it("is blocked whenever authorization is blocked", () => {
    expect(
      deriveOverallStatus({
        decision: "blocked",
        requestedScopes: ["code"],
        coverage: [coverage("code", "completed")],
      }),
    ).toBe("blocked");
  });

  it("is partial for scan all without web", () => {
    expect(
      deriveOverallStatus({
        decision: "allowed",
        requestedScopes: ["code", "history", "web"],
        coverage: [
          coverage("code", "completed"),
          coverage("history", "completed"),
          coverage("web", "not_tested"),
        ],
      }),
    ).toBe("partial");
  });

  it("ignores not_selected scopes", () => {
    expect(
      deriveOverallStatus({
        decision: "allowed",
        requestedScopes: ["code"],
        coverage: [coverage("code", "completed"), coverage("web", "not_selected")],
      }),
    ).toBe("completed");
  });

  it("is partial when a requested scope has no coverage", () => {
    expect(
      deriveOverallStatus({
        decision: "allowed",
        requestedScopes: ["code", "history"],
        coverage: [coverage("code", "completed")],
      }),
    ).toBe("partial");
  });
});
