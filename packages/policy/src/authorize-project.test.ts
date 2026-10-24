import { describe, expect, it, vi } from "vitest";
import { authorizeProject, isAuthorizationAllowed } from "./authorize-project.js";
import { AUTHORIZATION_CHECK_ORDER } from "./types.js";

describe("authorizeProject (interface revision)", () => {
  it("blocks every project and never signs in", async () => {
    const getGitHubSession = vi.fn();
    const outcome = await authorizeProject("/tmp/project", { getGitHubSession });
    expect(outcome.summary.decision).toBe("blocked");
    expect(outcome.summary.checks.map((check) => check.id)).toEqual(AUTHORIZATION_CHECK_ORDER);
    expect(isAuthorizationAllowed(outcome)).toBe(false);
    expect(getGitHubSession).not.toHaveBeenCalled();
  });
});

describe("isAuthorizationAllowed", () => {
  it("requires every check to pass, not just the decision flag", () => {
    const passed = AUTHORIZATION_CHECK_ORDER.map((id) => ({
      id,
      status: "passed" as const,
      reason: "",
    }));
    expect(
      isAuthorizationAllowed({
        summary: { decision: "allowed", checks: passed },
        repo: "o/r",
        revision: null,
      }),
    ).toBe(true);
    expect(
      isAuthorizationAllowed({
        summary: {
          decision: "allowed",
          checks: passed.map((check, index) =>
            index === 4 ? { ...check, status: "unverifiable" as const } : check,
          ),
        },
        repo: "o/r",
        revision: null,
      }),
    ).toBe(false);
    expect(
      isAuthorizationAllowed({
        summary: { decision: "allowed", checks: passed.slice(0, 4) },
        repo: "o/r",
        revision: null,
      }),
    ).toBe(false);
  });

  it("rejects duplicate or reordered check ids even when all are passed", () => {
    const duplicates = AUTHORIZATION_CHECK_ORDER.map(() => ({
      id: "repository" as const,
      status: "passed" as const,
      reason: "",
    }));
    expect(
      isAuthorizationAllowed({
        summary: { decision: "allowed", checks: duplicates },
        repo: "o/r",
        revision: null,
      }),
    ).toBe(false);
    const reordered = [...AUTHORIZATION_CHECK_ORDER].reverse().map((id) => ({
      id,
      status: "passed" as const,
      reason: "",
    }));
    expect(
      isAuthorizationAllowed({
        summary: { decision: "allowed", checks: reordered },
        repo: "o/r",
        revision: null,
      }),
    ).toBe(false);
  });

  it("rejects a blocked decision even when all checks passed", () => {
    const passed = AUTHORIZATION_CHECK_ORDER.map((id) => ({
      id,
      status: "passed" as const,
      reason: "",
    }));
    expect(
      isAuthorizationAllowed({
        summary: { decision: "blocked", checks: passed },
        repo: "o/r",
        revision: null,
      }),
    ).toBe(false);
  });
});
