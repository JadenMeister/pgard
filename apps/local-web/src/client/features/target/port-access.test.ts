import { describe, expect, it, vi } from "vitest";
import type { AuthStatus } from "../../../shared/api-types";
import {
  isPortAccessAllowed,
  PortAccessController,
  portAccessMessage,
  startPortRequests,
} from "./port-access";

function auth(overrides: Partial<AuthStatus>): AuthStatus {
  return {
    status: "idle",
    deviceCode: null,
    summary: null,
    repo: null,
    message: null,
    ...overrides,
  };
}

/** The five checks the server reports, in order; all passed unless one is named as failing. */
function checks(failing: string | null = null): NonNullable<AuthStatus["summary"]>["checks"] {
  return (
    ["repository", "github_identity", "owner_approval", "current_access", "contribution"] as const
  ).map((id) => ({
    id,
    status: id === failing ? "failed" : "passed",
    reason: id === failing ? "Check failed." : "Check passed.",
  }));
}

const ALLOWED = auth({
  status: "done",
  summary: { decision: "allowed", checks: checks() },
  repo: "owner/name",
});
const NOT_ALLOWED: Array<[string, AuthStatus | null]> = [
  ["before any check", null],
  ["idle (signed out)", auth({ status: "idle" })],
  ["while the check runs", auth({ status: "running" })],
  [
    "after a blocked check",
    auth({ status: "done", summary: { decision: "blocked", checks: checks("owner_approval") } }),
  ],
  ["after a failed check", auth({ status: "failed", message: "network" })],
  ["done without a summary", auth({ status: "done" })],
];

describe("target panel port access", () => {
  it.each(NOT_ALLOWED)("does not list or probe ports %s", (_label, status) => {
    const listPorts = vi.fn();
    const probe = vi.fn();
    expect(isPortAccessAllowed(status)).toBe(false);
    expect(startPortRequests(status, 3000, { listPorts, probe })).toBe(false);
    expect(listPorts).not.toHaveBeenCalled();
    expect(probe).not.toHaveBeenCalled();
    expect(portAccessMessage(status)).toMatch(/authoriz/i);
  });

  it("lists ports and probes the --target-port port once authorization is allowed", () => {
    const listPorts = vi.fn();
    const probe = vi.fn();
    expect(isPortAccessAllowed(ALLOWED)).toBe(true);
    expect(portAccessMessage(ALLOWED)).toBeNull();
    expect(startPortRequests(ALLOWED, 3000, { listPorts, probe })).toBe(true);
    expect(listPorts).toHaveBeenCalledTimes(1);
    expect(probe).toHaveBeenCalledWith(3000);
  });

  it("does not probe anything extra without a preset port", () => {
    const probe = vi.fn();
    startPortRequests(ALLOWED, null, { listPorts: vi.fn(), probe });
    expect(probe).not.toHaveBeenCalled();
  });

  it("explains a blocked authorization differently from a pending one", () => {
    expect(portAccessMessage(NOT_ALLOWED[3]![1])).toContain("blocked");
    expect(portAccessMessage(auth({ status: "running" }))).toContain("Waiting");
  });
});

describe("target panel port access controller", () => {
  function controller(presetPort: number | null = 3000) {
    const handlers = { listPorts: vi.fn(), probe: vi.fn(), reset: vi.fn() };
    return { access: new PortAccessController(presetPort, handlers), ...handlers };
  }

  it.each(NOT_ALLOWED)("sends nothing %s", (_label, status) => {
    const { access, listPorts, probe } = controller();
    access.update(status);
    access.update(status);
    expect(listPorts).not.toHaveBeenCalled();
    expect(probe).not.toHaveBeenCalled();
    expect(access.currentToken()).toBeNull();
  });

  it("sends nothing while the check runs and starts once when it is allowed", () => {
    const { access, listPorts, probe } = controller();
    access.update(null);
    access.update(auth({ status: "running" }));
    expect(listPorts).not.toHaveBeenCalled();
    access.update(ALLOWED);
    // Polling and re-renders deliver the same status again (also as new objects).
    access.update(ALLOWED);
    access.update({ ...ALLOWED });
    expect(listPorts).toHaveBeenCalledTimes(1);
    expect(probe).toHaveBeenCalledTimes(1);
    expect(probe).toHaveBeenCalledWith(3000);
  });

  it("resets on sign-out or a new check and starts again only when allowed again", () => {
    const { access, listPorts, reset } = controller(null);
    access.update(ALLOWED);
    access.update(auth({ status: "idle" }));
    expect(reset).toHaveBeenCalledTimes(1);
    access.update(auth({ status: "running" }));
    expect(reset).toHaveBeenCalledTimes(1);
    expect(listPorts).toHaveBeenCalledTimes(1);
    access.update(ALLOWED);
    expect(listPorts).toHaveBeenCalledTimes(2);
  });

  it("drops responses from an access period that has closed, even after it reopens", () => {
    const { access } = controller();
    access.update(ALLOWED);
    const first = access.currentToken();
    expect(access.isCurrent(first)).toBe(true);
    access.update(auth({ status: "idle" }));
    expect(access.isCurrent(first)).toBe(false);
    access.update(ALLOWED);
    expect(access.isCurrent(first)).toBe(false);
    expect(access.isCurrent(access.currentToken())).toBe(true);
    expect(access.isCurrent(null)).toBe(false);
  });
});
