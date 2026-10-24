import { describe, expect, it, vi } from "vitest";
import type { AuthStatus } from "../../../shared/api-types";
import { isPortAccessAllowed, portAccessMessage, startPortRequests } from "./port-access";

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

const ALLOWED = auth({ status: "done", summary: { decision: "allowed", checks: [] } });
const NOT_ALLOWED: Array<[string, AuthStatus | null]> = [
  ["before any check", null],
  ["idle (signed out)", auth({ status: "idle" })],
  ["while the check runs", auth({ status: "running" })],
  ["after a blocked check", auth({ status: "done", summary: { decision: "blocked", checks: [] } })],
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
