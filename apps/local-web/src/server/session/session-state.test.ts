import { describe, expect, it } from "vitest";
import {
  ACCOUNT_CHANGED_NOTICE,
  clearSessionState,
  createSessionState,
  isWithinWindow,
  setAuth,
} from "./session-state.js";
import { applySignInNotice } from "./stored-sign-in.js";

describe("session state", () => {
  it("aborts the running scan and in-flight probes on shutdown, then forgets everything", () => {
    const state = createSessionState();
    const scan = new AbortController();
    state.scan = {
      status: "running",
      scopes: ["code"],
      progress: [],
      result: null,
      message: null,
      controller: scan,
    };
    const probes = state.portAccessController;
    state.signInNotice = "Using the GitHub sign-in for octo saved in the OS keychain.";
    state.authAccount = { login: "octo", userId: 7 };
    clearSessionState(state);
    expect(scan.signal.aborted).toBe(true);
    expect(probes.signal.aborted).toBe(true);
    expect(state.portAccessController.signal.aborted).toBe(false);
    expect(state.scan).toMatchObject({ status: "idle", controller: null });
    expect(state.signInNotice).toBeNull();
    expect(state.authAccount).toBeNull();
  });

  it("treats a clock that moved back as outside every window", () => {
    expect(isWithinWindow(1_000, 1_000, 10)).toBe(true);
    expect(isWithinWindow(999, 1_000, 10)).toBe(false);
    expect(isWithinWindow(1_011, 1_000, 10)).toBe(false);
    expect(isWithinWindow(1_000, null, 10)).toBe(false);
  });

  it("resets the latest check when the provider adopts another account", () => {
    const state = createSessionState();
    setAuth(state, { status: "done", outcome: null, finishedAt: 1, message: null });
    state.authAccount = { login: "octo", userId: 7 };
    const probes = state.portAccessController;

    // The same account again (e.g. a token refresh) keeps the check.
    applySignInNotice(state, { kind: "reused", login: "octo", userId: 7, isRefreshed: true });
    expect(state.auth.status).toBe("done");

    // Same login, different account id: a different account.
    applySignInNotice(state, { kind: "saved", login: "octo", userId: 8 });
    expect(state.auth).toEqual({ status: "idle", outcome: null, finishedAt: null, message: null });
    expect(probes.signal.aborted).toBe(true);
    expect(state.authAccount).toBeNull();
    expect(state.signInNotice).toBe(ACCOUNT_CHANGED_NOTICE);
    expect(state.sessionAccount).toEqual({ login: "octo", userId: 8 });
  });
});
