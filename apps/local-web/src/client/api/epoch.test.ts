import { afterEach, describe, expect, it, vi } from "vitest";
import {
  apiGet,
  apiPost,
  getProjectEpoch,
  setProjectChangedListener,
  setProjectEpoch,
  setSessionSecret,
} from "./client";

function useToken(): void {
  setSessionSecret("abcdefghijklmnopqrstuvwxyz012345");
}

afterEach(() => {
  vi.unstubAllGlobals();
  setProjectEpoch(null);
  setProjectChangedListener(null);
});

function stubFetch(status = 200, body: unknown = {}) {
  const calls: Array<{ path: string; body: unknown }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: string, init: { body?: string }) => {
      calls.push({ path, body: init.body === undefined ? undefined : JSON.parse(init.body) });
      return new Response(JSON.stringify(body), { status });
    }),
  );
  return calls;
}

describe("project epoch on state-changing project calls", () => {
  it("adds the epoch to the verify, owner-approval, probe, target and scan calls only", async () => {
    useToken();
    const calls = stubFetch();
    setProjectEpoch(3);
    expect(getProjectEpoch()).toBe(3);
    for (const path of [
      "/api/auth/verify",
      "/api/auth/owner-approval",
      "/api/ports/probe",
      "/api/target/confirm",
      "/api/scan",
    ]) {
      await apiPost(path, { port: 3000 });
    }
    await apiPost("/api/auth/sign-out", { removeStored: true });
    await apiPost("/api/scan/cancel");
    expect(calls.slice(0, 5).every((call) => (call.body as { epoch: number }).epoch === 3)).toBe(
      true,
    );
    expect(calls[0]?.body).toEqual({ port: 3000, epoch: 3 });
    expect(calls[5]?.body).toEqual({ removeStored: true });
    expect(calls[6]?.body).toEqual({});
  });

  it("sends no epoch before the session told one", async () => {
    useToken();
    const calls = stubFetch();
    await apiPost("/api/scan", { scopes: ["code"] });
    expect(calls[0]?.body).toEqual({ scopes: ["code"] });
  });

  it("tells the page when the server says the project changed", async () => {
    useToken();
    stubFetch(409, { error: { code: "project_changed", message: "x" } });
    const changed = vi.fn();
    setProjectChangedListener(changed);
    await expect(apiPost("/api/scan", {})).rejects.toMatchObject({ code: "project_changed" });
    expect(changed).toHaveBeenCalledOnce();
    stubFetch(409, { error: { code: "scan_running", message: "x" } });
    await expect(apiGet("/api/scan")).rejects.toMatchObject({ code: "scan_running" });
    expect(changed).toHaveBeenCalledOnce();
  });
});
