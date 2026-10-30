import { afterEach, describe, expect, it, vi } from "vitest";
import type { PickerCandidate, PickerSearchResponse } from "../shared/picker-types.js";
import { repoCandidate } from "./test-support/fake-inspector.js";
import {
  apiGet,
  apiPost,
  json,
  result,
  send,
  startHarness,
  TOKEN,
  waitFor,
  type Harness,
} from "./test-support/web-harness.js";

/** `POST /api/code-scan`, the code-only scan of the simple screen (#414). */

let harness: Harness | null = null;
afterEach(async () => {
  await harness?.close();
  harness = null;
});

async function selectShop(h: Harness): Promise<void> {
  h.inspector.repos.set("shop", [repoCandidate("shop")]);
  h.clock.now += 2_000;
  const started = await apiPost(h.server, "/api/picker/search", {
    source: "typed",
    name: "shop",
    epoch: h.server.state.projectEpoch,
  });
  const { searchId } = json(started) as { searchId: string };
  const done = (await waitFor(
    async () => json(await apiGet(h.server, `/api/picker/search?id=${searchId}`)),
    (value) => value.status !== "running",
  )) as unknown as PickerSearchResponse;
  const candidate = done.candidates[0] as PickerCandidate;
  const confirmed = await apiPost(h.server, "/api/picker/confirm", {
    candidateId: candidate.candidateId,
    shown: candidate.shown,
    epoch: h.server.state.projectEpoch,
  });
  expect(confirmed.status).toBe(200);
}

describe("POST /api/code-scan", () => {
  it("is on in picker mode without any flag; ui: full keeps the route", async () => {
    harness = await startHarness();
    expect(json(await apiGet(harness.server, "/api/session")).ui).toBe("simple");
    const response = await apiPost(harness.server, "/api/code-scan", { epoch: 1 });
    expect((json(response).error as { code: string }).code).toBe("no_project");
    await harness.close();
    harness = await startHarness({ ui: "full" });
    expect(json(await apiGet(harness.server, "/api/session")).ui).toBe("full");
    expect((await apiPost(harness.server, "/api/code-scan", { epoch: 1 })).status).toBe(409);
  });

  it("is never on in fixed mode, even when asked for", async () => {
    harness = await startHarness({ fixedRoot: "/home/u/code/shop", ui: "simple" });
    expect(json(await apiGet(harness.server, "/api/session")).ui).toBe("full");
    expect((await apiPost(harness.server, "/api/code-scan", {})).status).toBe(404);
  });

  it("keeps the token, Host and Origin checks", async () => {
    harness = await startHarness();
    const port = harness.server.port;
    const noToken = await send(harness.server, "POST", "/api/code-scan", {
      headers: { origin: `http://127.0.0.1:${port}`, "content-type": "application/json" },
      body: "{}",
    });
    expect(noToken.status).toBe(401);
    const foreign = await send(harness.server, "POST", "/api/code-scan", {
      headers: {
        origin: "http://evil.example",
        "content-type": "application/json",
        "x-pgard-token": TOKEN,
      },
      body: "{}",
    });
    expect(foreign.status).toBe(403);
    const badHost = await send(harness.server, "POST", "/api/code-scan", {
      headers: {
        host: `localhost:${port}`,
        "x-pgard-token": TOKEN,
        origin: `http://127.0.0.1:${port}`,
        "content-type": "application/json",
      },
      body: "{}",
    });
    expect(badHost.status).toBe(421);
  });

  it("needs a confirmed project", async () => {
    harness = await startHarness();
    const response = await apiPost(harness.server, "/api/code-scan", { epoch: 1 });
    expect(response.status).toBe(409);
    expect((json(response).error as { code: string }).code).toBe("no_project");
  });

  it("runs the code-only scan without the gate and labels the result", async () => {
    const runCodeOnlyScan = vi.fn(async () =>
      result({
        target: { repo: null, revision: null, webOrigin: null },
        scanBasis: { mode: "code_only", authorization: "not_verified", reason: "not_checked" },
      }),
    );
    const runScan = vi.fn(async () => result());
    const verifyProject = vi.fn();
    harness = await startHarness({ deps: { runCodeOnlyScan, runScan, verifyProject } });
    await selectShop(harness);
    const started = await apiPost(harness.server, "/api/code-scan", {
      epoch: harness.server.state.projectEpoch,
    });
    expect(started.status).toBe(200);
    const done = await waitFor(
      async () => json(await apiGet(harness!.server, "/api/scan")),
      (value) => value.status === "done",
    );
    expect(done.codeOnly).toBe(true);
    expect(done.scopes).toEqual(["code"]);
    expect(runCodeOnlyScan).toHaveBeenCalledOnce();
    expect(runScan).not.toHaveBeenCalled();
    expect(verifyProject).not.toHaveBeenCalled();
    // The identity of the confirmed folder is re-checked before the scan, like an authorized one.
    expect(harness.inspector.runs.some((run) => run.job.kind === "inspect")).toBe(true);
    // The real path never reaches the browser.
    expect(JSON.stringify(done)).not.toContain("/home/u/code/shop");
    // D5: a code-only result is exported, with the "not authorized" banner.
    const report = await apiGet(harness.server, "/api/reports/html");
    expect(report.status).toBe(200);
    expect(report.body).toContain("Not authorized: code-only scan");
  });
});
