import type { ScanResult } from "@pgard/findings";
import type { AuthorizationOutcome, ScanDependencies } from "@pgard/scan-core";
import type { ServerDeps } from "./deps.js";

type ScanRequest = Parameters<ServerDeps["runScan"]>[0];
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ScanStatus } from "../shared/api-types.js";
import type { PickerPathResponse } from "../shared/picker-types.js";
import { gateReasonOf } from "./routes/api.js";
import { repoCandidate } from "./test-support/fake-inspector.js";
import {
  apiGet,
  apiPost,
  json,
  outcome,
  result,
  startHarness,
  waitFor,
  type Harness,
} from "./test-support/web-harness.js";

/**
 * The simple screen's scan (#414, phase 4): the gate first with an existing sign-in only, a
 * plain reason when it does not pass, and a code-only scan only after an explicit request.
 */

let harness: Harness | null = null;
afterEach(async () => {
  await harness?.close();
  harness = null;
});

const SHOP = "/home/u/code/shop";
const NOTES = "/home/u/code/notes";

const blocked = (failing: Parameters<typeof outcome>[0], extra = {}): AuthorizationOutcome =>
  outcome(failing, extra);

function blockedResult(gate: AuthorizationOutcome): ScanResult {
  return result({
    overallStatus: "blocked",
    authorization: gate.summary,
    scanBasis: { mode: "authorized", authorization: "not_verified", reason: "no_approval" },
  });
}

/** A `runScan` that hands the gate's outcome to the server, as scan-core does. */
function gateScan(gate: AuthorizationOutcome, scanned: ScanResult) {
  return vi.fn(async (_request: ScanRequest, deps: ScanDependencies) => {
    deps.onAuthorization?.(gate);
    return scanned;
  });
}

const codeOnlyResult = (): ScanResult =>
  result({
    target: { repo: null, revision: null, webOrigin: null },
    scanBasis: { mode: "code_only", authorization: "not_verified", reason: "no_approval" },
  });

async function choose(h: Harness, folder: string, candidate = repoCandidate("shop")) {
  h.inspector.resolved.set(folder, { candidate, folderBlock: null });
  const response = await apiPost(h.server, "/api/picker/path", { path: folder });
  const chosen = (json(response) as unknown as PickerPathResponse).candidate;
  expect(chosen?.selectable).toBe(true);
  const confirmed = await apiPost(h.server, "/api/picker/confirm", {
    candidateId: chosen!.candidateId,
    shown: chosen!.shown,
    epoch: h.server.state.projectEpoch,
  });
  expect(confirmed.status).toBe(200);
}

async function scan(h: Harness, body: Record<string, unknown> = {}) {
  return apiPost(h.server, "/api/scan", {
    scopes: ["code"],
    signIn: false,
    epoch: h.server.state.projectEpoch,
    ...body,
  });
}

async function finished(h: Harness): Promise<ScanStatus> {
  return (await waitFor(
    async () => json(await apiGet(h.server, "/api/scan")),
    (value) => value.status !== "running",
  )) as unknown as ScanStatus;
}

describe("the simple screen's scan", () => {
  it("runs the authorized code scan when the gate passes; no code-only scan, nothing stored", async () => {
    const runScan = gateScan(outcome(), result());
    const runCodeOnlyScan = vi.fn();
    const openResultStore = vi.fn(() => null);
    harness = await startHarness({ deps: { runScan, runCodeOnlyScan, openResultStore } });
    await choose(harness, SHOP);
    expect((await scan(harness)).status).toBe(200);
    const done = await finished(harness);
    expect(done.status).toBe("done");
    expect(done.gateReason).toBeNull();
    expect(done.codeOnly).toBe(false);
    expect(done.result?.overallStatus).toBe("completed");
    expect(runScan.mock.calls[0]?.[0].scopes).toEqual(["code"]);
    expect(runCodeOnlyScan).not.toHaveBeenCalled();
    expect(openResultStore).not.toHaveBeenCalled();
  });

  it("says why the gate did not pass and runs nothing else until the user clicks", async () => {
    const gate = blocked("owner_approval");
    const runScan = gateScan(gate, blockedResult(gate));
    const runCodeOnlyScan = vi.fn(async () => codeOnlyResult());
    const openResultStore = vi.fn(() => null);
    harness = await startHarness({ deps: { runScan, runCodeOnlyScan, openResultStore } });
    await choose(harness, SHOP);
    await scan(harness);
    const done = await finished(harness);
    expect(done.gateReason).toBe("no_approval");
    expect(done.codeOnly).toBe(false);
    // No click: nothing else runs, however long the page waits.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(runCodeOnlyScan).not.toHaveBeenCalled();
    expect((json(await apiGet(harness.server, "/api/scan")) as unknown as ScanStatus).status).toBe(
      "done",
    );
    // The click: a code-only scan with the gate's reason, labelled and never stored.
    const started = await apiPost(harness.server, "/api/code-scan", {
      epoch: harness.server.state.projectEpoch,
    });
    expect(started.status).toBe(200);
    const codeOnly = await finished(harness);
    expect(codeOnly.codeOnly).toBe(true);
    expect(codeOnly.gateReason).toBeNull();
    expect(runCodeOnlyScan).toHaveBeenCalledWith(
      { projectRoot: SHOP, reason: "no_approval" },
      expect.anything(),
    );
    expect(openResultStore).not.toHaveBeenCalled();
  });

  it("never starts a sign-in: no existing sign-in means not_signed_in", async () => {
    const deviceFlow = vi.fn(async () => {
      throw new Error("a device flow must not start");
    });
    const provider = Object.assign(deviceFlow, {
      invalidate: vi.fn(),
      signOut: vi.fn(),
      existing: vi.fn(async () => null),
    });
    const runScan = vi.fn(async (_request: ScanRequest, deps: ScanDependencies) => {
      const gate = blocked(null);
      try {
        await deps.authorization.getGitHubSession();
      } catch {
        gate.summary = {
          decision: "blocked",
          checks: gate.summary.checks.map((check) =>
            check.id === "repository"
              ? check
              : { ...check, status: "unverifiable", reason: "Not signed in." },
          ),
        };
      }
      deps.onAuthorization?.(gate);
      return blockedResult(gate);
    });
    harness = await startHarness({
      deps: { runScan, createSessionProvider: () => provider as never },
    });
    await choose(harness, SHOP);
    await scan(harness);
    const done = await finished(harness);
    expect(done.gateReason).toBe("not_signed_in");
    expect(deviceFlow).not.toHaveBeenCalled();
    expect(provider.existing).toHaveBeenCalled();
    expect(done.deviceCode).toBeNull();
  });

  it("names a missing remote from the repository check's code", async () => {
    const gate = blocked("repository", { repositoryCode: "no_remote" });
    harness = await startHarness({ deps: { runScan: gateScan(gate, blockedResult(gate)) } });
    await choose(harness, SHOP);
    await scan(harness);
    expect((await finished(harness)).gateReason).toBe("no_github_remote");
  });

  it("gives a folder without Git its reason at once, without the gate", async () => {
    const runScan = vi.fn();
    const runCodeOnlyScan = vi.fn(async () => codeOnlyResult());
    harness = await startHarness({ deps: { runScan, runCodeOnlyScan } });
    await choose(
      harness,
      NOTES,
      repoCandidate("notes", {
        block: { code: "not_a_git_root", paths: [] },
        remote: { status: "unreadable" },
      }),
    );
    // Without `signIn: false` the authorized scan still refuses the folder.
    expect((await scan(harness, { signIn: undefined })).status).toBe(409);
    expect((await scan(harness)).status).toBe(200);
    const done = await finished(harness);
    expect(done.gateReason).toBe("not_a_git_repository");
    expect(done.result).toBeNull();
    expect(runScan).not.toHaveBeenCalled();
    expect(runCodeOnlyScan).not.toHaveBeenCalled();
    await apiPost(harness.server, "/api/code-scan", { epoch: harness.server.state.projectEpoch });
    await finished(harness);
    expect(runCodeOnlyScan).toHaveBeenCalledWith(
      { projectRoot: NOTES, reason: "not_a_git_repository" },
      expect.anything(),
    );
  });

  it("refuses a folder that is too broad before anything else", async () => {
    const runScan = vi.fn();
    harness = await startHarness({ deps: { runScan } });
    harness.inspector.resolved.set("/home/u", { refused: "too_broad" });
    const response = await apiPost(harness.server, "/api/picker/path", { path: "~" });
    const body = json(response) as unknown as PickerPathResponse;
    expect(body.candidate).toBeNull();
    expect(body.refusal?.code).toBe("too_broad");
    expect(body.refusal?.reason).toBe(
      "This is your home folder or a system folder, not a project.",
    );
    expect(runScan).not.toHaveBeenCalled();
  });

  it("rejects a folder that changed after it was chosen", async () => {
    const runScan = vi.fn();
    const runCodeOnlyScan = vi.fn();
    harness = await startHarness({ deps: { runScan, runCodeOnlyScan } });
    await choose(harness, SHOP);
    harness.inspector.inspectChanged = true;
    const refused = await scan(harness);
    expect(refused.status).toBe(409);
    expect((json(refused).error as { code: string }).code).toBe("candidate_changed");
    const codeOnly = await apiPost(harness.server, "/api/code-scan", {
      epoch: harness.server.state.projectEpoch,
    });
    expect(codeOnly.status).toBe(409);
    expect(runScan).not.toHaveBeenCalled();
    expect(runCodeOnlyScan).not.toHaveBeenCalled();
  });

  it("validates signIn", async () => {
    harness = await startHarness();
    await choose(harness, SHOP);
    expect((await scan(harness, { signIn: "no" })).status).toBe(400);
  });
});

describe("gateReasonOf", () => {
  const blockedWith = (gate: AuthorizationOutcome) => blockedResult(gate);
  it("maps from codes and statuses, never from text", () => {
    expect(gateReasonOf(result(), outcome(), false)).toBeNull();
    const failed = result({
      overallStatus: "failed",
      scanBasis: { mode: "authorized", authorization: "not_verified", reason: "check_failed" },
    });
    expect(gateReasonOf(failed, null, false)).toBe("check_failed");
    const noCommits = blocked("repository", { repositoryCode: "no_commit_history" });
    expect(gateReasonOf(blockedWith(noCommits), noCommits, false)).toBe("not_a_git_repository");
    // A reason that mentions "remote" without the code is not a missing remote.
    const isolation = blocked("repository", { repositoryCode: "isolation_failed" });
    expect(gateReasonOf(blockedWith(isolation), isolation, false)).toBe("no_approval");
    const signedOut = blocked("github_identity");
    expect(gateReasonOf(blockedWith(signedOut), signedOut, true)).toBe("not_signed_in");
  });
});
