import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  INCREMENTAL_STATE_FORMAT,
  SCHEMA_VERSION,
  type IncrementalState,
  type ScanResult,
} from "@pgard/findings";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createResultStore, type ResultStore } from "./store.js";

const REPO_ID = 91;
const CHECKS = (
  ["repository", "github_identity", "owner_approval", "current_access", "contribution"] as const
).map((id) => ({ id, status: "passed" as const, reason: "ok" }));

function makeResult(scanId: string): ScanResult {
  return {
    schemaVersion: SCHEMA_VERSION,
    scanId,
    startedAt: "2026-10-24T00:00:00.000Z",
    finishedAt: "2026-10-24T00:00:05.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "owner/name", revision: "abc", webOrigin: null },
    authorization: { decision: "allowed", checks: CHECKS },
    coverage: [],
    findings: [],
    advisoryDb: { version: null, updatedAt: null },
    incremental: {
      used: true,
      reason: null,
      basedOn: { scanId: "earlier", revision: "abc" },
      filesRescanned: 1,
      filesReused: 4,
      commitsScanned: 2,
      commitsReused: 7,
      code: { mode: "incremental", reason: null },
      history: { mode: "incremental", reason: null },
    },
  };
}

const STATE: IncrementalState = {
  format: INCREMENTAL_STATE_FORMAT,
  analysisKey: "a".repeat(64),
  analyzerHash: "c".repeat(64),
  configHash: null,
  code: [
    {
      path: "src/a.ts",
      language: "typescript",
      hash: "b".repeat(64),
      findings: [],
      facts: { imports: ["pg"], stateChangingRoutes: [] },
      goImports: [],
      hasJsx: false,
      hasParseErrors: false,
      capped: false,
    },
  ],
};

let base: string;
let store: ResultStore;
beforeEach(async () => {
  base = await mkdtemp(path.join(os.tmpdir(), "pgard-store-incremental-"));
  store = createResultStore({ dir: path.join(base, "pgard") });
});
afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

describe("incremental state in the result store", () => {
  it("stores the state in the result file and reads it back with the scan", async () => {
    const saved = await store.save(makeResult("s1"), {
      repositoryId: REPO_ID,
      incrementalState: STATE,
    });
    expect(saved.ok).toBe(true);
    const found = await store.findNewest(REPO_ID, () => null);
    expect(found.scan?.incrementalState).toEqual(STATE);
    expect(found.scan?.result.incremental?.filesReused).toBe(4);
  });

  it("reads a scan stored without state as one with no state", async () => {
    await store.save(makeResult("s2"), { repositoryId: REPO_ID });
    const found = await store.findNewest(REPO_ID, () => null);
    expect(found.scan?.incrementalState).toBeNull();
  });

  it("stores the result without the state when the state holds a forbidden string", async () => {
    const withPath: IncrementalState = {
      ...STATE,
      code:
        STATE.code?.map((file) => ({ ...file, goImports: ["/home/me/secret-project"] })) ?? null,
    };
    const saved = await store.save(makeResult("s3"), {
      repositoryId: REPO_ID,
      forbidSubstrings: ["/home/me/secret-project"],
      incrementalState: withPath,
    });
    expect(saved.ok).toBe(true);
    const found = await store.findNewest(REPO_ID, () => null);
    expect(found.scan?.incrementalState).toBeNull();
    const dirs = await readdir(path.join(base, "pgard", "repos", String(REPO_ID)));
    const text = await readFile(
      path.join(
        base,
        "pgard",
        "repos",
        String(REPO_ID),
        dirs.find((n) => n.endsWith(".json")) ?? "",
      ),
      "utf8",
    );
    expect(text).not.toContain("secret-project");
  });

  it("still refuses a result that holds a forbidden string", async () => {
    const result = makeResult("s4");
    result.target.repo = "/home/me/secret-project";
    const saved = await store.save(result, {
      repositoryId: REPO_ID,
      forbidSubstrings: ["/home/me/secret-project"],
      incrementalState: STATE,
    });
    expect(saved.ok).toBe(false);
  });

  it("treats a state that is not valid as absent without failing the scan", async () => {
    await store.save(makeResult("s5"), { repositoryId: REPO_ID, incrementalState: STATE });
    const repoDir = path.join(base, "pgard", "repos", String(REPO_ID));
    const file = (await readdir(repoDir)).find((name) => name.endsWith(".json")) ?? "";
    const parsed = JSON.parse(await readFile(path.join(repoDir, file), "utf8")) as Record<
      string,
      unknown
    >;
    parsed.incrementalState = { format: 1, analysisKey: 3 };
    await writeFile(path.join(repoDir, file), JSON.stringify(parsed));
    const found = await store.findNewest(REPO_ID, () => null);
    expect(found.scan?.result.scanId).toBe("s5");
    expect(found.scan?.incrementalState).toBeNull();
  });
});

describe("why a state was left out", () => {
  it("records a state that was too large or rejected", async () => {
    const rejected: IncrementalState = {
      ...STATE,
      code:
        STATE.code?.map((file) => ({ ...file, goImports: ["/home/me/secret-project"] })) ?? null,
    };
    await store.save(makeResult("o1"), {
      repositoryId: REPO_ID,
      forbidSubstrings: ["/home/me/secret-project"],
      incrementalState: rejected,
    });
    expect((await store.findNewest(REPO_ID, () => null)).scan?.incrementalStateOmitted).toBe(
      "rejected",
    );
    const huge: IncrementalState = {
      ...STATE,
      code: Array.from({ length: 2 }, (_, index) => ({
        ...(STATE.code?.[0] as NonNullable<IncrementalState["code"]>[number]),
        path: `src/${index}.ts`,
        goImports: Array.from({ length: 200_000 }, (__, n) => `module-${n}-${"x".repeat(12)}`),
      })),
    };
    await store.save(makeResult("o2"), { repositoryId: REPO_ID, incrementalState: huge });
    const found = await store.findNewest(REPO_ID, (scan) =>
      scan.result.scanId === "o2" ? null : "skip",
    );
    expect(found.scan?.incrementalState).toBeNull();
    expect(found.scan?.incrementalStateOmitted).toBe("too_large");
  });

  it("records nothing when no state was offered", async () => {
    await store.save(makeResult("o3"), { repositoryId: REPO_ID });
    expect((await store.findNewest(REPO_ID, () => null)).scan?.incrementalStateOmitted).toBeNull();
  });
});
