import { mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { SCHEMA_VERSION } from "@pgard/findings";
import { createResultStore, type ResultStore } from "@pgard/result-store";
import type { AuthorizationOutcome } from "@pgard/scan-core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runHistoryClear } from "../commands/history.js";
import { runScanCommand } from "../commands/scan/index.js";
import {
  ALLOWED,
  BLOCKED,
  createTestContext,
  createTestDeps,
  createTestIo,
  testFinding,
  testResult,
} from "../test-support.js";
import { findPreviousScan } from "./scan-diff-summary.js";
import { NO_STORE_ENV, firstRunNotice, storeScanResult } from "./store-result.js";

const REPO_ID = 777;
const ALLOWED_OUTCOME: AuthorizationOutcome = {
  summary: ALLOWED,
  repo: "owner/name",
  revision: "abc",
  repositoryId: REPO_ID,
};
const DEFAULT_SCAN = {
  variant: "code",
  requireAuthorization: true,
  port: null,
  report: null,
} as const;

let base: string;
let store: ResultStore;

beforeEach(async () => {
  base = await mkdtemp(path.join(os.tmpdir(), "pgard-cli-store-"));
  store = createResultStore({ dir: path.join(base, "pgard") });
});
afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

function depsWith(
  outcome: AuthorizationOutcome | null,
  result = testResult(),
  resultStore: ResultStore | null = store,
) {
  return createTestDeps({
    openResultStore: () => resultStore,
    runScan: async (_request, deps) => {
      if (outcome !== null) deps?.onAuthorization?.(outcome);
      return result;
    },
  });
}

async function run(
  deps: ReturnType<typeof depsWith>,
  options: { env?: Record<string, string>; noStore?: boolean } = {},
) {
  const captured = createTestIo(options.env === undefined ? {} : { env: options.env });
  const code = await runScanCommand(createTestContext(captured, deps), {
    ...DEFAULT_SCAN,
    ...(options.noStore === undefined ? {} : { noStore: options.noStore }),
  });
  return { captured, code };
}

describe("storing a finished scan", () => {
  it("stores the allowed result under the GitHub repository id and prints the notice once", async () => {
    const first = await run(depsWith(ALLOWED_OUTCOME));
    expect(first.code).toBe(0);
    expect((await store.list(REPO_ID)).scans).toHaveLength(1);
    expect(first.captured.stderr()).toContain("PGARD now keeps your scan results");
    expect(first.captured.stderr()).toContain("--no-store");
    expect(first.captured.stderr()).toContain("PGARD_NO_STORE=1");
    expect(first.captured.stderr()).toContain("pgard history clear");
    expect(first.captured.stdout()).not.toContain("PGARD now keeps");

    const second = await run(depsWith(ALLOWED_OUTCOME, testResult({ scanId: "scan-2" })));
    expect(second.captured.stderr()).not.toContain("PGARD now keeps");
    expect((await store.list(REPO_ID)).scans).toHaveLength(2);
  });

  it("claims the notice only after a successful save, and keeps it on stderr", async () => {
    const broken: ResultStore = {
      ...store,
      save: async () => ({ ok: false, error: { code: "io", message: "disk full" } }),
    };
    await run(depsWith(ALLOWED_OUTCOME, testResult(), broken));
    // The failed save did not use up the notice: the next successful save shows it.
    const next = await run(depsWith(ALLOWED_OUTCOME));
    expect(next.captured.stderr()).toContain("PGARD now keeps");
    expect(next.captured.stdout()).not.toContain("PGARD now keeps");
  });

  it("words the notice for the platform", () => {
    expect(firstRunNotice("/d", "linux")).toContain("readable only by you");
    expect(firstRunNotice("C:\\d", "win32")).not.toContain("readable only by you");
    expect(firstRunNotice("C:\\d", "win32")).toContain("Windows profile");
  });

  it("refuses a result that carries the home directory, including a Windows path", async () => {
    for (const home of ["/home/ann", "C:\\Users\\ann"]) {
      const leaky = testResult({
        coverage: [
          { area: "a", scope: "code", status: "completed", ruleIds: [], note: `in ${home}\\x` },
        ],
      });
      const { captured } = await run(depsWith(ALLOWED_OUTCOME, leaky), { env: { HOME: home } });
      expect(captured.stderr(), home).toContain("was not stored");
    }
  });

  it("in --format json mode still stores, with one JSON document on stdout and the notice on stderr", async () => {
    const captured = createTestIo();
    const code = await runScanCommand(createTestContext(captured, depsWith(ALLOWED_OUTCOME)), {
      ...DEFAULT_SCAN,
      format: "json",
    });
    expect(code).toBe(0);
    expect(JSON.parse(captured.stdout())).toMatchObject({ scanId: "scan-1234abcd" });
    expect(captured.stdout()).not.toContain("PGARD now keeps");
    expect(captured.stderr()).toContain("PGARD now keeps your scan results");
    expect((await store.list(REPO_ID)).scans).toHaveLength(1);
  });

  it("stores nothing with --no-store, and does not print the notice or create the directory", async () => {
    const { captured, code } = await run(depsWith(ALLOWED_OUTCOME), { noStore: true });
    expect(code).toBe(0);
    expect(captured.stderr()).not.toContain("PGARD now keeps");
    await expect(stat(path.join(base, "pgard"))).rejects.toThrow();
  });

  it("stores nothing with PGARD_NO_STORE=1", async () => {
    const { captured } = await run(depsWith(ALLOWED_OUTCOME), { env: { [NO_STORE_ENV]: "1" } });
    expect(captured.stderr()).not.toContain("PGARD now keeps");
    await expect(stat(path.join(base, "pgard"))).rejects.toThrow();
  });

  it("only the exact value 1 opts out through the environment", async () => {
    await run(depsWith(ALLOWED_OUTCOME), { env: { [NO_STORE_ENV]: "0" } });
    expect((await store.list(REPO_ID)).scans).toHaveLength(1);
  });

  it("does not store a blocked scan", async () => {
    const blocked = testResult({ overallStatus: "blocked", authorization: BLOCKED, findings: [] });
    await run(depsWith({ ...ALLOWED_OUTCOME, summary: BLOCKED }, blocked));
    await expect(stat(path.join(base, "pgard"))).rejects.toThrow();
  });

  it("does not even call the store for a blocked outcome or a blocked or failed status", async () => {
    const calls: string[] = [];
    const spy: ResultStore = {
      ...store,
      claimFirstRunNotice: async () => {
        calls.push("claim");
        return true;
      },
      save: async () => {
        calls.push("save");
        return { ok: true, file: "x", pruned: 0 };
      },
    };
    // Inconsistent on purpose: only the outcome (this run's gate) says blocked.
    await run(depsWith({ ...ALLOWED_OUTCOME, summary: BLOCKED }, testResult(), spy));
    await run(depsWith(ALLOWED_OUTCOME, testResult({ overallStatus: "blocked" }), spy));
    await run(depsWith(ALLOWED_OUTCOME, testResult({ overallStatus: "failed" }), spy));
    expect(calls).toEqual([]);
  });

  it("does not store when the run produced no GitHub repository id", async () => {
    await run(depsWith({ ...ALLOWED_OUTCOME, repositoryId: null }));
    await run(depsWith(null));
    await expect(stat(path.join(base, "pgard"))).rejects.toThrow();
  });

  it("works without a store (no app-data directory)", async () => {
    const { code } = await run(depsWith(ALLOWED_OUTCOME, testResult(), null));
    expect(code).toBe(0);
  });

  it("a failing store is a warning and never changes the exit code", async () => {
    const broken: ResultStore = {
      ...store,
      claimFirstRunNotice: async () => false,
      save: async () => ({ ok: false, error: { code: "io", message: "disk full" } }),
    };
    const { captured, code } = await run(depsWith(ALLOWED_OUTCOME, testResult(), broken));
    expect(code).toBe(0);
    expect(captured.stderr()).toContain("was not stored: disk full");
  });

  it("refuses to store a result that carries the project root", async () => {
    const leaky = testResult({
      coverage: [
        { area: "a", scope: "code", status: "completed", ruleIds: [], note: "in /work/repo/x" },
      ],
    });
    const { captured } = await run(depsWith(ALLOWED_OUTCOME, leaky));
    expect(captured.stderr()).toContain("was not stored");
    expect((await store.list(REPO_ID)).scans).toEqual([]);
  });

  it("writes no absolute path and no authorization cache into the store", async () => {
    await run(depsWith(ALLOWED_OUTCOME));
    const repoDir = path.join(base, "pgard", "repos", String(REPO_ID));
    for (const name of await readdir(repoDir)) {
      const text = await readFile(path.join(repoDir, name), "utf8");
      expect(text).not.toContain("/work/repo");
      expect(text).not.toContain(base);
    }
    expect((await readdir(path.join(base, "pgard"))).sort()).toEqual([".notice-shown", "repos"]);
  });
});

describe("pgard history clear", () => {
  it("deletes everything and says how many", async () => {
    await run(depsWith(ALLOWED_OUTCOME));
    await run(depsWith(ALLOWED_OUTCOME, testResult({ scanId: "scan-2" })));
    const captured = createTestIo();
    const code = await runHistoryClear(createTestContext(captured, depsWith(null)), null);
    expect(code).toBe(0);
    expect(captured.stdout()).toContain("Deleted 2 stored scan results");
    expect((await store.list(REPO_ID)).scans).toEqual([]);
  });

  it("clears one repository by name", async () => {
    await run(depsWith(ALLOWED_OUTCOME));
    const captured = createTestIo();
    await runHistoryClear(createTestContext(captured, depsWith(null)), "someone/else");
    expect(captured.stdout()).toContain("Deleted 0 stored scan results for someone/else");
    expect((await store.list(REPO_ID)).scans).toHaveLength(1);
    await runHistoryClear(createTestContext(createTestIo(), depsWith(null)), "Owner/Name");
    expect((await store.list(REPO_ID)).scans).toEqual([]);
  });

  it("fails clearly when there is no store location", async () => {
    const captured = createTestIo();
    const code = await runHistoryClear(
      createTestContext(captured, depsWith(null, testResult(), null)),
      null,
    );
    expect(code).toBe(5);
    expect(captured.stderr()).toContain("nothing to clear");
  });
});

describe("comparison with the previous stored scan", () => {
  const moved = (line: number) =>
    testResult({
      scanId: `scan-${line}`,
      findings: [
        testFinding({
          location: { kind: "file", path: "src/a.ts", line, url: null, commit: null },
        }),
      ],
    });
  const repoDir = () => path.join(base, "pgard", "repos", String(REPO_ID));
  const summaryLines = (text: string) =>
    text.split("\n").filter((line) => line.includes("Since the last scan"));

  it("says nothing on the first scan", async () => {
    const { captured } = await run(depsWith(ALLOWED_OUTCOME));
    expect(captured.stdout()).not.toContain("Since the last scan");
    expect(captured.stderr()).not.toContain("Since the last scan");
  });

  it("prints one summary line on stdout for the second scan, moved code counted as unchanged", async () => {
    await run(depsWith(ALLOWED_OUTCOME, moved(10)));
    const { captured } = await run(depsWith(ALLOWED_OUTCOME, moved(30)));
    const lines = summaryLines(captured.stdout());
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(
      /^Since the last scan \(\d{4}-\d\d-\d\d \d\d:\d\d\): 0 new, 0 no longer reported, 1 unchanged \(1 moved\)$/,
    );
    expect(captured.stderr()).not.toContain("Since the last scan");
  });

  it("counts new and fixed findings", async () => {
    await run(depsWith(ALLOWED_OUTCOME, testResult({ scanId: "a", findings: [testFinding()] })));
    const next = testResult({
      scanId: "b",
      findings: [testFinding({ evidence: "different flow" })],
    });
    const { captured } = await run(depsWith(ALLOWED_OUTCOME, next));
    expect(captured.stdout()).toContain(": 1 new, 1 no longer reported, 0 unchanged");
  });

  it("names areas that cannot be compared and never calls their findings gone", async () => {
    await run(depsWith(ALLOWED_OUTCOME, testResult({ scanId: "a" })));
    const partial = testResult({
      scanId: "b",
      findings: [],
      coverage: [
        { area: "source:typescript", scope: "code", status: "partial", ruleIds: [], note: null },
        { area: "history:secrets", scope: "history", status: "completed", ruleIds: [], note: null },
      ],
    });
    const { captured } = await run(depsWith(ALLOWED_OUTCOME, partial));
    const [line] = summaryLines(captured.stdout());
    expect(line).toContain("0 no longer reported");
    expect(line).toContain(
      "Some findings could not be compared because source:typescript was only partially scanned",
    );
  });

  it("prints nothing with --no-store", async () => {
    await run(depsWith(ALLOWED_OUTCOME, moved(10)));
    const { captured } = await run(depsWith(ALLOWED_OUTCOME, moved(11)), { noStore: true });
    expect(captured.stdout()).not.toContain("Since the last scan");
    expect(captured.stderr()).not.toContain("Since the last scan");
  });

  it("with --format json keeps stdout a single JSON document and uses stderr", async () => {
    await run(depsWith(ALLOWED_OUTCOME, moved(10)));
    const captured = createTestIo();
    const code = await runScanCommand(
      createTestContext(captured, depsWith(ALLOWED_OUTCOME, moved(12))),
      { ...DEFAULT_SCAN, format: "json" },
    );
    expect(code).toBe(0);
    expect(JSON.parse(captured.stdout())).toMatchObject({ scanId: "scan-12" });
    expect(captured.stdout()).not.toContain("Since the last scan");
    expect(summaryLines(captured.stderr())).toHaveLength(1);
  });

  it("skips a corrupt previous file with a warning and compares with the next one", async () => {
    await run(depsWith(ALLOWED_OUTCOME, moved(10)));
    await writeFile(path.join(repoDir(), "9999999999999-0123456789abcdef.json"), "{not json");
    const { captured, code } = await run(depsWith(ALLOWED_OUTCOME, moved(11)));
    expect(code).toBe(0);
    expect(captured.stderr()).toContain(
      "Skipped stored result 9999999999999-0123456789abcdef.json",
    );
    expect(captured.stdout()).toContain("Since the last scan");
  });

  it("skips a previous file with a newer minor schema, with a warning", async () => {
    await run(depsWith(ALLOWED_OUTCOME, moved(10)));
    const [name] = await readdir(repoDir());
    const file = path.join(repoDir(), name as string);
    const text = (await readFile(file, "utf8")).replace(
      `"schemaVersion":"${SCHEMA_VERSION}"`,
      '"schemaVersion":"1.9"',
    );
    expect(text).toContain('"1.9"');
    await writeFile(file, text);
    const { captured } = await run(depsWith(ALLOWED_OUTCOME, moved(11)));
    expect(captured.stderr()).toContain("newer than this PGARD understands");
    expect(captured.stdout()).not.toContain("Since the last scan");
  });

  it("skips an oversized previous file", async () => {
    await run(depsWith(ALLOWED_OUTCOME, moved(10)));
    await writeFile(
      path.join(repoDir(), "9999999999999-0123456789abcdef.json"),
      Buffer.alloc(9 * 1024 * 1024, 32),
    );
    const { captured } = await run(depsWith(ALLOWED_OUTCOME, moved(11)));
    expect(captured.stderr()).toContain("Skipped stored result");
    expect(captured.stdout()).toContain("Since the last scan");
  });

  it("prints no summary when the save fails", async () => {
    await run(depsWith(ALLOWED_OUTCOME, moved(10)));
    const broken: ResultStore = {
      ...store,
      save: async () => ({ ok: false, error: { code: "io", message: "disk full" } }),
    };
    const { captured } = await run(depsWith(ALLOWED_OUTCOME, moved(11), broken));
    expect(captured.stdout()).not.toContain("Since the last scan");
  });

  it("never picks the scan being compared as its own previous scan", async () => {
    await run(depsWith(ALLOWED_OUTCOME, moved(10)));
    expect((await findPreviousScan(store, REPO_ID, "scan-10")).scan).toBeNull();
    expect((await findPreviousScan(store, REPO_ID, "other")).scan?.result.scanId).toBe("scan-10");
  });

  it("writes the summary to stderr, not stdout, when told the output is JSON", async () => {
    await run(depsWith(ALLOWED_OUTCOME, moved(10)));
    const captured = createTestIo();
    await storeScanResult(
      createTestContext(captured, depsWith(ALLOWED_OUTCOME)),
      moved(11),
      ALLOWED_OUTCOME,
      "/work/repo",
      false,
      true,
    );
    expect(captured.stdout()).toBe("");
    expect(captured.stderr()).toContain("Since the last scan");
  });

  it("compares with the newest of several stored scans, not the oldest", async () => {
    let clock = 1_800_000_000_000;
    const timed = createResultStore({ dir: path.join(base, "timed"), now: () => (clock += 1000) });
    for (const line of [10, 20, 30]) {
      expect((await timed.save(moved(line), { repositoryId: REPO_ID })).ok).toBe(true);
    }
    const found = await findPreviousScan(timed, REPO_ID, "other");
    expect(found.scan?.result.scanId).toBe("scan-30");
  });

  it("strips terminal control characters from area names taken from a stored file", async () => {
    const area = (status: "completed" | "partial") => ({
      area: "evil\u001b[31m-area",
      scope: "code" as const,
      status,
      ruleIds: ["PG-SQL-001"],
      note: null,
    });
    await run(
      depsWith(ALLOWED_OUTCOME, testResult({ scanId: "a", coverage: [area("completed")] })),
    );
    const { captured } = await run(
      depsWith(ALLOWED_OUTCOME, testResult({ scanId: "b", coverage: [area("partial")] })),
    );
    const [line] = summaryLines(captured.stdout());
    expect(line).toContain("-area");
    expect(line).not.toContain("\u001b");
  });

  it("shows the previous revision when HEAD changed, and an unusual severity change", async () => {
    await run(depsWith(ALLOWED_OUTCOME, testResult({ scanId: "a" })));
    const next = testResult({
      scanId: "b",
      target: { repo: "owner/name", revision: "1111111222222", webOrigin: null },
      findings: [testFinding({ severity: "critical" })],
    });
    const { captured } = await run(depsWith(ALLOWED_OUTCOME, next));
    const [line] = summaryLines(captured.stdout());
    expect(line).toContain(", at abcdef1)");
    expect(line).toContain("1 changed severity or status");
  });

  it("names the area in the new-findings qualifier and for a scope change", async () => {
    await run(depsWith(ALLOWED_OUTCOME, testResult({ scanId: "a", findings: [], coverage: [] })));
    const next = testResult({
      scanId: "b",
      findings: [testFinding()],
      coverage: [
        {
          area: "source:typescript",
          scope: "code",
          status: "completed",
          ruleIds: ["PG-SQL-001"],
          note: null,
        },
      ],
    });
    const { captured } = await run(depsWith(ALLOWED_OUTCOME, next));
    const [line] = summaryLines(captured.stdout());
    expect(line).toContain("1 new (1 in areas not fully compared: source:typescript)");
    expect(line).toContain("source:typescript was not in the last scan's scope");
  });
});
