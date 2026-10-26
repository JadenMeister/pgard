import { mkdtemp, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { ScanResult } from "@pgard/findings";
import { createResultStore, type ResultStore } from "@pgard/result-store";
import type { AuthorizationOutcome } from "@pgard/scan-core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { NO_STORE_ENV } from "../flows/store-result.js";
import {
  ALLOWED,
  BLOCKED,
  createTestContext,
  createTestDeps,
  createTestIo,
  testFinding,
  testResult,
} from "../test-support.js";
import { runBaseline } from "./baseline.js";
import { runHistoryClear } from "./history.js";
import { runScanCommand, type ScanCommand } from "./scan/index.js";

const REPO_ID = 777;
const OUTCOME: AuthorizationOutcome = {
  summary: ALLOWED,
  repo: "owner/name",
  revision: "abc",
  repositoryId: REPO_ID,
};
const SCAN: ScanCommand = { variant: "code", port: null, report: null };

let base: string;
let store: ResultStore;

beforeEach(async () => {
  base = await mkdtemp(path.join(os.tmpdir(), "pgard-cli-baseline-"));
  store = createResultStore({ dir: path.join(base, "pgard") });
});
afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

const old = testFinding({ id: "old", location: { ...testFinding().location, line: 10 } });
const fresh = testFinding({
  id: "fresh",
  ruleId: "PG-XSS-001",
  title: "Unescaped output",
  location: { kind: "file", path: "src/view.ts", line: 5, url: null, commit: null },
  evidence: "req.query -> html",
});

function deps(
  options: {
    outcome?: AuthorizationOutcome;
    result?: ScanResult;
    resultStore?: ResultStore | null;
  } = {},
) {
  const outcome = options.outcome ?? OUTCOME;
  const resultStore = options.resultStore === undefined ? store : options.resultStore;
  return createTestDeps({
    openResultStore: () => resultStore,
    verifyProject: async () => outcome,
    runScan: async (_request, scanDeps) => {
      scanDeps?.onAuthorization?.(outcome);
      return options.result ?? testResult({ findings: [old, fresh], scanId: "now" });
    },
  });
}

async function baseline(
  action: "set" | "show" | "clear",
  testDeps = deps(),
  options: { env?: Record<string, string>; fromCurrent?: boolean } = {},
) {
  const captured = createTestIo(options.env === undefined ? {} : { env: options.env });
  const code = await runBaseline(
    createTestContext(captured, testDeps),
    action,
    options.fromCurrent === true,
  );
  return { captured, code };
}

async function scan(
  testDeps = deps(),
  options: { env?: Record<string, string>; noStore?: boolean; json?: boolean; all?: boolean } = {},
) {
  const captured = createTestIo(options.env === undefined ? {} : { env: options.env });
  const code = await runScanCommand(createTestContext(captured, testDeps), {
    ...SCAN,
    ...(options.noStore === true ? { noStore: true } : {}),
    ...(options.json === true ? { format: "json" as const } : {}),
    ...(options.all === true ? { allFindings: true } : {}),
  });
  return { captured, code };
}

const storeScan = (result: ScanResult) => store.save(result, { repositoryId: REPO_ID });

describe("pgard baseline set", () => {
  it("uses the newest stored scan of this repository and says what it holds", async () => {
    await storeScan(testResult({ scanId: "older", findings: [] }));
    await storeScan(testResult({ scanId: "newer", findings: [old, fresh] }));
    const { captured, code } = await baseline("set");
    expect(code).toBe(0);
    expect(captured.stdout()).toContain("Baseline set from the scan of ");
    expect(captured.stdout()).toContain("2 findings (2 high)");
    expect(captured.stdout()).toContain('under "In baseline"');
    const loaded = await store.getBaseline(REPO_ID);
    expect(loaded.ok && loaded.baseline?.result.scanId).toBe("newer");
  });

  it("stores the baseline without the marks of an earlier baseline", async () => {
    await storeScan(
      testResult({
        findings: [{ ...old, inBaseline: true }],
        baseline: {
          setAt: "2026-10-01T00:00:00.000Z",
          scanId: "x",
          revision: null,
          total: 1,
          matched: 1,
          new: 0,
          newInUncertainAreas: 0,
          toolVersionChanged: false,
        },
      }),
    );
    await baseline("set");
    const loaded = await store.getBaseline(REPO_ID);
    expect(loaded.ok && loaded.baseline?.result.baseline).toBeUndefined();
    expect(loaded.ok && loaded.baseline?.result.findings[0]?.inBaseline).toBeUndefined();
  });

  it("says so when there is no stored scan, and writes nothing", async () => {
    const { captured, code } = await baseline("set");
    expect(code).toBe(2);
    expect(captured.stderr()).toContain("No stored scan of owner/name");
    expect(captured.stderr()).toContain("--from-current");
    expect((await store.getBaseline(REPO_ID)).ok).toBe(true);
  });

  it("warns that a partial scan makes findings in uncovered areas read as new", async () => {
    await storeScan(testResult({ overallStatus: "partial" }));
    const { captured } = await baseline("set");
    expect(captured.stdout()).toContain("! That scan was partial");
  });

  it("with --from-current scans now and uses that scan, printing the result too", async () => {
    const { captured, code } = await baseline("set", deps(), { fromCurrent: true });
    expect(code).toBe(0);
    expect(captured.stdout()).toContain("PGARD scan result");
    expect(captured.stdout()).toContain("Baseline set from this scan: 2 findings");
    const loaded = await store.getBaseline(REPO_ID);
    expect(loaded.ok && loaded.baseline?.result.scanId).toBe("now");
  });

  it("with --from-current refuses a blocked scan and sets nothing", async () => {
    const blockedOutcome: AuthorizationOutcome = { ...OUTCOME, summary: BLOCKED };
    const blocked = testResult({ overallStatus: "blocked", authorization: BLOCKED, findings: [] });
    const { code } = await baseline("set", deps({ outcome: blockedOutcome, result: blocked }), {
      fromCurrent: true,
    });
    expect(code).toBe(3);
    expect(await store.getBaseline(REPO_ID)).toEqual({ ok: true, baseline: null });
  });

  it("does not run for a repository the gate did not allow", async () => {
    await storeScan(testResult());
    const { captured, code } = await baseline(
      "set",
      deps({ outcome: { ...OUTCOME, summary: BLOCKED } }),
    );
    expect(code).toBe(3);
    expect(captured.stderr()).toContain("not verified");
    expect(await store.getBaseline(REPO_ID)).toEqual({ ok: true, baseline: null });
  });

  it("does not run with PGARD_NO_STORE=1 and creates no directory", async () => {
    await storeScan(testResult());
    const { captured, code } = await baseline("set", deps(), { env: { [NO_STORE_ENV]: "1" } });
    expect(code).toBe(2);
    expect(captured.stderr()).toContain(NO_STORE_ENV);
    expect(await store.getBaseline(REPO_ID)).toEqual({ ok: true, baseline: null });
  });

  it("reports a baseline that could not be saved as a partial failure", async () => {
    await storeScan(testResult());
    const broken: ResultStore = {
      ...store,
      setBaseline: async () => ({ ok: false, error: { code: "io", message: "disk full" } }),
    };
    const { captured, code } = await baseline("set", deps({ resultStore: broken }));
    expect(code).toBe(4);
    expect(captured.stderr()).toContain("was not saved: disk full");
  });
});

describe("pgard baseline show and clear", () => {
  it("shows when it was set and what it holds", async () => {
    await storeScan(testResult({ findings: [old, fresh] }));
    await baseline("set");
    const { captured, code } = await baseline("show");
    expect(code).toBe(0);
    expect(captured.stdout()).toContain("Baseline of owner/name");
    expect(captured.stdout()).toContain("Findings: 2 findings (2 high)");
    expect(captured.stdout()).toContain("--no-store");
  });

  it("says how to set one when there is none", async () => {
    const { captured, code } = await baseline("show");
    expect(code).toBe(0);
    expect(captured.stdout()).toContain("No baseline for owner/name");
  });

  it("reports a damaged baseline and how to recover", async () => {
    await storeScan(testResult());
    await baseline("set");
    await writeFile(path.join(base, "pgard", "repos", String(REPO_ID), "baseline.json"), "{nope");
    const { captured, code } = await baseline("show");
    expect(code).toBe(4);
    expect(captured.stderr()).toContain("pgard baseline clear");
  });

  it("clears it, keeps the stored scans, and says when there was none", async () => {
    await storeScan(testResult());
    await baseline("set");
    expect((await baseline("clear")).captured.stdout()).toContain(
      "Baseline of owner/name cleared.",
    );
    expect((await baseline("clear")).captured.stdout()).toContain("There was no baseline");
    expect(await store.getBaseline(REPO_ID)).toEqual({ ok: true, baseline: null });
    expect((await store.list(REPO_ID)).scans).toHaveLength(1);
  });

  it("clear and show also refuse an unverified repository and PGARD_NO_STORE=1", async () => {
    for (const action of ["show", "clear"] as const) {
      expect(
        (await baseline(action, deps({ outcome: { ...OUTCOME, summary: BLOCKED } }))).code,
      ).toBe(3);
      expect((await baseline(action, deps(), { env: { [NO_STORE_ENV]: "1" } })).code).toBe(2);
    }
  });
});

describe("a scan with a baseline", () => {
  beforeEach(async () => {
    await storeScan(testResult({ scanId: "base", findings: [old] }));
    await baseline("set");
  });

  it("groups findings in the baseline, emphasises new ones and always shows the counts", async () => {
    const { captured, code } = await scan();
    const text = captured.stdout();
    expect(code).toBe(0);
    expect(text).toContain("Baseline (set ");
    expect(text).toContain("1 in baseline, 1 new");
    expect(text).toContain("New findings by severity (1 total)");
    expect(text).toContain("New findings since the baseline (1)");
    expect(text).toContain("Unescaped output");
    expect(text).toContain("In baseline (1)");
    expect(text).toContain("plus 1 in baseline");
  });

  it("puts the baseline summary and the flags into the JSON result, and lists everything", async () => {
    const { captured } = await scan(deps(), { json: true });
    const parsed = JSON.parse(captured.stdout()) as ScanResult;
    expect(parsed.findings).toHaveLength(2);
    expect(parsed.baseline).toMatchObject({ scanId: "base", total: 1, matched: 1, new: 1 });
    expect(parsed.findings.filter((f) => f.inBaseline === true).map((f) => f.id)).toEqual(["old"]);
  });

  it("lists the findings in the baseline in full with --all-findings", async () => {
    const quiet = await scan();
    expect(quiet.captured.stdout()).toContain("By rule: PG-SQL-001 x1");
    const all = await scan(deps(), { all: true });
    expect(all.captured.stdout()).not.toContain("By rule: PG-SQL-001 x1");
    expect(all.captured.stdout()).toContain("src/api/users.ts:10");
  });

  it("never changes the exit code or the status", async () => {
    const partial = testResult({ overallStatus: "partial", findings: [old, fresh] });
    const { captured, code } = await scan(deps({ result: partial }));
    expect(code).toBe(4);
    expect(captured.stdout()).toContain("Partial");
    const blockedOutcome: AuthorizationOutcome = { ...OUTCOME, summary: BLOCKED };
    const blocked = testResult({ overallStatus: "blocked", authorization: BLOCKED, findings: [] });
    expect((await scan(deps({ outcome: blockedOutcome, result: blocked }))).code).toBe(3);
  });

  it("is neither read nor applied with --no-store or PGARD_NO_STORE=1", async () => {
    for (const options of [{ noStore: true }, { env: { [NO_STORE_ENV]: "1" } }]) {
      const { captured } = await scan(deps(), options);
      expect(captured.stdout()).not.toContain("In baseline");
      expect(captured.stdout()).not.toContain("Baseline (set");
      expect(captured.stdout()).toContain("Findings by severity (2 total)");
    }
  });

  it("is not applied for a repository other than the baseline's", async () => {
    const other: AuthorizationOutcome = { ...OUTCOME, repositoryId: 1 };
    const { captured } = await scan(deps({ outcome: other }));
    expect(captured.stdout()).not.toContain("In baseline");
  });

  it("warns and shows every finding when the baseline cannot be read", async () => {
    await writeFile(path.join(base, "pgard", "repos", String(REPO_ID), "baseline.json"), "{nope");
    const { captured, code } = await scan();
    expect(code).toBe(0);
    expect(captured.stderr()).toContain("The baseline could not be read and was not applied");
    expect(captured.stdout()).not.toContain("In baseline");
    expect(captured.stdout()).toContain("Findings by severity (2 total)");
  });

  it("is deleted by history clear, and the message says so", async () => {
    const captured = createTestIo();
    const code = await runHistoryClear(createTestContext(captured, deps()), null);
    expect(code).toBe(0);
    expect(captured.stdout()).toContain("Deleted 1 stored scan result and 1 baseline");
    expect(await store.getBaseline(REPO_ID)).toEqual({ ok: true, baseline: null });
    expect(await readdir(base)).not.toContain("never");
    await expect(stat(path.join(base, "pgard", "repos"))).rejects.toThrow();
  });
});
