/**
 * Integration: `pgard scan` builds on the last stored scan. The real pipeline runs (gate, source
 * and history analyzers, result store in a temporary HOME) against a throwaway Git repository;
 * GitHub is the policy package's in-memory mock and nothing touches the network or the real
 * app-data folder.
 */
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { readScanResult, type ScanResult } from "@pgard/findings";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createDefaultDeps, main, type CliDeps } from "../../apps/cli/src/app.js";
import { createTestIo, noInterrupts } from "../../apps/cli/src/test-support.js";
import {
  createGitFixture,
  type GitFixture,
} from "../../packages/git-history/src/test-support/git-fixture.js";
import {
  ME,
  createMockGitHub,
  ownerInstallation,
  userRepository,
  type MockGitHubState,
} from "../../packages/policy/src/test-support/mock-github.js";

const SQL_VULN = (name: string) =>
  `import { Pool } from "pg";\nconst pool = new Pool();\nexport const ${name} = (req) => pool.query(\`SELECT * FROM t WHERE id = \${req.query.id}\`);\n`;

let fixture: GitFixture | null = null;
let home: string;

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new Error("network access is not allowed in this test");
    }),
  );
  home = mkdtempSync(path.join(tmpdir(), "pgard-incremental-home-"));
});

afterEach(() => {
  vi.unstubAllGlobals();
  fixture?.cleanup();
  fixture = null;
  rmSync(home, { recursive: true, force: true });
});

function allowedState(head: string): MockGitHubState {
  return {
    user: ME,
    repository: userRepository(),
    installations: [ownerInstallation()],
    installationRepositories: { 77: [555] },
    pulls: {},
    commits: { [head]: { sha: head, authorId: ME.id, committerId: ME.id, isVerified: true } },
    compare: { [head]: "identical" },
  };
}

function createProject(): GitFixture {
  fixture = createGitFixture({ remotes: { origin: "git@github.com:me/app.git" } });
  const me = { authorName: ME.name ?? "Me Person", authorEmail: ME.email ?? "me@example.com" };
  fixture.commit({
    ...me,
    files: {
      "package.json": '{ "name": "app", "version": "1.0.0" }\n',
      "src/a.ts": SQL_VULN("a"),
      "src/b.ts": "export const b = 1;\n",
      "src/c.ts": "export const c = 2;\n",
    },
  });
  return fixture;
}

/** Runs `pgard scan` with the given arguments in a temporary HOME. */
async function pgardScan(
  repo: GitFixture,
  args: string[],
  extraEnv: Record<string, string> = {},
): Promise<{ stdout: string; stderr: string; result: ScanResult }> {
  const head = repo.git("rev-parse", "HEAD").trim();
  const { session } = createMockGitHub(allowedState(head));
  const provider = Object.assign(async () => session, {
    invalidate: () => undefined,
    signOut: () => undefined,
    existing: async () => session,
  });
  const defaults = createDefaultDeps();
  const results: ScanResult[] = [];
  const deps: CliDeps = {
    ...defaults,
    createSessionProvider: () => provider,
    runScan: async (request, scanDeps) => {
      const result = await defaults.runScan(request, scanDeps);
      results.push(result);
      return result;
    },
  };
  const captured = createTestIo({
    cwd: repo.root,
    env: { HOME: home, XDG_DATA_HOME: path.join(home, "data"), ...extraEnv },
  });
  await main(args, captured.io, { deps, interrupts: noInterrupts });
  expect(results).toHaveLength(1);
  return {
    stdout: captured.stdout(),
    stderr: captured.stderr(),
    result: results[0] as ScanResult,
  };
}

const words = (text: string): string => text.replace(/\s+/g, " ");

describe("pgard scan builds on the last stored scan", () => {
  it("shows a full scan first, then an incremental one that re-scans only what changed", async () => {
    const repo = createProject();
    const first = await pgardScan(repo, ["scan", "code"]);
    expect(first.result.incremental).toMatchObject({ used: false, reason: "no_previous_scan" });
    expect(words(first.stdout)).toContain("Full scan no earlier stored scan of this repository");

    writeFileSync(path.join(repo.root, "src/b.ts"), "export const b = 2;\n");
    const second = await pgardScan(repo, ["scan", "code"]);
    expect(second.result.incremental).toMatchObject({
      used: true,
      filesRescanned: 1,
      filesReused: 2,
      basedOn: { scanId: first.result.scanId },
    });
    expect(words(second.stdout)).toContain(
      `Incremental re-scanned 1 file, reused 2 (based on scan ${first.result.scanId.slice(0, 8)})`,
    );
    expect(second.result.findings.map((f) => f.id)).toEqual(first.result.findings.map((f) => f.id));
  }, 30_000);

  it("says it in Korean with --lang ko", async () => {
    const repo = createProject();
    await pgardScan(repo, ["scan", "code"]);
    const second = await pgardScan(repo, ["scan", "code", "--lang", "ko"]);
    expect(words(second.stdout)).toContain("증분 검사 파일 0개 다시 검사, 3개 재사용");
  }, 30_000);

  it("scans everything again with --full, and says why", async () => {
    const repo = createProject();
    await pgardScan(repo, ["scan", "code"]);
    const full = await pgardScan(repo, ["scan", "code", "--full"]);
    expect(full.result.incremental).toMatchObject({
      used: false,
      reason: "requested_full",
      filesRescanned: 3,
      filesReused: 0,
    });
    expect(words(full.stdout)).toContain("Full scan a full scan was requested (--full)");
  }, 30_000);

  it("does not read or keep anything with --no-store", async () => {
    const repo = createProject();
    await pgardScan(repo, ["scan", "code"]);
    const noStore = await pgardScan(repo, ["scan", "code", "--no-store"]);
    expect(noStore.result.incremental).toMatchObject({ used: false, reason: "store_unavailable" });
  }, 30_000);

  it("prints the incremental field in JSON and keeps stdout a single document", async () => {
    const repo = createProject();
    await pgardScan(repo, ["scan", "code"]);
    const json = await pgardScan(repo, ["scan", "code", "--format", "json"]);
    const read = readScanResult(JSON.parse(json.stdout));
    expect(read.ok && read.result.incremental?.used).toBe(true);
    expect(read.ok && read.result.schemaVersion).toBe("1.4");
  }, 30_000);

  it("falls back to a full scan when the history was rewritten", async () => {
    const repo = createProject();
    await pgardScan(repo, ["scan"]);
    writeFileSync(path.join(repo.root, "src/b.ts"), "export const b = 3;\n");
    repo.git("add", "-A");
    repo.git(
      "-c",
      "user.name=Me",
      "-c",
      "user.email=me@example.com",
      "commit",
      "-q",
      "--amend",
      "-m",
      "amended",
    );
    const after = await pgardScan(repo, ["scan"]);
    expect(after.result.incremental).toMatchObject({ used: false, reason: "head_not_ancestor" });
    expect(words(after.stdout)).toContain("not in this branch's history");
  }, 30_000);

  it("never writes a path or a source line into the stored state", async () => {
    const repo = createProject();
    await pgardScan(repo, ["scan", "code"]);
    const stored = listJsonFiles(home);
    expect(stored.length).toBeGreaterThan(0);
    for (const file of stored) {
      const text = readFileSync(file, "utf8");
      expect(text).toContain("incrementalState");
      expect(text).not.toContain(repo.root);
      expect(text).not.toContain("SELECT * FROM t");
    }
  }, 30_000);
});

function listJsonFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) return listJsonFiles(full);
    return entry.name.endsWith(".json") ? [full] : [];
  });
}
