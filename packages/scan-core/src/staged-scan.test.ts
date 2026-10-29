import { afterEach, describe, expect, it, vi } from "vitest";

// Each test starts a few Git processes; a busy machine or a slow runner needs more than 5 s.
vi.setConfig({ testTimeout: 30_000 });
import {
  createGitFixture,
  type GitFixture,
} from "../../git-history/src/test-support/git-fixture.js";
import {
  STAGED_COVERAGE_AREA,
  createStagedAnalyzer,
  isStagedReportIncomplete,
  type StagedScanReport,
} from "./staged-scan.js";
import type { AnalyzerContext } from "./types.js";

const GITHUB_TOKEN = `ghp_${"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"}`;

const SQL_BAD = `import Fastify from "fastify";
import { Pool } from "pg";
const pool = new Pool();
const app = Fastify();
app.get("/items", async (request) => {
  const { col } = request.query as any;
  const { rows } = await pool.query(\`SELECT * FROM items ORDER BY \${col}\`);
  return rows;
});
`;

describe("createStagedAnalyzer", () => {
  const fixtures: GitFixture[] = [];
  afterEach(() => {
    for (const fixture of fixtures.splice(0)) {
      try {
        fixture.cleanup();
      } catch {
        // On Windows a git process killed by a test (timeout, cancellation) can hold the
        // directory for a moment; the temporary directory is left for the system to clean.
      }
    }
  });
  const repo = (files: Record<string, string> = { "README.md": "x\n" }) => {
    const fixture = createGitFixture();
    fixtures.push(fixture);
    fixture.commit({ files });
    return fixture;
  };
  const run = async (
    fixture: GitFixture,
    context: Partial<AnalyzerContext> = {},
    settings: Parameters<typeof createStagedAnalyzer>[0] = {},
  ) => {
    let report: StagedScanReport | null = null;
    const output = await createStagedAnalyzer({
      ...settings,
      onReport: (value) => {
        report = value;
      },
    })({
      projectRoot: fixture.root,
      revision: null,
      env: {},
      now: () => new Date(),
      projectConfig: null,
      ...context,
    });
    return { output, report: report as unknown as StagedScanReport };
  };

  it("reports a secret and a source finding on staged lines, as code findings", async () => {
    const fixture = repo();
    fixture.writeFile("src/app.ts", SQL_BAD);
    fixture.writeFile("src/keys.txt", `token = "${GITHUB_TOKEN}"\n`);
    fixture.git("add", "-A");
    const { output, report } = await run(fixture);
    expect(output.findings.map((finding) => finding.ruleId).sort()).toEqual([
      "PG-SECRET-002",
      "PG-SQL-001",
    ]);
    expect(output.findings.every((finding) => finding.sources.join() === "code")).toBe(true);
    expect(output.coverage).toMatchObject([
      { area: STAGED_COVERAGE_AREA, scope: "code", status: "completed" },
    ]);
    expect(report).toMatchObject({ scanned: 2, sourceChecked: 1, secretsOnly: 1 });
    expect(JSON.stringify(output)).not.toContain(GITHUB_TOKEN);
  });

  it("does not report a finding on a line the commit leaves alone", async () => {
    const fixture = repo({ "src/app.ts": SQL_BAD });
    fixture.writeFile("src/app.ts", `${SQL_BAD}// a comment\n`);
    fixture.git("add", "-A");
    const { output, report } = await run(fixture);
    expect(output.findings).toEqual([]);
    expect(report.preexisting).toBe(1);
  });

  it("reads staged content only: an unstaged secret and a staged-then-removed one", async () => {
    const fixture = repo();
    fixture.writeFile("a.txt", `staged = "${GITHUB_TOKEN}"\n`);
    fixture.git("add", "a.txt");
    fixture.writeFile("a.txt", "clean now\n");
    fixture.writeFile("b.txt", `unstaged = "${GITHUB_TOKEN}"\n`);
    const { output } = await run(fixture);
    expect(output.findings.map((finding) => finding.location.path)).toEqual(["a.txt"]);
  });

  it("applies the exclude patterns to source rules but never to secrets", async () => {
    const fixture = repo();
    fixture.writeFile("legacy/app.ts", SQL_BAD);
    fixture.writeFile("legacy/keys.txt", `token = "${GITHUB_TOKEN}"\n`);
    fixture.git("add", "-A");
    const { output, report } = await run(fixture, {
      projectConfig: {
        version: 1,
        exclude: ["legacy/**"],
        testDirectories: [],
        suppressions: [],
      },
    });
    expect(output.findings.map((finding) => finding.ruleId)).toEqual(["PG-SECRET-002"]);
    expect(report.excluded).toBe(2);
  });

  it("is partial, not clean, when a file could not be read", async () => {
    const fixture = repo();
    fixture.writeFile("big.txt", "x".repeat(3 * 1024 * 1024));
    fixture.git("add", "-A");
    const { output, report } = await run(fixture);
    expect(output.coverage[0]?.status).toBe("partial");
    expect(output.coverage[0]?.note).toContain("over the size limit");
    expect(isStagedReportIncomplete(report)).toBe(true);
  });

  it("does not count binary files, symbolic links or deletions as unscanned", async () => {
    const fixture = repo({ "gone.txt": "bye\n", "keep.txt": "keep\n" });
    fixture.git("rm", "-q", "gone.txt");
    fixture.writeFile(
      "bin.dat",
      Buffer.from(
        Array.from({ length: 300 }, (_, i) => (i % 3 === 0 ? 0 : (i * 7) % 256)),
      ).toString("latin1"),
    );
    fixture.git("add", "-A");
    const { output, report } = await run(fixture);
    expect(output.coverage[0]?.status).toBe("completed");
    expect(report).toMatchObject({ scanned: 0, deleted: 1 });
  });

  it("reports an unreadable repository as not tested, never as clean", async () => {
    const fixture = repo();
    const { output, report } = await run(
      fixture,
      { projectRoot: `${fixture.root}/missing` },
      { budgetMs: 2000 },
    );
    expect(output.findings).toEqual([]);
    expect(output.coverage[0]?.status).toBe("not_tested");
    expect(report.failure?.kind).toBe("error");
  });

  it("reports an exhausted time cap as a timeout, not as clean", async () => {
    const fixture = repo();
    fixture.writeFile("a.txt", "a\n");
    fixture.git("add", "-A");
    // The first reading of the clock starts the analysis; every later one is far past the cap.
    let clock = 0;
    const { output, report } = await run(
      fixture,
      {},
      {
        budgetMs: 2000,
        now: () => {
          const value = clock;
          clock = 10_000;
          return value;
        },
      },
    );
    expect(report.failure?.kind).toBe("timeout");
    expect(output.coverage[0]?.status).toBe("not_tested");
    expect(output.findings).toEqual([]);
  });

  it("rethrows a cancellation instead of calling it a result", async () => {
    const fixture = repo();
    fixture.writeFile("a.txt", "a\n");
    fixture.git("add", "-A");
    const controller = new AbortController();
    controller.abort();
    await expect(run(fixture, { signal: controller.signal })).rejects.toBeDefined();
  });
});
