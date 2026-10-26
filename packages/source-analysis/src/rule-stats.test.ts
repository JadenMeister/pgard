import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanSourceCode } from "./scan-source.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function project(files: Record<string, string | Buffer>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-stats-")));
  roots.push(root);
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  return root;
}

const SQL_VULN =
  'import { Pool } from "pg";\nconst pool = new Pool();\nexport const q = (req) => pool.query(`SELECT * FROM t WHERE id = ${req.query.id}`);\n';

type Output = Awaited<ReturnType<typeof scanSourceCode>>;
const statFor = (output: Output, area: string, ruleId: string) =>
  output.ruleStats?.find((stat) => stat.area === area && stat.ruleId === ruleId);

describe("scanSourceCode rule stats", () => {
  it("counts the files each language analyzer really ran on and the rule's findings in them", async () => {
    const root = project({
      "src/a.ts": SQL_VULN,
      "src/b.ts": SQL_VULN,
      "src/clean.ts": "export const x = 1;\n",
      "src/c.js": SQL_VULN,
      "src/binary.js": Buffer.from([0x63, 0x6f, 0x00, 0x6e, 0x73, 0x74]),
      "src/view.jsx":
        "export const V = ({ h }) => <div dangerouslySetInnerHTML={{ __html: h }} />;",
    });
    const output = await scanSourceCode(root);
    // Three TypeScript files were analyzed; two of them hold the SQL finding.
    expect(statFor(output, "source:typescript", "PG-SQL-001")).toMatchObject({
      scope: "code",
      status: "completed",
      targets: [{ unit: "files", examined: 3, reason: null }],
      findings: 2,
    });
    // The binary .js file was found but never analyzed; view.jsx and c.js were.
    expect(statFor(output, "source:javascript", "PG-SQL-001")).toMatchObject({
      targets: [{ unit: "files", examined: 2 }],
      findings: 1,
    });
    expect(statFor(output, "source:react", "PG-XSS-002")).toMatchObject({
      targets: [{ unit: "files", examined: 1 }],
      findings: 1,
    });
    // No Go or Vue files: those rules did not run, so there is no row for them.
    expect(output.ruleStats?.some((stat) => stat.area === "source:go")).toBe(false);
    expect(output.ruleStats?.some((stat) => stat.area === "source:vue")).toBe(false);
  });

  it("has exactly one row per rule that a completed or partial area lists", async () => {
    const root = project({ "src/a.ts": SQL_VULN, "cmd/main.go": "package main\n" });
    const output = await scanSourceCode(root);
    const expected = output.coverage
      .filter((entry) => entry.status === "completed" || entry.status === "partial")
      .flatMap((entry) => entry.ruleIds.map((ruleId) => `${entry.area}|${ruleId}`))
      .sort();
    expect(output.ruleStats?.map((stat) => `${stat.area}|${stat.ruleId}`).sort()).toEqual(expected);
    expect(expected.length).toBeGreaterThan(0);
  });

  it("does not count files that were skipped for the time budget", async () => {
    const root = project({ "src/a.ts": SQL_VULN, "src/b.ts": SQL_VULN });
    let tick = 0;
    // The clock jumps 1000 ms per reading, so the 1500 ms budget is gone after the first file.
    const output = await scanSourceCode(root, { timeBudgetMs: 1500, now: () => (tick += 1000) });
    const stat = statFor(output, "source:typescript", "PG-SQL-001");
    expect(stat?.status).toBe("partial");
    expect(stat?.targets[0]?.examined).toBeLessThan(2);
  });
});
