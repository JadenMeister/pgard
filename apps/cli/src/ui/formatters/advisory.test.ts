import { mkdirSync, mkdtempSync, realpathSync, rmSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runDoctor } from "../../commands/doctor.js";
import { runRulesList } from "../../commands/rules/list.js";
import type { CommandContext } from "../../context.js";
import { createDefaultDeps } from "../../deps.js";
import { createTestContext, createTestDeps, createTestIo } from "../../test-support.js";
import { formatAdvisoryStatus, readAdvisoryStatusSafely } from "./advisory.js";
import { createStyle } from "./style.js";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function tempDir(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-cli-adv-")));
  dirs.push(root);
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  return root;
}

const ADVISORY = {
  id: "GHSA-test-lodash",
  modified: "2026-10-20T00:00:00Z",
  affected: [
    {
      package: { ecosystem: "npm", name: "lodash" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
    },
  ],
};

function dbFile(content: string): string {
  return path.join(tempDir({ "osv.json": content }), "osv.json");
}

/** Status line produced by the real default dep for a configured DB location. */
async function statusLine(location: string | undefined): Promise<string> {
  const env = location === undefined ? {} : { PGARD_ADVISORY_DB: location };
  return formatAdvisoryStatus(await readAdvisoryStatusSafely(createDefaultDeps(), env));
}

/** Runs a command with test deps, except for the real default advisory status dep. */
async function runWithDefaultStatus(
  run: (context: CommandContext) => Promise<unknown>,
  location: string,
): Promise<string> {
  const captured = createTestIo({ env: { PGARD_ADVISORY_DB: location } });
  const deps = createTestDeps({ readAdvisoryDbStatus: createDefaultDeps().readAdvisoryDbStatus });
  await run(createTestContext(captured, deps));
  return captured.stdout();
}

describe("default advisory DB status (peek)", () => {
  it("marks a directory DB as not fully validated and never prints its path", async () => {
    const dir = tempDir({ "npm/GHSA-test-lodash.json": JSON.stringify(ADVISORY) });
    const line = await statusLine(dir);
    expect(line).toMatch(/^unverified - not fully validated - An advisory database is configured/);
    expect(line).toContain("version and freshness were not verified");
    expect(line).not.toContain("version none");
    expect(line).not.toContain(dir);

    const list = await runWithDefaultStatus((context) => runRulesList(context, null), dir);
    expect(list).toContain("Advisory database status: unverified - not fully validated - ");
    expect(list).not.toContain(dir);
    const doctor = await runWithDefaultStatus(runDoctor, dir);
    expect(doctor).toContain("[warn] Advisory database: unverified - not fully validated - ");
    expect(doctor).not.toContain(dir);
  });

  it("marks a large DB file as not fully validated without loading it", async () => {
    const file = dbFile(`{"vulnerabilities": [${" ".repeat(8 * 1024 * 1024 + 1)}]}`);
    const line = await statusLine(file);
    expect(line).toMatch(
      /^unverified - not fully validated - An advisory database file is configured/,
    );
    expect(line).toContain("Only its first bytes were checked");
    expect(line).not.toContain(file);
  });

  it("shows a large, stale but unvalidated DB as [warn] in doctor and yellow in rules list", async () => {
    const file = dbFile(
      JSON.stringify({
        version: "osv-2020",
        updatedAt: "2020-01-01T00:00:00Z",
        vulnerabilities: [ADVISORY],
        padding: " ".repeat(8 * 1024 * 1024 + 1),
      }),
    );
    const doctor = await runWithDefaultStatus(runDoctor, file);
    expect(doctor).toContain("[warn] Advisory database: unverified - not fully validated - ");
    expect(doctor).not.toContain("[ok]   Advisory database");
    expect(doctor).not.toContain("osv-2020");
    expect(doctor).not.toContain(file);

    const captured = createTestIo({ env: { PGARD_ADVISORY_DB: file } });
    const deps = createTestDeps({ readAdvisoryDbStatus: createDefaultDeps().readAdvisoryDbStatus });
    await runRulesList({ ...createTestContext(captured, deps), style: createStyle(true) }, null);
    expect(captured.stdout()).toContain(
      "\u001b[33m  Advisory database status: unverified - not fully validated - ",
    );
  });

  it("shows a DB file over the load limit as invalid [warn], as a scan would refuse it", async () => {
    const file = dbFile('{"vulnerabilities": [');
    truncateSync(file, 512 * 1024 * 1024 + 1); // sparse: no real disk use
    expect(await statusLine(file)).toBe(
      "invalid - version none, updated never - The advisory database file is too large to load.",
    );
    const doctor = await runWithDefaultStatus(runDoctor, file);
    expect(doctor).toContain(
      "[warn] Advisory database: invalid - version none, updated never - The advisory database file is too large to load.",
    );
    expect(doctor).not.toContain(file);
  });

  it("still fully reads a small DB file for its version and date", async () => {
    const updatedAt = new Date(Date.now() - 86_400_000).toISOString();
    const file = dbFile(
      JSON.stringify({ version: "osv-small-1", updatedAt, vulnerabilities: [ADVISORY] }),
    );
    expect(await statusLine(file)).toBe(
      `ok - version osv-small-1, updated ${updatedAt} - 1 advisories, updated ${updatedAt.slice(0, 10)}.`,
    );
  });

  it("reports missing, invalid and stale small DBs as before", async () => {
    expect(await statusLine(undefined)).toMatch(/^missing - version none, updated never - /);
    const absent = path.join(tempDir({}), "absent.json");
    const missing = await statusLine(absent);
    expect(missing).toMatch(/^missing - version none, updated never - .*was not found/);
    expect(missing).not.toContain(absent);

    expect(await statusLine(dbFile("not json"))).toBe(
      "invalid - version none, updated never - The advisory database could not be read or is not valid JSON.",
    );

    const stale = await statusLine(
      dbFile(
        JSON.stringify({
          version: "osv-old",
          updatedAt: "2020-01-01T00:00:00Z",
          vulnerabilities: [ADVISORY],
        }),
      ),
    );
    expect(stale).toMatch(
      /^stale - version osv-old, updated 2020-01-01T00:00:00\.000Z - Advisory data is stale/,
    );
  });

  it("shows the fixed note without the path when the status read throws", async () => {
    const dbPath = "/home/user/secret-place/osv";
    const deps = createTestDeps({
      readAdvisoryDbStatus: async () => {
        throw new Error(`EACCES: permission denied, scandir '${dbPath}'`);
      },
    });
    expect(
      formatAdvisoryStatus(await readAdvisoryStatusSafely(deps, { PGARD_ADVISORY_DB: dbPath })),
    ).toBe(
      "invalid - version none, updated never - The advisory database status could not be read.",
    );
    const captured = createTestIo({ env: { PGARD_ADVISORY_DB: dbPath } });
    await runDoctor(createTestContext(captured, deps));
    expect(captured.stdout()).toContain(
      "[warn] Advisory database: invalid - version none, updated never - The advisory database status could not be read.",
    );
    expect(captured.stdout()).not.toContain(dbPath);
    expect(captured.stdout()).not.toContain("EACCES");
  });
});
