import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
// Review-fix tests (#90-#93) live at the end of this file.
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  parseGoMod,
  parseGoSum,
  parsePackageLock,
  parsePnpmLock,
  parseYarnLock,
} from "./lockfiles.js";
import { isVersionAffected, loadAdvisoryDb } from "./osv-db.js";
import { scanDependencies } from "./scan-dependencies.js";
import { compareVersions } from "./version.js";

const NOW = new Date("2026-10-24T00:00:00Z");
const now = () => NOW;
const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function tempDir(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-adv-")));
  dirs.push(root);
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  return root;
}

const LODASH_ADVISORY = {
  id: "GHSA-test-lodash",
  aliases: ["CVE-2021-23337"],
  summary: "Command injection in template",
  modified: "2026-10-20T00:00:00Z",
  database_specific: { severity: "HIGH" },
  affected: [
    {
      package: { ecosystem: "npm", name: "lodash" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
    },
  ],
};
const GO_ADVISORY = {
  id: "GO-2026-0001",
  aliases: ["CVE-2026-0001"],
  modified: "2026-10-01T00:00:00Z",
  affected: [
    {
      package: { ecosystem: "Go", name: "golang.org/x/text" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.3.8" }] }],
    },
  ],
};

function dbFile(records: unknown, extra: Record<string, unknown> = {}): string {
  const dir = tempDir({
    "osv.json": JSON.stringify({
      version: "test-1",
      updatedAt: "2026-10-20T00:00:00Z",
      vulnerabilities: records,
      ...extra,
    }),
  });
  return path.join(dir, "osv.json");
}

describe("compareVersions", () => {
  it.each([
    ["1.0.0", "1.0.1", -1],
    ["v0.3.8", "0.3.7", 1],
    ["1.0.0-alpha", "1.0.0", -1],
    ["1.0.0-alpha.2", "1.0.0-alpha.10", -1],
    ["2", "1.9.9", 1],
    ["1.2.3+build", "1.2.3", 0],
  ])("%s vs %s", (a, b, sign) => {
    expect(Math.sign(compareVersions(a, b))).toBe(sign);
  });
});

describe("isVersionAffected", () => {
  const affected = {
    ecosystem: "npm",
    name: "x",
    ranges: [
      {
        type: "SEMVER",
        events: [
          { introduced: "1.0.0" },
          { fixed: "1.2.0" },
          { introduced: "2.0.0" },
          { last_affected: "2.1.0" },
        ],
      },
    ],
    versions: ["0.9.0"],
  };
  it.each([
    ["0.9.0", true],
    ["0.9.1", false],
    ["1.0.0", true],
    ["1.1.9", true],
    ["1.2.0", false],
    ["2.1.0", true],
    ["2.1.1", false],
  ])("%s -> %s", (version, expected) => {
    expect(isVersionAffected(version, affected)).toBe(expected);
  });
});

describe("lockfile parsers", () => {
  it("parses package-lock v3 (scoped, nested, links skipped)", () => {
    const { packages } = parsePackageLock(
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "app" },
          "node_modules/lodash": { version: "4.17.20" },
          "node_modules/@scope/pkg": { version: "1.0.0" },
          "node_modules/a/node_modules/lodash": { version: "3.10.1" },
          "node_modules/local": { link: true },
        },
      }),
    );
    expect(packages.map((p) => `${p.name}@${p.version}`)).toEqual([
      "lodash@4.17.20",
      "@scope/pkg@1.0.0",
      "lodash@3.10.1",
    ]);
  });

  it("parses package-lock v1", () => {
    const { packages } = parsePackageLock(
      JSON.stringify({
        lockfileVersion: 1,
        dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "2.0.0" } } } },
      }),
    );
    expect(packages.map((p) => `${p.name}@${p.version}`)).toEqual(["a@1.0.0", "b@2.0.0"]);
  });

  it("reports invalid package-lock", () => {
    expect(parsePackageLock("{nope").error).toMatch(/not valid JSON/);
  });

  it.each([
    [
      "v9",
      "lockfileVersion: '9.0'\n\npackages:\n\n  lodash@4.17.20:\n    resolution: {integrity: x}\n\n  '@babel/core@7.0.0(supports-color@8.0.0)':\n    resolution: {integrity: y}\n",
    ],
    [
      "v6",
      "lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.20:\n    resolution: {integrity: x}\n\n  /@babel/core@7.0.0:\n    resolution: {integrity: y}\n",
    ],
    [
      "v5",
      "lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.20:\n    resolution: {integrity: x}\n\n  /@babel/core/7.0.0_supports-color@8.0.0:\n    resolution: {integrity: y}\n",
    ],
  ])("parses pnpm-lock %s", (_label, text) => {
    expect(parsePnpmLock(text).packages.map((p) => `${p.name}@${p.version}`)).toEqual([
      "lodash@4.17.20",
      "@babel/core@7.0.0",
    ]);
  });

  it("parses yarn.lock v1 and berry", () => {
    const v1 =
      '# yarn lockfile v1\n\n"lodash@^4.17.0", lodash@^4.17.20:\n  version "4.17.20"\n  resolved "https://x"\n\n"@scope/pkg@^1.0.0":\n  version "1.0.0"\n';
    const berry =
      '__metadata:\n  version: 6\n\n"lodash@npm:^4.17.20":\n  version: 4.17.20\n  resolution: "lodash@npm:4.17.20"\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n';
    expect(parseYarnLock(v1).packages.map((p) => `${p.name}@${p.version}`)).toEqual([
      "lodash@4.17.20",
      "@scope/pkg@1.0.0",
    ]);
    expect(parseYarnLock(berry).packages.map((p) => `${p.name}@${p.version}`)).toEqual([
      "lodash@4.17.20",
    ]);
  });

  it("parses go.mod and go.sum", () => {
    const mod =
      "module x\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.7\n\nrequire (\n\tgithub.com/a/b v1.2.3 // indirect\n)\n";
    expect(parseGoMod(mod).packages.map((p) => `${p.name}@${p.version}`)).toEqual([
      "golang.org/x/text@v0.3.7",
      "github.com/a/b@v1.2.3",
    ]);
    const sum = "golang.org/x/text v0.3.7 h1:abc=\ngolang.org/x/text v0.3.7/go.mod h1:def=\n";
    expect(parseGoSum(sum).packages).toEqual([
      { ecosystem: "Go", name: "golang.org/x/text", version: "v0.3.7" },
    ]);
  });
});

describe("loadAdvisoryDb", () => {
  it("reports missing configuration and missing files", async () => {
    expect((await loadAdvisoryDb({}, now)).status.status).toBe("missing");
    expect(
      (await loadAdvisoryDb({ PGARD_ADVISORY_DB: "/nonexistent/osv.json" }, now)).status.status,
    ).toBe("missing");
  });

  it("rejects invalid JSON and invalid records", async () => {
    const bad = path.join(tempDir({ "a.json": "{nope" }), "a.json");
    expect((await loadAdvisoryDb({ PGARD_ADVISORY_DB: bad }, now)).status.status).toBe("invalid");
    expect(
      (await loadAdvisoryDb({ PGARD_ADVISORY_DB: dbFile([{ id: "x" }]) }, now)).status.status,
    ).toBe("invalid");
    expect((await loadAdvisoryDb({ PGARD_ADVISORY_DB: dbFile([]) }, now)).status.status).toBe(
      "invalid",
    );
  });

  it("loads version and update time, and flags data older than 30 days as stale", async () => {
    const fresh = await loadAdvisoryDb({ PGARD_ADVISORY_DB: dbFile([LODASH_ADVISORY]) }, now);
    expect(fresh.status).toMatchObject({
      status: "ok",
      version: "test-1",
      updatedAt: "2026-10-20T00:00:00.000Z",
      advisoryCount: 1,
    });
    const stale = await loadAdvisoryDb(
      { PGARD_ADVISORY_DB: dbFile([LODASH_ADVISORY], { updatedAt: "2026-08-01T00:00:00Z" }) },
      now,
    );
    expect(stale.status.status).toBe("stale");
    expect(stale.status.note).toMatch(/stale/);
  });

  it("loads a directory of OSV files and derives the update time from records", async () => {
    const dir = tempDir({
      "npm/a.json": JSON.stringify(LODASH_ADVISORY),
      "go/b.json": JSON.stringify(GO_ADVISORY),
    });
    const db = await loadAdvisoryDb({ PGARD_ADVISORY_DB: dir }, now);
    expect(db.status).toMatchObject({
      status: "ok",
      advisoryCount: 2,
      updatedAt: "2026-10-20T00:00:00.000Z",
    });
    expect(db.status.note).not.toContain(dir);
  });
});

describe("scanDependencies", () => {
  const project = () =>
    tempDir({
      "package-lock.json": JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "node_modules/lodash": { version: "4.17.20" },
          "node_modules/safe": { version: "1.0.0" },
        },
      }),
      "services/api/go.mod": "module api\n\nrequire golang.org/x/text v0.3.7\n",
      "node_modules/lodash/package-lock.json": JSON.stringify({
        lockfileVersion: 3,
        packages: { "node_modules/lodash": { version: "1.0.0" } },
      }),
    });

  it("reports advisory matches with lockfile location, CVE and fix", async () => {
    const result = await scanDependencies(project(), {
      env: { PGARD_ADVISORY_DB: dbFile([LODASH_ADVISORY, GO_ADVISORY]) },
      now,
    });
    expect(result.findings.map((f) => [f.ruleId, f.location.path, f.severity])).toEqual([
      ["PG-DEP-001", "package-lock.json", "high"],
      ["PG-DEP-001", "services/api/go.mod", "medium"],
    ]);
    expect(result.findings[0]?.references.cve).toEqual(["CVE-2021-23337"]);
    expect(result.findings[0]?.evidence).toMatch(/Fixed in 4\.17\.21/);
    expect(result.findings[0]?.location.kind).toBe("dependency");
    expect(result.advisoryDb).toEqual({ version: "test-1", updatedAt: "2026-10-20T00:00:00.000Z" });
    const coverage = Object.fromEntries(result.coverage.map((entry) => [entry.area, entry.status]));
    expect(coverage).toEqual({
      "dependencies:npm": "completed",
      "dependencies:go": "completed",
      "dependencies:advisory-db": "completed",
    });
  });

  it("does not report fixed versions", async () => {
    const root = tempDir({
      "package-lock.json": JSON.stringify({
        lockfileVersion: 3,
        packages: { "node_modules/lodash": { version: "4.17.21" } },
      }),
    });
    const result = await scanDependencies(root, {
      env: { PGARD_ADVISORY_DB: dbFile([LODASH_ADVISORY]) },
      now,
    });
    expect(result.findings).toEqual([]);
  });

  it("never treats missing advisory data as safe", async () => {
    const result = await scanDependencies(project(), { env: {}, now });
    expect(result.findings).toEqual([]);
    const coverage = Object.fromEntries(result.coverage.map((entry) => [entry.area, entry]));
    expect(coverage["dependencies:npm"]?.status).toBe("not_tested");
    expect(coverage["dependencies:go"]?.status).toBe("not_tested");
    expect(coverage["dependencies:advisory-db"]?.status).toBe("not_tested");
    expect(coverage["dependencies:advisory-db"]?.note).toMatch(/no network update command/);
    expect(result.advisoryDb).toEqual({ version: null, updatedAt: null });
  });

  it("marks stale advisory data as partial while still reporting matches", async () => {
    const result = await scanDependencies(project(), {
      env: { PGARD_ADVISORY_DB: dbFile([LODASH_ADVISORY], { updatedAt: "2026-07-01T00:00:00Z" }) },
      now,
    });
    expect(result.findings).toHaveLength(1);
    expect(result.coverage.find((entry) => entry.area === "dependencies:npm")?.status).toBe(
      "partial",
    );
    expect(result.coverage.find((entry) => entry.area === "dependencies:advisory-db")?.status).toBe(
      "partial",
    );
  });

  it("never reports a root package.json without a lockfile as completed", async () => {
    const root = tempDir({
      "package.json": JSON.stringify({ dependencies: { lodash: "^4.0.0" } }),
    });
    const result = await scanDependencies(root, {
      env: { PGARD_ADVISORY_DB: dbFile([LODASH_ADVISORY]) },
      now,
    });
    const npm = result.coverage.find((entry) => entry.area === "dependencies:npm");
    expect(npm?.status).toBe("not_tested");
    expect(npm?.note).toMatch(/without a covering lockfile \(package\.json\)/);
  });
});

const lodashLock = (version: string) =>
  JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/lodash": { version } } });

describe("withdrawn advisories (#90)", () => {
  it("never reports a withdrawn advisory", async () => {
    const withdrawn = { ...LODASH_ADVISORY, withdrawn: "2026-10-21T00:00:00Z" };
    const root = tempDir({ "package-lock.json": lodashLock("4.17.20") });
    const result = await scanDependencies(root, {
      env: { PGARD_ADVISORY_DB: dbFile([withdrawn, GO_ADVISORY]) },
      now,
    });
    expect(result.findings).toEqual([]);
    expect(result.coverage.find((e) => e.area === "dependencies:advisory-db")?.note).toMatch(
      /1 withdrawn/,
    );
  });
});

describe("database limits (#91)", () => {
  it("refuses a directory over the file limit instead of using a truncated database", async () => {
    const dir = tempDir({
      "a.json": JSON.stringify(GO_ADVISORY),
      "b.json": JSON.stringify({ ...GO_ADVISORY, id: "GO-2" }),
      "c.json": JSON.stringify(LODASH_ADVISORY),
    });
    const db = await loadAdvisoryDb({ PGARD_ADVISORY_DB: dir }, now, undefined, {
      maxFiles: 2,
      maxBytes: 1e9,
    });
    expect(db.status.status).toBe("invalid");
    expect(db.status.note).toMatch(/file count limit/);
  });

  it("refuses a directory over the total size limit", async () => {
    const dir = tempDir({ "a.json": JSON.stringify(LODASH_ADVISORY) });
    const db = await loadAdvisoryDb({ PGARD_ADVISORY_DB: dir }, now, undefined, {
      maxFiles: 10,
      maxBytes: 10,
    });
    expect(db.status.status).toBe("invalid");
  });
});

describe("completeness (#92)", () => {
  it("skips package-less affected entries instead of rejecting the database", async () => {
    const gitOnly = {
      id: "OSV-GIT-1",
      modified: "2026-10-19T00:00:00Z",
      affected: [{ ranges: [{ type: "GIT", events: [{ introduced: "abc" }] }] }],
    };
    const db = await loadAdvisoryDb({ PGARD_ADVISORY_DB: dbFile([gitOnly, LODASH_ADVISORY]) }, now);
    expect(db.status.status).toBe("ok");
  });

  it("rejects an update time in the future", async () => {
    const db = await loadAdvisoryDb(
      { PGARD_ADVISORY_DB: dbFile([LODASH_ADVISORY], { updatedAt: "2027-01-01T00:00:00Z" }) },
      now,
    );
    expect(db.status.status).toBe("invalid");
  });

  it("counts git/file/alias entries as not compared and reports partial", async () => {
    const root = tempDir({
      "package-lock.json": JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "node_modules/lodash": { version: "4.17.21" },
          "node_modules/fromgit": {
            version: "1.0.0",
            resolved: "git+ssh://git@github.com/o/r.git#abc",
          },
          "node_modules/local": { version: "file:../local" },
        },
      }),
    });
    const result = await scanDependencies(root, {
      env: { PGARD_ADVISORY_DB: dbFile([LODASH_ADVISORY]) },
      now,
    });
    const npm = result.coverage.find((entry) => entry.area === "dependencies:npm");
    expect(npm?.status).toBe("partial");
    expect(npm?.note).toMatch(/2 dependency entries .* could not be compared/);
  });

  it("resolves yarn aliases to the real package", () => {
    const text = '# yarn lockfile v1\n\n"my-lodash@npm:lodash@^4.17.0":\n  version "4.17.20"\n';
    expect(parseYarnLock(text).packages).toEqual([
      { ecosystem: "npm", name: "lodash", version: "4.17.20" },
    ]);
  });

  it("applies go.mod replace directives", () => {
    const mod =
      "module x\n\nrequire (\n\tgolang.org/x/text v0.3.7\n\texample.com/a v1.0.0\n)\n\nreplace golang.org/x/text => golang.org/x/text v0.3.8\nreplace example.com/a => ../a\n";
    const result = parseGoMod(mod);
    expect(result.packages).toEqual([
      { ecosystem: "Go", name: "golang.org/x/text", version: "v0.3.8" },
    ]);
    expect(result.uncomparable).toBe(1);
  });

  it("reports unrecognized yarn.lock, go.mod and go.sum as errors", () => {
    expect(parseYarnLock("garbage text\nmore").error).toMatch(/not recognized/);
    expect(parseGoMod("garbage").error).toMatch(/not recognized/);
    expect(parseGoSum("garbage").error).toMatch(/not recognized/);
  });
});

describe("cost (#93)", () => {
  it("still reports a missing database when there is nothing to compare (#111)", async () => {
    const root = tempDir({ "README.md": "x" });
    const result = await scanDependencies(root, {
      env: { PGARD_ADVISORY_DB: "/nonexistent/db.json" },
      now,
    });
    expect(result.advisoryDb).toEqual({ version: null, updatedAt: null });
    const entry = result.coverage.find((e) => e.area === "dependencies:advisory-db");
    expect(entry?.status).toBe("not_tested");
    expect(entry?.note).toMatch(/not found/);
  });

  it("reports small database metadata even without manifests (#111)", async () => {
    const root = tempDir({ "README.md": "x" });
    const result = await scanDependencies(root, {
      env: { PGARD_ADVISORY_DB: dbFile([LODASH_ADVISORY]) },
      now,
    });
    expect(result.advisoryDb).toEqual({ version: "test-1", updatedAt: "2026-10-20T00:00:00.000Z" });
    expect(result.coverage.find((e) => e.area === "dependencies:advisory-db")?.status).toBe(
      "completed",
    );
  });

  it("accepts a go.sum with only /go.mod lines (#111)", () => {
    expect(parseGoSum("golang.org/x/text v0.3.7/go.mod h1:def=\n")).toEqual({
      packages: [],
      error: null,
    });
  });

  it("compares npm >= 7 lockfiles with registry tarball URLs (#110)", async () => {
    const root = tempDir({
      "package-lock.json": JSON.stringify({
        name: "app",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": { name: "app", dependencies: { lodash: "^4.17.20" } },
          "node_modules/lodash": {
            version: "4.17.20",
            resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
            integrity:
              "sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==",
          },
        },
      }),
    });
    const result = await scanDependencies(root, {
      env: { PGARD_ADVISORY_DB: dbFile([LODASH_ADVISORY]) },
      now,
    });
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(["PG-DEP-001"]);
    expect(result.coverage.find((e) => e.area === "dependencies:npm")?.status).toBe("completed");
  });

  it("rejects promptly when aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    const root = tempDir({ "package-lock.json": lodashLock("4.17.20") });
    await expect(
      scanDependencies(root, {
        env: { PGARD_ADVISORY_DB: dbFile([LODASH_ADVISORY]) },
        now,
        signal: controller.signal,
      }),
    ).rejects.toBeDefined();
  });
});

describe("package.json lockfile coverage (#114)", () => {
  const npmCoverage = async (files: Record<string, string>) => {
    const result = await scanDependencies(tempDir(files), {
      env: { PGARD_ADVISORY_DB: dbFile([LODASH_ADVISORY]) },
      now,
    });
    return result.coverage.find((entry) => entry.area === "dependencies:npm");
  };
  const manifest = JSON.stringify({ dependencies: { lodash: "^4.0.0" } });

  it("reports a nested package.json without any lockfile as not tested", async () => {
    const npm = await npmCoverage({ "web/package.json": manifest });
    expect(npm?.status).toBe("not_tested");
    expect(npm?.note).toMatch(/web\/package\.json/);
  });

  it("reports a nested package.json beside another directory's lockfile as partial", async () => {
    const npm = await npmCoverage({
      "api/package.json": manifest,
      "api/package-lock.json": lodashLock("4.17.21"),
      "web/package.json": manifest,
    });
    expect(npm?.status).toBe("partial");
    expect(npm?.note).toMatch(/without a covering lockfile \(web\/package\.json\)/);
    expect(npm?.note).not.toMatch(/api\/package\.json/);
  });

  it("treats workspace packages under a root lockfile as covered", async () => {
    const npm = await npmCoverage({
      "package.json": JSON.stringify({ workspaces: ["packages/*"] }),
      "package-lock.json": lodashLock("4.17.21"),
      "packages/a/package.json": manifest,
      "packages/b/nested/package.json": manifest,
    });
    expect(npm?.status).toBe("completed");
  });

  it("does not treat a sibling directory with a shared prefix as an ancestor", async () => {
    const npm = await npmCoverage({
      "app/yarn.lock": '# yarn lockfile v1\n\nlodash@^4.17.0:\n  version "4.17.21"\n',
      "app2/package.json": manifest,
    });
    expect(npm?.status).toBe("partial");
    expect(npm?.note).toMatch(/app2\/package\.json/);
  });

  it("caps the number of listed paths", async () => {
    const npm = await npmCoverage(
      Object.fromEntries(
        Array.from({ length: 7 }, (_, index) => [`p${index}/package.json`, manifest]),
      ),
    );
    expect(npm?.status).toBe("not_tested");
    expect(npm?.note).toMatch(/p4\/package\.json and 2 more/);
  });
});
