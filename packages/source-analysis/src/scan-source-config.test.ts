import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { ProjectConfig } from "@pgard/findings";
import { afterEach, describe, expect, it } from "vitest";
import { describeConfigExcluded, scanSourceCode } from "./scan-source.js";
import { walkSourceTree } from "./walk.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-cfg-")));
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

const config = (overrides: Partial<ProjectConfig> = {}): ProjectConfig => ({
  version: 1,
  exclude: [],
  testDirectories: [],
  suppressions: [],
  ...overrides,
});

const area = (output: Awaited<ReturnType<typeof scanSourceCode>>, name: string) =>
  output.coverage.find((entry) => entry.area === name);

describe("exclude patterns in the source scan", () => {
  const files = {
    "src/db.ts": SQL_VULN,
    "legacy/old.ts": SQL_VULN,
    "legacy/deep/older.ts": SQL_VULN,
    "gen/x.generated.ts": SQL_VULN,
    "app/main.py": "print('hi')\n",
    "legacy/tool.py": "print('hi')\n",
  };

  it("does not analyze excluded files and counts them", async () => {
    const root = project(files);
    const output = await scanSourceCode(root, {
      projectConfig: config({ exclude: ["legacy", "*.generated.ts"] }),
    });
    expect(output.findings.map((f) => f.location.path)).toEqual(["src/db.ts"]);
    const excluded = area(output, "source:config-excluded");
    expect(excluded?.status).toBe("completed");
    expect(excluded?.ruleIds).toEqual([]);
    expect(excluded?.note).toMatch(
      /^4 files excluded by pgard\.config\.json \(of 6 source files; 2 patterns, set [0-9a-f]{8}\)\./,
    );
    expect(excluded?.note).toContain('Patterns: "legacy", "*.generated.ts".');
    // A track-language (Python) file is excluded too, so it is not listed as detected.
    expect(area(output, "source:python")?.note ?? "").not.toContain("legacy");
  });

  it("without a config everything is analyzed and no coverage area is added", async () => {
    const root = project(files);
    for (const projectConfig of [undefined, null, config()]) {
      const output = await scanSourceCode(root, { projectConfig });
      expect(output.findings).toHaveLength(4);
      expect(area(output, "source:config-excluded")).toBeUndefined();
    }
  });

  it("shows a pattern that matched nothing (a typo is visible)", async () => {
    const root = project(files);
    const output = await scanSourceCode(root, { projectConfig: config({ exclude: ["lagacy"] }) });
    expect(output.findings).toHaveLength(4);
    expect(area(output, "source:config-excluded")?.note).toMatch(/^0 files excluded/);
  });

  it("flags a catch-all pattern as a warning and partial coverage", async () => {
    const root = project(files);
    for (const pattern of ["**", "*", "**/*"]) {
      const output = await scanSourceCode(root, { projectConfig: config({ exclude: [pattern] }) });
      expect(output.findings).toEqual([]);
      const excluded = area(output, "source:config-excluded");
      expect(excluded?.status).toBe("partial");
      expect(excluded?.note).toContain("WARNING");
      expect(excluded?.note).toMatch(/^6 files excluded by pgard\.config\.json/);
    }
  });

  it("flags exclusions that leave nothing to analyze even without a catch-all pattern", async () => {
    const root = project({ "a/x.ts": SQL_VULN, "b/y.ts": SQL_VULN });
    const output = await scanSourceCode(root, { projectConfig: config({ exclude: ["a", "b"] }) });
    const excluded = area(output, "source:config-excluded");
    expect(excluded?.status).toBe("partial");
    expect(excluded?.note).toContain("WARNING: every source file is excluded.");
  });

  it("keeps the note within the display limit and quotes hostile patterns safely", async () => {
    const hostile = [
      'a"b',
      "x‮y",
      "**/it's?",
      "z".repeat(190),
      ...Array.from({ length: 150 }, (_, i) => `d${i}`),
    ];
    const root = project(files);
    const output = await scanSourceCode(root, {
      projectConfig: config({ exclude: hostile.filter((p) => !p.includes("‮")) }),
    });
    const note = area(output, "source:config-excluded")?.note ?? "";
    expect(note.length).toBeLessThanOrEqual(300);
    expect(note).toMatch(/^0 files excluded by pgard\.config\.json/);
    expect(note).toContain('"a\\"b"');
    expect(note).toMatch(/and \d+ more\.$/);
  });

  it("changes the note when the excluded file set changes, even with the same count", async () => {
    const one = project({ "src/a.ts": SQL_VULN, "gen/x.ts": SQL_VULN });
    const two = project({ "src/a.ts": SQL_VULN, "gen/y.ts": SQL_VULN });
    const options = { projectConfig: config({ exclude: ["gen"] }) };
    const first = area(await scanSourceCode(one, options), "source:config-excluded");
    const second = area(await scanSourceCode(two, options), "source:config-excluded");
    expect(first?.note).not.toBe(second?.note);
  });

  it("excluded files do not count toward the file limit and are not read", async () => {
    const root = project({ "gen/big.ts": "x".repeat(2 * 1024 * 1024), "src/a.ts": SQL_VULN });
    const walk = await walkSourceTree(root, { isExcluded: (p) => p.startsWith("gen/") });
    expect(walk.excluded.count).toBe(1);
    expect(walk.skippedLarge).toBe(0);
    expect(walk.files.map((f) => f.relativePath)).toEqual(["src/a.ts"]);
  });

  it("never lists dependency or build directories as excluded files", async () => {
    const root = project({
      "node_modules/p/i.ts": SQL_VULN,
      "dist/a.ts": SQL_VULN,
      "src/a.ts": SQL_VULN,
    });
    const walk = await walkSourceTree(root, { isExcluded: () => true });
    expect(walk.excluded.count).toBe(1);
  });
});

describe("describeConfigExcluded", () => {
  it("uses singular wording and is deterministic", () => {
    const first = describeConfigExcluded(["a"], { count: 1, digest: "abcd1234" }, 3);
    expect(first.note).toMatch(
      /^1 file excluded by pgard\.config\.json \(of 3 source files; 1 pattern, set /,
    );
    expect(describeConfigExcluded(["a"], { count: 1, digest: "abcd1234" }, 3)).toEqual(first);
  });

  it("a different pattern set gives a different hash", () => {
    const a = describeConfigExcluded(["a"], { count: 0, digest: "" }, 3).note;
    const b = describeConfigExcluded(["b"], { count: 0, digest: "" }, 3).note;
    expect(a).not.toBe(b);
  });
});
