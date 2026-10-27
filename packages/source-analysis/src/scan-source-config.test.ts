import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { ProjectConfig } from "@pgard/findings";
import { afterEach, describe, expect, it } from "vitest";
import {
  describeConfigExcluded,
  describeConfigTestDirectories,
  scanSourceCode,
} from "./scan-source.js";
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
      /^4 files excluded by pgard\.config\.json \(of 6 source files; 2 patterns, set [0-9a-f]{16}\)\./,
    );
    expect(excluded?.note).toContain('Patterns: "legacy", "*.generated.ts".');
    // A track-language (Python) file is excluded too, so it is not listed as detected.
    expect(area(output, "source:python")?.note ?? "").not.toContain("legacy");
  });

  it("an excluded minified bundle counts as excluded, not as source:minified", async () => {
    const root = project({ "src/db.ts": SQL_VULN, "public/vendor/jquery.min.js": SQL_VULN });
    const output = await scanSourceCode(root, {
      projectConfig: config({ exclude: ["public/**"] }),
    });
    expect(area(output, "source:minified")).toBeUndefined();
    expect(area(output, "source:config-excluded")?.note).toMatch(/^1 file excluded/);
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

  it("flags a catch-all pattern even when there are no source files at all", async () => {
    const output = await scanSourceCode(project({ "README.md": "x" }), {
      projectConfig: config({ exclude: ["**"] }),
    });
    const excluded = area(output, "source:config-excluded");
    expect(excluded?.status).toBe("partial");
    expect(excluded?.note).toContain('WARNING: "**" matches every file.');
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
    expect(walk.excluded.digest).toMatch(/^[0-9a-f]{16}$/);
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

describe("testDirectories in the source scan", () => {
  const prod = {
    "src/a.ts": SQL_VULN,
    "src/b.ts": SQL_VULN,
    "lib/c.ts": SQL_VULN,
  };

  it("reports how many production files the patterns demote", async () => {
    const output = await scanSourceCode(project(prod), {
      projectConfig: config({ testDirectories: ["lib"] }),
    });
    const entry = area(output, "source:config-test");
    expect(entry?.status).toBe("completed");
    expect(entry?.ruleIds).toEqual([]);
    expect(entry?.note).toMatch(/^1 of 3 source files are classified as test code by/);
    expect(entry?.note).toContain('Patterns: "lib".');
  });

  it("no area without testDirectories", async () => {
    const output = await scanSourceCode(project(prod), { projectConfig: config() });
    expect(area(output, "source:config-test")).toBeUndefined();
  });

  it.each(["*.*", "src", "**", "*", "?*"])(
    "warns when %s marks every production file as test code",
    async (pattern) => {
      const output = await scanSourceCode(project({ "src/a.ts": SQL_VULN, "src/b.ts": SQL_VULN }), {
        projectConfig: config({ testDirectories: [pattern] }),
      });
      const entry = area(output, "source:config-test");
      expect(entry?.status).toBe("partial");
      expect(entry?.note).toContain("WARNING");
      expect(entry?.note).toMatch(/^2 of 2 source files/);
    },
  );

  it("files already test code by the built-in rules are not counted as demoted", async () => {
    const output = await scanSourceCode(
      project({ "tests/a.ts": SQL_VULN, "src/b.ts": SQL_VULN, "src/c.ts": SQL_VULN }),
      { projectConfig: config({ testDirectories: ["tests"] }) },
    );
    const entry = area(output, "source:config-test");
    expect(entry?.status).toBe("completed");
    expect(entry?.note).toMatch(/^0 of 2 source files/);
  });

  it("warns at 50% and more than 20 files, and not below either bound", () => {
    const paths = (count: number, prefix: string) =>
      Array.from({ length: count }, (_, i) => `${prefix}/f${i}.ts`);
    const matchesDemo = (filePath: string) => filePath.startsWith("demo/");
    const run = (demo: number, other: number) =>
      describeConfigTestDirectories(
        ["demo"],
        [...paths(demo, "demo"), ...paths(other, "core")],
        matchesDemo,
      ).status;
    expect(run(21, 21)).toBe("partial"); // 50% and more than 20
    expect(run(21, 20)).toBe("partial");
    expect(run(20, 20)).toBe("completed"); // not more than 20 files
    expect(run(21, 22)).toBe("completed"); // under 50%
    expect(run(3, 3)).toBe("completed"); // small
    expect(run(3, 0)).toBe("partial"); // every production file
  });
});
