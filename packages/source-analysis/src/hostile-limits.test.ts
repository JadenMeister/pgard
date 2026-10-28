import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { scanSourceCode } from "./scan-source.js";
import { walkSourceTree } from "./walk.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function project(files: Record<string, string>, directories: string[] = []): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-hostile-")));
  roots.push(root);
  for (const directory of directories) mkdirSync(path.join(root, directory), { recursive: true });
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  return root;
}

const SQL_VULN =
  'import { Pool } from "pg";\nconst pool = new Pool();\nexport const q = (req) => pool.query(`SELECT * FROM t WHERE id = ${req.query.id}`);\n';
const GO_VULN =
  'package main\nimport ("database/sql"; "net/http")\nfunc h(db *sql.DB, r *http.Request) { db.Query("SELECT * FROM t WHERE id=" + r.URL.Query().Get("id")) }\n';
/** Quadratic in the Go analyzer's `var` handling: several seconds, far over the test limits. */
const SLOW_GO = `package main\nfunc f() {\n${"var a\n".repeat(150_000)}}\n`;
/** Nesting that overflows the TypeScript parser's stack. */
const DEEP_JS = `${"function f(a){ ".repeat(20_000)}x(a);${" }".repeat(20_000)}\n`;

const coverageOf = (output: Awaited<ReturnType<typeof scanSourceCode>>, area: string) =>
  output.coverage.find((entry) => entry.area === area);

describe("stack limit (M3)", () => {
  it.each([
    ["deep.js", DEEP_JS, "source:javascript"],
    ["deep.ts", DEEP_JS, "source:typescript"],
    ["Deep.vue", `<script>\n${DEEP_JS}</script>\n`, "source:vue"],
  ])("reports %s as not analyzed, not as a syntax error", async (name, content, area) => {
    const root = project({ [name]: content, "ok.js": SQL_VULN });
    const output = await scanSourceCode(root, { analysisWorker: null });
    const entry = coverageOf(output, area);
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain(
      `1 file(s) nested too deeply to analyze (stack limit reached; not analyzed: "${name}")`,
    );
    expect(entry?.note).not.toContain("syntax errors");
    // The other file keeps its finding.
    expect(output.findings.some((finding) => finding.location.path === "ok.js")).toBe(true);
  });
});

describe("walk limits (L4)", () => {
  it("stops at the entry cap and makes the scan partial with a note", async () => {
    const directories = Array.from({ length: 30 }, (_, index) => `empty/d${index}`);
    const root = project({ "zz/app.js": SQL_VULN }, directories);
    const walk = await walkSourceTree(root, { maxEntries: 10 });
    expect(walk.stoppedEarly).toEqual({ reason: "entries", visited: 10 });
    const output = await scanSourceCode(root, { analysisWorker: null, maxWalkEntries: 10 });
    expect(coverageOf(output, "source:walk")).toMatchObject({
      status: "partial",
      note: expect.stringContaining("stopped after 10 entries (limit 10)"),
    });
    expect(coverageOf(output, "source:javascript")?.status).toBe("partial");
  });

  it("counts against the time budget", async () => {
    const directories = Array.from({ length: 200 }, (_, index) => `d${index}`);
    const root = project({ "app.js": SQL_VULN }, directories);
    let clock = 0;
    const output = await scanSourceCode(root, {
      analysisWorker: null,
      timeBudgetMs: 1000,
      // Each clock read is a second later, so the budget is gone by the walk's first check.
      now: () => (clock += 1000),
    });
    expect(coverageOf(output, "source:walk")).toMatchObject({
      status: "partial",
      note: expect.stringContaining("because the time budget ran out"),
    });
  });

  it("leaves a normal tree complete", async () => {
    const output = await scanSourceCode(project({ "app.js": SQL_VULN }), { analysisWorker: null });
    expect(coverageOf(output, "source:walk")).toBeUndefined();
    expect(coverageOf(output, "source:javascript")?.status).toBe("completed");
  });
});

describe("incremental cache and redaction (L2)", () => {
  it("does not cache a file whose path redaction would change", async () => {
    const secretName = `ghp_${"a".repeat(36)}.js`;
    const root = project({
      [secretName]: SQL_VULN,
      "bidi‮gnp.js": SQL_VULN,
      "plain.js": SQL_VULN,
    });
    const output = await scanSourceCode(root, { analysisWorker: null });
    expect(output.fileCache.map((entry) => entry.path)).toEqual(["plain.js"]);
    // The files are still analyzed.
    expect(output.findings.filter((finding) => finding.ruleId === "PG-SQL-001")).toHaveLength(3);
    expect(JSON.stringify(output.fileCache)).not.toContain("ghp_aaaa");
  });
});

// The worker is the built `dist/analyze-worker.js`: tests run from source, where a worker cannot
// load the TypeScript modules. CI builds before testing; a local run without a build skips these.
const WORKER = new URL("../dist/analyze-worker.js", import.meta.url);
const hasWorker = existsSync(fileURLToPath(WORKER));
if (!hasWorker && process.env.CI) throw new Error("dist/analyze-worker.js is missing; build first");

describe.skipIf(!hasWorker)("per-file hard limit (worker)", () => {
  it("stops a file at the per-file limit, reports it and analyzes the next file", async () => {
    const root = project({ "a/slow.go": SLOW_GO, "b/ok.go": GO_VULN });
    const started = performance.now();
    const output = await scanSourceCode(root, { analysisWorker: WORKER, perFileTimeLimitMs: 500 });
    expect(performance.now() - started).toBeLessThan(4000);
    const go = coverageOf(output, "source:go");
    expect(go?.status).toBe("partial");
    expect(go?.note).toContain(
      '1 file(s) took longer than the per-file limit of 0.5 s (stopped; not analyzed: "a/slow.go")',
    );
    expect(output.findings.map((finding) => finding.location.path)).toEqual(["b/ok.go"]);
    expect(output.fileCache.map((entry) => entry.path)).toEqual(["b/ok.go"]);
  }, 15_000);

  it("stops a file when the time budget runs out", async () => {
    const root = project({ "slow.go": SLOW_GO });
    const started = performance.now();
    const output = await scanSourceCode(root, { analysisWorker: WORKER, timeBudgetMs: 600 });
    expect(performance.now() - started).toBeLessThan(4000);
    expect(coverageOf(output, "source:go")?.note).toContain(
      '1 file(s) stopped when the time budget ran out (not analyzed: "slow.go")',
    );
  }, 15_000);

  it("stops at once when the scan is cancelled during a long file", async () => {
    const root = project({ "slow.go": SLOW_GO });
    const controller = new AbortController();
    setTimeout(() => controller.abort(new Error("cancelled")), 300);
    const started = performance.now();
    await expect(
      scanSourceCode(root, { analysisWorker: WORKER, signal: controller.signal }),
    ).rejects.toThrow("cancelled");
    expect(performance.now() - started).toBeLessThan(2000);
  }, 15_000);

  it("gives the same result as the inline analysis", async () => {
    const root = project({ "db.ts": SQL_VULN, "main.go": GO_VULN, "deep.js": DEEP_JS });
    const inline = await scanSourceCode(root, { analysisWorker: null });
    const worker = await scanSourceCode(root, { analysisWorker: WORKER });
    expect(worker.findings).toEqual(inline.findings);
    expect(worker.fileCache).toEqual(inline.fileCache);
  }, 15_000);
});
