import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { liveWorkerCount, MAX_WORKER_FAILURES } from "./file-worker.js";
import { scanSourceCode } from "./scan-source.js";
import { walkSourceTree } from "./walk.js";
import { TIME_FACTOR } from "../../../tests/support/timing.js";

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
/**
 * Quadratic in the Go analyzer's per-constant scope check: tens of seconds, far over the limits
 * under test (the limit, not a fix of this shape, is what the tests are about).
 */
const SLOW_GO = `package main\n${Array.from({ length: 40_000 }, (_, index) => `const c${index} = 1\n`).join("")}`;
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

describe("paths in coverage notes", () => {
  it("are marked like finding paths, so two names cannot look the same", async () => {
    const root = project({ "a‮gnp.js": DEEP_JS, "agnp.js": DEEP_JS });
    const output = await scanSourceCode(root, { analysisWorker: null });
    const note = coverageOf(output, "source:javascript")?.note ?? "";
    expect(note).toContain('"a\\\\u202egnp.js"');
    expect(note).toContain('"agnp.js"');
    expect(note).not.toContain("‮");
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

describe("early walk stop marks every source area (M-1)", () => {
  /** One file for every walk-dependent area, under `z/` so the walk sees them before `a-junk/`. */
  const FILES: Record<string, string> = {
    "z/app.js": SQL_VULN,
    "z/db.ts": SQL_VULN,
    "z/view.jsx": "export const V = (p) => <div dangerouslySetInnerHTML={{ __html: p.h }} />;\n",
    "z/Page.vue": '<template><p v-html="$route.query.m"></p></template>\n',
    "z/main.go": GO_VULN,
    "z/app.py": "import os\nfrom flask import request\nos.system(request.args['a'])\n",
    "z/requirements.txt": "Flask==3.0\n",
    "z/ping.php": "<?php\nsystem($_GET['a']);\n",
    "z/src/main/java/T.java":
      'class T { void t(HttpServletRequest request) throws Exception { Runtime.getRuntime().exec(request.getParameter("a")); } }\n',
    "z/src/main/kotlin/K.kt":
      'class K { fun t(request: HttpServletRequest) { Runtime.getRuntime().exec(request.getParameter("a")) } }\n',
    "z/src/main/resources/application.properties": "management.endpoints.web.exposure.include=*\n",
    "z/src/main/resources/UserMapper.xml":
      '<mapper namespace="U"><select id="f">SELECT * FROM u WHERE n = ${n}</select></mapper>\n',
    "z/src/main/resources/templates/page.html": '<p th:utext="${msg}"></p>\n',
    "z/pom.xml": "<project></project>\n",
    "z/node_modules/x/index.js": "",
    "z/dist/out.js": "",
    "z/app.min.js": "x",
  };
  const junk = Array.from({ length: 80 }, (_, index) => `a-junk/d${index}`);

  const assertAllPartial = (output: Awaited<ReturnType<typeof scanSourceCode>>) => {
    const areas = output.coverage.filter(
      (entry) => entry.area.startsWith("source:") && entry.area !== "source:walk",
    );
    // The project reaches every kind of area, so a new one cannot silently miss the note.
    expect(areas.length).toBeGreaterThan(15);
    for (const entry of areas) {
      expect(entry.status, entry.area).not.toBe("completed");
      expect(entry.note, entry.area).toMatch(/^The directory walk stopped early/);
    }
    for (const stat of output.ruleStats ?? []) {
      if (stat.area.startsWith("source:")) expect(stat.status, stat.area).not.toBe("completed");
    }
    const build = output.coverage.find((entry) => entry.area === "source:build-output");
    expect(build?.walkedDirectories?.complete).not.toBe(true);
  };

  it("on the entry cap", async () => {
    const root = project(FILES, junk);
    // Root (2 entries) and everything under z/ fit; a-junk/ does not.
    const output = await scanSourceCode(root, { analysisWorker: null, maxWalkEntries: 60 });
    expect(coverageOf(output, "source:walk")?.status).toBe("partial");
    assertAllPartial(output);
  });

  it("on the time budget", async () => {
    const root = project(FILES, junk);
    let clock = 0;
    let reads = 0;
    const output = await scanSourceCode(root, {
      analysisWorker: null,
      timeBudgetMs: 10_000,
      // The budget runs out at the walk's first check (after 64 directories).
      now: () => {
        reads += 1;
        return reads <= 1 ? clock : (clock += 1_000_000);
      },
    });
    expect(coverageOf(output, "source:walk")?.note).toContain("time budget");
    assertAllPartial(output);
  });

  it("leaves areas alone when the walk finished", async () => {
    const output = await scanSourceCode(project(FILES), { analysisWorker: null });
    expect(coverageOf(output, "source:walk")).toBeUndefined();
    for (const entry of output.coverage) {
      expect(entry.note ?? "").not.toMatch(/directory walk stopped early/);
    }
  });
});

// The worker is the built `dist/analyze-worker.js`: tests run from source, where a worker cannot
// load the TypeScript modules. CI builds before testing; a local run without a build skips these.
const WORKER = new URL("../dist/analyze-worker.js", import.meta.url);
const hasWorker = existsSync(fileURLToPath(WORKER));
if (!hasWorker && process.env.CI) throw new Error("dist/analyze-worker.js is missing; build first");

/** Bounds far above the limits under test and far below SLOW_GO's own run time (tens of seconds). */
const STOPPED_WITHIN_MS = 15_000 * TIME_FACTOR;

async function waitFor(condition: () => boolean, ms = 5_000): Promise<boolean> {
  const until = Date.now() + ms;
  while (!condition()) {
    if (Date.now() > until) return false;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return true;
}

describe.skipIf(!hasWorker)("per-file hard limit (worker)", () => {
  it("stops a file at the per-file limit, reports it and analyzes the next file", async () => {
    const root = project({ "a/slow.go": SLOW_GO, "b/ok.go": GO_VULN });
    const started = performance.now();
    const output = await scanSourceCode(root, { analysisWorker: WORKER, perFileTimeLimitMs: 500 });
    expect(performance.now() - started).toBeLessThan(STOPPED_WITHIN_MS);
    const go = coverageOf(output, "source:go");
    expect(go?.status).toBe("partial");
    expect(go?.note).toContain(
      '1 file(s) took longer than the per-file limit of 0.5 s (stopped; not analyzed: "a/slow.go")',
    );
    expect(output.findings.map((finding) => finding.location.path)).toEqual(["b/ok.go"]);
    expect(output.fileCache.map((entry) => entry.path)).toEqual(["b/ok.go"]);
  }, 60_000);

  it("terminates the stopped worker", async () => {
    const root = project({ "slow.go": SLOW_GO });
    await scanSourceCode(root, { analysisWorker: WORKER, perFileTimeLimitMs: 300 });
    // The only worker ran the slow file and was stopped; nothing may keep running it.
    expect(await waitFor(() => liveWorkerCount() === 0)).toBe(true);
  }, 60_000);

  it("stops a file when the time budget runs out", async () => {
    const root = project({ "slow.go": SLOW_GO });
    const started = performance.now();
    const output = await scanSourceCode(root, { analysisWorker: WORKER, timeBudgetMs: 600 });
    expect(performance.now() - started).toBeLessThan(STOPPED_WITHIN_MS);
    expect(coverageOf(output, "source:go")?.note).toContain(
      '1 file(s) stopped when the time budget ran out (not analyzed: "slow.go")',
    );
  }, 60_000);

  it("stops at once when the scan is cancelled during a long file", async () => {
    const root = project({ "slow.go": SLOW_GO });
    const controller = new AbortController();
    setTimeout(() => controller.abort(new Error("cancelled")), 300);
    const started = performance.now();
    await expect(
      scanSourceCode(root, { analysisWorker: WORKER, signal: controller.signal }),
    ).rejects.toThrow("cancelled");
    expect(performance.now() - started).toBeLessThan(STOPPED_WITHIN_MS);
  }, 60_000);

  it("gives the same result as the inline analysis", async () => {
    const root = project({ "db.ts": SQL_VULN, "main.go": GO_VULN, "deep.js": DEEP_JS });
    const inline = await scanSourceCode(root, { analysisWorker: null });
    const worker = await scanSourceCode(root, { analysisWorker: WORKER });
    expect(worker.findings).toEqual(inline.findings);
    expect(worker.fileCache).toEqual(inline.fileCache);
  }, 60_000);

  it("works when the process runs with flags a worker refuses, and exits after a stopped file", () => {
    const script = path.join(project({}), "run.mjs");
    writeFileSync(
      script,
      [
        "const [index, root] = process.argv.slice(2);",
        "const { scanSourceCode } = await import(index);",
        "const out = await scanSourceCode(root, { perFileTimeLimitMs: 300 });",
        'process.stdout.write(JSON.stringify(out.coverage.find((c) => c.area === "source:go")));',
      ].join("\n"),
    );
    const root = project({ "a/slow.go": SLOW_GO, "b/ok.go": GO_VULN });
    const index = new URL("../dist/index.js", import.meta.url).href;
    const started = Date.now();
    const result = spawnSync(
      process.execPath,
      ["--max-old-space-size=512", "--stack-size=900", "--expose-gc", script, index, root],
      { encoding: "utf8", timeout: 50_000 },
    );
    // Exits on its own: the stopped worker is terminated and the idle one does not hold it.
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(Date.now() - started).toBeLessThan(45_000 * TIME_FACTOR);
    const go = JSON.parse(result.stdout) as { status: string; note: string };
    expect(go.status).toBe("partial");
    expect(go.note).toContain('per-file limit of 0.3 s (stopped; not analyzed: "a/slow.go")');
    expect(go.note).not.toContain("worker failed");
  }, 60_000);
});

describe("analysis worker failures", () => {
  /** A stand-in worker script; `starts` gets one line per start. */
  function fakeWorker(body: string): { url: URL; starts: () => number } {
    const dir = project({});
    const log = path.join(dir, "starts.log");
    const file = path.join(dir, "worker.mjs");
    writeFileSync(
      file,
      [
        'import { appendFileSync } from "node:fs";',
        'import { parentPort } from "node:worker_threads";',
        `appendFileSync(${JSON.stringify(log)}, "x\\n");`,
        body,
      ].join("\n"),
    );
    return {
      url: pathToFileURL(file),
      starts: () => (existsSync(log) ? readFileSync(log, "utf8").split("\n").length - 1 : 0),
    };
  }
  const files = {
    "a.js": SQL_VULN,
    "b.js": SQL_VULN,
    "c.js": SQL_VULN,
    "d.js": SQL_VULN,
    "e.js": SQL_VULN,
  };

  const expectWorkerFailed = (
    output: Awaited<ReturnType<typeof scanSourceCode>>,
    count: number,
  ) => {
    const js = coverageOf(output, "source:javascript");
    expect(js?.status).toBe("partial");
    expect(js?.note).toContain(`${count} file(s) not analyzed: the analysis worker failed`);
    expect(js?.note).not.toContain("syntax errors");
    expect(output.findings.filter((finding) => finding.ruleId === "PG-SQL-001")).toEqual([]);
  };

  it("reports a worker that cannot be created, without failing the scan", async () => {
    const output = await scanSourceCode(project(files), {
      analysisWorker: new URL("http://localhost/not-a-worker.js"),
    });
    expectWorkerFailed(output, 5);
  });

  it("stops starting workers after repeated crashes", async () => {
    const fake = fakeWorker('throw new Error("boom");');
    const output = await scanSourceCode(project(files), { analysisWorker: fake.url });
    expectWorkerFailed(output, 5);
    expect(fake.starts()).toBe(MAX_WORKER_FAILURES);
  });

  it("treats a worker that exits as a failure", async () => {
    const fake = fakeWorker(
      'parentPort.postMessage({ id: -1, kind: "ready" });\nparentPort.on("message", () => process.exit(3));',
    );
    expectWorkerFailed(await scanSourceCode(project(files), { analysisWorker: fake.url }), 5);
  });

  it.each([
    ["a malformed result", '{ id: m.id, kind: "done", entry: { findings: 1 } }'],
    ["an unknown kind", '{ id: m.id, kind: "weird" }'],
  ])("treats %s as a failure", async (_name, reply) => {
    const fake = fakeWorker(
      `parentPort.postMessage({ id: -1, kind: "ready" });\nparentPort.on("message", (m) => parentPort.postMessage(${reply}));`,
    );
    expectWorkerFailed(await scanSourceCode(project(files), { analysisWorker: fake.url }), 5);
    expect(fake.starts()).toBe(MAX_WORKER_FAILURES);
  });
});
