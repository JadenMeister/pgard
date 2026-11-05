import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { itScaled, scaled } from "../../../tests/support/timing.js";
import { liveWorkerCount } from "./file-worker.js";
import { scanJvm } from "./jvm/scan-jvm.js";
import { scanSourceCode } from "./scan-source.js";
import { detectLanguageTrack } from "./tree-sitter/language-track.js";
import {
  createWorkerTrackExecutor,
  type TrackExecutor,
  type TrackJob,
} from "./tree-sitter/track-jobs.js";
import { walkSourceTree } from "./walk.js";

// The worker is the built `dist/track-worker.js` (tests run from source, where a worker cannot
// load the TypeScript modules). CI builds before testing; a local run without a build skips these.
const DIST = fileURLToPath(new URL("../dist", import.meta.url));
const hasWorker = existsSync(path.join(DIST, "track-worker.js"));
if (!hasWorker && process.env.CI) throw new Error("dist/track-worker.js is missing; build first");

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-track-")));
  roots.push(root);
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  return root;
}

const coverageOf = (output: Awaited<ReturnType<typeof scanSourceCode>>, area: string) =>
  output.coverage.find((entry) => entry.area === area);

async function waitFor(condition: () => boolean, ms = 5_000): Promise<boolean> {
  const until = Date.now() + ms;
  while (!condition()) {
    if (Date.now() > until) return false;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return true;
}

const JAVA_VULN = `package demo;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
class A {
  void q(Statement st, HttpServletRequest req) throws Exception {
    st.executeQuery("SELECT * FROM t WHERE id = " + req.getParameter("id"));
  }
}
`;
const PY_VULN = `import os
from flask import request
os.system("ls " + request.args["a"])
`;
const PHP_VULN = `<?php
function q($db) { $db->query("SELECT * FROM t WHERE id = " . $_GET["id"]); }
`;
const MAPPER = `<?xml version="1.0"?>
<mapper namespace="demo.M">
  <select id="byName" resultType="demo.U">SELECT * FROM u WHERE name = '\${name}'</select>
</mapper>
`;
const MIXED = {
  "src/A.java": JAVA_VULN,
  "app.py": PY_VULN,
  "index.php": PHP_VULN,
  "src/main/resources/M.xml": MAPPER,
  "pom.xml": "<project><dependencies></dependencies></project>",
};

describe.skipIf(!hasWorker)("tree-sitter tracks in a worker", () => {
  const WORKER = pathToFileURL(path.join(DIST, "analyze-worker.js"));

  itScaled(
    "gives the same result as the inline analysis",
    async () => {
      const root = project(MIXED);
      const inline = await scanSourceCode(root, { analysisWorker: null });
      const worker = await scanSourceCode(root, { analysisWorker: WORKER });
      expect(worker.findings.length).toBeGreaterThanOrEqual(4);
      expect(worker.findings).toEqual(inline.findings);
      expect(worker.coverage).toEqual(inline.coverage);
      expect(worker.ruleStats).toEqual(inline.ruleStats);
    },
    120_000,
  );

  itScaled(
    "passes the controller model attributes to the Thymeleaf templates",
    async () => {
      const root = project({
        "src/C.java": `package demo;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
@Controller
class C {
  @GetMapping("/hi")
  String hi(@RequestParam String name, Model model) {
    model.addAttribute("name", name);
    return "hi";
  }
}
`,
        "src/main/resources/templates/hi.html": `<html xmlns:th="http://www.thymeleaf.org"><p th:utext="\${name}">x</p></html>`,
        "pom.xml": "<project/>",
      });
      const inline = await scanSourceCode(root, { analysisWorker: null });
      const worker = await scanSourceCode(root, { analysisWorker: WORKER });
      expect(inline.findings.some((f) => f.ruleId === "PG-XSS-004")).toBe(true);
      expect(worker.findings).toEqual(inline.findings);
    },
    120_000,
  );

  itScaled(
    "verifies the grammar checksum in the worker and never loads a grammar that fails it",
    async () => {
      // A copy of the built package whose Python grammar is changed: the worker must refuse it.
      const copy = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-track-copy-")));
      roots.push(copy);
      cpSync(DIST, path.join(copy, "dist"), { recursive: true });
      cpSync(path.join(DIST, "../grammars"), path.join(copy, "grammars"), { recursive: true });
      writeFileSync(path.join(copy, "package.json"), '{"type":"module"}');
      const modules = createRequire(import.meta.url).resolve("web-tree-sitter");
      symlinkSync(
        modules.slice(0, modules.indexOf("node_modules") + "node_modules".length),
        path.join(copy, "node_modules"),
      );
      const python = path.join(copy, "grammars/tree-sitter-python.wasm");
      writeFileSync(python, Buffer.concat([readFileSync(python), Buffer.from([0])]));

      const executor = createWorkerTrackExecutor(
        pathToFileURL(path.join(copy, "dist/track-worker.js")),
      );
      try {
        const job = (language: "python" | "java", source: string): TrackJob => ({
          kind: "tree",
          language,
          source,
          relativePath: "a",
          timeoutMs: 5_000,
          maxBytes: 1024 * 1024,
          django: false,
        });
        const bad = await executor.run(job("python", PY_VULN), 20_000, undefined);
        expect(bad).toMatchObject({
          kind: "done",
          value: {
            kind: "tree",
            outcome: {
              status: "unavailable",
              reason: expect.stringContaining("does not match its pinned SHA-256 checksum"),
            },
          },
        });
        // The untouched grammar of the same copy still loads, so the refusal is the checksum.
        const good = await executor.run(job("java", JAVA_VULN), 20_000, undefined);
        expect(good).toMatchObject({
          kind: "done",
          value: { kind: "tree", outcome: { status: "parsed" } },
        });
      } finally {
        executor.release();
      }
    },
    120_000,
  );
});

describe("hard per-file limit for the tree-sitter tracks", () => {
  /**
   * A stand-in `track-worker.js` (next to a stand-in `analyze-worker.js`, as the real ones are):
   * it answers every job with an empty analysis, but spins forever on a source with `SLOW`.
   */
  function fakeWorkers(): URL {
    const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-track-fake-")));
    roots.push(dir);
    writeFileSync(path.join(dir, "analyze-worker.js"), "");
    writeFileSync(
      path.join(dir, "track-worker.js"),
      [
        'const { parentPort } = require("node:worker_threads");',
        'parentPort.on("message", (m) => {',
        "  const job = m.job;",
        '  if (JSON.stringify(job).includes("SLOW")) for (;;) {}',
        "  const empty = { findings: [], capped: false, incomplete: false, unsupportedForms: [], unsupportedLibraries: [], unsupportedOsLibraries: [], unsupportedTemplateLibraries: [], unsupportedCryptoLibraries: [], reflectionWeb: false, modelAttributes: [], unsupportedSecurityForms: [], usesSpringSecurity: false, unsupportedProcessLibraries: [], frameworks: [], isMapper: true, malformedLine: null, actuatorExposure: [], kind: null };",
        '  const result = job.kind === "tree"',
        '    ? { kind: "tree", outcome: { status: "parsed", errorCount: 0, missingCount: 0, analysis: empty, namespaceFrameworks: [] } }',
        "    : { kind: job.kind, analysis: empty };",
        '  parentPort.postMessage({ id: m.id, kind: "done", result });',
        "});",
        'parentPort.postMessage({ id: -1, kind: "ready" });',
      ].join("\n"),
    );
    return pathToFileURL(path.join(dir, "analyze-worker.js"));
  }

  const SLOW_JAVA = "// SLOW\nclass S {}\n";
  const SLOW_PY = "# SLOW\nx = 1\n";
  const SLOW_PHP = "<?php // SLOW\n";

  it.each([
    ["Java", "source:java", { "S.java": SLOW_JAVA, "T.java": "class T {}\n" }],
    ["Python", "source:python", { "s.py": SLOW_PY, "t.py": "x = 2\n" }],
    ["PHP", "source:php", { "s.php": SLOW_PHP, "t.php": "<?php\n" }],
  ])(
    "stops a %s file at the limit, reports it and goes on with the next file",
    async (_name, area, files) => {
      const before = liveWorkerCount();
      const started = performance.now();
      const output = await scanSourceCode(project(files), {
        analysisWorker: fakeWorkers(),
        perFileTimeLimitMs: 400,
      });
      expect(performance.now() - started).toBeLessThan(scaled(20_000));
      const entry = coverageOf(output, area);
      expect(entry?.status).toBe("partial");
      expect(entry?.note).toMatch(/1 file\(s\) took longer than the per-file limit/);
      expect(entry?.note).toContain("not analyzed");
      expect(entry?.note).toContain("not a safe result");
      // The worker that spun was terminated; the next file got a new one and was analyzed.
      expect(await waitFor(() => liveWorkerCount() <= before + 1)).toBe(true);
    },
    60_000,
  );

  it("stops a MyBatis mapper at the limit and reports it", async () => {
    const output = await scanSourceCode(
      project({
        "pom.xml": "<project/>",
        "A.java": "class A {}\n",
        "M.xml": '<mapper namespace="x"><!-- SLOW --></mapper>',
      }),
      { analysisWorker: fakeWorkers(), perFileTimeLimitMs: 400 },
    );
    const entry = output.coverage.find((entry) => entry.area === "source:mybatis");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("stopped at the per-file limit");
  });

  it("reports a stopped Thymeleaf template as partial, never drops it", async () => {
    const output = await scanSourceCode(
      project({
        "pom.xml": "<project/>",
        "A.java": "class A {}\n",
        "src/main/resources/templates/page.html": `<html xmlns:th="http://www.thymeleaf.org"><p th:utext="\${q}">SLOW</p></html>`,
      }),
      { analysisWorker: fakeWorkers(), perFileTimeLimitMs: 400 },
    );
    const entry = output.coverage.find((entry) => entry.area === "source:jvm-templates");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("1 JSP or Thymeleaf template(s) were stopped");
  });

  it("stops reading mapper XML after repeated stops and reports the files left", async () => {
    const mapper = (name: string) => [
      `${name}.xml`,
      `<mapper namespace="x"><!-- SLOW --></mapper>`,
    ];
    const output = await scanSourceCode(
      project({
        "pom.xml": "<project/>",
        "A.java": "class A {}\n",
        ...Object.fromEntries(["a", "b", "c", "d", "e"].map(mapper)),
      }),
      { analysisWorker: fakeWorkers(), perFileTimeLimitMs: 300 },
    );
    const entry = output.coverage.find((entry) => entry.area === "source:mybatis");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("3 XML file(s) were stopped");
    expect(entry?.note).toContain("2 XML file(s) were not read");
  });

  it("starts no mapper, template or configuration job once the scan deadline has passed", async () => {
    const root = project({
      "pom.xml": "<project/>",
      "A.java": "class A {}\n",
      "a.xml": `<mapper namespace="x"></mapper>`,
      "src/main/resources/templates/p.html": `<html xmlns:th="http://www.thymeleaf.org"><p th:utext="\${q}">x</p></html>`,
      "application.properties": "server.servlet.session.cookie.secure=false\n",
    });
    const walk = await walkSourceTree(root);
    const detection = await detectLanguageTrack(walk);
    const jobs: string[] = [];
    const executor: TrackExecutor = {
      run: async (job) => {
        if (job.kind !== "tree") jobs.push(job.kind);
        return { kind: "timeout" };
      },
      release: () => {},
    };
    // An injected clock that is already past the deadline: nothing depends on real time.
    const expired = { endsAt: 0, totalMs: 1, now: () => 1 };
    const output = await scanJvm(walk, detection, { deadline: expired, executor });
    expect(jobs).toEqual([]);
    expect(output.coverage.find((entry) => entry.area === "source:mybatis")?.note).toContain(
      "were not read because the scan time budget ran out",
    );
    expect(output.coverage.find((entry) => entry.area === "source:jvm-templates")?.note).toContain(
      "template file(s) were not read because the scan time budget ran out",
    );
    expect(output.coverage.find((entry) => entry.area === "source:jvm-config")?.note).toContain(
      "were not read because the scan time budget ran out",
    );
  });

  it("stops at once when the scan is cancelled during a long file", async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(new Error("cancelled")), 300);
    const before = liveWorkerCount();
    const started = performance.now();
    await expect(
      scanSourceCode(project({ "S.java": SLOW_JAVA }), {
        analysisWorker: fakeWorkers(),
        signal: controller.signal,
      }),
    ).rejects.toThrow("cancelled");
    expect(performance.now() - started).toBeLessThan(scaled(10_000));
    expect(await waitFor(() => liveWorkerCount() === before, scaled(2_000))).toBe(true);
  }, 60_000);

  it("reports a worker that cannot start as not analyzed, never as a clean result", async () => {
    const output = await scanSourceCode(project({ "A.java": "class A {}\n" }), {
      analysisWorker: new URL("http://localhost/analyze-worker.js"),
    });
    const entry = coverageOf(output, "source:java");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("the analysis worker failed");
  });
});
