import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  MAX_DEPENDENCY_NOTE_LENGTH,
  describeSkippedDependencyDirectories,
  scanSourceCode,
} from "./scan-source.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function project(files: Record<string, string | Buffer>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-src-")));
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

describe("scanSourceCode", () => {
  it("scans JS/TS/Vue/Go, skips dependency and build folders, and reports coverage", async () => {
    const outside = project({ "evil.ts": SQL_VULN });
    const root = project({
      "src/db.ts": SQL_VULN,
      "src/Page.vue": '<template><p v-html="$route.query.m"></p></template>',
      "src/view.jsx":
        "export const V = ({ h }) => <div dangerouslySetInnerHTML={{ __html: h }} />;",
      "cmd/main.go":
        'package main\n\nimport (\n\t"database/sql"\n\t"fmt"\n)\n\nfunc f(n string) { db.Query(fmt.Sprintf("SELECT %s", n)) }\n',
      "node_modules/lib/index.js": SQL_VULN,
      "vendor/x/y.go": 'package y\nimport "database/sql"\nfunc f() { db.Query("a" + b) }\n',
      "dist/bundle.js": SQL_VULN,
      "src/app.min.js": SQL_VULN,
      "src/types.d.ts": SQL_VULN,
      "src/huge.ts": `${"// pad\n".repeat(200_000)}${SQL_VULN}`,
      "src/binary.js": Buffer.from([0x63, 0x6f, 0x00, 0x6e, 0x73, 0x74]),
      "package.json": JSON.stringify({ dependencies: { typeorm: "0.3.0", express: "4" } }),
    });
    symlinkSync(path.join(outside, "evil.ts"), path.join(root, "src", "link.ts"));

    const result = await scanSourceCode(root);
    const paths = result.findings.map((finding) => finding.location.path);
    expect(paths).toEqual(
      expect.arrayContaining(["src/db.ts", "src/Page.vue", "src/view.jsx", "cmd/main.go"]),
    );
    for (const skipped of [
      "node_modules/lib/index.js",
      "vendor/x/y.go",
      "dist/bundle.js",
      "src/app.min.js",
      "src/types.d.ts",
      "src/huge.ts",
      "src/link.ts",
    ]) {
      expect(paths).not.toContain(skipped);
    }
    expect(JSON.stringify(result)).not.toContain(root);

    const coverage = Object.fromEntries(result.coverage.map((entry) => [entry.area, entry]));
    expect(coverage["source:typescript"]).toMatchObject({ status: "completed", scope: "code" });
    expect(coverage["source:javascript"]).toMatchObject({ status: "partial" });
    expect(coverage["source:javascript"]?.note).toMatch(/binary or unreadable/);
    expect(coverage["source:vue"]?.status).toBe("completed");
    expect(coverage["source:symlinks"]).toMatchObject({
      status: "completed",
      ruleIds: [],
      note: expect.stringMatching(/^1 symbolic link\(s\) were not followed \(set [0-9a-f]{8}\)\.$/),
    });
    expect(coverage["source:go"]?.note).toMatch(/syntax-level/);
    expect(coverage["source:react"]?.ruleIds).toEqual(["PG-XSS-002"]);
    expect(coverage["source:large-files"]).toMatchObject({ status: "partial" });
    expect(coverage["source:orm:typeorm"]).toMatchObject({ status: "partial" });
    expect(coverage["source:orm:typeorm"]?.note).toMatch(/not supported/);
  });

  it("analyzes first-party vendor/ modules under src/, app/ or lib/ in any letter case", async () => {
    const root = project({
      "package.json": "{}",
      "src/vendor/a.ts": SQL_VULN,
      "packages/web/Src/vendor/x.ts": SQL_VULN,
      "packages/api/lib/vendor/b.ts": SQL_VULN,
    });
    const result = await scanSourceCode(root);
    const paths = result.findings.map((finding) => finding.location.path);
    expect(paths).toEqual(
      expect.arrayContaining([
        "src/vendor/a.ts",
        "packages/web/Src/vendor/x.ts",
        "packages/api/lib/vendor/b.ts",
      ]),
    );
    expect(result.coverage.find((entry) => entry.area === "source:typescript")?.note).toMatch(
      /^3 TypeScript file\(s\)/,
    );
    expect(result.coverage.map((entry) => entry.area)).not.toContain(
      "source:dependency-directories",
    );
  });

  it("skips dependency vendor/ directories and node_modules anywhere, and lists them", async () => {
    const root = project({
      "composer.json": "{}",
      "vendor/acme/lib.ts": SQL_VULN,
      "svc/go.mod": "module example.com/svc\n",
      "svc/vendor/x/y.ts": SQL_VULN,
      "src/composer.json": "{}",
      "src/vendor/own.ts": SQL_VULN,
      "tools/vendor/script.ts": SQL_VULN,
      "packages/web/node_modules/pkg/index.js": SQL_VULN,
      "src/node_modules/pkg/index.js": SQL_VULN,
    });
    const result = await scanSourceCode(root);
    const paths = result.findings.map((finding) => finding.location.path);
    // A vendor/ under src/ or without a manifest next to it is analyzed (its findings are later
    // grouped as vendored suggestions when the path is vendored).
    expect(paths).toEqual(expect.arrayContaining(["src/vendor/own.ts", "tools/vendor/script.ts"]));
    for (const skipped of [
      "vendor/acme/lib.ts",
      "svc/vendor/x/y.ts",
      "packages/web/node_modules/pkg/index.js",
      "src/node_modules/pkg/index.js",
    ]) {
      expect(paths).not.toContain(skipped);
    }
    const coverage = result.coverage.find(
      (entry) => entry.area === "source:dependency-directories",
    );
    expect(coverage).toMatchObject({ status: "completed", scope: "code", ruleIds: [] });
    expect(coverage?.note).toBe(
      "Skipped 4 dependency directories (third-party code, not analyzed): packages/web/node_modules/, src/node_modules/, svc/vendor/ (go.mod), vendor/ (composer.json).",
    );
    expect(result.coverage.find((entry) => entry.area === "source:typescript")?.note).toMatch(
      /^2 TypeScript file\(s\)/,
    );
  });

  it("skips a root vendor/ without a manifest", async () => {
    const root = project({ "vendor/a.ts": SQL_VULN, "src/b.ts": SQL_VULN });
    const result = await scanSourceCode(root);
    expect(result.findings.map((finding) => finding.location.path)).not.toContain("vendor/a.ts");
    expect(
      result.coverage.find((entry) => entry.area === "source:dependency-directories")?.note,
    ).toContain("vendor/ (repository root, no manifest; assumed third-party)");
  });

  it("reports languages without files as completed with a note, never as findings", async () => {
    const root = project({ "README.md": "# x" });
    const result = await scanSourceCode(root);
    expect(result.findings).toEqual([]);
    expect(result.coverage.find((entry) => entry.area === "source:go")?.note).toBe(
      "No Go files found.",
    );
  });

  it("marks files with syntax errors as partial coverage", async () => {
    const root = project({ "src/broken.ts": "function (", "src/ok.ts": "export const a = 1;" });
    const result = await scanSourceCode(root);
    expect(result.coverage.find((entry) => entry.area === "source:typescript")).toMatchObject({
      status: "partial",
    });
  });

  it("raises CSRF and brute-force heuristics only without protection libraries", async () => {
    const server =
      "import express from 'express';\nimport session from 'express-session';\nconst app = express();\napp.use(session({ secret: process.env.S, cookie: { secure: true, sameSite: 'lax' } }));\napp.post('/login', login);\napp.post('/items', create);\n";
    const unprotected = await scanSourceCode(project({ "server.js": server }));
    const rules = unprotected.findings.map((finding) => finding.ruleId);
    expect(rules).toContain("PG-CSRF-001");
    expect(rules).toContain("PG-BRUTE-001");
    for (const finding of unprotected.findings.filter((f) =>
      ["PG-CSRF-001", "PG-BRUTE-001"].includes(f.ruleId),
    )) {
      expect(finding).toMatchObject({ status: "suspected", confidence: "low" });
    }

    const protectedResult = await scanSourceCode(
      project({
        "server.js": `import csrf from 'csurf';\nimport rateLimit from 'express-rate-limit';\n${server}`,
      }),
    );
    const protectedRules = protectedResult.findings.map((finding) => finding.ruleId);
    expect(protectedRules).not.toContain("PG-CSRF-001");
    expect(protectedRules).not.toContain("PG-BRUTE-001");
  });

  it("treats PUT/DELETE as CSRF-able only with credentialed permissive CORS, and a cookie-set alone is no session", async () => {
    const csrfIn = async (files: Record<string, string>) =>
      (await scanSourceCode(project(files))).findings.some((f) => f.ruleId === "PG-CSRF-001");
    const head =
      "const express = require('express');\nconst cookieParser = require('cookie-parser');\nconst cors = require('cors');\nconst app = express();\napp.use(cookieParser());\n";
    const route = "app.delete('/account', (req, res) => res.sendStatus(204));\n";
    expect(await csrfIn({ "s.js": `${head}${route}` })).toBe(false);
    expect(
      await csrfIn({
        "s.js": `${head}app.use(cors({ origin: true, credentials: true }));\n${route}`,
      }),
    ).toBe(true);
    expect(
      await csrfIn({ "s.js": `${head}app.post('/account', (req, res) => res.end());\n` }),
    ).toBe(true);
    // Only setting a non-session cookie, with no session library.
    expect(
      await csrfIn({
        "s.js": "app.post('/x', (req, res) => { res.cookie('theme', 'v', {}); res.end(); });\n",
      }),
    ).toBe(false);
    // Fastify sessions count as cookie sessions.
    expect(
      await csrfIn({
        "s.js":
          "const fastify = require('fastify')();\nfastify.register(require('@fastify/secure-session'), {});\nfastify.post('/x', async () => ({}));\n",
      }),
    ).toBe(true);
  });

  it("keeps PUT/PATCH/DELETE in when CORS is unknown, and reports the earliest counted route", async () => {
    const scan = async (files: Record<string, string>) =>
      (await scanSourceCode(project(files))).findings.filter((f) => f.ruleId === "PG-CSRF-001");
    const head = "const cookieParser = require('cookie-parser');\nconst cors = require('cors');\n";
    const put = "app.put('/p', (req, res) => res.end());\n";
    const post = "app.post('/q', (req, res) => res.end());\n";
    // Unresolvable CORS options, a hand-set header and method-override keep the preflight methods.
    expect(await scan({ "s.js": `${head}app.use(cors(opts));\n${put}` })).toHaveLength(1);
    expect(
      await scan({
        "s.js": `${head}app.use((q, r) => r.header('Access-Control-Allow-Credentials', 'true'));\n${put}`,
      }),
    ).toHaveLength(1);
    expect(
      await scan({ "s.js": `${head}const mo = require('method-override');\n${put}` }),
    ).toHaveLength(1);
    // Provably restrictive CORS keeps them out.
    expect(
      await scan({
        "s.js": `${head}app.use(cors({ origin: ['https://a.example'], credentials: true }));\n${put}`,
      }),
    ).toEqual([]);
    // The finding points at the earliest counted route, not the first POST.
    const [mixed] = await scan({
      "s.js": `${head}app.use(cors({ origin: true, credentials: true }));\n${put}${post}`,
    });
    expect(mixed?.location?.line).toBe(4);
    const [postOnly] = await scan({ "s.js": `${head}\n\n${put}${post}` });
    expect(postOnly?.location?.line).toBe(6);
    // SameSite=Strict express-session is not CSRF-able; a lax one is.
    const session = (sameSite: string) =>
      `const session = require('express-session');\napp.use(session({ secret: process.env.S, cookie: { httpOnly: true, secure: true, sameSite: '${sameSite}' } }));\n${post}`;
    expect(await scan({ "s.js": session("strict") })).toEqual([]);
    expect(await scan({ "s.js": session("lax") })).toHaveLength(1);
  });

  it("produces stable ids across runs", async () => {
    const root = project({ "src/db.ts": SQL_VULN });
    const first = await scanSourceCode(root);
    const second = await scanSourceCode(root);
    expect(first.findings.map((f) => f.id)).toEqual(second.findings.map((f) => f.id));
  });
});

describe("hand-written files with long strings (#105)", () => {
  const longDataUri = `const logo = "data:image/svg+xml;base64,${"A".repeat(6000)}";`;

  it("analyzes a server file that embeds a long data URI", async () => {
    const root = project({
      "server.js": `${longDataUri}\nimport { exec } from "child_process";\napp.get("/ls", (req, res) => exec(\`ls \${req.query.dir}\`));\n`,
    });
    const result = await scanSourceCode(root);
    expect(result.findings.map((finding) => finding.ruleId)).toContain("PG-CMD-001");
  });

  it("analyzes a Vue component with a long inline SVG", async () => {
    const svg = `<svg>${"<path d='M0 0'/>".repeat(800)}</svg>`;
    const root = project({
      "src/Icon.vue": `<template><div>${svg}<p v-html="$route.query.m"></p></div></template>\n`,
    });
    const result = await scanSourceCode(root);
    expect(result.findings.map((finding) => finding.ruleId)).toContain("PG-XSS-003");
  });

  it("checks the time budget after the last file", async () => {
    const root = project({ "only.ts": "export const a = 1;" });
    let clock = 0;
    const result = await scanSourceCode(root, { timeBudgetMs: 150, now: () => (clock += 100) });
    const ts = result.coverage.find((entry) => entry.area === "source:typescript");
    expect(ts?.status).toBe("partial");
  });
});

describe("coverage notes (#109)", () => {
  it("names the files that hit the per-file finding cap", async () => {
    const bundle = `${"var a=document;a.body.innerHTML=x;".repeat(400)}\n`;
    const root = project({ "public/a.js": bundle, "public/b.js": bundle, "src/ok.js": "1;" });
    const result = await scanSourceCode(root);
    const note = result.coverage.find((entry) => entry.area === "source:javascript")?.note;
    expect(note).toMatch(
      /2 file\(s\) hit the per-file finding cap \("public\/a\.js", "public\/b\.js"\)/,
    );
  });

  it("quotes capped paths so a name containing a comma stays unambiguous", async () => {
    const bundle = `${"var a=document;a.body.innerHTML=x;".repeat(400)}\n`;
    const root = project({ "public/a, b.js": bundle, "src/ok.js": "1;" });
    const result = await scanSourceCode(root);
    const note = result.coverage.find((entry) => entry.area === "source:javascript")?.note;
    expect(note).toContain('per-file finding cap ("public/a, b.js")');
  });

  it("starts the problem list with a capital letter", async () => {
    const root = project({ "only.ts": "export const a = 1;" });
    let clock = 0;
    const result = await scanSourceCode(root, { timeBudgetMs: 150, now: () => (clock += 100) });
    const note = result.coverage.find((entry) => entry.area === "source:typescript")?.note;
    expect(note).toMatch(/taint tracking\. The time budget was exceeded/);
  });
});

describe("time budget, parse errors and caps (#87, #89)", () => {
  it("stops at the time budget with partial coverage", async () => {
    const root = project({ "a.ts": "export const a = 1;", "b.ts": "export const b = 2;" });
    let clock = 0;
    const result = await scanSourceCode(root, { timeBudgetMs: 50, now: () => (clock += 100) });
    const ts = result.coverage.find((entry) => entry.area === "source:typescript");
    expect(ts?.status).toBe("partial");
    expect(ts?.note).toMatch(/time budget/);
  });

  it("marks unparsable Go as partial coverage", async () => {
    const root = project({ "bad.go": "package main\nfunc f( {\n" });
    const result = await scanSourceCode(root);
    expect(result.coverage.find((entry) => entry.area === "source:go")?.status).toBe("partial");
  });

  it("bounds findings from minified bundles with the per-file cap", async () => {
    const bundle = `${"var a=document;a.body.innerHTML=x;".repeat(400)}\n`;
    const root = project({ "public/bundle.js": bundle });
    const result = await scanSourceCode(root);
    expect(result.findings.length).toBeLessThanOrEqual(25);
    expect(result.coverage.find((entry) => entry.area === "source:javascript")?.note).toMatch(
      /finding cap/,
    );
  });
});

describe("describeSkippedDependencyDirectories", () => {
  it("lists at most five directories, sorted, and counts the rest", () => {
    const directories = Array.from({ length: 7 }, (_, index) => ({
      path: `packages/p${6 - index}/node_modules`,
      reason: null,
    }));
    const note = describeSkippedDependencyDirectories(directories);
    expect(note).toBe(
      "Skipped 7 dependency directories (third-party code, not analyzed): packages/p0/node_modules/, packages/p1/node_modules/, packages/p2/node_modules/, packages/p3/node_modules/, packages/p4/node_modules/ and 2 more.",
    );
  });

  it("quotes unusual names and marks a root vendor/ without a manifest as an assumption", () => {
    expect(
      describeSkippedDependencyDirectories([
        { path: "my app/vendor", reason: "Gemfile" },
        { path: "vendor", reason: "repository root" },
      ]),
    ).toBe(
      'Skipped 2 dependency directories (third-party code, not analyzed): "my app/vendor/" (Gemfile), vendor/ (repository root, no manifest; assumed third-party).',
    );
  });

  it("lists fewer names when paths are long so the count is never cut off", () => {
    const directories = Array.from({ length: 6 }, (_, index) => ({
      path: `${"deeply/nested/workspace/".repeat(4)}p${index}/node_modules`,
      reason: null,
    }));
    const note = describeSkippedDependencyDirectories(directories);
    expect(note.length).toBeLessThanOrEqual(MAX_DEPENDENCY_NOTE_LENGTH);
    expect(note).toMatch(/^Skipped 6 dependency directories/);
    expect(note).toMatch(/ and \d more\.$/);
    // Long paths keep their last characters.
    expect(note).toContain("…");
    expect(note).toContain("p0/node_modules/");
  });

  describe("skip signals for later comparison", () => {
    const area = (result: Awaited<ReturnType<typeof scanSourceCode>>, name: string) =>
      result.coverage.find((entry) => entry.area === name);

    it("counts a directory replaced by a symlink, and notices a swap with the same count", async () => {
      const outside = project({ "x.ts": "export {};\n" });
      const first = project({ "a/f.ts": "export {};\n", "b/g.ts": "export {};\n" });
      const second = project({ "a/f.ts": "export {};\n", "b/g.ts": "export {};\n" });
      const third = project({ "a/f.ts": "export {};\n", "b/g.ts": "export {};\n" });
      rmSync(path.join(first, "a"), { recursive: true });
      symlinkSync(outside, path.join(first, "a"), "dir");
      rmSync(path.join(second, "b"), { recursive: true });
      symlinkSync(outside, path.join(second, "b"), "dir");
      const none = await scanSourceCode(third);
      const one = await scanSourceCode(first);
      const other = await scanSourceCode(second);
      expect(area(none, "source:symlinks")).toBeUndefined();
      expect(area(one, "source:symlinks")?.note).toMatch(/^1 symbolic link/);
      expect(area(other, "source:symlinks")?.note).toMatch(/^1 symbolic link/);
      expect(area(one, "source:symlinks")?.note).not.toBe(area(other, "source:symlinks")?.note);
    });

    const canChmod = process.platform !== "win32" && process.getuid?.() !== 0;
    it.skipIf(!canChmod)("reports an unreadable directory as a partial area", async () => {
      const root = project({ "ok/f.ts": "export {};\n", "locked/g.ts": "export {};\n" });
      chmodSync(path.join(root, "locked"), 0o000);
      try {
        const result = await scanSourceCode(root);
        expect(area(result, "source:unreadable")).toMatchObject({
          status: "partial",
          ruleIds: [],
          note: expect.stringContaining("1 directory could not be read"),
        });
      } finally {
        chmodSync(path.join(root, "locked"), 0o700);
      }
    });
  });
});
