import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanSourceCode } from "./scan-source.js";

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
    expect(coverage["source:go"]?.note).toMatch(/syntax-level/);
    expect(coverage["source:react"]?.ruleIds).toEqual(["PG-XSS-002"]);
    expect(coverage["source:large-files"]).toMatchObject({ status: "partial" });
    expect(coverage["source:orm:typeorm"]).toMatchObject({ status: "partial" });
    expect(coverage["source:orm:typeorm"]?.note).toMatch(/not supported/);
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

  it("produces stable ids across runs", async () => {
    const root = project({ "src/db.ts": SQL_VULN });
    const first = await scanSourceCode(root);
    const second = await scanSourceCode(root);
    expect(first.findings.map((f) => f.id)).toEqual(second.findings.map((f) => f.id));
  });
});
