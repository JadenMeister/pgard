import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { CachedSourceFile } from "@pgard/findings";
import { afterEach, describe, expect, it } from "vitest";
import { scanSourceCode } from "./scan-source.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-reuse-")));
  roots.push(root);
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  return root;
}

const SQL = (name: string) =>
  `import { Pool } from "pg";\nconst pool = new Pool();\nexport const ${name} = (req) => pool.query(\`SELECT * FROM t WHERE id = \${req.query.id}\`);\n`;

const reuseOf = (entries: CachedSourceFile[]) => ({
  files: new Map(entries.map((entry) => [entry.path, entry])),
  label: "abcd1234",
});

describe("scanSourceCode with results of an earlier scan", () => {
  it("returns one cache entry per analyzed file and reuses it for an unchanged file", async () => {
    const root = project({ "a.js": SQL("a"), "b.js": "export const b = 1;\n" });
    const first = await scanSourceCode(root);
    expect(first.reuse).toEqual({ rescanned: 2, reused: 0 });
    expect(first.fileCache.map((entry) => entry.path).sort()).toEqual(["a.js", "b.js"]);
    const second = await scanSourceCode(root, { reuse: reuseOf(first.fileCache) });
    expect(second.reuse).toEqual({ rescanned: 0, reused: 2 });
    expect(second.findings).toEqual(first.findings);
    expect(second.ruleStats).toEqual(first.ruleStats);
    expect(second.coverage.find((entry) => entry.area === "source:javascript")?.note).toContain(
      "2 file(s) reused from scan abcd1234",
    );
  });

  it("analyzes a file again when its text changed, and ignores files that are gone", async () => {
    const root = project({ "a.js": SQL("a"), "b.js": "export const b = 1;\n" });
    const first = await scanSourceCode(root);
    writeFileSync(path.join(root, "b.js"), "export const b = 2;\n");
    rmSync(path.join(root, "a.js"));
    const second = await scanSourceCode(root, { reuse: reuseOf(first.fileCache) });
    expect(second.reuse).toEqual({ rescanned: 1, reused: 0 });
    expect(second.findings).toEqual([]);
  });

  it("evaluates the project-wide checks again from the facts of reused files", async () => {
    const server =
      "import express from 'express';\nimport session from 'express-session';\nconst app = express();\napp.use(session({ secret: process.env.S, cookie: { secure: true, sameSite: 'lax' } }));\napp.post('/login', login);\n";
    const root = project({ "server.js": server });
    const first = await scanSourceCode(root);
    expect(first.findings.map((f) => f.ruleId)).toContain("PG-CSRF-001");
    writeFileSync(path.join(root, "guard.js"), "import csrf from 'csurf';\nexport default csrf;\n");
    const second = await scanSourceCode(root, { reuse: reuseOf(first.fileCache) });
    expect(second.reuse).toEqual({ rescanned: 1, reused: 1 });
    expect(second.findings.map((f) => f.ruleId)).not.toContain("PG-CSRF-001");
  });

  it("does not trust an entry whose facts have the wrong shape", async () => {
    const root = project({ "a.js": SQL("a") });
    const first = await scanSourceCode(root);
    const broken = first.fileCache.map((entry) => ({
      ...entry,
      facts: { imports: "pg" } as unknown as Record<string, unknown>,
    }));
    const second = await scanSourceCode(root, { reuse: reuseOf(broken) });
    expect(second.reuse).toEqual({ rescanned: 1, reused: 0 });
    expect(second.findings).toEqual(first.findings);
  });
});
