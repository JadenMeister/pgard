import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { analyzeGoSource } from "./go/analyze-go.js";
import { analyzeJsSource } from "./js/analyze-js.js";
import { scanSourceCode } from "./scan-source.js";

const js = (code: string, file = "src/app.ts") =>
  analyzeJsSource(code, file).findings.map((f) => f.ruleId);
const goFile = (imports: string[], body: string) =>
  `package main\n\nimport (\n${imports.map((name) => `\t"${name}"`).join("\n")}\n)\n\n${body}\n`;
const go = (source: string) => analyzeGoSource(source, "main.go").findings.map((f) => f.ruleId);

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-src2-")));
  roots.push(root);
  for (const [relative, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
    writeFileSync(path.join(root, relative), content);
  }
  return root;
}

describe("#84 SQL through local db modules, identifier args and multi-line SQL", () => {
  it("flags a query string assigned to a variable and run through a local db module", () => {
    expect(
      js(
        "import db from './db';\nconst q = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(q);",
      ),
    ).toEqual(["PG-SQL-001"]);
  });

  it("flags multi-line SQL templates", () => {
    expect(
      js("import db from './db';\ndb.query(`\n  SELECT *\n  FROM users\n  WHERE id = ${id}\n`);"),
    ).toEqual(["PG-SQL-001"]);
  });

  it("still ignores non-SQL query() calls on unknown receivers", () => {
    expect(js("search.query(`${term} near ${place}`);")).toEqual([]);
  });
});

describe("#85 request input passed straight to raw SQL sinks", () => {
  it.each([
    ["import { Pool } from 'pg'; pool.query(req.body.sql);"],
    ["import db from './db'; db.query(req.body.sql);"],
    ["await prisma.$queryRawUnsafe(req.body.q);"],
    ["const q = req.body.q; await prisma.$executeRawUnsafe(q);"],
  ])("flags %s", (code) => {
    expect(js(code).some((id) => id.startsWith("PG-SQL"))).toBe(true);
  });

  it("flags GORM Order/Where with request input", () => {
    expect(
      go(
        goFile(
          ["gorm.io/gorm"],
          `func f(c *gin.Context) {
	db.Order(c.Query("sort")).Find(&u)
	s := c.Query("filter")
	db.Where(s).Find(&u)
}`,
        ),
      ),
    ).toEqual(["PG-SQL-004", "PG-SQL-004"]);
  });

  it("does not flag literal GORM arguments", () => {
    expect(
      go(goFile(["gorm.io/gorm"], 'func f() { db.Order("created_at desc").Find(&u) }')),
    ).toEqual([]);
  });
});

describe("#86 shells via spawn/execFile and promisified exec", () => {
  it.each([
    ["import { spawn } from 'child_process'; spawn('sh', ['-c', req.query.cmd]);"],
    ["import { execFile } from 'node:child_process'; execFile('bash', ['-c', 'ls ' + dir]);"],
    [
      "import util from 'util'; import { exec } from 'child_process'; const run = util.promisify(exec); run(req.body.cmd);",
    ],
    [
      "import { promisify } from 'util'; import cp from 'child_process'; const run = promisify(cp.exec); await run(`tar ${f}`);",
    ],
  ])("flags %s", (code) => {
    expect(js(code)).toContain("PG-CMD-001");
  });

  it("does not flag a constant script", () => {
    expect(js("import { spawn } from 'child_process'; spawn('sh', ['-c', 'echo ok']);")).toEqual(
      [],
    );
  });
});

describe("#87 linear cost and caps", () => {
  it("analyzes a large Go file quickly", () => {
    const body = Array.from(
      { length: 6000 },
      (_, index) =>
        `\tv${index} := r.FormValue("k${index}")\n\tdb.Query(fmt.Sprintf("SELECT %s", v${index}))`,
    ).join("\n");
    const source = goFile(
      ["database/sql", "fmt", "net/http"],
      `func h(w http.ResponseWriter, r *http.Request) {\n${body}\n}`,
    );
    expect(source.length).toBeGreaterThan(300_000);
    const start = performance.now();
    const analysis = analyzeGoSource(source, "big.go");
    expect(performance.now() - start).toBeLessThan(3000);
    expect(analysis.findings.length).toBeLessThanOrEqual(25);
    expect(analysis.cappedRules).toEqual(["PG-SQL-003"]);
  });

  it("analyzes a large JS file quickly", () => {
    const code = Array.from(
      { length: 8000 },
      (_, index) =>
        `function f${index}(req) { const password = req.body.p${index}; el.innerHTML = x${index}; return check(password); }`,
    ).join("\n");
    expect(code.length).toBeGreaterThan(500_000);
    const start = performance.now();
    const analysis = analyzeJsSource(code, "big.js");
    expect(performance.now() - start).toBeLessThan(5000);
    expect(analysis.cappedRules).toContain("PG-XSS-001");
  });

  it("stops at the time budget with partial coverage", async () => {
    const root = project({ "a.ts": "export const a = 1;", "b.ts": "export const b = 2;" });
    let clock = 0;
    const result = await scanSourceCode(root, { timeBudgetMs: 50, now: () => (clock += 100) });
    const ts = result.coverage.find((entry) => entry.area === "source:typescript");
    expect(ts?.status).toBe("partial");
    expect(ts?.note).toMatch(/time budget/);
  });
});

describe("#88 precision", () => {
  it("treats new URLSearchParams(location.search) as browser input", () => {
    const [finding] = analyzeJsSource(
      "const p = new URLSearchParams(location.search); el.innerHTML = p.get('m');",
      "a.ts",
    ).findings;
    expect(finding).toMatchObject({ ruleId: "PG-XSS-001", severity: "high" });
  });

  it("does not treat constant += concatenation as dynamic SQL", () => {
    expect(
      js(
        "import { Pool } from 'pg'; let sql = 'SELECT * FROM t'; sql += ' WHERE a = $1'; pool.query(sql, [a]);",
      ),
    ).toEqual([]);
  });

  it("tracks Go `var q = ...` assignments", () => {
    expect(
      go(
        goFile(
          ["database/sql"],
          `func f(name string) {
	var q = "SELECT * FROM t WHERE n = '" + name + "'"
	db.Query(q)
}`,
        ),
      ),
    ).toEqual(["PG-SQL-003"]);
  });
});

describe("#89 hygiene", () => {
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
