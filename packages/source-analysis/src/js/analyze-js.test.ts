import { describe, expect, it } from "vitest";
import { analyzeJsSource } from "./analyze-js.js";

const rulesIn = (code: string, path = "src/app.ts") =>
  analyzeJsSource(code, path).findings.map((finding) => finding.ruleId);
const findingsIn = (code: string, path = "src/app.ts") => analyzeJsSource(code, path).findings;

describe("PG-SQL-001 pg/mysql2", () => {
  it("flags request input interpolated into pool.query", () => {
    const [finding] = findingsIn(`
      import { Pool } from "pg";
      const pool = new Pool();
      app.get("/u", async (req, res) => {
        const rows = await pool.query(\`SELECT * FROM users WHERE id = \${req.query.id}\`);
      });
    `);
    expect(finding).toMatchObject({
      ruleId: "PG-SQL-001",
      severity: "high",
      status: "confirmed",
      line: 5,
    });
  });

  it("flags concatenation through a variable (suspected)", () => {
    const [finding] = findingsIn(`
      import mysql from "mysql2/promise";
      export async function find(req, conn) {
        const name = req.body.name;
        const sql = "SELECT * FROM t WHERE name = '" + name + "'";
        return conn.execute(sql);
      }
    `);
    expect(finding).toMatchObject({ ruleId: "PG-SQL-001", severity: "high", status: "suspected" });
  });

  it("flags SQL text built dynamically even without a driver import", () => {
    expect(rulesIn("db.query(`SELECT * FROM t WHERE x = ${value}`);")).toEqual(["PG-SQL-001"]);
  });

  it.each([
    ['import { Pool } from "pg"; pool.query("SELECT * FROM users WHERE id = $1", [req.query.id]);'],
    ['import mysql from "mysql2"; conn.execute("SELECT * FROM t WHERE a = ?", [req.body.a]);'],
    ['import { Pool } from "pg"; pool.query({ text: "SELECT 1 WHERE id = $1", values: [id] });'],
    ["const result = items.query(`${a}`);"],
    ['import { Pool } from "pg"; const sql = "SELECT 1"; pool.query(sql);'],
  ])("does not flag parameter binding or static SQL: %s", (code) => {
    expect(rulesIn(code)).not.toContain("PG-SQL-001");
  });
});

describe("PG-SQL-002 Prisma", () => {
  it("flags $queryRawUnsafe with interpolation", () => {
    expect(
      rulesIn("await prisma.$queryRawUnsafe(`SELECT * FROM u WHERE id = ${req.params.id}`);"),
    ).toEqual(["PG-SQL-002"]);
  });

  it("flags Prisma.raw with dynamic SQL", () => {
    expect(rulesIn("prisma.$queryRaw(Prisma.raw('SELECT * FROM ' + table));")).toEqual([
      "PG-SQL-002",
    ]);
  });

  it.each([
    ["await prisma.$queryRaw`SELECT * FROM u WHERE id = ${req.params.id}`;"],
    ['await prisma.$queryRawUnsafe("SELECT * FROM u WHERE id = $1", req.params.id);'],
    ["await prisma.$executeRaw(Prisma.sql`DELETE FROM u WHERE id = ${id}`);"],
  ])("does not flag tagged templates or bound parameters: %s", (code) => {
    expect(rulesIn(code)).toEqual([]);
  });
});

describe("PG-XSS-001/002 HTML sinks", () => {
  it("rates request/browser input into innerHTML higher than unknown values", () => {
    const [fromInput] = findingsIn("el.innerHTML = location.search;");
    const [unknown] = findingsIn("el.innerHTML = html;");
    expect(fromInput).toMatchObject({
      ruleId: "PG-XSS-001",
      severity: "high",
      confidence: "medium",
      status: "suspected",
    });
    expect(unknown).toMatchObject({
      ruleId: "PG-XSS-001",
      severity: "low",
      confidence: "low",
      status: "suspected",
    });
  });

  it("never marks API use alone as confirmed", () => {
    for (const finding of findingsIn("el.innerHTML = `<b>${name}</b>`; document.write(x);")) {
      expect(finding.status).toBe("suspected");
    }
  });

  it.each([
    ['el.innerHTML = "<b>static</b>";'],
    ["el.innerHTML = `<b>static</b>`;"],
    ["el.innerHTML = DOMPurify.sanitize(req.body.html);"],
    ["el.textContent = req.body.html;"],
  ])("does not flag static or sanitized HTML: %s", (code) => {
    expect(rulesIn(code)).toEqual([]);
  });

  it("flags dangerouslySetInnerHTML with dynamic HTML", () => {
    const findings = findingsIn(
      "export const A = ({ q }) => <div dangerouslySetInnerHTML={{ __html: useSearchParams()[0].get('q') }} />;",
      "src/A.tsx",
    );
    expect(findings[0]).toMatchObject({ ruleId: "PG-XSS-002", severity: "high" });
  });

  it("does not flag dangerouslySetInnerHTML with a literal or sanitizer", () => {
    expect(
      rulesIn(
        'const A = () => <><i dangerouslySetInnerHTML={{ __html: "<b>x</b>" }} /><i dangerouslySetInnerHTML={{ __html: sanitize(x) }} /></>;',
        "src/A.jsx",
      ),
    ).toEqual([]);
  });
});

describe("PG-SSRF-001", () => {
  it.each([
    ["app.get('/p', async (req, res) => { await fetch(req.query.url); });"],
    ["import axios from 'axios'; const target = req.body.target; axios.get(target);"],
    ["import axios from 'axios'; axios({ url: req.query.u, method: 'get' });"],
  ])("flags request input as an outbound URL: %s", (code) => {
    expect(rulesIn(code)).toContain("PG-SSRF-001");
  });

  it.each([
    ["fetch('https://api.example.com/x');"],
    ["fetch(`https://api.example.com/items/${id}`);"],
    ["fetch(location.search);"],
  ])("does not flag fixed URLs or browser-only input: %s", (code) => {
    expect(rulesIn(code)).not.toContain("PG-SSRF-001");
  });
});

describe("PG-CMD-001", () => {
  it("flags exec with request input as critical", () => {
    const [finding] = findingsIn(
      "import { exec } from 'child_process'; exec(`ping ${req.query.host}`);",
    );
    expect(finding).toMatchObject({
      ruleId: "PG-CMD-001",
      severity: "critical",
      status: "confirmed",
    });
  });

  it("flags execSync on a namespace import with a dynamic string", () => {
    expect(
      rulesIn("const cp = require('node:child_process'); cp.execSync('tar -xf ' + file);"),
    ).toEqual(["PG-CMD-001"]);
  });

  it("flags spawn with shell: true and request input", () => {
    expect(
      rulesIn(
        "import { spawn } from 'child_process'; spawn('ls ' + req.query.dir, { shell: true });",
      ),
    ).toEqual(["PG-CMD-001"]);
  });

  it.each([
    ["import { exec } from 'child_process'; exec('ls -la');"],
    ["import { execFile } from 'child_process'; execFile('git', ['log', req.query.ref]);"],
    ["const m = /x/.exec(input); regex.exec(req.body.text);"],
    ["import { spawn } from 'child_process'; spawn('ls', [dir]);"],
  ])("does not flag static commands, argument arrays or unrelated exec: %s", (code) => {
    expect(rulesIn(code)).toEqual([]);
  });
});

describe("PG-PATH-001", () => {
  it.each([
    ["import fs from 'fs'; fs.readFile(req.query.file, cb);"],
    [
      "import { readFileSync } from 'node:fs'; import path from 'path'; readFileSync(path.join(__dirname, req.params.name));",
    ],
    ["app.get('/d', (req, res) => res.download(`/files/${req.query.f}`));"],
  ])("flags request input reaching file reads: %s", (code) => {
    expect(rulesIn(code)).toContain("PG-PATH-001");
  });

  it.each([
    [
      "import fs from 'fs'; import path from 'path'; fs.readFile(path.basename(req.query.file), cb);",
    ],
    ["res.sendFile(req.params.name, { root: '/srv/public' });"],
    ["import fs from 'fs'; fs.readFile('config.json', cb);"],
  ])("does not flag basename, rooted sendFile or fixed paths: %s", (code) => {
    expect(rulesIn(code)).not.toContain("PG-PATH-001");
  });
});

describe("PG-CRYPTO rules", () => {
  it("flags MD5/SHA-1 of passwords only", () => {
    expect(
      rulesIn(
        "import crypto from 'crypto'; const h = crypto.createHash('md5').update(password).digest('hex');",
      ),
    ).toEqual(["PG-CRYPTO-001"]);
    expect(
      rulesIn(
        "import crypto from 'crypto'; const etag = crypto.createHash('sha1').update(body).digest('hex');",
      ),
    ).toEqual([]);
    expect(
      rulesIn("import crypto from 'crypto'; crypto.createHash('sha256').update(password);"),
    ).toEqual([]);
  });

  it("flags hardcoded keys and secrets without echoing them", () => {
    const findings = findingsIn(`
      import crypto from "crypto";
      import jwt from "jsonwebtoken";
      const c = crypto.createCipheriv("aes-256-gcm", "0123456789abcdef0123456789abcdef", iv);
      const t = jwt.sign(payload, "my-jwt-signing-value");
      const v = jwt.verify(token, process.env.JWT_SECRET || "fallback-value");
    `);
    expect(findings.map((finding) => finding.ruleId)).toEqual([
      "PG-CRYPTO-002",
      "PG-CRYPTO-002",
      "PG-CRYPTO-002",
    ]);
    expect(findings[2]).toMatchObject({ severity: "medium", status: "suspected" });
    const text = JSON.stringify(findings);
    expect(text).not.toContain("0123456789abcdef");
    expect(text).not.toContain("my-jwt-signing-value");
    expect(text).not.toContain("fallback-value");
  });

  it("does not flag keys loaded from the environment", () => {
    expect(
      rulesIn(
        "import jwt from 'jsonwebtoken'; jwt.sign(p, process.env.JWT_SECRET); crypto.createCipheriv('aes-256-gcm', key, iv);",
      ),
    ).toEqual([]);
  });

  it("flags broken ciphers", () => {
    expect(
      rulesIn(
        "import crypto from 'crypto'; crypto.createCipheriv('des-ede3', key, iv); crypto.createCipher('aes192', key);",
      ),
    ).toEqual(["PG-CRYPTO-003", "PG-CRYPTO-003"]);
    expect(
      rulesIn("import crypto from 'crypto'; crypto.createCipheriv('aes-256-gcm', key, iv);"),
    ).toEqual([]);
  });
});

describe("PG-AUTH-001 plaintext password storage", () => {
  it("flags storing request password without hashing", () => {
    expect(
      rulesIn(
        "async function signup(req) { await User.create({ email: req.body.email, password: req.body.password }); }",
      ),
    ).toEqual(["PG-AUTH-001"]);
    expect(
      rulesIn(
        "async function signup(email, password) { await prisma.user.create({ data: { email, password } }); }",
      ),
    ).toEqual(["PG-AUTH-001"]);
  });

  it("does not flag when the password is hashed in the same function", () => {
    expect(
      rulesIn(
        "import bcrypt from 'bcrypt'; async function signup(req) { const password = await bcrypt.hash(req.body.password, 12); await User.create({ password }); }",
      ),
    ).toEqual([]);
    expect(rulesIn("async function f(req) { await User.create({ password: hashed }); }")).toEqual(
      [],
    );
  });
});

describe("PG-COOKIE-001", () => {
  it("flags session cookies without flags", () => {
    const [finding] = findingsIn("res.cookie('session', token);");
    expect(finding).toMatchObject({ ruleId: "PG-COOKIE-001", severity: "medium" });
    expect(finding?.evidence).toContain("httpOnly");
  });

  it("flags express-session without secure", () => {
    expect(
      rulesIn(
        "import session from 'express-session'; app.use(session({ secret: process.env.S, cookie: { httpOnly: true, sameSite: 'lax' } }));",
      ),
    ).toEqual(["PG-COOKIE-001"]);
  });

  it("does not flag fully configured cookies", () => {
    expect(
      rulesIn(
        "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' });",
      ),
    ).toEqual([]);
    expect(
      rulesIn(
        "import session from 'express-session'; app.use(session({ secret: process.env.S, cookie: { secure: true, httpOnly: true, sameSite: 'lax' } }));",
      ),
    ).toEqual([]);
  });
});

describe("facts and robustness", () => {
  it("collects routes, imports and cookie usage for project heuristics", () => {
    const { facts } = analyzeJsSource(
      "import express from 'express'; const app = express(); app.post('/login', h); app.delete('/items/:id', h); res.cookie('sid', v, opts);",
      "src/server.js",
    );
    expect(facts.imports).toContain("express");
    expect(facts.authRoutes).toEqual([{ line: 1, routePath: "/login" }]);
    expect(facts.stateChangingRoutes).toHaveLength(2);
    expect(facts.usesCookieSession).toBe(true);
  });

  it("reports syntax errors without throwing", () => {
    const analysis = analyzeJsSource("function (", "src/broken.ts");
    expect(analysis.hasParseErrors).toBe(true);
  });

  it("applies the line offset for embedded scripts", () => {
    const { findings } = analyzeJsSource("\n\nel.innerHTML = html;", "c.vue", { lineOffset: 10 });
    expect(findings[0]?.line).toBe(13);
  });
});

describe("per-function facts stay linear (#104)", () => {
  it("analyzes many crypto and persistence call sites in one large function quickly", () => {
    const body = Array.from(
      { length: 6000 },
      (_, index) =>
        `  crypto.createHash("md5").update(x${index}); await User.create({ password: req.body.p${index} });`,
    ).join("\n");
    const code = `import crypto from "crypto";\nasync function big(req) {\n${body}\n}\n`;
    expect(code.length).toBeGreaterThan(400_000);
    const start = performance.now();
    analyzeJsSource(code, "big.js");
    expect(performance.now() - start).toBeLessThan(5000);
  });

  it("still detects MD5 of passwords via update() in the same function", () => {
    const rules = analyzeJsSource(
      "import crypto from 'crypto'; function f(password) { const h = crypto.createHash('md5'); h.update(password); }",
      "a.js",
    ).findings.map((f) => f.ruleId);
    expect(rules).toEqual(["PG-CRYPTO-001"]);
  });
});
